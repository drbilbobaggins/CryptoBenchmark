#include "adapters/RsaPssAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <array>
#include <cstddef>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::AdapterFactory;
using crypto::RsaPssAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::RsaModulusBits;
using core::SignatureConfig;
using core::SignatureDigest;
using core::ValidationResult;

struct RsaPssCase {
    AlgorithmProfileId profile;
    RsaModulusBits modulusBits;
    SignatureDigest digest;
    std::size_t digestBytes;
    std::size_t signatureBytes;
};

constexpr std::array pssCases{
    RsaPssCase{AlgorithmProfileId::RsaPss2048Sha256, RsaModulusBits::Bits2048, SignatureDigest::Sha256, 32, 256},
    RsaPssCase{AlgorithmProfileId::RsaPss2048Sha384, RsaModulusBits::Bits2048, SignatureDigest::Sha384, 48, 256},
    RsaPssCase{AlgorithmProfileId::RsaPss2048Sha512, RsaModulusBits::Bits2048, SignatureDigest::Sha512, 64, 256},
    RsaPssCase{AlgorithmProfileId::RsaPss3072Sha256, RsaModulusBits::Bits3072, SignatureDigest::Sha256, 32, 384},
    RsaPssCase{AlgorithmProfileId::RsaPss3072Sha384, RsaModulusBits::Bits3072, SignatureDigest::Sha384, 48, 384},
    RsaPssCase{AlgorithmProfileId::RsaPss3072Sha512, RsaModulusBits::Bits3072, SignatureDigest::Sha512, 64, 384},
    RsaPssCase{AlgorithmProfileId::RsaPss4096Sha256, RsaModulusBits::Bits4096, SignatureDigest::Sha256, 32, 512},
    RsaPssCase{AlgorithmProfileId::RsaPss4096Sha384, RsaModulusBits::Bits4096, SignatureDigest::Sha384, 48, 512},
    RsaPssCase{AlgorithmProfileId::RsaPss4096Sha512, RsaModulusBits::Bits4096, SignatureDigest::Sha512, 64, 512}};

struct KeyGenCase {
    AlgorithmProfileId profile;
    RsaModulusBits modulusBits;
    std::size_t signatureBytes;
};

constexpr std::array keyGenCases{
    KeyGenCase{AlgorithmProfileId::Rsa2048KeyGen, RsaModulusBits::Bits2048, 256},
    KeyGenCase{AlgorithmProfileId::Rsa3072KeyGen, RsaModulusBits::Bits3072, 384},
    KeyGenCase{AlgorithmProfileId::Rsa4096KeyGen, RsaModulusBits::Bits4096, 512}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical RSA profile was not found");
    return *profile;
}

core::ValidatedBenchmarkConfig validateConfig(
    AlgorithmProfileId profileId,
    BenchmarkOperation operation,
    SignatureConfig signatureConfig)
{
    const core::BenchmarkConfig config{profileId, operation, 1, 1, std::move(signatureConfig)};
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "RSA configuration validation failed");
    return std::move(*validated);
}

std::unique_ptr<core::AlgorithmAdapter> createAdapter(
    AlgorithmProfileId profileId,
    BenchmarkOperation operation,
    SignatureConfig signatureConfig)
{
    auto validated = validateConfig(profileId, operation, std::move(signatureConfig));
    return AdapterFactory{}.create(profileFor(profileId), operation, validated);
}

RsaPssAdapter& asRsaPss(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<RsaPssAdapter*>(&adapter);
    require(result != nullptr, "factory did not create RsaPssAdapter");
    return *result;
}

std::string_view digestName(SignatureDigest digest)
{
    switch (digest) {
    case SignatureDigest::Sha256: return "SHA256";
    case SignatureDigest::Sha384: return "SHA384";
    case SignatureDigest::Sha512: return "SHA512";
    }
    throw std::invalid_argument("unknown RSA digest");
}

std::vector<unsigned char> fixedDigest(std::size_t bytes)
{
    return std::vector<unsigned char>(bytes, 0xA5U);
}

crypto::openssl::EvpMdPtr fetchDigest(SignatureDigest digest)
{
    crypto::openssl::EvpMdPtr result(
        EVP_MD_fetch(nullptr, digestName(digest).data(), nullptr), &EVP_MD_free);
    require(result != nullptr, "could not fetch direct RSA-PSS digest");
    return result;
}

void configurePss(EVP_PKEY_CTX* context, EVP_MD* digest)
{
    require(EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) == 1, "direct PSS padding failed");
    require(EVP_PKEY_CTX_set_signature_md(context, digest) == 1, "direct signature digest failed");
    require(EVP_PKEY_CTX_set_rsa_mgf1_md(context, digest) == 1, "direct MGF1 digest failed");
    require(
        EVP_PKEY_CTX_set_rsa_pss_saltlen(context, RSA_PSS_SALTLEN_DIGEST) == 1,
        "direct PSS salt length failed");
}

std::vector<unsigned char> directSign(
    EVP_PKEY* key,
    SignatureDigest digest,
    std::span<const unsigned char> digestBytes,
    std::size_t signatureBytes)
{
    require(key != nullptr, "KeyGen produced a null RSA key");
    auto md = fetchDigest(digest);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct RSA-PSS sign context");
    require(EVP_PKEY_sign_init(context.get()) == 1, "direct sign init failed");
    configurePss(context.get(), md.get());
    std::vector<unsigned char> signature(signatureBytes);
    std::size_t signatureLength = signature.size();
    require(
        EVP_PKEY_sign(
            context.get(), signature.data(), &signatureLength,
            digestBytes.data(), digestBytes.size()) == 1,
        "direct RSA-PSS sign failed");
    require(signatureLength == signatureBytes, "direct RSA-PSS signature length mismatch");
    return signature;
}

void requireDirectVerify(
    EVP_PKEY* key,
    SignatureDigest digest,
    std::span<const unsigned char> digestBytes,
    std::span<const unsigned char> signature)
{
    require(key != nullptr, "RSA verification key was null");
    auto md = fetchDigest(digest);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct RSA-PSS verify context");
    require(EVP_PKEY_verify_init(context.get()) == 1, "direct verify init failed");
    configurePss(context.get(), md.get());
    require(
        EVP_PKEY_verify(
            context.get(), signature.data(), signature.size(),
            digestBytes.data(), digestBytes.size()) == 1,
        "direct RSA-PSS verification failed");
}

void testKeyGenUsability()
{
    for (const auto& testCase : keyGenCases) {
        auto adapterOwner = createAdapter(
            testCase.profile, BenchmarkOperation::KeyGen,
            SignatureConfig{core::NoSignatureInput{}});
        auto& adapter = asRsaPss(*adapterOwner);
        adapter.prepareSeries();
        adapter.executeIteration();
        const auto digest = fixedDigest(32);
        const auto signature = directSign(
            adapter.currentKeyForTesting(), SignatureDigest::Sha256, digest, testCase.signatureBytes);
        require(signature.size() == testCase.signatureBytes, "KeyGen signature length mismatch");
        requireDirectVerify(
            adapter.currentKeyForTesting(), SignatureDigest::Sha256, digest, signature);
    }
}

void testRepeatedKeyGenUsability()
{
    auto adapterOwner = createAdapter(
        AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen,
        SignatureConfig{core::NoSignatureInput{}});
    auto& adapter = asRsaPss(*adapterOwner);
    adapter.prepareSeries();
    adapter.executeIteration();
    EVP_PKEY* firstKey = adapter.currentKeyForTesting();
    require(firstKey != nullptr, "first RSA key was null");
    require(EVP_PKEY_up_ref(firstKey) == 1, "could not retain first RSA key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstKeyReference(firstKey, &EVP_PKEY_free);
    adapter.executeIteration();
    EVP_PKEY* secondKey = adapter.currentKeyForTesting();
    require(secondKey != nullptr, "second RSA key was null");
    require(EVP_PKEY_eq(firstKeyReference.get(), secondKey) == 0, "repeated RSA KeyGen reused the key");
    const auto digest = fixedDigest(32);
    const auto signature = directSign(secondKey, SignatureDigest::Sha256, digest, 256);
    requireDirectVerify(secondKey, SignatureDigest::Sha256, digest, signature);
}

void testProductionSignCorrectness()
{
    for (const auto& testCase : pssCases) {
        auto adapterOwner = createAdapter(
            testCase.profile, BenchmarkOperation::Sign,
            SignatureConfig{core::PrehashedInput{}});
        auto& adapter = asRsaPss(*adapterOwner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.digestForTesting().size() == testCase.digestBytes, "digest length mismatch");
        require(adapter.signatureForTesting().size() == testCase.signatureBytes, "signature length mismatch");
        requireDirectVerify(
            adapter.signingKeyForTesting(), testCase.digest,
            adapter.digestForTesting(), adapter.signatureForTesting());
    }
}

void testProductionVerifyCorrectness()
{
    for (const auto& testCase : pssCases) {
        auto adapterOwner = createAdapter(
            testCase.profile, BenchmarkOperation::Verify,
            SignatureConfig{core::PrehashedInput{}});
        auto& adapter = asRsaPss(*adapterOwner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.digestForTesting().size() == testCase.digestBytes, "verify digest length mismatch");
        require(adapter.signatureForTesting().size() == testCase.signatureBytes, "verify signature length mismatch");
    }
}

void testRepeatedSignAndVerify()
{
    auto signOwner = createAdapter(
        AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign,
        SignatureConfig{core::PrehashedInput{}});
    auto& sign = asRsaPss(*signOwner);
    sign.prepareSeries();
    sign.executeIteration();
    const auto firstSignature = std::vector<unsigned char>(
        sign.signatureForTesting().begin(), sign.signatureForTesting().end());
    requireDirectVerify(sign.signingKeyForTesting(), SignatureDigest::Sha256, sign.digestForTesting(), firstSignature);
    sign.executeIteration();
    require(sign.signatureForTesting().size() == 256, "repeated RSA-PSS signature length mismatch");
    requireDirectVerify(sign.signingKeyForTesting(), SignatureDigest::Sha256, sign.digestForTesting(), sign.signatureForTesting());

    auto verifyOwner = createAdapter(
        AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Verify,
        SignatureConfig{core::PrehashedInput{}});
    auto& verify = asRsaPss(*verifyOwner);
    verify.prepareSeries();
    verify.executeIteration();
    verify.executeIteration();
}

void testFactoryCreatesAllM075Paths()
{
    for (const auto& testCase : keyGenCases) {
        auto adapter = createAdapter(
            testCase.profile, BenchmarkOperation::KeyGen,
            SignatureConfig{core::NoSignatureInput{}});
        adapter->prepareSeries();
        adapter->executeIteration();
    }
    for (const auto& testCase : pssCases) {
        for (const auto operation : {BenchmarkOperation::Sign, BenchmarkOperation::Verify}) {
            auto adapter = createAdapter(
                testCase.profile, operation,
                SignatureConfig{core::PrehashedInput{}});
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
}

void testMessageInputRemainsUnsupported()
{
    const auto validated = validateConfig(
        AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign,
        SignatureConfig{core::MessageInput{1}});
    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(
            profileFor(AlgorithmProfileId::RsaPss2048Sha256), BenchmarkOperation::Sign, validated));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "RSA-PSS Message input was not rejected before M07.6");
}

void testFactoryRejectsIncorrectParameterVariant()
{
    const auto validated = validateConfig(
        AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen,
        SignatureConfig{core::NoSignatureInput{}});
    auto mismatchedProfile = profileFor(AlgorithmProfileId::Rsa2048KeyGen);
    mismatchedProfile.parameters = core::EcdsaParameters{core::EcCurve::P256, SignatureDigest::Sha256};

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::KeyGen, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "RSA factory accepted an incorrect parameter variant");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"RSA KeyGen usability", &testKeyGenUsability},
            std::pair{"repeated RSA KeyGen usability", &testRepeatedKeyGenUsability},
            std::pair{"production Prehashed Sign correctness", &testProductionSignCorrectness},
            std::pair{"production Prehashed Verify correctness", &testProductionVerifyCorrectness},
            std::pair{"repeated RSA-PSS Sign and Verify", &testRepeatedSignAndVerify},
            std::pair{"all M07.5 factory paths", &testFactoryCreatesAllM075Paths},
            std::pair{"Message input remains unsupported", &testMessageInputRemainsUnsupported},
            std::pair{"factory rejects incorrect parameter variant", &testFactoryRejectsIncorrectParameterVariant}};
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS RSA-PSS adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
