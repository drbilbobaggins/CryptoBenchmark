#include "adapters/EcdsaAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <openssl/evp.h>

#include <array>
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
using crypto::EcdsaAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::EcCurve;
using core::EcdsaParameters;
using core::SignatureConfig;
using core::SignatureDigest;
using core::ValidationResult;

struct EcdsaCase {
    AlgorithmProfileId profile;
    EcCurve curve;
    SignatureDigest digest;
    std::size_t digestBytes;
    std::size_t signatureCapacity;
};

constexpr std::array ecdsaCases{
    EcdsaCase{AlgorithmProfileId::EcdsaP256Sha256, EcCurve::P256, SignatureDigest::Sha256, 32, 72},
    EcdsaCase{AlgorithmProfileId::EcdsaP256Sha384, EcCurve::P256, SignatureDigest::Sha384, 48, 72},
    EcdsaCase{AlgorithmProfileId::EcdsaP256Sha512, EcCurve::P256, SignatureDigest::Sha512, 64, 72},
    EcdsaCase{AlgorithmProfileId::EcdsaP384Sha256, EcCurve::P384, SignatureDigest::Sha256, 32, 104},
    EcdsaCase{AlgorithmProfileId::EcdsaP384Sha384, EcCurve::P384, SignatureDigest::Sha384, 48, 104},
    EcdsaCase{AlgorithmProfileId::EcdsaP384Sha512, EcCurve::P384, SignatureDigest::Sha512, 64, 104},
    EcdsaCase{AlgorithmProfileId::EcdsaP521Sha256, EcCurve::P521, SignatureDigest::Sha256, 32, 139},
    EcdsaCase{AlgorithmProfileId::EcdsaP521Sha384, EcCurve::P521, SignatureDigest::Sha384, 48, 139},
    EcdsaCase{AlgorithmProfileId::EcdsaP521Sha512, EcCurve::P521, SignatureDigest::Sha512, 64, 139}};

constexpr std::array keyGenCases{
    std::pair{AlgorithmProfileId::EcdsaP256KeyGen, EcCurve::P256},
    std::pair{AlgorithmProfileId::EcdsaP384KeyGen, EcCurve::P384},
    std::pair{AlgorithmProfileId::EcdsaP521KeyGen, EcCurve::P521}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical ECDSA profile was not found");
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
    require(validated.has_value() && validation.isValid(), "ECDSA configuration validation failed");
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

EcdsaAdapter& asEcdsa(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<EcdsaAdapter*>(&adapter);
    require(result != nullptr, "factory did not create EcdsaAdapter");
    return *result;
}

std::string_view digestName(SignatureDigest digest)
{
    switch (digest) {
    case SignatureDigest::Sha256: return "SHA256";
    case SignatureDigest::Sha384: return "SHA384";
    case SignatureDigest::Sha512: return "SHA512";
    }
    throw std::invalid_argument("unknown ECDSA digest");
}

crypto::openssl::EvpMdPtr fetchDigest(SignatureDigest digest)
{
    crypto::openssl::EvpMdPtr result(
        EVP_MD_fetch(nullptr, digestName(digest).data(), nullptr), &EVP_MD_free);
    require(result != nullptr, "could not fetch direct ECDSA digest");
    return result;
}

void directVerify(
    EVP_PKEY* key,
    SignatureDigest digest,
    std::span<const unsigned char> digestBytes,
    std::span<const unsigned char> signature)
{
    require(key != nullptr, "ECDSA key was null");
    auto md = fetchDigest(digest);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ECDSA verify context");
    require(EVP_PKEY_verify_init(context.get()) == 1, "direct ECDSA verify init failed");
    require(EVP_PKEY_CTX_set_signature_md(context.get(), md.get()) == 1, "direct ECDSA digest setup failed");
    require(
        EVP_PKEY_verify(context.get(), signature.data(), signature.size(), digestBytes.data(), digestBytes.size()) == 1,
        "direct ECDSA verification failed");
}

std::vector<unsigned char> directSign(EVP_PKEY* key, SignatureDigest digest, std::span<const unsigned char> digestBytes)
{
    auto md = fetchDigest(digest);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ECDSA sign context");
    require(EVP_PKEY_sign_init(context.get()) == 1, "direct ECDSA sign init failed");
    require(EVP_PKEY_CTX_set_signature_md(context.get(), md.get()) == 1, "direct ECDSA digest setup failed");
    std::vector<unsigned char> signature(139);
    std::size_t signatureLength = signature.size();
    require(
        EVP_PKEY_sign(context.get(), signature.data(), &signatureLength, digestBytes.data(), digestBytes.size()) == 1,
        "direct ECDSA sign failed");
    signature.resize(signatureLength);
    return signature;
}

void requireSignatureBounds(const EcdsaAdapter& adapter, std::size_t capacity)
{
    require(adapter.signatureForTesting().size() > 0, "ECDSA signature was empty");
    require(adapter.signatureForTesting().size() <= capacity, "ECDSA signature exceeded DER capacity");
}

void testKeyGenUsability()
{
    for (const auto& [profile, curve] : keyGenCases) {
        auto owner = createAdapter(profile, BenchmarkOperation::KeyGen, SignatureConfig{core::NoSignatureInput{}});
        auto& adapter = asEcdsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        const auto digest = std::vector<unsigned char>(32, 0xA5U);
        const auto signature = directSign(adapter.currentKeyForTesting(), SignatureDigest::Sha256, digest);
        directVerify(adapter.currentKeyForTesting(), SignatureDigest::Sha256, digest, signature);
        static_cast<void>(curve);
    }
}

void testRepeatedKeyGen()
{
    auto owner = createAdapter(
        AlgorithmProfileId::EcdsaP256KeyGen, BenchmarkOperation::KeyGen,
        SignatureConfig{core::NoSignatureInput{}});
    auto& adapter = asEcdsa(*owner);
    adapter.prepareSeries();
    adapter.executeIteration();
    EVP_PKEY* first = adapter.currentKeyForTesting();
    require(first != nullptr && EVP_PKEY_up_ref(first) == 1, "could not retain first ECDSA key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstReference(first, &EVP_PKEY_free);
    adapter.executeIteration();
    EVP_PKEY* second = adapter.currentKeyForTesting();
    require(second != nullptr && EVP_PKEY_eq(firstReference.get(), second) == 0, "repeated ECDSA KeyGen reused the key");
    const auto digest = std::vector<unsigned char>(32, 0xA5U);
    directVerify(second, SignatureDigest::Sha256, digest, directSign(second, SignatureDigest::Sha256, digest));
}

void testProductionSignCorrectness()
{
    for (const auto& testCase : ecdsaCases) {
        auto owner = createAdapter(testCase.profile, BenchmarkOperation::Sign, SignatureConfig{core::PrehashedInput{}});
        auto& adapter = asEcdsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.digestForTesting().size() == testCase.digestBytes, "ECDSA digest length mismatch");
        requireSignatureBounds(adapter, testCase.signatureCapacity);
        directVerify(adapter.signingKeyForTesting(), testCase.digest, adapter.digestForTesting(), adapter.signatureForTesting());
    }
}

void testProductionVerifyCorrectness()
{
    for (const auto& testCase : ecdsaCases) {
        auto owner = createAdapter(testCase.profile, BenchmarkOperation::Verify, SignatureConfig{core::PrehashedInput{}});
        auto& adapter = asEcdsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.digestForTesting().size() == testCase.digestBytes, "ECDSA verify digest length mismatch");
        requireSignatureBounds(adapter, testCase.signatureCapacity);
    }
}

void testRepeatedSignAndVerify()
{
    auto signOwner = createAdapter(
        AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign,
        SignatureConfig{core::PrehashedInput{}});
    auto& sign = asEcdsa(*signOwner);
    sign.prepareSeries();
    sign.executeIteration();
    directVerify(sign.signingKeyForTesting(), SignatureDigest::Sha256, sign.digestForTesting(), sign.signatureForTesting());
    sign.executeIteration();
    requireSignatureBounds(sign, 72);
    directVerify(sign.signingKeyForTesting(), SignatureDigest::Sha256, sign.digestForTesting(), sign.signatureForTesting());

    auto verifyOwner = createAdapter(
        AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Verify,
        SignatureConfig{core::PrehashedInput{}});
    auto& verify = asEcdsa(*verifyOwner);
    verify.prepareSeries();
    verify.executeIteration();
    verify.executeIteration();
}

void testFactoryCreatesAllM077Paths()
{
    for (const auto& [profile, curve] : keyGenCases) {
        auto adapter = createAdapter(profile, BenchmarkOperation::KeyGen, SignatureConfig{core::NoSignatureInput{}});
        adapter->prepareSeries();
        adapter->executeIteration();
        static_cast<void>(curve);
    }
    for (const auto& testCase : ecdsaCases) {
        for (const auto operation : {BenchmarkOperation::Sign, BenchmarkOperation::Verify}) {
            auto adapter = createAdapter(testCase.profile, operation, SignatureConfig{core::PrehashedInput{}});
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
}

void testMessageModeRemainsUnsupported()
{
    bool rejected = false;
    try {
        static_cast<void>(createAdapter(
            AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign,
            SignatureConfig{core::MessageInput{1}}));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "ECDSA Message mode was not rejected before M07.8");
}

void testFactoryRejectsWrongVariants()
{
    const auto validated = validateConfig(
        AlgorithmProfileId::EcdsaP256KeyGen, BenchmarkOperation::KeyGen,
        SignatureConfig{core::NoSignatureInput{}});
    auto mismatchedProfile = profileFor(AlgorithmProfileId::EcdsaP256KeyGen);
    mismatchedProfile.parameters = EcdsaParameters{EcCurve::P256, SignatureDigest::Sha256};
    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::KeyGen, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "ECDSA factory accepted an incorrect parameter variant");

    bool operationRejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(
            profileFor(AlgorithmProfileId::EcdsaP256KeyGen), BenchmarkOperation::Sign, validated));
    } catch (const std::logic_error&) {
        operationRejected = true;
    }
    require(operationRejected, "ECDSA factory accepted an operation/profile mismatch");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"ECDSA KeyGen usability", &testKeyGenUsability},
            std::pair{"repeated ECDSA KeyGen", &testRepeatedKeyGen},
            std::pair{"production Prehashed Sign correctness", &testProductionSignCorrectness},
            std::pair{"production Prehashed Verify correctness", &testProductionVerifyCorrectness},
            std::pair{"repeated ECDSA Sign and Verify", &testRepeatedSignAndVerify},
            std::pair{"all M07.7 factory paths", &testFactoryCreatesAllM077Paths},
            std::pair{"Message mode remains unsupported", &testMessageModeRemainsUnsupported},
            std::pair{"factory rejects wrong variants", &testFactoryRejectsWrongVariants}};
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS ECDSA adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
