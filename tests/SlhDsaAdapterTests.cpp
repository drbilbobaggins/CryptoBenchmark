#include "adapters/SlhDsaAdapter.h"

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/crypto/AdapterFactory.h>

#include <openssl/evp.h>

#include <array>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::AdapterFactory;
using crypto::SlhDsaAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::SignatureConfig;
using core::SlhDsaParameters;
using core::SlhHashFamily;
using core::SlhSecurityLevel;
using core::SlhVariant;
using core::ValidationResult;

struct SlhDsaCase {
    AlgorithmProfileId profile;
    SlhDsaParameters parameters;
    std::string_view algorithm;
    std::size_t publicKeyBytes;
    std::size_t privateKeyBytes;
    std::size_t signatureBytes;
};

constexpr std::array cases{
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2128S,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits128, SlhVariant::Small},
        "SLH-DSA-SHA2-128s", 32, 64, 7856},
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2128F,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits128, SlhVariant::Fast},
        "SLH-DSA-SHA2-128f", 32, 64, 17088},
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2192S,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits192, SlhVariant::Small},
        "SLH-DSA-SHA2-192s", 48, 96, 16224},
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2192F,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits192, SlhVariant::Fast},
        "SLH-DSA-SHA2-192f", 48, 96, 35664},
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2256S,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits256, SlhVariant::Small},
        "SLH-DSA-SHA2-256s", 64, 128, 29792},
    SlhDsaCase{AlgorithmProfileId::SlhDsaSha2256F,
        {SlhHashFamily::Sha2, SlhSecurityLevel::Bits256, SlhVariant::Fast},
        "SLH-DSA-SHA2-256f", 64, 128, 49856},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake128S,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits128, SlhVariant::Small},
        "SLH-DSA-SHAKE-128s", 32, 64, 7856},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake128F,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits128, SlhVariant::Fast},
        "SLH-DSA-SHAKE-128f", 32, 64, 17088},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake192S,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits192, SlhVariant::Small},
        "SLH-DSA-SHAKE-192s", 48, 96, 16224},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake192F,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits192, SlhVariant::Fast},
        "SLH-DSA-SHAKE-192f", 48, 96, 35664},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake256S,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits256, SlhVariant::Small},
        "SLH-DSA-SHAKE-256s", 64, 128, 29792},
    SlhDsaCase{AlgorithmProfileId::SlhDsaShake256F,
        {SlhHashFamily::Shake, SlhSecurityLevel::Bits256, SlhVariant::Fast},
        "SLH-DSA-SHAKE-256f", 64, 128, 49856}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical SLH-DSA profile was not found");
    return *profile;
}

core::ValidatedBenchmarkConfig validateConfig(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    SignatureConfig signatureConfig)
{
    const core::BenchmarkConfig config{profile, operation, 1, 1, std::move(signatureConfig)};
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "SLH-DSA configuration validation failed");
    return std::move(*validated);
}

std::unique_ptr<core::AlgorithmAdapter> createAdapter(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    SignatureConfig signatureConfig)
{
    auto validated = validateConfig(profile, operation, std::move(signatureConfig));
    return AdapterFactory{}.create(profileFor(profile), operation, validated);
}

SlhDsaAdapter& asSlhDsa(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<SlhDsaAdapter*>(&adapter);
    require(result != nullptr, "factory did not create SlhDsaAdapter");
    return *result;
}

int directVerify(
    EVP_PKEY* key,
    std::string_view algorithm,
    std::span<const unsigned char> message,
    std::span<const unsigned char> signature)
{
    require(key != nullptr, "SLH-DSA key was null");
    crypto::openssl::EvpSignaturePtr signatureAlgorithm(
        EVP_SIGNATURE_fetch(nullptr, algorithm.data(), nullptr), &EVP_SIGNATURE_free);
    require(signatureAlgorithm != nullptr, "could not fetch direct SLH-DSA signature");
    crypto::openssl::EvpPkeyCtxPtr context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct SLH-DSA verify context");
    require(EVP_PKEY_verify_message_init(context.get(), signatureAlgorithm.get(), nullptr) == 1,
            "direct SLH-DSA verify message init failed");
    return EVP_PKEY_verify(context.get(), signature.data(), signature.size(), message.data(), message.size());
}

void testFixedMetadata()
{
    for (const auto& testCase : cases) {
        const auto& characteristics = std::get<core::SignatureCharacteristics>(
            profileFor(testCase.profile).characteristics);
        require(characteristics.publicKeyBytes && *characteristics.publicKeyBytes == testCase.publicKeyBytes,
                "SLH-DSA public-key metadata mismatch");
        require(characteristics.privateKeyBytes && *characteristics.privateKeyBytes == testCase.privateKeyBytes,
                "SLH-DSA private-key metadata mismatch");
        require(characteristics.signatureSize &&
                    characteristics.signatureSize->kind == core::SignatureSizeReferenceKind::Fixed,
                "SLH-DSA signature metadata was not fixed");
        require(characteristics.signatureSize->bytes == testCase.signatureBytes,
                "SLH-DSA signature metadata mismatch");
    }
}

void testAllProductionPaths()
{
    constexpr std::array message{'a', 'b', 'c'};
    const auto messageBytes = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(message.data()), message.size());

    for (const auto& testCase : cases) {
        auto keygenOwner = createAdapter(testCase.profile, BenchmarkOperation::KeyGen,
                                         SignatureConfig{core::NoSignatureInput{}});
        auto& keygen = asSlhDsa(*keygenOwner);
        keygen.prepareSeries();
        keygen.executeIteration();
        require(keygen.currentKeyForTesting() != nullptr, "SLH-DSA KeyGen did not produce a key");

        auto signOwner = createAdapter(testCase.profile, BenchmarkOperation::Sign,
                                       SignatureConfig{core::MessageInput{message.size()}});
        auto& sign = asSlhDsa(*signOwner);
        sign.prepareSeries();
        sign.executeIteration();
        require(sign.signatureForTesting().size() == testCase.signatureBytes,
                "SLH-DSA production signature size mismatch");
        require(directVerify(sign.signingKeyForTesting(), testCase.algorithm,
                             sign.messageForTesting(), sign.signatureForTesting()) == 1,
                "SLH-DSA production signature failed independent verification");

        auto tamperedSignature = std::vector<unsigned char>(
            sign.signatureForTesting().begin(), sign.signatureForTesting().end());
        tamperedSignature.back() ^= 0x01U;
        require(directVerify(sign.signingKeyForTesting(), testCase.algorithm,
                             messageBytes, tamperedSignature) == 0,
                "tampered SLH-DSA signature unexpectedly verified");

        auto verifyOwner = createAdapter(testCase.profile, BenchmarkOperation::Verify,
                                         SignatureConfig{core::MessageInput{message.size()}});
        auto& verify = asSlhDsa(*verifyOwner);
        verify.prepareSeries();
        require(verify.signatureForTesting().size() == testCase.signatureBytes,
                "SLH-DSA prerequisite signature size mismatch");
        verify.executeIteration();
    }
}

void testTypedAndInputNegativeCoverage()
{
    const auto canonicalProfile = profileFor(AlgorithmProfileId::SlhDsaSha2128S);
    auto wrongParametersProfile = canonicalProfile;
    wrongParametersProfile.parameters = core::MlDsaParameters{core::MlDsaLevel::MlDsa44};
    auto validated = validateConfig(AlgorithmProfileId::SlhDsaSha2128S, BenchmarkOperation::Sign,
                                    SignatureConfig{core::MessageInput{3}});
    bool wrongParametersRejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(wrongParametersProfile, BenchmarkOperation::Sign, validated));
    } catch (const std::logic_error&) {
        wrongParametersRejected = true;
    }
    require(wrongParametersRejected, "SLH-DSA wrong parameter variant was not rejected");

    bool prehashedRejected = false;
    try {
        static_cast<void>(validateConfig(AlgorithmProfileId::SlhDsaSha2128S, BenchmarkOperation::Sign,
                                         SignatureConfig{core::PrehashedInput{}}));
    } catch (const std::runtime_error&) {
        prehashedRejected = true;
    }
    require(prehashedRejected, "SLH-DSA Prehashed input was not rejected");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    const std::array tests{
        std::pair{"SLH-DSA fixed metadata", &testFixedMetadata},
        std::pair{"SLH-DSA production paths", &testAllProductionPaths},
        std::pair{"SLH-DSA typed and input negatives", &testTypedAndInputNegativeCoverage}};
    try {
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
    return 0;
}
