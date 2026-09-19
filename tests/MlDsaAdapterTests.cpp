#include "adapters/MlDsaAdapter.h"

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
using crypto::MlDsaAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::MlDsaLevel;
using core::MlDsaParameters;
using core::SignatureConfig;
using core::ValidationResult;

struct MlDsaCase {
    AlgorithmProfileId profile;
    MlDsaLevel level;
    std::string_view algorithm;
    std::size_t publicKeyBytes;
    std::size_t privateKeyBytes;
    std::size_t signatureBytes;
};

constexpr std::array cases{
    MlDsaCase{AlgorithmProfileId::MlDsa44, MlDsaLevel::MlDsa44, "ML-DSA-44", 1312, 2560, 2420},
    MlDsaCase{AlgorithmProfileId::MlDsa65, MlDsaLevel::MlDsa65, "ML-DSA-65", 1952, 4032, 3309},
    MlDsaCase{AlgorithmProfileId::MlDsa87, MlDsaLevel::MlDsa87, "ML-DSA-87", 2592, 4896, 4627}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical ML-DSA profile was not found");
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
    require(validated.has_value() && validation.isValid(), "ML-DSA configuration validation failed");
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

MlDsaAdapter& asMlDsa(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<MlDsaAdapter*>(&adapter);
    require(result != nullptr, "factory did not create MlDsaAdapter");
    return *result;
}

crypto::openssl::EvpSignaturePtr fetchSignature(std::string_view algorithm)
{
    crypto::openssl::EvpSignaturePtr result(
        EVP_SIGNATURE_fetch(nullptr, algorithm.data(), nullptr), &EVP_SIGNATURE_free);
    require(result != nullptr, "could not fetch direct ML-DSA signature");
    return result;
}

std::vector<unsigned char> directSign(
    EVP_PKEY* key,
    std::string_view algorithm,
    std::span<const unsigned char> message,
    std::size_t signatureBytes)
{
    require(key != nullptr, "ML-DSA key was null");
    auto signatureAlgorithm = fetchSignature(algorithm);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ML-DSA sign context");
    require(EVP_PKEY_sign_message_init(context.get(), signatureAlgorithm.get(), nullptr) == 1,
            "direct ML-DSA sign message init failed");
    std::vector<unsigned char> signature(signatureBytes);
    std::size_t signatureLength = signature.size();
    require(EVP_PKEY_sign(context.get(), signature.data(), &signatureLength, message.data(), message.size()) == 1,
            "direct ML-DSA sign failed");
    require(signatureLength == signatureBytes, "direct ML-DSA signature length mismatch");
    return signature;
}

int directVerify(
    EVP_PKEY* key,
    std::string_view algorithm,
    std::span<const unsigned char> message,
    std::span<const unsigned char> signature)
{
    require(key != nullptr, "ML-DSA key was null");
    auto signatureAlgorithm = fetchSignature(algorithm);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ML-DSA verify context");
    require(EVP_PKEY_verify_message_init(context.get(), signatureAlgorithm.get(), nullptr) == 1,
            "direct ML-DSA verify message init failed");
    return EVP_PKEY_verify(context.get(), signature.data(), signature.size(), message.data(), message.size());
}

void testKeyGenerationUsabilityAndRepeatedKeyGeneration()
{
    for (const auto& testCase : cases) {
        auto owner = createAdapter(testCase.profile, BenchmarkOperation::KeyGen,
                                   SignatureConfig{core::NoSignatureInput{}});
        auto& adapter = asMlDsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.currentKeyForTesting() != nullptr, "ML-DSA KeyGen did not produce a key");
        const std::array message{'a', 'b', 'c'};
        const auto messageBytes = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(message.data()), message.size());
        const auto signature = directSign(adapter.currentKeyForTesting(), testCase.algorithm,
                                          messageBytes, testCase.signatureBytes);
        require(directVerify(adapter.currentKeyForTesting(), testCase.algorithm, messageBytes, signature) == 1,
                "ML-DSA KeyGen key was not usable");
    }

    auto owner = createAdapter(AlgorithmProfileId::MlDsa44, BenchmarkOperation::KeyGen,
                               SignatureConfig{core::NoSignatureInput{}});
    auto& adapter = asMlDsa(*owner);
    adapter.prepareSeries();
    adapter.executeIteration();
    EVP_PKEY* first = adapter.currentKeyForTesting();
    require(first != nullptr && EVP_PKEY_up_ref(first) == 1, "could not retain first ML-DSA key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstReference(first, &EVP_PKEY_free);
    adapter.executeIteration();
    EVP_PKEY* second = adapter.currentKeyForTesting();
    require(second != nullptr && EVP_PKEY_eq(firstReference.get(), second) == 0,
            "repeated ML-DSA KeyGen reused the key");
    const std::array secondMessage{'x', 'y', 'z'};
    const auto secondMessageBytes = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(secondMessage.data()), secondMessage.size());
    const auto secondSignature = directSign(second, "ML-DSA-44", secondMessageBytes, 2420);
    require(directVerify(second, "ML-DSA-44", secondMessageBytes, secondSignature) == 1,
            "repeated ML-DSA KeyGen second key was not usable");
}

void testProductionSignAndVerify()
{
    for (const auto& testCase : cases) {
        auto signOwner = createAdapter(testCase.profile, BenchmarkOperation::Sign,
                                       SignatureConfig{core::MessageInput{32}});
        auto& sign = asMlDsa(*signOwner);
        sign.prepareSeries();
        sign.executeIteration();
        require(sign.signatureForTesting().size() == testCase.signatureBytes,
                "ML-DSA production signature size mismatch");
        require(directVerify(sign.signingKeyForTesting(), testCase.algorithm,
                             sign.messageForTesting(), sign.signatureForTesting()) == 1,
                "ML-DSA production signature failed independent verification");

        auto verifyOwner = createAdapter(testCase.profile, BenchmarkOperation::Verify,
                                         SignatureConfig{core::MessageInput{32}});
        auto& verify = asMlDsa(*verifyOwner);
        verify.prepareSeries();
        require(verify.signatureForTesting().size() == testCase.signatureBytes,
                "ML-DSA prerequisite signature size mismatch");
        verify.executeIteration();
        verify.executeIteration();
    }
}

void testRepeatedSignAndTamperNegatives()
{
    auto owner = createAdapter(AlgorithmProfileId::MlDsa44, BenchmarkOperation::Sign,
                               SignatureConfig{core::MessageInput{32}});
    auto& adapter = asMlDsa(*owner);
    adapter.prepareSeries();
    adapter.executeIteration();
    require(directVerify(adapter.signingKeyForTesting(), "ML-DSA-44",
                         adapter.messageForTesting(), adapter.signatureForTesting()) == 1,
            "first repeated ML-DSA Sign failed");
    adapter.executeIteration();
    require(adapter.signatureForTesting().size() == 2420, "repeated ML-DSA signature size mismatch");
    require(directVerify(adapter.signingKeyForTesting(), "ML-DSA-44",
                         adapter.messageForTesting(), adapter.signatureForTesting()) == 1,
            "second repeated ML-DSA Sign failed");

    auto wrongMessage = std::vector<unsigned char>(adapter.messageForTesting().begin(), adapter.messageForTesting().end());
    wrongMessage[0] ^= 0x01U;
    require(directVerify(adapter.signingKeyForTesting(), "ML-DSA-44", wrongMessage,
                         adapter.signatureForTesting()) == 0,
            "altered ML-DSA message unexpectedly verified");
    auto tamperedSignature = std::vector<unsigned char>(
        adapter.signatureForTesting().begin(), adapter.signatureForTesting().end());
    tamperedSignature.back() ^= 0x01U;
    require(directVerify(adapter.signingKeyForTesting(), "ML-DSA-44", adapter.messageForTesting(),
                         tamperedSignature) == 0,
            "tampered ML-DSA signature unexpectedly verified");
}

void testAllFactoryPathsAndFixedMetadata()
{
    for (const auto& testCase : cases) {
        const auto& profile = profileFor(testCase.profile);
        const auto& characteristics = std::get<core::SignatureCharacteristics>(profile.characteristics);
        require(characteristics.publicKeyBytes && *characteristics.publicKeyBytes == testCase.publicKeyBytes,
                "ML-DSA public-key metadata mismatch");
        require(characteristics.privateKeyBytes && *characteristics.privateKeyBytes == testCase.privateKeyBytes,
                "ML-DSA private-key metadata mismatch");
        require(characteristics.signatureSize && characteristics.signatureSize->kind == core::SignatureSizeReferenceKind::Fixed,
                "ML-DSA signature metadata was not fixed");
        require(characteristics.signatureSize->bytes == testCase.signatureBytes,
                "ML-DSA signature metadata mismatch");

        for (const auto operation : {BenchmarkOperation::KeyGen, BenchmarkOperation::Sign, BenchmarkOperation::Verify}) {
            auto input = operation == BenchmarkOperation::KeyGen
                ? SignatureConfig{core::NoSignatureInput{}}
                : SignatureConfig{core::MessageInput{32}};
            auto owner = createAdapter(testCase.profile, operation, std::move(input));
            auto& adapter = asMlDsa(*owner);
            adapter.prepareSeries();
            adapter.executeIteration();
        }
    }
}

void testTypedAndInputNegativeCoverage()
{
    const auto canonicalProfile = profileFor(AlgorithmProfileId::MlDsa44);
    auto wrongParametersProfile = canonicalProfile;
    wrongParametersProfile.parameters = core::EdDsaParameters{core::EdDsaVariant::Ed25519};
    auto validated = validateConfig(AlgorithmProfileId::MlDsa44, BenchmarkOperation::Sign,
                                    SignatureConfig{core::MessageInput{32}});
    bool wrongParametersRejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(wrongParametersProfile, BenchmarkOperation::Sign, validated));
    } catch (const std::logic_error&) {
        wrongParametersRejected = true;
    }
    require(wrongParametersRejected, "ML-DSA wrong parameter variant was not rejected");

    bool prehashedRejected = false;
    try {
        static_cast<void>(validateConfig(AlgorithmProfileId::MlDsa44, BenchmarkOperation::Sign,
                                         SignatureConfig{core::PrehashedInput{}}));
    } catch (const std::runtime_error&) {
        prehashedRejected = true;
    }
    require(prehashedRejected, "ML-DSA Prehashed input was not rejected");

    const auto slhProfile = profileFor(AlgorithmProfileId::SlhDsaSha2128S);
    auto slhValidated = validateConfig(AlgorithmProfileId::SlhDsaSha2128S, BenchmarkOperation::Sign,
                                       SignatureConfig{core::MessageInput{32}});
    bool slhRejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(slhProfile, BenchmarkOperation::Sign, slhValidated));
    } catch (const std::invalid_argument&) {
        slhRejected = true;
    }
    require(slhRejected, "SLH-DSA unsupported strategy was not rejected");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    const std::array tests{
        std::pair{"ML-DSA KeyGen usability and repetition", &testKeyGenerationUsabilityAndRepeatedKeyGeneration},
        std::pair{"ML-DSA production Sign and Verify", &testProductionSignAndVerify},
        std::pair{"ML-DSA repeated Sign and tamper negatives", &testRepeatedSignAndTamperNegatives},
        std::pair{"ML-DSA factory paths and metadata", &testAllFactoryPathsAndFixedMetadata},
        std::pair{"ML-DSA typed and input negatives", &testTypedAndInputNegativeCoverage}};
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
