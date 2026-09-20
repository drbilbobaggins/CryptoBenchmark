#include "adapters/EdDsaAdapter.h"

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
using crypto::EdDsaAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::EdDsaParameters;
using core::EdDsaVariant;
using core::SignatureConfig;
using core::ValidationResult;

struct EdDsaCase {
    AlgorithmProfileId profile;
    EdDsaVariant variant;
    std::size_t signatureBytes;
};

constexpr std::array eddsaCases{
    EdDsaCase{AlgorithmProfileId::Ed25519, EdDsaVariant::Ed25519, 64},
    EdDsaCase{AlgorithmProfileId::Ed448, EdDsaVariant::Ed448, 114}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical EdDSA profile was not found");
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
    require(validated.has_value() && validation.isValid(), "EdDSA configuration validation failed");
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

EdDsaAdapter& asEdDsa(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<EdDsaAdapter*>(&adapter);
    require(result != nullptr, "factory did not create EdDsaAdapter");
    return *result;
}

std::string_view algorithmName(EdDsaVariant variant)
{
    switch (variant) {
    case EdDsaVariant::Ed25519: return "ED25519";
    case EdDsaVariant::Ed448: return "ED448";
    }
    throw std::invalid_argument("unknown EdDSA variant");
}

crypto::openssl::EvpSignaturePtr fetchSignature(EdDsaVariant variant)
{
    crypto::openssl::EvpSignaturePtr result(
        EVP_SIGNATURE_fetch(nullptr, algorithmName(variant).data(), nullptr), &EVP_SIGNATURE_free);
    require(result != nullptr, "could not fetch direct EdDSA signature");
    return result;
}

int directVerify(
    EVP_PKEY* key,
    EdDsaVariant variant,
    std::span<const unsigned char> message,
    std::span<const unsigned char> signature)
{
    require(key != nullptr, "EdDSA key was null");
    auto signatureAlgorithm = fetchSignature(variant);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct EdDSA verify context");
    require(
        EVP_PKEY_verify_message_init(context.get(), signatureAlgorithm.get(), nullptr) == 1,
        "direct EdDSA verify message init failed");
    return EVP_PKEY_verify(context.get(), signature.data(), signature.size(), message.data(), message.size());
}

std::vector<unsigned char> directSign(
    EVP_PKEY* key,
    EdDsaVariant variant,
    std::span<const unsigned char> message,
    std::size_t signatureBytes)
{
    require(key != nullptr, "EdDSA key was null");
    auto signatureAlgorithm = fetchSignature(variant);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct EdDSA sign context");
    require(
        EVP_PKEY_sign_message_init(context.get(), signatureAlgorithm.get(), nullptr) == 1,
        "direct EdDSA sign message init failed");
    std::vector<unsigned char> signature(signatureBytes);
    std::size_t signatureLength = signature.size();
    require(
        EVP_PKEY_sign(context.get(), signature.data(), &signatureLength, message.data(), message.size()) == 1,
        "direct EdDSA sign failed");
    require(signatureLength == signatureBytes, "direct EdDSA signature length mismatch");
    return signature;
}

void requireSignature(const EdDsaAdapter& adapter, std::size_t signatureBytes)
{
    require(adapter.signatureForTesting().size() == signatureBytes, "EdDSA signature size mismatch");
}

void testKeyGenUsability()
{
    for (const auto& testCase : eddsaCases) {
        auto owner = createAdapter(testCase.profile, BenchmarkOperation::KeyGen, SignatureConfig{core::NoSignatureInput{}});
        auto& adapter = asEdDsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        require(adapter.currentKeyForTesting() != nullptr, "EdDSA KeyGen did not produce a key");
        const std::array message{'a', 'b', 'c'};
        const auto signature = directSign(
            adapter.currentKeyForTesting(), testCase.variant,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()), message.size()),
            testCase.signatureBytes);
        require(
            directVerify(
                adapter.currentKeyForTesting(), testCase.variant,
                std::span<const unsigned char>(
                    reinterpret_cast<const unsigned char*>(message.data()), message.size()), signature) == 1,
            "independent EdDSA KeyGen key verification failed");
    }
}

void testUnpreparedKeyGenFailsClearly()
{
    EdDsaAdapter adapter(
        EdDsaParameters{EdDsaVariant::Ed25519}, BenchmarkOperation::KeyGen,
        EdDsaAdapter::InputMode::NoInput, 64);
    bool rejected = false;
    try {
        adapter.executeIteration();
    } catch (const std::logic_error& error) {
        rejected = std::string_view(error.what()) == "EdDsaAdapter is not prepared";
    }
    require(rejected, "unprepared EdDSA KeyGen did not fail with the canonical state error");
}

void testRepeatedKeyGen()
{
    auto owner = createAdapter(
        AlgorithmProfileId::Ed25519, BenchmarkOperation::KeyGen,
        SignatureConfig{core::NoSignatureInput{}});
    auto& adapter = asEdDsa(*owner);
    adapter.prepareSeries();
    adapter.executeIteration();
    EVP_PKEY* first = adapter.currentKeyForTesting();
    require(first != nullptr && EVP_PKEY_up_ref(first) == 1, "could not retain first EdDSA key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstReference(first, &EVP_PKEY_free);
    adapter.executeIteration();
    EVP_PKEY* second = adapter.currentKeyForTesting();
    require(second != nullptr && EVP_PKEY_eq(firstReference.get(), second) == 0, "repeated EdDSA KeyGen reused the key");
    const std::array message{'a', 'b', 'c'};
    const auto messageBytes = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(message.data()), message.size());
    const auto signature = directSign(second, EdDsaVariant::Ed25519, messageBytes, 64);
    require(
        directVerify(second, EdDsaVariant::Ed25519, messageBytes, signature) == 1,
        "repeated EdDSA KeyGen key was not usable");
}

void testMessageSignCorrectness()
{
    for (const auto& testCase : eddsaCases) {
        auto owner = createAdapter(
            testCase.profile, BenchmarkOperation::Sign, SignatureConfig{core::MessageInput{32}});
        auto& adapter = asEdDsa(*owner);
        adapter.prepareSeries();
        require(adapter.messageForTesting().size() == 32, "EdDSA message size mismatch");
        adapter.executeIteration();
        requireSignature(adapter, testCase.signatureBytes);
        require(
            directVerify(
                adapter.signingKeyForTesting(), testCase.variant,
                adapter.messageForTesting(), adapter.signatureForTesting()) == 1,
            "independent EdDSA Message Sign verification failed");
    }
}

void testMessageVerifyCorrectness()
{
    for (const auto& testCase : eddsaCases) {
        auto owner = createAdapter(
            testCase.profile, BenchmarkOperation::Verify, SignatureConfig{core::MessageInput{32}});
        auto& adapter = asEdDsa(*owner);
        adapter.prepareSeries();
        adapter.executeIteration();
        requireSignature(adapter, testCase.signatureBytes);
    }
}

void testRepresentativeMessageSizes()
{
    constexpr std::array messageSizes{
        std::size_t{1}, std::size_t{32}, std::size_t{1024},
        std::size_t{16 * 1024}, std::size_t{1024 * 1024}, std::size_t{16 * 1024 * 1024}};
    for (const auto messageSize : messageSizes) {
        auto owner = createAdapter(
            AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign,
            SignatureConfig{core::MessageInput{messageSize}});
        auto& adapter = asEdDsa(*owner);
        adapter.prepareSeries();
        require(adapter.messageForTesting().size() == messageSize, "EdDSA representative message size mismatch");
        for (std::size_t index = 0; index < messageSize; ++index) {
            require(
                adapter.messageForTesting()[index] == static_cast<unsigned char>('a' + (index % 3)),
                "EdDSA message pattern mismatch");
        }
        adapter.executeIteration();
        requireSignature(adapter, 64);
        require(
            directVerify(
                adapter.signingKeyForTesting(), EdDsaVariant::Ed25519,
                adapter.messageForTesting(), adapter.signatureForTesting()) == 1,
            "EdDSA representative production signature failed independent verification");
    }
}

void testRepeatedMessageOperationsAndTamperNegatives()
{
    auto signOwner = createAdapter(
        AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign,
        SignatureConfig{core::MessageInput{32}});
    auto& sign = asEdDsa(*signOwner);
    sign.prepareSeries();
    sign.executeIteration();
    requireSignature(sign, 64);
    require(
        directVerify(sign.signingKeyForTesting(), EdDsaVariant::Ed25519,
                     sign.messageForTesting(), sign.signatureForTesting()) == 1,
        "first repeated EdDSA Sign failed");
    sign.executeIteration();
    requireSignature(sign, 64);
    require(
        directVerify(sign.signingKeyForTesting(), EdDsaVariant::Ed25519,
                     sign.messageForTesting(), sign.signatureForTesting()) == 1,
        "second repeated EdDSA Sign failed");

    auto wrongMessage = std::vector<unsigned char>(sign.messageForTesting().begin(), sign.messageForTesting().end());
    wrongMessage[0] ^= 0x01U;
    require(
        directVerify(sign.signingKeyForTesting(), EdDsaVariant::Ed25519,
                     wrongMessage, sign.signatureForTesting()) == 0,
        "altered EdDSA message unexpectedly verified");

    auto tamperedSignature = std::vector<unsigned char>(
        sign.signatureForTesting().begin(), sign.signatureForTesting().end());
    tamperedSignature.back() ^= 0x01U;
    require(
        directVerify(sign.signingKeyForTesting(), EdDsaVariant::Ed25519,
                     sign.messageForTesting(), tamperedSignature) == 0,
        "tampered EdDSA signature unexpectedly verified");

    auto verifyOwner = createAdapter(
        AlgorithmProfileId::Ed448, BenchmarkOperation::Verify,
        SignatureConfig{core::MessageInput{32}});
    auto& verify = asEdDsa(*verifyOwner);
    verify.prepareSeries();
    verify.executeIteration();
    verify.executeIteration();
}

void testFactoryCreatesAllEdDsaPaths()
{
    for (const auto& testCase : eddsaCases) {
        auto keyGen = createAdapter(testCase.profile, BenchmarkOperation::KeyGen, SignatureConfig{core::NoSignatureInput{}});
        asEdDsa(*keyGen).prepareSeries();
        asEdDsa(*keyGen).executeIteration();

        auto sign = createAdapter(testCase.profile, BenchmarkOperation::Sign, SignatureConfig{core::MessageInput{32}});
        asEdDsa(*sign).prepareSeries();
        asEdDsa(*sign).executeIteration();

        auto verify = createAdapter(testCase.profile, BenchmarkOperation::Verify, SignatureConfig{core::MessageInput{32}});
        asEdDsa(*verify).prepareSeries();
        asEdDsa(*verify).executeIteration();
    }
}

void testFixedSignatureMetadata()
{
    for (const auto& testCase : eddsaCases) {
        const auto& profile = profileFor(testCase.profile);
        const auto& characteristics = std::get<core::SignatureCharacteristics>(profile.characteristics);
        require(characteristics.signatureSize.has_value(), "EdDSA signature metadata was missing");
        require(
            characteristics.signatureSize->kind == core::SignatureSizeReferenceKind::Fixed,
            "EdDSA signature metadata was not fixed");
        require(
            characteristics.signatureSize->bytes == testCase.signatureBytes,
            "EdDSA signature metadata size mismatch");
    }
}

void testTypedAndInputNegativeCoverage()
{
    const auto canonicalProfile = profileFor(AlgorithmProfileId::Ed25519);
    auto wrongParametersProfile = canonicalProfile;
    wrongParametersProfile.parameters = core::MlDsaParameters{core::MlDsaLevel::MlDsa44};
    auto validated = validateConfig(
        AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign,
        SignatureConfig{core::MessageInput{32}});
    bool wrongParametersRejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(
            wrongParametersProfile, BenchmarkOperation::Sign, validated));
    } catch (const std::logic_error&) {
        wrongParametersRejected = true;
    }
    require(wrongParametersRejected, "EdDSA wrong parameter variant was not rejected");

    bool prehashedRejected = false;
    try {
        static_cast<void>(validateConfig(
            AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign,
            SignatureConfig{core::PrehashedInput{}}));
    } catch (const std::runtime_error&) {
        prehashedRejected = true;
    }
    require(prehashedRejected, "EdDSA Prehashed input was not rejected");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    const std::array tests{
        std::pair{"EdDSA KeyGen usability", &testKeyGenUsability},
        std::pair{"unprepared EdDSA KeyGen", &testUnpreparedKeyGenFailsClearly},
        std::pair{"repeated EdDSA KeyGen", &testRepeatedKeyGen},
        std::pair{"EdDSA Message Sign correctness", &testMessageSignCorrectness},
        std::pair{"EdDSA Message Verify correctness", &testMessageVerifyCorrectness},
        std::pair{"EdDSA representative message sizes", &testRepresentativeMessageSizes},
        std::pair{"EdDSA repeated and tamper tests", &testRepeatedMessageOperationsAndTamperNegatives},
        std::pair{"all EdDSA factory paths", &testFactoryCreatesAllEdDsaPaths},
        std::pair{"fixed EdDSA signature metadata", &testFixedSignatureMetadata},
        std::pair{"typed and input negative coverage", &testTypedAndInputNegativeCoverage}};
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
