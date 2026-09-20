#include "adapters/MlKemAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <openssl/evp.h>

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
using crypto::MlKemAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::KeyEstablishmentConfig;
using core::MlKemLevel;
using core::MlKemParameters;
using core::ValidationResult;

struct MlKemCase {
    AlgorithmProfileId profile;
    MlKemLevel level;
    std::size_t ciphertextBytes;
};

struct EncapsulationResult {
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> sharedSecret;
};

constexpr std::array cases{
    MlKemCase{AlgorithmProfileId::MlKem512, MlKemLevel::MlKem512, 768},
    MlKemCase{AlgorithmProfileId::MlKem768, MlKemLevel::MlKem768, 1088},
    MlKemCase{AlgorithmProfileId::MlKem1024, MlKemLevel::MlKem1024, 1568}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical ML-KEM profile was not found");
    return *profile;
}

core::ValidatedBenchmarkConfig validateConfig(AlgorithmProfileId profile, BenchmarkOperation operation)
{
    const core::BenchmarkConfig config{profile, operation, 1, 1, KeyEstablishmentConfig{}};
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "ML-KEM config validation failed");
    return std::move(*validated);
}

std::unique_ptr<core::AlgorithmAdapter> createAdapter(
    AlgorithmProfileId profile,
    BenchmarkOperation operation)
{
    auto validated = validateConfig(profile, operation);
    return AdapterFactory{}.create(profileFor(profile), operation, validated);
}

EncapsulationResult directEncapsulate(
    EVP_PKEY* recipientKey,
    std::size_t ciphertextBytes,
    std::size_t sharedSecretBytes)
{
    require(recipientKey != nullptr, "KeyGen did not produce a usable ML-KEM key");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, recipientKey, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ML-KEM encapsulation context");
    require(EVP_PKEY_encapsulate_init(context.get(), nullptr) == 1, "direct encapsulation init failed");

    std::vector<unsigned char> ciphertext(ciphertextBytes);
    std::vector<unsigned char> sharedSecret(sharedSecretBytes);
    std::size_t actualCiphertextBytes = ciphertext.size();
    std::size_t actualSharedSecretBytes = sharedSecret.size();
    require(
        EVP_PKEY_encapsulate(
            context.get(), ciphertext.data(), &actualCiphertextBytes,
            sharedSecret.data(), &actualSharedSecretBytes) == 1,
        "direct ML-KEM encapsulation failed");
    require(actualCiphertextBytes == ciphertextBytes, "direct ciphertext length mismatch");
    require(actualSharedSecretBytes == sharedSecretBytes, "direct shared-secret length mismatch");
    return EncapsulationResult{std::move(ciphertext), std::move(sharedSecret)};
}

std::vector<unsigned char> directDecapsulate(
    EVP_PKEY* recipientKey,
    std::span<const unsigned char> ciphertext,
    std::size_t sharedSecretBytes)
{
    require(recipientKey != nullptr, "recipient key was null");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, recipientKey, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct ML-KEM decapsulation context");
    require(EVP_PKEY_decapsulate_init(context.get(), nullptr) == 1, "direct decapsulation init failed");

    std::vector<unsigned char> sharedSecret(sharedSecretBytes);
    std::size_t actualSharedSecretBytes = sharedSecret.size();
    require(
        EVP_PKEY_decapsulate(
            context.get(), sharedSecret.data(), &actualSharedSecretBytes,
            ciphertext.data(), ciphertext.size()) == 1,
        "direct ML-KEM decapsulation failed");
    require(actualSharedSecretBytes == sharedSecretBytes, "direct decapsulated length mismatch");
    return sharedSecret;
}

void testEncapsulateDecapsulateEquality()
{
    for (const auto& testCase : cases) {
        auto encapsulate = createAdapter(testCase.profile, BenchmarkOperation::Encapsulate);
        auto& encapsulateAdapter = dynamic_cast<MlKemAdapter&>(*encapsulate);
        encapsulateAdapter.prepareSeries();
        encapsulateAdapter.executeIteration();
        require(encapsulateAdapter.ciphertext().size() == testCase.ciphertextBytes, "ciphertext length mismatch");
        require(encapsulateAdapter.sharedSecret().size() == 32, "encapsulated secret length mismatch");
        const auto productionDecapsulated = directDecapsulate(
            encapsulateAdapter.recipientKeyForTesting(), encapsulateAdapter.ciphertext(), 32);
        require(productionDecapsulated.size() == 32, "production decapsulated secret length mismatch");
        require(
            std::vector<unsigned char>(
                encapsulateAdapter.sharedSecret().begin(), encapsulateAdapter.sharedSecret().end()) ==
                productionDecapsulated,
            "production ML-KEM shared secrets differ");

        auto decapsulate = createAdapter(testCase.profile, BenchmarkOperation::Decapsulate);
        auto& decapsulateAdapter = dynamic_cast<MlKemAdapter&>(*decapsulate);
        decapsulateAdapter.prepareSeries();
        decapsulateAdapter.executeIteration();
        require(decapsulateAdapter.ciphertext().size() == testCase.ciphertextBytes, "prerequisite ciphertext length mismatch");
        require(decapsulateAdapter.sharedSecret().size() == 32, "decapsulated secret length mismatch");

        const auto decapsulated = std::vector<unsigned char>(
            decapsulateAdapter.sharedSecret().begin(), decapsulateAdapter.sharedSecret().end());
        require(decapsulated.size() == 32, "decapsulated secret was not 32 bytes");
        require(
            std::vector<unsigned char>(
                decapsulateAdapter.prerequisiteSharedSecretForTesting().begin(),
                decapsulateAdapter.prerequisiteSharedSecretForTesting().end()) == decapsulated,
            "ML-KEM Encapsulate/Decapsulate shared secrets differ");

        const auto directResult = directEncapsulate(
            decapsulateAdapter.recipientKeyForTesting(), testCase.ciphertextBytes, 32);
        const auto directSecret = directDecapsulate(
            decapsulateAdapter.recipientKeyForTesting(), directResult.ciphertext, 32);
        require(directResult.ciphertext.size() == testCase.ciphertextBytes, "direct ciphertext length mismatch");
        require(directResult.sharedSecret.size() == 32, "direct encapsulated secret length mismatch");
        require(directSecret.size() == 32, "direct encapsulate/decapsulate secret was not 32 bytes");
        require(directResult.sharedSecret == directSecret, "direct ML-KEM shared secrets differ");
    }
}

void testKeyGenUsability()
{
    for (const auto& testCase : cases) {
        auto keygen = createAdapter(testCase.profile, BenchmarkOperation::KeyGen);
        auto& keygenAdapter = dynamic_cast<MlKemAdapter&>(*keygen);
        keygenAdapter.prepareSeries();
        keygenAdapter.executeIteration();
        const auto result = directEncapsulate(keygenAdapter.currentKeyForTesting(), testCase.ciphertextBytes, 32);
        const auto sharedSecret = directDecapsulate(
            keygenAdapter.currentKeyForTesting(), result.ciphertext, 32);
        require(result.ciphertext.size() == testCase.ciphertextBytes, "KeyGen ciphertext length mismatch");
        require(result.sharedSecret.size() == 32, "KeyGen encapsulated secret length mismatch");
        require(sharedSecret.size() == 32, "KeyGen decapsulated secret length mismatch");
        require(result.sharedSecret == sharedSecret, "KeyGen ML-KEM shared secrets differ");
    }
}

void testRepeatedOperations()
{
    auto keygen = createAdapter(AlgorithmProfileId::MlKem512, BenchmarkOperation::KeyGen);
    auto& keygenAdapter = dynamic_cast<MlKemAdapter&>(*keygen);
    keygenAdapter.prepareSeries();
    keygenAdapter.executeIteration();
    EVP_PKEY* firstKey = keygenAdapter.currentKeyForTesting();
    require(firstKey != nullptr, "first ML-KEM key was null");
    require(EVP_PKEY_up_ref(firstKey) == 1, "could not retain first ML-KEM key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstKeyReference(firstKey, &EVP_PKEY_free);
    keygenAdapter.executeIteration();
    EVP_PKEY* secondKey = keygenAdapter.currentKeyForTesting();
    require(secondKey != nullptr, "second ML-KEM key was null");
    require(EVP_PKEY_eq(firstKeyReference.get(), secondKey) == 0, "repeated ML-KEM KeyGen reused the key");
    const auto secondResult = directEncapsulate(secondKey, 768, 32);
    const auto secondSecret = directDecapsulate(secondKey, secondResult.ciphertext, 32);
    require(secondResult.ciphertext.size() == 768, "second KeyGen ciphertext length mismatch");
    require(secondResult.sharedSecret.size() == 32, "second KeyGen encapsulated secret length mismatch");
    require(secondSecret.size() == 32, "second KeyGen decapsulated secret length mismatch");
    require(secondResult.sharedSecret == secondSecret, "second KeyGen ML-KEM shared secrets differ");

    auto encapsulate = createAdapter(AlgorithmProfileId::MlKem512, BenchmarkOperation::Encapsulate);
    auto& encapsulateAdapter = dynamic_cast<MlKemAdapter&>(*encapsulate);
    encapsulateAdapter.prepareSeries();
    encapsulateAdapter.executeIteration();
    require(encapsulateAdapter.ciphertext().size() == 768, "first repeated ciphertext length mismatch");
    encapsulateAdapter.executeIteration();
    require(encapsulateAdapter.ciphertext().size() == 768, "second repeated ciphertext length mismatch");
    require(encapsulateAdapter.sharedSecret().size() == 32, "repeated encapsulation secret length mismatch");

    auto decapsulate = createAdapter(AlgorithmProfileId::MlKem512, BenchmarkOperation::Decapsulate);
    auto& decapsulateAdapter = dynamic_cast<MlKemAdapter&>(*decapsulate);
    decapsulateAdapter.prepareSeries();
    decapsulateAdapter.executeIteration();
    const auto firstSecret = std::vector<unsigned char>(
        decapsulateAdapter.sharedSecret().begin(), decapsulateAdapter.sharedSecret().end());
    decapsulateAdapter.executeIteration();
    require(
        std::vector<unsigned char>(decapsulateAdapter.sharedSecret().begin(), decapsulateAdapter.sharedSecret().end()) == firstSecret,
        "repeated decapsulation changed the fixed prerequisite result");
}

void testFactoryCreatesAllCanonicalPairs()
{
    for (const auto& testCase : cases) {
        for (const auto operation : {
                 BenchmarkOperation::KeyGen,
                 BenchmarkOperation::Encapsulate,
                 BenchmarkOperation::Decapsulate}) {
            auto adapter = createAdapter(testCase.profile, operation);
            require(adapter != nullptr, "factory did not create ML-KEM adapter");
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
}

void testFactoryRejectsIncorrectParameterVariant()
{
    auto validated = validateConfig(AlgorithmProfileId::MlKem512, BenchmarkOperation::KeyGen);
    auto mismatchedProfile = profileFor(AlgorithmProfileId::MlKem512);
    mismatchedProfile.parameters = core::XdhParameters{core::XdhVariant::X25519};

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::KeyGen, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory accepted an incorrect ML-KEM parameter variant");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"Encapsulate/Decapsulate equality", &testEncapsulateDecapsulateEquality},
            std::pair{"KeyGen usability", &testKeyGenUsability},
            std::pair{"repeated ML-KEM operations", &testRepeatedOperations},
            std::pair{"factory creates all ML-KEM pairs", &testFactoryCreatesAllCanonicalPairs},
            std::pair{"factory rejects incorrect parameter variant", &testFactoryRejectsIncorrectParameterVariant}};
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS ML-KEM adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
