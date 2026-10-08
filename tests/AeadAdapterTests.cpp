#include "adapters/AeadAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/CommonWorkload.h>
#include <cryptobench/core/ConfigValidator.h>

#include <array>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::AeadAdapter;
using crypto::AdapterFactory;
using core::AeadConfig;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::ValidationResult;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical AEAD profile was not found");
    return *profile;
}

core::ValidatedBenchmarkConfig validateConfig(AlgorithmProfileId profileId, BenchmarkOperation operation, core::WorkloadBytes plaintextSize)
{
    const core::BenchmarkConfig config{profileId, operation, 1, 1, AeadConfig{plaintextSize}};
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "AEAD test configuration validation failed");
    return std::move(*validated);
}

std::unique_ptr<core::AlgorithmAdapter> createAdapter(
    AlgorithmProfileId profileId,
    BenchmarkOperation operation,
    core::WorkloadBytes plaintextSize)
{
    auto validated = validateConfig(profileId, operation, plaintextSize);
    return AdapterFactory{}.create(profileFor(profileId), operation, validated);
}

AeadAdapter& asAead(core::AlgorithmAdapter& adapter)
{
    auto* result = dynamic_cast<AeadAdapter*>(&adapter);
    require(result != nullptr, "factory did not create AeadAdapter");
    return *result;
}

constexpr std::array profiles{
    AlgorithmProfileId::Aes128Gcm,
    AlgorithmProfileId::Aes192Gcm,
    AlgorithmProfileId::Aes256Gcm,
    AlgorithmProfileId::ChaCha20Poly1305};

void testValidRoundtripAndRepeatedExecution()
{
    for (const auto profileId : profiles) {
        auto encrypt = createAdapter(profileId, BenchmarkOperation::Encrypt, 16);
        auto& encryptAdapter = asAead(*encrypt);
        encryptAdapter.prepareSeries();
        encryptAdapter.executeIteration();
        require(encryptAdapter.ciphertext().size() == 16, "ciphertext length mismatch");
        require(encryptAdapter.tag().size() == 16, "authentication tag length mismatch");
        const auto ciphertext = std::vector<unsigned char>(encryptAdapter.ciphertext().begin(), encryptAdapter.ciphertext().end());
        const auto tag = std::vector<unsigned char>(encryptAdapter.tag().begin(), encryptAdapter.tag().end());
        encryptAdapter.executeIteration();
        require(
            std::vector<unsigned char>(encryptAdapter.ciphertext().begin(), encryptAdapter.ciphertext().end()) == ciphertext,
            "repeated encryption is not stable");

        auto decrypt = createAdapter(profileId, BenchmarkOperation::Decrypt, 16);
        auto& decryptAdapter = asAead(*decrypt);
        decryptAdapter.prepareSeries();
        require(decryptAdapter.ciphertext().size() == ciphertext.size(), "decrypt prerequisite ciphertext length mismatch");
        require(decryptAdapter.tag().size() == tag.size(), "decrypt prerequisite tag length mismatch");
        require(
            std::vector<unsigned char>(decryptAdapter.ciphertext().begin(), decryptAdapter.ciphertext().end()) == ciphertext,
            "encrypt/decrypt ciphertext mismatch");
        require(
            std::vector<unsigned char>(decryptAdapter.tag().begin(), decryptAdapter.tag().end()) == tag,
            "encrypt/decrypt authentication tag mismatch");
        decryptAdapter.executeIteration();
        require(
            std::vector<unsigned char>(decryptAdapter.decryptedPlaintext().begin(), decryptAdapter.decryptedPlaintext().end()) ==
                std::vector<unsigned char>(decryptAdapter.plaintext().begin(), decryptAdapter.plaintext().end()),
            "AEAD roundtrip plaintext mismatch");
        decryptAdapter.executeIteration();
    }
}

void requireAuthenticationFailure(AeadAdapter& adapter)
{
    bool rejected = false;
    try {
        adapter.executeIteration();
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "modified AEAD input was accepted");
}

void testModifiedTagAndCiphertextRejection()
{
    for (const auto profileId : profiles) {
        auto tagAdapterOwner = createAdapter(profileId, BenchmarkOperation::Decrypt, 16);
        auto& tagAdapter = asAead(*tagAdapterOwner);
        tagAdapter.prepareSeries();
        const auto originalTag = tagAdapter.tag().front();
        tagAdapter.mutableTag().front() ^= 0x01U;
        requireAuthenticationFailure(tagAdapter);
        tagAdapter.mutableTag().front() = originalTag;
        tagAdapter.executeIteration();

        auto ciphertextAdapterOwner = createAdapter(profileId, BenchmarkOperation::Decrypt, 16);
        auto& ciphertextAdapter = asAead(*ciphertextAdapterOwner);
        ciphertextAdapter.prepareSeries();
        ciphertextAdapter.mutableCiphertext().front() ^= 0x01U;
        requireAuthenticationFailure(ciphertextAdapter);
    }
}

void testPayloadSizes()
{
    constexpr std::array sizes{16U, 1024U, 4096U};
    for (const auto profileId : profiles) {
        for (const auto size : sizes) {
            auto encrypt = createAdapter(profileId, BenchmarkOperation::Encrypt, size);
            auto& encryptAdapter = asAead(*encrypt);
            encryptAdapter.prepareSeries();
            encryptAdapter.executeIteration();
            require(encryptAdapter.ciphertext().size() == size, "payload ciphertext size mismatch");
            require(encryptAdapter.tag().size() == 16, "payload tag size mismatch");

            auto decrypt = createAdapter(profileId, BenchmarkOperation::Decrypt, size);
            auto& decryptAdapter = asAead(*decrypt);
            decryptAdapter.prepareSeries();
            decryptAdapter.executeIteration();
            require(decryptAdapter.decryptedPlaintext().size() == size, "payload plaintext size mismatch");
        }
    }
}

void testCommonWorkloadMigrationPreservesPlaintextAndSupportsEmptyInput()
{
    std::vector<unsigned char> plaintext{0xffU, 0x01U, 0x80U, 0x42U};
    const auto expectedPlaintext = plaintext;
    const auto originalAddress = plaintext.data();
    auto validated = validateConfig(AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Encrypt, plaintext.size());
    const auto& profile = profileFor(AlgorithmProfileId::Aes128Gcm);
    auto adapterOwner = AdapterFactory{}.create(
        profile, BenchmarkOperation::Encrypt, validated,
        core::CommonWorkload{std::move(plaintext)});
    auto& adapter = asAead(*adapterOwner);
    require(adapter.plaintext().data() == originalAddress, "AEAD workload allocation was copied");
    require(std::vector(adapter.plaintext().begin(), adapter.plaintext().end()) == expectedPlaintext,
            "AEAD migrated plaintext changed before preparation");
    adapter.prepareSeries();
    adapter.executeIteration();
    require(adapter.ciphertext().size() == expectedPlaintext.size(), "migrated AEAD ciphertext size mismatch");

    AeadAdapter emptyAdapter(
        std::get<core::AesGcmParameters>(profile.parameters),
        BenchmarkOperation::Encrypt,
        core::CommonWorkload{std::vector<unsigned char>{}});
    emptyAdapter.prepareSeries();
    emptyAdapter.executeIteration();
    require(emptyAdapter.plaintext().empty() && emptyAdapter.ciphertext().empty(),
            "migrated empty AEAD workload was regenerated");
}

void testFactoryCreatesAllCanonicalPairs()
{
    for (const auto profileId : profiles) {
        for (const auto operation : {BenchmarkOperation::Encrypt, BenchmarkOperation::Decrypt}) {
            auto adapter = createAdapter(profileId, operation, 16);
            require(adapter != nullptr, "factory did not create canonical AEAD adapter");
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
}

void testFactoryRejectsIncorrectParameterVariant()
{
    const auto validated = validateConfig(AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Encrypt, 16);
    auto mismatchedProfile = profileFor(AlgorithmProfileId::Aes128Gcm);
    mismatchedProfile.parameters = core::ChaCha20Poly1305Parameters{};

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::Encrypt, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory accepted an incorrect AEAD parameter variant");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"valid AEAD roundtrip and repeated execution", &testValidRoundtripAndRepeatedExecution},
            std::pair{"modified AEAD tag and ciphertext rejection", &testModifiedTagAndCiphertextRejection},
            std::pair{"AEAD payload sizes", &testPayloadSizes},
            std::pair{"common workload migration preserves plaintext and supports empty input", &testCommonWorkloadMigrationPreservesPlaintextAndSupportsEmptyInput},
            std::pair{"factory creates all canonical AEAD pairs", &testFactoryCreatesAllCanonicalPairs},
            std::pair{"factory rejects incorrect AEAD parameter variant", &testFactoryRejectsIncorrectParameterVariant}};
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS AEAD adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
