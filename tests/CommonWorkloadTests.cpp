#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/CommonWorkload.h>
#include <cryptobench/core/ConfigValidator.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace cryptobench::core;

static_assert(!std::is_copy_constructible_v<CommonWorkload>);
static_assert(!std::is_copy_assignable_v<CommonWorkload>);
static_assert(std::is_move_constructible_v<CommonWorkload>);
static_assert(std::is_move_assignable_v<CommonWorkload>);
static_assert(std::is_nothrow_move_constructible_v<CommonWorkload>);
static_assert(std::is_nothrow_move_assignable_v<CommonWorkload>);

namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

const AlgorithmProfile& profileFor(AlgorithmProfileId id)
{
    const auto* profile = AlgorithmRegistry::find(id);
    require(profile != nullptr, "canonical profile was not found");
    return *profile;
}

ValidatedBenchmarkConfig validated(BenchmarkConfig config)
{
    ValidationResult validation;
    auto result = ConfigValidator{}.validateAndCreate(config, validation);
    require(result.has_value() && validation.isValid(), "test configuration was rejected");
    return std::move(*result);
}

CommonWorkload workload(BenchmarkConfig config)
{
    const auto& profile = profileFor(config.profile);
    auto configValue = validated(std::move(config));
    return buildCommonWorkload(configValue, profile);
}

void testMessageAndPrehashedInputs()
{
    const auto message = workload({AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 1, 1,
                                   SignatureConfig{MessageInput{7}}});
    require(std::vector<unsigned char>(message.bytes().begin(), message.bytes().end()) ==
                std::vector<unsigned char>{'a', 'b', 'c', 'a', 'b', 'c', 'a'},
            "message pattern mismatch");

    const std::array cases{
        std::pair{AlgorithmProfileId::RsaPss2048Sha256, std::size_t{32}},
        std::pair{AlgorithmProfileId::RsaPss2048Sha384, std::size_t{48}},
        std::pair{AlgorithmProfileId::RsaPss2048Sha512, std::size_t{64}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha256, std::size_t{32}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha384, std::size_t{48}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha512, std::size_t{64}}};
    for (const auto [profile, size] : cases) {
        const auto digest = workload({profile, BenchmarkOperation::Verify, 1, 1,
                                      SignatureConfig{PrehashedInput{}}});
        require(digest.size() == size, "prehashed digest size mismatch");
        require(std::all_of(digest.bytes().begin(), digest.bytes().end(),
                            [](unsigned char value) { return value == 0xA5U; }),
                "prehashed digest pattern mismatch");
    }
}

void testEmptyAndPatternedInputs()
{
    const std::array signatureKeyGenProfiles{
        AlgorithmProfileId::Rsa2048KeyGen,
        AlgorithmProfileId::EcdsaP256KeyGen,
        AlgorithmProfileId::Ed25519,
        AlgorithmProfileId::MlDsa44,
        AlgorithmProfileId::SlhDsaSha2128F};
    for (const auto profile : signatureKeyGenProfiles) {
        require(workload({profile, BenchmarkOperation::KeyGen, 1, 1,
                          SignatureConfig{NoSignatureInput{}}}).empty(),
                "signature key generation workload was not empty");
    }

    const auto aead = workload({AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Decrypt, 1, 1,
                                AeadConfig{260}});
    require(aead.size() == 260 && aead.bytes()[0] == 0 && aead.bytes()[255] == 0xff &&
                aead.bytes()[256] == 0,
            "AEAD plaintext pattern mismatch");

    const auto hash = workload({AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 1, 1,
                                HashConfig{5}});
    require(std::vector<unsigned char>(hash.bytes().begin(), hash.bytes().end()) ==
                std::vector<unsigned char>{'a', 'b', 'c', 'a', 'b'},
            "hash pattern mismatch");
    require(workload({AlgorithmProfileId::MlDsa44, BenchmarkOperation::Sign, 1, 1,
                      SignatureConfig{MessageInput{3}}}).size() == 3,
            "ML-DSA message workload size mismatch");
    require(workload({AlgorithmProfileId::SlhDsaSha2128F, BenchmarkOperation::Verify, 1, 1,
                      SignatureConfig{MessageInput{3}}}).size() == 3,
            "SLH-DSA message workload size mismatch");
    require(workload({AlgorithmProfileId::EcdhP256, BenchmarkOperation::KeyGen, 1, 1,
                      KeyEstablishmentConfig{}}).empty(),
            "ECDH workload was not empty");
    require(workload({AlgorithmProfileId::Shake128_28B, BenchmarkOperation::Xof, 1, 1,
                      HashConfig{0}}).empty(), "zero-length XOF workload was not empty");
    require(workload({AlgorithmProfileId::X25519, BenchmarkOperation::Derive, 1, 1,
                      KeyEstablishmentConfig{}}).empty(), "XDH workload was not empty");
    require(workload({AlgorithmProfileId::MlKem512, BenchmarkOperation::Decapsulate, 1, 1,
                      KeyEstablishmentConfig{}}).empty(), "ML-KEM workload was not empty");
}

void testMovePreservesStorage()
{
    auto original = workload({AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 1, 1,
                              HashConfig{32}});
    const auto* originalData = original.bytes().data();
    auto moved = std::move(original);
    require(moved.bytes().data() == originalData, "moving workload performed a deep copy");

    auto assignmentSource = workload({AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 1, 1,
                                      HashConfig{32}});
    const auto* assignmentData = assignmentSource.bytes().data();
    CommonWorkload assigned;
    assigned = std::move(assignmentSource);
    require(assigned.bytes().data() == assignmentData,
            "move assignment performed a deep copy");
}

void testProfileMismatchIsRejected()
{
    auto config = validated({AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 1, 1, HashConfig{1}});
    bool rejected = false;
    try {
        buildCommonWorkload(config, profileFor(AlgorithmProfileId::Sha3_256));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "profile/config mismatch was accepted");
}

} // namespace

int main()
{
    try {
        testMessageAndPrehashedInputs();
        testEmptyAndPatternedInputs();
        testMovePreservesStorage();
        testProfileMismatchIsRejected();
        std::cout << "CommonWorkloadTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CommonWorkloadTests failed: " << error.what() << '\n';
        return 1;
    }
}
