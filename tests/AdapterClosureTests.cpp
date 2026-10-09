#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/crypto/AdapterFactory.h>

#include <array>
#include <algorithm>
#include <iostream>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

#include "adapters/AeadAdapter.h"
#include "adapters/DigestAdapter.h"
#include "adapters/EcdhAdapter.h"
#include "adapters/EcdsaAdapter.h"
#include "adapters/EdDsaAdapter.h"
#include "adapters/MlDsaAdapter.h"
#include "adapters/MlKemAdapter.h"
#include "adapters/RsaPssAdapter.h"
#include "adapters/SlhDsaAdapter.h"
#include "adapters/XdhAdapter.h"
#include "adapters/XofAdapter.h"

namespace cryptobench::tests {
namespace {

using namespace core;

enum class InputMode {
    None,
    NoSignature,
    Prehashed,
    Message
};

struct CanonicalCase {
    const AlgorithmProfile* profile;
    BenchmarkOperation operation;
    InputMode inputMode;
};

constexpr std::array allOperations{
    BenchmarkOperation::KeyGen,
    BenchmarkOperation::Sign,
    BenchmarkOperation::Verify,
    BenchmarkOperation::Derive,
    BenchmarkOperation::Encapsulate,
    BenchmarkOperation::Decapsulate,
    BenchmarkOperation::Encrypt,
    BenchmarkOperation::Decrypt,
    BenchmarkOperation::Hash,
    BenchmarkOperation::Xof
};

[[noreturn]] void fail(std::string_view message)
{
    throw std::runtime_error(std::string(message));
}

void require(bool condition, std::string_view message)
{
    if (!condition) fail(message);
}

std::string caseDescription(const CanonicalCase& testCase)
{
    std::string description(toStableProfileId(testCase.profile->id));
    description += " / operation=";
    description += std::to_string(static_cast<int>(testCase.operation));
    description += " / input-mode=";
    description += std::to_string(static_cast<int>(testCase.inputMode));
    return description;
}

BenchmarkConfig makeConfig(const CanonicalCase& testCase)
{
    PrimitiveConfig parameters;
    switch (testCase.profile->category) {
        case PrimitiveCategory::Signature:
            switch (testCase.inputMode) {
                case InputMode::NoSignature:
                    parameters = SignatureConfig{NoSignatureInput{}};
                    break;
                case InputMode::Prehashed:
                    parameters = SignatureConfig{PrehashedInput{}};
                    break;
                case InputMode::Message:
                    parameters = SignatureConfig{MessageInput{3}};
                    break;
                case InputMode::None:
                    fail("signature case has no input mode");
            }
            break;
        case PrimitiveCategory::KeyEstablishment:
            parameters = KeyEstablishmentConfig{};
            break;
        case PrimitiveCategory::Aead:
            parameters = AeadConfig{1};
            break;
        case PrimitiveCategory::HashXof:
            parameters = HashConfig{3};
            break;
    }

    return {
        testCase.profile->id,
        testCase.operation,
        1,
        1,
        std::move(parameters)
    };
}

void assertAdapterType(const AlgorithmProfile& profile, const std::unique_ptr<core::AlgorithmAdapter>& adapter)
{
    require(adapter != nullptr, "factory returned a null adapter");
    bool correctType = false;
    switch (profile.executionStrategy) {
        case ExecutionStrategyId::RsaPssSignature:
            correctType = dynamic_cast<const crypto::RsaPssAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::EcdsaSignature:
            correctType = dynamic_cast<const crypto::EcdsaAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::EdDsaSignature:
            correctType = dynamic_cast<const crypto::EdDsaAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::MlDsaSignature:
            correctType = dynamic_cast<const crypto::MlDsaAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::SlhDsaSignature:
            correctType = dynamic_cast<const crypto::SlhDsaAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::Ecdh:
            correctType = dynamic_cast<const crypto::EcdhAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::Xdh:
            correctType = dynamic_cast<const crypto::XdhAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::MlKem:
            correctType = dynamic_cast<const crypto::MlKemAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::Aead:
            correctType = dynamic_cast<const crypto::AeadAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::Digest:
            correctType = dynamic_cast<const crypto::DigestAdapter*>(adapter.get()) != nullptr;
            break;
        case ExecutionStrategyId::Xof:
            correctType = dynamic_cast<const crypto::XofAdapter*>(adapter.get()) != nullptr;
            break;
    }
    require(correctType, "factory returned the wrong concrete adapter type");
}

std::vector<CanonicalCase> enumerateCases(std::set<AlgorithmProfileId>& profileIds,
                                          std::set<ExecutionStrategyId>& strategies,
                                          std::set<std::pair<AlgorithmProfileId, BenchmarkOperation>>& pairs)
{
    std::vector<CanonicalCase> cases;
    for (const auto& profile : AlgorithmRegistry::all()) {
        require(profileIds.insert(profile.id).second, "duplicate canonical profile");
        strategies.insert(profile.executionStrategy);
        for (const auto operation : allOperations) {
            if (!profile.operations.contains(operation)) continue;
            require(pairs.insert({profile.id, operation}).second,
                    "duplicate canonical operation pair");

            if (profile.category == PrimitiveCategory::Signature &&
                operation != BenchmarkOperation::KeyGen) {
                const auto& capability = std::get<SignatureInputCapability>(profile.inputCapability);
                if (capability.support == SignatureInputSupport::PrehashedAndMessage) {
                    cases.push_back({&profile, operation, InputMode::Prehashed});
                    cases.push_back({&profile, operation, InputMode::Message});
                } else {
                    cases.push_back({&profile, operation, InputMode::Message});
                }
            } else if (profile.category == PrimitiveCategory::Signature) {
                cases.push_back({&profile, operation, InputMode::NoSignature});
            } else {
                cases.push_back({&profile, operation, InputMode::None});
            }
        }
    }
    return cases;
}

void testCanonicalClosure()
{
    std::set<AlgorithmProfileId> profileIds;
    std::set<ExecutionStrategyId> strategies;
    std::set<std::pair<AlgorithmProfileId, BenchmarkOperation>> pairs;
    const auto cases = enumerateCases(profileIds, strategies, pairs);

    require(profileIds.size() == 72, "canonical profile count is not 72");
    require(pairs.size() == 139, "canonical profile-operation pair count is not 139");
    require(strategies.size() == 11, "execution strategy count is not 11");
    require(cases.size() == 175, "input-mode-aware case count is not 175");

    const std::set expectedStrategies{
        ExecutionStrategyId::RsaPssSignature,
        ExecutionStrategyId::EcdsaSignature,
        ExecutionStrategyId::EdDsaSignature,
        ExecutionStrategyId::MlDsaSignature,
        ExecutionStrategyId::SlhDsaSignature,
        ExecutionStrategyId::Ecdh,
        ExecutionStrategyId::Xdh,
        ExecutionStrategyId::MlKem,
        ExecutionStrategyId::Aead,
        ExecutionStrategyId::Digest,
        ExecutionStrategyId::Xof
    };
    require(strategies == expectedStrategies, "canonical execution strategy set is incomplete");

    std::set<std::tuple<AlgorithmProfileId, BenchmarkOperation, InputMode>> uniqueCases;
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    for (const auto& testCase : cases) {
        require(uniqueCases.insert({testCase.profile->id, testCase.operation, testCase.inputMode}).second,
                "duplicate input-mode-aware canonical case");
        const auto config = makeConfig(testCase);
        ValidationResult validation;
        const auto validated = validator.validateAndCreate(config, validation);
        require(validated.has_value() && validation.isValid(), caseDescription(testCase));
        try {
            const auto adapter = factory.create(*testCase.profile, testCase.operation, *validated);
            assertAdapterType(*testCase.profile, adapter);
        } catch (const std::exception& error) {
            throw std::runtime_error(caseDescription(testCase) + ": " + error.what());
        }
    }
}

void testNegativeContracts()
{
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    const auto* ed25519 = AlgorithmRegistry::find(AlgorithmProfileId::Ed25519);
    const auto* sha256 = AlgorithmRegistry::find(AlgorithmProfileId::Sha256);
    const auto* rsa = AlgorithmRegistry::find(AlgorithmProfileId::RsaPss2048Sha256);
    require(ed25519 != nullptr && sha256 != nullptr && rsa != nullptr, "negative-test profile missing");

    auto expectInvalid = [&validator](BenchmarkConfig config) {
        ValidationResult validation;
        require(!validator.validateAndCreate(config, validation).has_value() && !validation.isValid(),
                "invalid configuration was accepted");
    };
    expectInvalid({sha256->id, BenchmarkOperation::Sign, 1, 1, HashConfig{3}});
    expectInvalid({ed25519->id, BenchmarkOperation::Sign, 1, 1, SignatureConfig{PrehashedInput{}}});
    expectInvalid({ed25519->id, BenchmarkOperation::KeyGen, 1, 1, SignatureConfig{MessageInput{3}}});
    expectInvalid({ed25519->id, BenchmarkOperation::Sign, 1, 1, KeyEstablishmentConfig{}});

    const CanonicalCase rsaCase{rsa, BenchmarkOperation::Sign, InputMode::Message};
    ValidationResult validation;
    const auto validated = validator.validateAndCreate(makeConfig(rsaCase), validation);
    require(validated.has_value() && validation.isValid(), "negative-test baseline config is invalid");

    bool threw = false;
    try {
        factory.create(*AlgorithmRegistry::find(AlgorithmProfileId::RsaPss2048Sha384),
                       rsaCase.operation, *validated);
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "factory accepted a profile/config identity mismatch");

    threw = false;
    try {
        factory.create(*rsa, BenchmarkOperation::Verify, *validated);
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "factory accepted an operation mismatch");

    auto wrongProfile = *sha256;
    wrongProfile.parameters = XofParameters{XofAlgorithm::Shake128, 28};
    ValidationResult hashValidation;
    const auto validatedHash = validator.validateAndCreate(
        {sha256->id, BenchmarkOperation::Hash, 1, 1, HashConfig{3}}, hashValidation);
    require(validatedHash.has_value() && hashValidation.isValid(), "typed-mismatch baseline config is invalid");
    threw = false;
    try {
        factory.create(wrongProfile, BenchmarkOperation::Hash, *validatedHash);
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "factory accepted a typed parameter mismatch");
}

std::span<const unsigned char> messageInputFor(const AlgorithmProfile& profile, const core::AlgorithmAdapter& adapter)
{
    switch (profile.executionStrategy) {
    case ExecutionStrategyId::RsaPssSignature:
        return dynamic_cast<const crypto::RsaPssAdapter&>(adapter).messageForTesting();
    case ExecutionStrategyId::EcdsaSignature:
        return dynamic_cast<const crypto::EcdsaAdapter&>(adapter).messageForTesting();
    case ExecutionStrategyId::EdDsaSignature:
        return dynamic_cast<const crypto::EdDsaAdapter&>(adapter).messageForTesting();
    case ExecutionStrategyId::MlDsaSignature:
        return dynamic_cast<const crypto::MlDsaAdapter&>(adapter).messageForTesting();
    case ExecutionStrategyId::SlhDsaSignature:
        return dynamic_cast<const crypto::SlhDsaAdapter&>(adapter).messageForTesting();
    default:
        fail("unexpected strategy for migrated message input");
    }
}

std::span<const unsigned char> digestInputFor(const AlgorithmProfile& profile, const core::AlgorithmAdapter& adapter)
{
    switch (profile.executionStrategy) {
    case ExecutionStrategyId::RsaPssSignature:
        return dynamic_cast<const crypto::RsaPssAdapter&>(adapter).digestForTesting();
    case ExecutionStrategyId::EcdsaSignature:
        return dynamic_cast<const crypto::EcdsaAdapter&>(adapter).digestForTesting();
    default:
        fail("unexpected strategy for migrated digest input");
    }
}

void testMigratedMessageSignAndVerify()
{
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    const std::array signatureProfiles{
        AlgorithmProfileId::RsaPss2048Sha256,
        AlgorithmProfileId::EcdsaP256Sha256,
        AlgorithmProfileId::Ed25519,
        AlgorithmProfileId::MlDsa44,
        AlgorithmProfileId::SlhDsaSha2128F};
    const std::vector<unsigned char> expected{0x01U, 0xFEU, 0x7BU};

    for (const auto profileId : signatureProfiles) {
        const auto* profile = AlgorithmRegistry::find(profileId);
        require(profile != nullptr, "migrated signature profile was not found");
        for (const auto operation : {BenchmarkOperation::Sign, BenchmarkOperation::Verify}) {
            ValidationResult validation;
            const auto config = BenchmarkConfig{
                profileId, operation, 1, 1, SignatureConfig{MessageInput{expected.size()}}};
            const auto validated = validator.validateAndCreate(config, validation);
            require(validated.has_value() && validation.isValid(), "migrated signature config was invalid");
            auto bytes = expected;
            const auto* originalData = bytes.data();
            auto adapter = factory.create(
                *profile, operation, *validated, CommonWorkload{std::move(bytes)});
            require(messageInputFor(*profile, *adapter).data() == originalData,
                    "migrated message pointer changed during factory transfer");
            adapter->prepareSeries();
            require(messageInputFor(*profile, *adapter).data() == originalData,
                    "migrated message pointer changed during preparation");
            adapter->executeIteration();
            require(messageInputFor(*profile, *adapter).data() == originalData,
                    "migrated message pointer changed during execution");
            require(std::equal(messageInputFor(*profile, *adapter).begin(),
                               messageInputFor(*profile, *adapter).end(), expected.begin(), expected.end()),
                    "migrated signature input was regenerated or copied incorrectly");
        }
    }
}

void testMigratedPrehashedSignAndVerify()
{
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    constexpr std::array cases{
        std::pair{AlgorithmProfileId::RsaPss2048Sha256, std::size_t{32}},
        std::pair{AlgorithmProfileId::RsaPss2048Sha384, std::size_t{48}},
        std::pair{AlgorithmProfileId::RsaPss2048Sha512, std::size_t{64}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha256, std::size_t{32}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha384, std::size_t{48}},
        std::pair{AlgorithmProfileId::EcdsaP256Sha512, std::size_t{64}}};

    for (const auto& [profileId, digestSize] : cases) {
        const auto* profile = AlgorithmRegistry::find(profileId);
        require(profile != nullptr, "migrated prehashed profile was not found");
        for (const auto operation : {BenchmarkOperation::Sign, BenchmarkOperation::Verify}) {
            ValidationResult validation;
            const auto config = BenchmarkConfig{
                profileId, operation, 1, 1, SignatureConfig{PrehashedInput{}}};
            const auto validated = validator.validateAndCreate(config, validation);
            require(validated.has_value() && validation.isValid(), "migrated prehashed config was invalid");
            std::vector<unsigned char> digest(digestSize, 0x3CU);
            const auto* originalData = digest.data();
            auto adapter = factory.create(
                *profile, operation, *validated, CommonWorkload{std::move(digest)});
            require(digestInputFor(*profile, *adapter).data() == originalData,
                    "migrated digest pointer changed during factory transfer");
            adapter->prepareSeries();
            require(digestInputFor(*profile, *adapter).data() == originalData,
                    "migrated digest pointer changed during preparation");
            require(digestInputFor(*profile, *adapter).size() == digestSize,
                    "migrated digest size was not retained");
            require(std::all_of(digestInputFor(*profile, *adapter).begin(),
                                digestInputFor(*profile, *adapter).end(),
                                [](unsigned char value) { return value == 0x3CU; }),
                    "migrated digest contents were changed during preparation");
            adapter->executeIteration();
            require(digestInputFor(*profile, *adapter).data() == originalData,
                    "migrated digest pointer changed during execution");
        }
    }
}

void testMigratedEmptyWorkloadRouting()
{
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    constexpr std::array cases{
        std::pair{AlgorithmProfileId::Ed25519, BenchmarkOperation::KeyGen},
        std::pair{AlgorithmProfileId::X25519, BenchmarkOperation::KeyGen},
        std::pair{AlgorithmProfileId::X448, BenchmarkOperation::KeyGen},
        std::pair{AlgorithmProfileId::MlKem512, BenchmarkOperation::KeyGen}};
    for (const auto& [profileId, operation] : cases) {
        const auto* profile = AlgorithmRegistry::find(profileId);
        require(profile != nullptr, "empty-workload profile was not found");
        ValidationResult validation;
        const auto parameters = profile->category == PrimitiveCategory::Signature
            ? PrimitiveConfig{SignatureConfig{NoSignatureInput{}}}
            : PrimitiveConfig{KeyEstablishmentConfig{}};
        const auto config = BenchmarkConfig{profileId, operation, 1, 1, parameters};
        const auto validated = validator.validateAndCreate(config, validation);
        require(validated.has_value() && validation.isValid(), "empty-workload config was invalid");
        auto adapter = factory.create(*profile, operation, *validated, CommonWorkload{});
        assertAdapterType(*profile, adapter);
        adapter->prepareSeries();
        adapter->executeIteration();

        bool rejected = false;
        try {
            static_cast<void>(factory.create(
                *profile, operation, *validated,
                CommonWorkload{std::vector<unsigned char>{0x01U}}));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "empty-only strategy accepted a nonempty common workload");
    }
}

void testMigratedWorkloadRejectionsAndCanonicalConstruction()
{
    ConfigValidator validator;
    crypto::AdapterFactory factory;
    const auto expectWorkloadRejected = [&](AlgorithmProfileId profileId,
                                            BenchmarkOperation operation,
                                            SignatureConfig parameters,
                                            std::vector<unsigned char> bytes) {
        const auto* profile = AlgorithmRegistry::find(profileId);
        require(profile != nullptr, "invalid-workload profile was not found");
        ValidationResult validation;
        const auto config = BenchmarkConfig{profileId, operation, 1, 1, std::move(parameters)};
        const auto validated = validator.validateAndCreate(config, validation);
        require(validated.has_value() && validation.isValid(), "invalid-workload config was invalid");
        bool rejected = false;
        try {
            static_cast<void>(factory.create(
                *profile, operation, *validated, CommonWorkload{std::move(bytes)}));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "factory accepted an invalid migrated workload size");
    };
    expectWorkloadRejected(AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign,
                           SignatureConfig{MessageInput{3}}, {0x01U, 0x02U});
    expectWorkloadRejected(AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign,
                           SignatureConfig{PrehashedInput{}}, std::vector<unsigned char>(31, 0x01U));
    expectWorkloadRejected(AlgorithmProfileId::Ed25519, BenchmarkOperation::Verify,
                           SignatureConfig{MessageInput{3}}, {0x01U, 0x02U});

    ValidationResult inputModeValidation;
    const auto unsupportedInput = validator.validateAndCreate(
        {AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 1, 1,
         SignatureConfig{PrehashedInput{}}},
        inputModeValidation);
    require(!unsupportedInput.has_value() && !inputModeValidation.isValid(),
            "EdDSA accepted the unsupported Prehashed input mode");

    std::set<AlgorithmProfileId> profileIds;
    std::set<ExecutionStrategyId> strategies;
    std::set<std::pair<AlgorithmProfileId, BenchmarkOperation>> pairs;
    const auto canonicalCases = enumerateCases(profileIds, strategies, pairs);
    std::set<std::tuple<AlgorithmProfileId, BenchmarkOperation, InputMode>> seen;
    for (const auto& testCase : canonicalCases) {
        if (!seen.insert({testCase.profile->id, testCase.operation, testCase.inputMode}).second) continue;
        ValidationResult validation;
        const auto config = makeConfig(testCase);
        const auto validated = validator.validateAndCreate(config, validation);
        require(validated.has_value() && validation.isValid(), "canonical four-argument config was invalid");
        auto adapter = factory.create(
            *testCase.profile, testCase.operation, *validated,
            buildCommonWorkload(*validated, *testCase.profile));
        assertAdapterType(*testCase.profile, adapter);
    }
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testCanonicalClosure();
        cryptobench::tests::testNegativeContracts();
        cryptobench::tests::testMigratedMessageSignAndVerify();
        cryptobench::tests::testMigratedPrehashedSignAndVerify();
        cryptobench::tests::testMigratedEmptyWorkloadRouting();
        cryptobench::tests::testMigratedWorkloadRejectionsAndCanonicalConstruction();
        return 0;
    } catch (const std::exception& error) {
        return (std::cerr << "FAIL " << error.what() << '\n'), 1;
    }
}
