#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/crypto/AdapterFactory.h>

#include <array>
#include <iostream>
#include <memory>
#include <set>
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

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testCanonicalClosure();
        cryptobench::tests::testNegativeContracts();
        return 0;
    } catch (const std::exception& error) {
        return (std::cerr << "FAIL " << error.what() << '\n'), 1;
    }
}
