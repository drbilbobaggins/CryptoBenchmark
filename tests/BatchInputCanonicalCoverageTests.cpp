#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BatchInputDocumentBuilder.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/StructuralCharacteristics.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireCharacteristicsEqual(const StructuralCharacteristics& actual,
                                 const StructuralCharacteristics& expected)
{
    require(actual.index() == expected.index(), "structural characteristic variant mismatch");
    std::visit([](const auto& left, const auto& right) {
        using Left = std::decay_t<decltype(left)>;
        using Right = std::decay_t<decltype(right)>;
        if constexpr (std::is_same_v<Left, Right>) {
            if constexpr (std::is_same_v<Left, SignatureCharacteristics>) {
                require(left.publicKeyBytes == right.publicKeyBytes, "signature public key mismatch");
                require(left.privateKeyBytes == right.privateKeyBytes, "signature private key mismatch");
                require(left.signatureSize.has_value() == right.signatureSize.has_value(), "signature size presence mismatch");
                if (left.signatureSize.has_value()) {
                    require(left.signatureSize->bytes == right.signatureSize->bytes, "signature size bytes mismatch");
                    require(left.signatureSize->kind == right.signatureSize->kind, "signature size kind mismatch");
                }
            } else if constexpr (std::is_same_v<Left, KeyEstablishmentCharacteristics>) {
                require(left.sharedSecretBytes == right.sharedSecretBytes, "shared secret size mismatch");
                require(left.publicKeyBytes == right.publicKeyBytes, "key establishment public key mismatch");
                require(left.privateKeyBytes == right.privateKeyBytes, "key establishment private key mismatch");
                require(left.ciphertextBytes == right.ciphertextBytes, "ciphertext size mismatch");
            } else if constexpr (std::is_same_v<Left, AeadCharacteristics>) {
                require(left.keyBytes == right.keyBytes, "AEAD key size mismatch");
                require(left.nonceBytes == right.nonceBytes, "AEAD nonce size mismatch");
                require(left.aadBytes == right.aadBytes, "AEAD AAD size mismatch");
                require(left.tagBytes == right.tagBytes, "AEAD tag size mismatch");
            } else {
                require(left.outputBytes == right.outputBytes, "hash output size mismatch");
            }
        }
    }, actual, expected);
}

void requirePrimitiveConfigEqual(const PrimitiveConfig& actual, const PrimitiveConfig& expected)
{
    require(actual.index() == expected.index(), "primitive configuration variant mismatch");
    if (std::holds_alternative<SignatureConfig>(actual)) {
        const auto& left = std::get<SignatureConfig>(actual);
        const auto& right = std::get<SignatureConfig>(expected);
        require(left.input.index() == right.input.index(), "signature input variant mismatch");
        if (std::holds_alternative<MessageInput>(left.input)) {
            require(std::get<MessageInput>(left.input).messageSize
                        == std::get<MessageInput>(right.input).messageSize,
                    "signature message size mismatch");
        }
    } else if (std::holds_alternative<AeadConfig>(actual)) {
        require(std::get<AeadConfig>(actual).plaintextSize
                    == std::get<AeadConfig>(expected).plaintextSize,
                "AEAD plaintext size mismatch");
    } else if (std::holds_alternative<HashConfig>(actual)) {
        require(std::get<HashConfig>(actual).inputSize
                    == std::get<HashConfig>(expected).inputSize,
                "hash input size mismatch");
    } else {
        require(std::holds_alternative<KeyEstablishmentConfig>(expected),
                "key-establishment configuration mismatch");
    }
}

void requireConfigEqual(const BenchmarkConfig& actual, const BenchmarkConfig& expected)
{
    require(actual.profile == expected.profile, "profile mismatch after roundtrip");
    require(actual.operation == expected.operation, "operation mismatch after roundtrip");
    require(actual.iterationsPerRun == expected.iterationsPerRun, "iterations mismatch after roundtrip");
    require(actual.runs == expected.runs, "runs mismatch after roundtrip");
    requirePrimitiveConfigEqual(actual.parameters, expected.parameters);
}

std::array<BenchmarkOperation, 10> canonicalOperations()
{
    return {BenchmarkOperation::KeyGen, BenchmarkOperation::Sign, BenchmarkOperation::Verify,
            BenchmarkOperation::Derive, BenchmarkOperation::Encapsulate, BenchmarkOperation::Decapsulate,
            BenchmarkOperation::Encrypt, BenchmarkOperation::Decrypt, BenchmarkOperation::Hash,
            BenchmarkOperation::Xof};
}

void appendCasesForProfile(const AlgorithmProfile& profile, std::vector<BenchmarkConfig>& cases,
                           std::set<std::pair<int, int>>& supportedPairs,
                           std::array<bool, 10>& representedOperations)
{
    const auto operations = canonicalOperations();
    for (std::size_t operationIndex = 0; operationIndex < operations.size(); ++operationIndex) {
        const auto operation = operations[operationIndex];
        if (!profile.operations.contains(operation)) {
            continue;
        }
        supportedPairs.emplace(static_cast<int>(profile.id), static_cast<int>(operation));
        representedOperations[operationIndex] = true;

        if (profile.category == PrimitiveCategory::Signature) {
            if (operation == BenchmarkOperation::KeyGen) {
                cases.push_back({profile.id, operation, 1, 1, SignatureConfig{NoSignatureInput{}}});
                continue;
            }
            if (operation != BenchmarkOperation::Sign && operation != BenchmarkOperation::Verify) {
                throw std::runtime_error("signature profile has an unexpected canonical operation");
            }
            const auto capability = std::get<SignatureInputCapability>(profile.inputCapability);
            if (capability.support == SignatureInputSupport::PrehashedAndMessage) {
                cases.push_back({profile.id, operation, 1, 1, SignatureConfig{PrehashedInput{}}});
            }
            cases.push_back({profile.id, operation, 1, 1, SignatureConfig{MessageInput{64}}});
        } else if (profile.category == PrimitiveCategory::KeyEstablishment) {
            cases.push_back({profile.id, operation, 1, 1, KeyEstablishmentConfig{}});
        } else if (profile.category == PrimitiveCategory::Aead) {
            cases.push_back({profile.id, operation, 1, 1, AeadConfig{64}});
        } else {
            cases.push_back({profile.id, operation, 1, 1, HashConfig{64}});
        }
    }
}

void testRegistryDrivenCanonicalRoundtrips()
{
    const auto profiles = AlgorithmRegistry::all();
    require(profiles.size() == 72, "canonical registry profile count changed");

    std::vector<BenchmarkConfig> cases;
    std::set<std::pair<int, int>> supportedPairs;
    std::array<bool, 10> representedOperations{};
    std::set<int> uniqueProfiles;
    for (const auto& profile : profiles) {
        uniqueProfiles.insert(static_cast<int>(profile.id));
        appendCasesForProfile(profile, cases, supportedPairs, representedOperations);
    }

    require(uniqueProfiles.size() == 72, "unique canonical profile count changed");
    require(supportedPairs.size() == 139, "supported profile-operation count changed");
    require(cases.size() == 175, "input-mode-aware canonical case count changed");
    require(std::count(representedOperations.begin(), representedOperations.end(), true) == 10,
            "canonical operation coverage changed");

    const ConfigValidator validator;
    std::size_t successfulRoundtrips = 0;
    for (const auto& sourceConfig : cases) {
        const auto validation = validator.validate(sourceConfig);
        require(validation.isValid(), "registry-derived canonical config failed validation");

        const auto bytes = BatchInputDocumentBuilder{}.build({sourceConfig});
        const auto result = BatchInputParser{}.parseData(bytes);
        require(result.issues.empty(), "canonical batch roundtrip produced issues");
        require(result.definition.has_value(), "canonical batch roundtrip produced no definition");
        const auto& entries = result.definition->entries();
        require(entries.size() == 1, "canonical batch roundtrip entry count mismatch");
        require(entries.front().entryIndex == 1, "canonical batch entry index mismatch");
        require(!entries.front().id.has_value(), "canonical batch unexpectedly contains an ID");
        requireConfigEqual(entries.front().config, sourceConfig);

        const auto* profile = AlgorithmRegistry::find(entries.front().config.profile);
        require(profile != nullptr, "roundtrip profile was not found in registry");
        requireCharacteristicsEqual(entries.front().characteristics, profile->characteristics);
        ++successfulRoundtrips;
    }

    require(successfulRoundtrips == 175, "canonical semantic roundtrip count changed");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testRegistryDrivenCanonicalRoundtrips();
        std::cout << "PASS canonical registry roundtrips: 72 profiles, 139 pairs, 175 cases, 10 operations\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchInputCanonicalCoverage: " << error.what() << '\n';
        return 1;
    }
}
