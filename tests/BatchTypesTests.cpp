#include <cryptobench/application/BatchTypes.h>

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

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

template <typename Enum>
void requireUnsupportedValueRejected(Enum value, std::string_view message)
{
    bool rejected = false;
    try {
        static_cast<void>(toStableString(value));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void testIssueCodeStrings()
{
    const std::array expected{
        std::pair{BatchInputIssueCode::FileOpenFailed, "fileOpenFailed"},
        std::pair{BatchInputIssueCode::InputTooLarge, "inputTooLarge"},
        std::pair{BatchInputIssueCode::InvalidUtf8, "invalidUtf8"},
        std::pair{BatchInputIssueCode::InvalidJson, "invalidJson"},
        std::pair{BatchInputIssueCode::DuplicateKey, "duplicateKey"},
        std::pair{BatchInputIssueCode::InvalidRootType, "invalidRootType"},
        std::pair{BatchInputIssueCode::UnknownField, "unknownField"},
        std::pair{BatchInputIssueCode::MissingField, "missingField"},
        std::pair{BatchInputIssueCode::InvalidType, "invalidType"},
        std::pair{BatchInputIssueCode::InvalidValue, "invalidValue"},
        std::pair{BatchInputIssueCode::UnsupportedFormat, "unsupportedFormat"},
        std::pair{BatchInputIssueCode::UnsupportedSchemaVersion, "unsupportedSchemaVersion"},
        std::pair{BatchInputIssueCode::InvalidEntryCount, "invalidEntryCount"},
        std::pair{BatchInputIssueCode::InvalidId, "invalidId"},
        std::pair{BatchInputIssueCode::DuplicateId, "duplicateId"},
        std::pair{BatchInputIssueCode::UnknownProfileId, "unknownProfileId"},
        std::pair{BatchInputIssueCode::UnknownOperation, "unknownOperation"},
        std::pair{BatchInputIssueCode::InvalidParameters, "invalidParameters"},
        std::pair{BatchInputIssueCode::ConfigurationInvalid, "configurationInvalid"}
    };

    for (const auto& [code, expectedString] : expected) {
        require(toStableString(code) == expectedString, "batch issue code string mismatch");
    }
}

void testValidationCodeStrings()
{
    const std::array expected{
        std::pair{ValidationErrorCode::UnsupportedOperation, "unsupportedOperation"},
        std::pair{ValidationErrorCode::PrimitiveConfigMismatch, "primitiveConfigMismatch"},
        std::pair{ValidationErrorCode::SignatureInputMismatch, "signatureInputMismatch"},
        std::pair{ValidationErrorCode::IterationsOutOfRange, "iterationsOutOfRange"},
        std::pair{ValidationErrorCode::RunsOutOfRange, "runsOutOfRange"},
        std::pair{ValidationErrorCode::SeriesIterationBudgetExceeded, "seriesIterationBudgetExceeded"},
        std::pair{ValidationErrorCode::WorkloadOutOfRange, "workloadOutOfRange"}
    };

    for (const auto& [code, expectedString] : expected) {
        require(toStableString(code) == expectedString, "validation code string mismatch");
    }
}

void testUnsupportedValuesRejected()
{
    requireUnsupportedValueRejected(static_cast<BatchInputIssueCode>(99), "unsupported issue code was accepted");
    requireUnsupportedValueRejected(static_cast<ValidationErrorCode>(99), "unsupported validation code was accepted");
}

void testBatchInputIssuePreservesValues()
{
    const BatchInputIssue issue{
        BatchInputIssueCode::ConfigurationInvalid,
        "entries[0].iterationsPerRun",
        "iterations exceed the configured limit",
        ValidationErrorCode::IterationsOutOfRange
    };

    require(issue.code == BatchInputIssueCode::ConfigurationInvalid, "issue code mismatch");
    require(issue.path == "entries[0].iterationsPerRun", "issue path mismatch");
    require(issue.technicalMessage == "iterations exceed the configured limit", "issue message mismatch");
    require(issue.domainCode == ValidationErrorCode::IterationsOutOfRange, "issue domain code mismatch");
}

void testBatchEntryPreservesCanonicalValues()
{
    const BenchmarkConfig config{
        AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        64,
        2,
        HashConfig{128}
    };
    const StructuralCharacteristics characteristics = HashCharacteristics{32};
    const BatchEntryDefinition entry{3, std::string{"hash-entry"}, config, characteristics};

    require(entry.entryIndex == 3, "entry index mismatch");
    require(entry.id == "hash-entry", "entry id mismatch");
    require(entry.config.profile == config.profile && entry.config.operation == config.operation
                && entry.config.iterationsPerRun == config.iterationsPerRun && entry.config.runs == config.runs,
            "entry config mismatch");
    require(std::get<HashConfig>(entry.config.parameters).inputSize == 128, "entry parameters mismatch");
    require(std::get<HashCharacteristics>(entry.characteristics).outputBytes == 32,
            "entry characteristics mismatch");
}

void testBatchDefinitionReadOnlyCreationBoundary()
{
    static_assert(std::is_same_v<decltype(std::declval<const BatchDefinition&>().entries()),
                                 const std::vector<BatchEntryDefinition>&>);
    static_assert(!std::is_constructible_v<BatchDefinition, std::vector<BatchEntryDefinition>>);
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testIssueCodeStrings();
        std::cout << "PASS batch issue code strings\n";
        cryptobench::tests::testValidationCodeStrings();
        std::cout << "PASS validation code strings\n";
        cryptobench::tests::testUnsupportedValuesRejected();
        std::cout << "PASS unsupported values rejected\n";
        cryptobench::tests::testBatchInputIssuePreservesValues();
        std::cout << "PASS batch input issue values\n";
        cryptobench::tests::testBatchEntryPreservesCanonicalValues();
        std::cout << "PASS batch entry canonical values\n";
        cryptobench::tests::testBatchDefinitionReadOnlyCreationBoundary();
        std::cout << "PASS batch definition API boundary\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchTypes: " << error.what() << '\n';
        return 1;
    }
}
