#include <cryptobench/application/ResultDocument.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

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

BenchmarkConfig sampleConfig()
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 64, 2, HashConfig{128}};
}

StructuralCharacteristics sampleCharacteristics()
{
    return HashCharacteristics{32};
}

EnvironmentInfo sampleEnvironment()
{
    return {"0.1.0", "abc123", "3.6.4", "Windows", "x64", "Debug", std::chrono::system_clock::time_point{}};
}

BenchmarkStatistics sampleStatistics()
{
    return {
        Statistics<double>{1.0, 1.0, 1.0, 1.0, 0.0},
        Statistics<double>{2.0, 2.0, 2.0, 2.0, 0.0},
        Statistics<double>{3.0, 3.0, 3.0, 3.0, 0.0}
    };
}

ErrorInfo sampleError()
{
    return {ErrorCode::InternalError, FailureStage::ResultAssembly, std::nullopt, "failed", std::nullopt};
}

void testResultModeStrings()
{
    require(toStableString(ResultMode::Single) == "single", "single mode string mismatch");
    require(toStableString(ResultMode::Batch) == "batch", "batch mode string mismatch");
}

void testDocumentStatusStrings()
{
    require(toStableString(ResultDocumentStatus::InProgress) == "inProgress", "in-progress status string mismatch");
    require(toStableString(ResultDocumentStatus::Completed) == "completed", "completed status string mismatch");
    require(toStableString(ResultDocumentStatus::CompletedWithFailures) == "completedWithFailures",
            "completed-with-failures status string mismatch");
    require(toStableString(ResultDocumentStatus::Cancelled) == "cancelled", "cancelled status string mismatch");
    require(toStableString(ResultDocumentStatus::Failed) == "failed", "failed status string mismatch");
}

void testEntryStatusStrings()
{
    require(toStableString(ExportEntryStatus::NotStarted) == "notStarted", "not-started status string mismatch");
    require(toStableString(ExportEntryStatus::Completed) == "completed", "completed entry string mismatch");
    require(toStableString(ExportEntryStatus::Failed) == "failed", "failed entry string mismatch");
    require(toStableString(ExportEntryStatus::Cancelled) == "cancelled", "cancelled entry string mismatch");
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

void testUnsupportedValuesRejected()
{
    requireUnsupportedValueRejected(static_cast<ResultMode>(99), "unsupported result mode was accepted");
    requireUnsupportedValueRejected(static_cast<ResultDocumentStatus>(99), "unsupported document status was accepted");
    requireUnsupportedValueRejected(static_cast<ExportEntryStatus>(99), "unsupported entry status was accepted");
}

void testExportEntryPreservesCanonicalValues()
{
    const auto config = sampleConfig();
    const auto characteristics = sampleCharacteristics();
    const auto environment = sampleEnvironment();
    const auto statistics = sampleStatistics();
    const ExportEntry entry{
        1, "entry-1", ExportEntryStatus::Completed, config, characteristics, environment, statistics, std::nullopt
    };

    require(entry.entryIndex == 1 && entry.id == "entry-1", "entry identity mismatch");
    require(entry.status == ExportEntryStatus::Completed, "entry status mismatch");
    require(entry.config.profile == config.profile && entry.config.operation == config.operation
                && entry.config.iterationsPerRun == config.iterationsPerRun && entry.config.runs == config.runs,
            "entry config mismatch");
    require(std::get<HashConfig>(entry.config.parameters).inputSize == 128, "entry config parameters mismatch");
    require(std::get<HashCharacteristics>(entry.characteristics).outputBytes == 32,
            "entry characteristics mismatch");
    require(entry.environment.has_value() && entry.environment->gitCommit == environment.gitCommit,
            "entry environment mismatch");
    require(entry.statistics.has_value() && entry.statistics->cpuNanosecondsPerOperation.mean == 2.0,
            "entry statistics mismatch");
    require(!entry.error.has_value(), "completed entry unexpectedly contains an error");
}

void testOptionalFieldsCanBeAbsent()
{
    const ExportEntry entry{
        1, std::nullopt, ExportEntryStatus::NotStarted, sampleConfig(), sampleCharacteristics(),
        std::nullopt, std::nullopt, std::nullopt
    };
    require(!entry.id.has_value() && !entry.environment.has_value() && !entry.statistics.has_value()
                && !entry.error.has_value(),
            "absent optional fields were not preserved");
}

void testDocumentPreservesModeStatusAndOrdering()
{
    const ExportEntry first{
        1, std::nullopt, ExportEntryStatus::Completed, sampleConfig(), sampleCharacteristics(),
        std::nullopt, std::nullopt, std::nullopt
    };
    const ExportEntry second{
        2, std::nullopt, ExportEntryStatus::Failed, sampleConfig(), sampleCharacteristics(),
        sampleEnvironment(), std::nullopt, sampleError()
    };
    const ResultDocument document{ResultMode::Batch, ResultDocumentStatus::CompletedWithFailures, {first, second}};

    require(document.mode == ResultMode::Batch, "document mode mismatch");
    require(document.status == ResultDocumentStatus::CompletedWithFailures, "document status mismatch");
    require(document.entries.size() == 2 && document.entries[0].entryIndex == 1
                && document.entries[1].entryIndex == 2,
            "document entry ordering mismatch");
    require(document.entries[0].status == ExportEntryStatus::Completed
                && document.entries[1].status == ExportEntryStatus::Failed,
            "document entry statuses mismatch");
    require(document.entries[1].error.has_value() && !document.entries[1].statistics.has_value(),
            "failed entry optional fields mismatch");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testResultModeStrings();
        std::cout << "PASS result mode strings\n";
        cryptobench::tests::testDocumentStatusStrings();
        std::cout << "PASS document status strings\n";
        cryptobench::tests::testEntryStatusStrings();
        std::cout << "PASS entry status strings\n";
        cryptobench::tests::testUnsupportedValuesRejected();
        std::cout << "PASS unsupported values rejected\n";
        cryptobench::tests::testExportEntryPreservesCanonicalValues();
        std::cout << "PASS export entry canonical values\n";
        cryptobench::tests::testOptionalFieldsCanBeAbsent();
        std::cout << "PASS optional fields\n";
        cryptobench::tests::testDocumentPreservesModeStatusAndOrdering();
        std::cout << "PASS result document ordering\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL ResultDocument: " << error.what() << '\n';
        return 1;
    }
}