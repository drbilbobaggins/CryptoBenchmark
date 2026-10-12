#include <cryptobench/application/SingleResultDocumentService.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
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
    return {"0.1.0", "abc123", "3.6.4", "Windows", "x64", "Debug",
            std::chrono::system_clock::time_point{std::chrono::milliseconds{1790035200177LL}}};
}

BenchmarkStatistics sampleStatistics()
{
    return {
        Statistics<double>{1.25, 1.5, 1.0, 2.0, 0.125},
        Statistics<double>{2.75, 2.5, 2.0, 3.0, 0.25},
        MemoryV2Statistics{
            Statistics<double>{-1.0, -1.0, -2.0, 0.0, 0.5},
            Statistics<double>{3.5, 3.25, 3.0, 4.0, 0.5},
            Statistics<double>{5.5, 5.25, 5.0, 6.0, 0.5},
            Statistics<double>{6.5, 6.25, 6.0, 7.0, 0.5}}
    };
}

RunResult sampleRun(std::uint32_t index)
{
    return {index, std::chrono::nanoseconds{100}, MeanOperationDuration{1.25},
            std::chrono::nanoseconds{80}, MeanOperationDuration{1.0},
            MemoryRunMeasurement{100, 120, 20}};
}

BenchmarkResult completedResult()
{
        return {sampleConfig(), {sampleRun(0), sampleRun(1)}, sampleStatistics(), sampleCharacteristics(),
            sampleEnvironment(), BenchmarkStatus::Completed, std::nullopt, MeasurementSettings{2}};
}

void requireCharacteristicsEqual(const StructuralCharacteristics& actual,
                                 const StructuralCharacteristics& expected,
                                 std::string_view message)
{
    require(std::holds_alternative<HashCharacteristics>(actual)
                && std::holds_alternative<HashCharacteristics>(expected),
            message);
    require(std::get<HashCharacteristics>(actual).outputBytes
                == std::get<HashCharacteristics>(expected).outputBytes,
            message);
}

void requireEnvironmentEqual(const EnvironmentInfo& actual, const EnvironmentInfo& expected,
                             std::string_view message)
{
    require(actual.applicationVersion == expected.applicationVersion
                && actual.gitCommit == expected.gitCommit
                && actual.opensslVersion == expected.opensslVersion
                && actual.operatingSystem == expected.operatingSystem
                && actual.architecture == expected.architecture
                && actual.buildType == expected.buildType
                && actual.measuredAt == expected.measuredAt,
            message);
}

void requireStatisticGroupEqual(const Statistics<double>& actual, const Statistics<double>& expected,
                                std::string_view message)
{
    require(actual.mean == expected.mean && actual.median == expected.median
                && actual.min == expected.min && actual.max == expected.max
                && actual.stddev == expected.stddev,
            message);
}

void requireStatisticsEqual(const BenchmarkStatistics& actual, const BenchmarkStatistics& expected,
                            std::string_view message)
{
    requireStatisticGroupEqual(actual.elapsedNanosecondsPerOperation,
                               expected.elapsedNanosecondsPerOperation, message);
    requireStatisticGroupEqual(actual.cpuNanosecondsPerOperation,
                               expected.cpuNanosecondsPerOperation, message);
    const auto& actualMemory = std::get<MemoryV2Statistics>(actual.memory);
    const auto& expectedMemory = std::get<MemoryV2Statistics>(expected.memory);
    requireStatisticGroupEqual(actualMemory.readyStatePrivateUsageDeltaBytes,
                               expectedMemory.readyStatePrivateUsageDeltaBytes, message);
    requireStatisticGroupEqual(actualMemory.preparationPeakPrivateUsageDeltaBytes,
                               expectedMemory.preparationPeakPrivateUsageDeltaBytes, message);
    requireStatisticGroupEqual(actualMemory.executionPeakPrivateUsageDeltaBytes,
                               expectedMemory.executionPeakPrivateUsageDeltaBytes, message);
    requireStatisticGroupEqual(actualMemory.operationalPeakPrivateUsageDeltaBytes,
                               expectedMemory.operationalPeakPrivateUsageDeltaBytes, message);
}

void requireErrorStateEqual(const std::optional<ErrorInfo>& actual,
                            const std::optional<ErrorInfo>& expected,
                            std::string_view message)
{
    require(actual.has_value() == expected.has_value(), message);
    if (actual.has_value()) {
        require(actual->code == expected->code && actual->stage == expected->stage
                    && actual->runIndex == expected->runIndex
                    && actual->technicalMessage == expected->technicalMessage
                    && actual->libraryDetails == expected->libraryDetails,
                message);
    }
}

void requireRunEqual(const RunResult& actual, const RunResult& expected, std::string_view message)
{
    const auto& actualMemory = std::get<MemoryRunMeasurement>(actual.memory);
    const auto& expectedMemory = std::get<MemoryRunMeasurement>(expected.memory);
    require(actual.runIndex == expected.runIndex
                && actual.totalElapsedTime == expected.totalElapsedTime
                && actual.meanElapsedTimePerOperation.count()
                    == expected.meanElapsedTimePerOperation.count()
                && actual.totalCpuTime == expected.totalCpuTime
                && actual.meanCpuTimePerOperation.count() == expected.meanCpuTimePerOperation.count()
                && actualMemory.baselineBytes == expectedMemory.baselineBytes
                && actualMemory.peakSampledBytes == expectedMemory.peakSampledBytes
                && actualMemory.peakDeltaBytes == expectedMemory.peakDeltaBytes,
            message);
}

template <typename Function>
void requireInvalidArgument(Function&& function, std::string_view message)
{
    bool rejected = false;
    try {
        static_cast<void>(function());
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void testCompletedMapping()
{
    const auto source = completedResult();
    const auto document = SingleResultDocumentService{}.create(source);

    require(document.mode == ResultMode::Single, "document mode mismatch");
    require(document.status == ResultDocumentStatus::Completed, "document status mismatch");
    require(document.entries.size() == 1, "document entry count mismatch");

    const auto& entry = document.entries.front();
    require(entry.entryIndex == 1, "entry index mismatch");
    require(!entry.id.has_value(), "completed single entry has an id");
    require(entry.status == ExportEntryStatus::Completed, "entry status mismatch");
    require(!entry.error.has_value(), "completed entry has an error");
    require(entry.config.profile == source.config.profile && entry.config.operation == source.config.operation
                && entry.config.iterationsPerRun == source.config.iterationsPerRun
                && entry.config.runs == source.config.runs,
            "config fields were not preserved");
    require(std::get<HashConfig>(entry.config.parameters).inputSize
                == std::get<HashConfig>(source.config.parameters).inputSize,
            "primitive config payload was not preserved");
    requireCharacteristicsEqual(entry.characteristics, source.characteristics,
                                 "characteristics were not preserved");
    require(entry.environment.has_value(), "entry environment is missing");
    requireEnvironmentEqual(*entry.environment, source.environment, "environment was not preserved");
    require(entry.statistics.has_value(), "entry statistics are missing");
    requireStatisticsEqual(*entry.statistics, *source.statistics, "statistics were not preserved");
    require(entry.statistics->elapsedNanosecondsPerOperation.mean == 1.25
                && entry.statistics->cpuNanosecondsPerOperation.stddev == 0.25,
            "fractional statistics were changed");
}

void testSourceIsNotMutated()
{
    const auto source = completedResult();
    const auto before = source;
    static_cast<void>(SingleResultDocumentService{}.create(source));
    require(source.config.profile == before.config.profile && source.config.operation == before.config.operation
                && source.config.iterationsPerRun == before.config.iterationsPerRun
                && source.config.runs == before.config.runs
                && std::get<HashConfig>(source.config.parameters).inputSize
                    == std::get<HashConfig>(before.config.parameters).inputSize,
            "source config was mutated");
    require(source.runs.size() == before.runs.size(), "source run count was mutated");
    for (std::size_t index = 0; index < source.runs.size(); ++index) {
        requireRunEqual(source.runs[index], before.runs[index], "source run was mutated");
    }
    require(source.statistics.has_value() == before.statistics.has_value(),
            "source statistics presence was mutated");
    if (source.statistics.has_value()) {
        requireStatisticsEqual(*source.statistics, *before.statistics, "source statistics were mutated");
    }
    requireCharacteristicsEqual(source.characteristics, before.characteristics,
                                "source characteristics were mutated");
    requireEnvironmentEqual(source.environment, before.environment, "source environment was mutated");
    require(source.status == before.status, "source status was mutated");
    requireErrorStateEqual(source.error, before.error, "source error state was mutated");
}

void testRejectedStatusesAndMalformedCompletedResults()
{
    auto failed = completedResult();
    failed.status = BenchmarkStatus::Failed;
    failed.statistics = std::nullopt;
    failed.error = ErrorInfo{ErrorCode::InternalError, FailureStage::ResultAssembly, std::nullopt, "failed", std::nullopt};
    requireInvalidArgument([&] { return SingleResultDocumentService{}.create(failed); }, "failed result was accepted");

    auto cancelled = completedResult();
    cancelled.status = BenchmarkStatus::Cancelled;
    cancelled.statistics = std::nullopt;
    cancelled.error = std::nullopt;
    requireInvalidArgument([&] { return SingleResultDocumentService{}.create(cancelled); }, "cancelled result was accepted");

    auto missingStatistics = completedResult();
    missingStatistics.statistics = std::nullopt;
    requireInvalidArgument([&] { return SingleResultDocumentService{}.create(missingStatistics); },
                           "completed result without statistics was accepted");

    auto completedWithError = completedResult();
    completedWithError.error = ErrorInfo{ErrorCode::InternalError, FailureStage::ResultAssembly, std::nullopt, "error", std::nullopt};
    requireInvalidArgument([&] { return SingleResultDocumentService{}.create(completedWithError); },
                           "completed result with error was accepted");

    auto missingMeasurement = completedResult();
    missingMeasurement.measurementSettings.reset();
    requireInvalidArgument([&] { return SingleResultDocumentService{}.create(missingMeasurement); },
                           "completed result without measurement settings was accepted");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testCompletedMapping();
        std::cout << "PASS completed mapping\n";
        cryptobench::tests::testSourceIsNotMutated();
        std::cout << "PASS source immutability\n";
        cryptobench::tests::testRejectedStatusesAndMalformedCompletedResults();
        std::cout << "PASS rejection boundary\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL SingleResultDocumentService: " << error.what() << '\n';
        return 1;
    }
}
