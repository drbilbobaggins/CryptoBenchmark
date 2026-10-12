#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BatchResultDocumentService.h>

#include <QFile>
#include <QTemporaryDir>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace cryptobench;
using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

BatchDefinition definition()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory is invalid");
    const auto path = directory.filePath("batch.json");
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch fixture could not be opened");
    const QByteArray input =
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"first","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}},)"
        R"({"profileId":"sha3-256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}}]})";
    require(file.write(input) == input.size(), "batch fixture could not be written");
    file.close();
    const auto parsed = BatchInputParser{}.parseFile(path);
    require(parsed.issues.empty() && parsed.definition.has_value(), "batch fixture was rejected");
    return *parsed.definition;
}

EnvironmentInfo environment()
{
    return {"app-9.8.7", "git-distinctive", "openssl-distinctive", "Windows 11 x64",
            "amd64", "RelWithDebInfo", std::chrono::system_clock::time_point{
                std::chrono::milliseconds{123456789}}};
}

BenchmarkStatistics statistics()
{
    return {Statistics<double>{1.25, 1.5, 0.75, 2.25, 0.125},
            Statistics<double>{3.25, 3.5, 2.75, 4.25, 0.225},
            MemoryV2Statistics{
                Statistics<double>{-1.25, -1.5, -2.25, -0.25, 0.125},
                Statistics<double>{5.25, 5.5, 4.75, 6.25, 0.325},
                Statistics<double>{7.25, 7.5, 6.75, 8.25, 0.425},
                Statistics<double>{9.25, 9.5, 8.75, 10.25, 0.525}}};
}

BatchExecutionState state()
{
    auto value = createBatchExecutionState(definition(), {});
    value.measurementSettings = MeasurementSettings{3};
    return value;
}

bool sameEnvironment(const EnvironmentInfo& left, const EnvironmentInfo& right)
{
    return left.applicationVersion == right.applicationVersion && left.gitCommit == right.gitCommit &&
           left.opensslVersion == right.opensslVersion && left.operatingSystem == right.operatingSystem &&
           left.architecture == right.architecture && left.buildType == right.buildType &&
           left.measuredAt == right.measuredAt;
}

BenchmarkResult resultFor(const BatchEntryDefinition& entry, BenchmarkStatus status)
{
    const auto error = status == BenchmarkStatus::Failed
        ? std::optional<ErrorInfo>{ErrorInfo{ErrorCode::InternalError, FailureStage::Measurement,
                                              std::nullopt, "failure", std::nullopt}}
        : std::nullopt;
    const auto resultStatistics = status == BenchmarkStatus::Completed
        ? std::optional<BenchmarkStatistics>{statistics()}
        : std::nullopt;
    return {entry.config, {}, resultStatistics, entry.characteristics, environment(), status, error,
            MeasurementSettings{3}};
}

void testMappingAndFieldMatrix()
{
    auto batchState = state();
    batchState.entries[0].status = BatchEntryStatus::Completed;
    batchState.entries[0].result = resultFor(batchState.entries[0].definition, BenchmarkStatus::Completed);
    batchState.entries[1].status = BatchEntryStatus::Failed;
    batchState.entries[1].result = resultFor(batchState.entries[1].definition, BenchmarkStatus::Failed);
    batchState.status = BatchStatus::CompletedWithFailures;

    const auto document = BatchResultDocumentService{}.create(batchState);
    require(document.mode == ResultMode::Batch &&
                document.status == ResultDocumentStatus::CompletedWithFailures,
            "top-level batch mapping is incorrect");
    require(document.entries.size() == 2 && document.entries[0].entryIndex == 1 &&
                document.entries[1].entryIndex == 2,
            "entry order was not preserved");
    require(document.entries[0].id == "first" && document.entries[0].statistics.has_value() &&
                !document.entries[0].error.has_value(),
            "completed entry field mapping is incorrect");
    require(document.entries[0].environment.has_value() &&
                sameEnvironment(*document.entries[0].environment, environment()),
            "completed entry environment was not preserved");
    require(document.entries[0].statistics->elapsedNanosecondsPerOperation.mean == 1.25 &&
                document.entries[0].statistics->cpuNanosecondsPerOperation.stddev == 0.225 &&
                std::get<MemoryV2Statistics>(document.entries[0].statistics->memory)
                    .preparationPeakPrivateUsageDeltaBytes.max == 6.25,
            "completed entry statistics were not preserved");
    require(document.entries[1].error.has_value() && !document.entries[1].statistics.has_value() &&
                document.entries[1].environment.has_value(),
            "failed entry field mapping is incorrect");
    require(document.entries[1].environment.has_value() &&
                sameEnvironment(*document.entries[1].environment, environment()) &&
                document.entries[1].error->code == ErrorCode::InternalError &&
                document.entries[1].error->stage == FailureStage::Measurement &&
                document.entries[1].error->technicalMessage == "failure" &&
                !document.entries[1].error->runIndex.has_value() &&
                !document.entries[1].error->libraryDetails.has_value(),
            "failed entry values were not preserved");
}

void testInitialAndSuccessfulBatchMapping()
{
    const auto initial = BatchResultDocumentService{}.create(
        state());
    require(initial.mode == ResultMode::Batch && initial.status == ResultDocumentStatus::InProgress,
            "initial batch status mapping is incorrect");
    require(initial.entries.size() == 2 && initial.entries[0].status == ExportEntryStatus::NotStarted &&
                initial.entries[1].status == ExportEntryStatus::NotStarted,
            "initial entries were not mapped as not-started");
    for (const auto& entry : initial.entries) {
        require(!entry.environment.has_value() && !entry.statistics.has_value() &&
                    !entry.error.has_value(),
                "initial entry contains runtime fields");
    }

    auto batchState = state();
    for (auto& entry : batchState.entries) {
        entry.status = BatchEntryStatus::Completed;
        entry.result = resultFor(entry.definition, BenchmarkStatus::Completed);
    }
    batchState.status = BatchStatus::Completed;
    const auto completed = BatchResultDocumentService{}.create(batchState);
    require(completed.status == ResultDocumentStatus::Completed &&
                completed.entries[0].status == ExportEntryStatus::Completed &&
                completed.entries[1].status == ExportEntryStatus::Completed,
            "successful batch status mapping is incorrect");
}

void testCancelledAndNotStartedMapping()
{
    auto batchState = state();
    batchState.entries[0].status = BatchEntryStatus::Cancelled;
    batchState.entries[0].result = resultFor(batchState.entries[0].definition, BenchmarkStatus::Cancelled);
    batchState.status = BatchStatus::Cancelled;
    const auto document = BatchResultDocumentService{}.create(batchState);
    require(document.entries[0].environment.has_value() &&
                !document.entries[0].statistics.has_value() && !document.entries[0].error.has_value(),
            "cancelled entry field matrix is incorrect");
    require(document.entries[1].status == ExportEntryStatus::NotStarted &&
                !document.entries[1].environment.has_value() &&
                !document.entries[1].statistics.has_value() && !document.entries[1].error.has_value(),
            "not-started tail field matrix is incorrect");
}

void testFailedBatchErrorAndInvalidState()
{
    auto batchState = state();
    batchState.status = BatchStatus::Failed;
    batchState.batchError = BatchError{BatchErrorCode::OutputWriteFailed,
                                  BatchErrorStage::SnapshotPersistence, 1, "write failed"};
    const auto document = BatchResultDocumentService{}.create(batchState);
    require(document.batchError.has_value() && document.batchError->entryIndex == 1,
            "failed batch error was not mapped");

    batchState.status = BatchStatus::InProgress;
    bool rejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(batchState));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "batch error on a non-failed state was accepted");
}

void testImpossibleEntryCombinationRejected()
{
    auto batchState = state();
    batchState.entries[0].status = BatchEntryStatus::Completed;
    batchState.entries[0].result = resultFor(batchState.entries[0].definition, BenchmarkStatus::Failed);
    bool rejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(batchState));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "impossible entry status/result combination was repaired");
}

void testMismatchedCanonicalResultRejected()
{
    auto configState = state();
    configState.entries[0].status = BatchEntryStatus::Completed;
    configState.entries[0].result = resultFor(configState.entries[0].definition,
                                               BenchmarkStatus::Completed);
    configState.entries[0].result->config.iterationsPerRun++;
    bool configRejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(configState));
    } catch (const std::invalid_argument&) {
        configRejected = true;
    }
    require(configRejected, "mismatched benchmark config was accepted");

    auto characteristicsState = state();
    characteristicsState.entries[0].status = BatchEntryStatus::Cancelled;
    characteristicsState.entries[0].result = resultFor(characteristicsState.entries[0].definition,
                                                        BenchmarkStatus::Cancelled);
    auto& characteristics = std::get<HashCharacteristics>(
        characteristicsState.entries[0].result->characteristics);
    characteristics.outputBytes++;
    bool characteristicsRejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(characteristicsState));
    } catch (const std::invalid_argument&) {
        characteristicsRejected = true;
    }
    require(characteristicsRejected, "mismatched structural characteristics were accepted");
}

void testMeasurementProvenanceRejected()
{
    auto missingBatchSettings = state();
    missingBatchSettings.measurementSettings.reset();
    bool missingBatchRejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(missingBatchSettings));
    } catch (const std::invalid_argument&) {
        missingBatchRejected = true;
    }
    require(missingBatchRejected, "batch document without measurement settings was accepted");

    auto missingEntrySettings = state();
    missingEntrySettings.entries[0].status = BatchEntryStatus::Completed;
    missingEntrySettings.entries[0].result = resultFor(
        missingEntrySettings.entries[0].definition, BenchmarkStatus::Completed);
    missingEntrySettings.entries[0].result->measurementSettings.reset();
    bool missingEntryRejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(missingEntrySettings));
    } catch (const std::invalid_argument&) {
        missingEntryRejected = true;
    }
    require(missingEntryRejected, "batch entry without measurement settings was accepted");

    auto mismatchedEntrySettings = state();
    mismatchedEntrySettings.entries[0].status = BatchEntryStatus::Completed;
    mismatchedEntrySettings.entries[0].result = resultFor(
        mismatchedEntrySettings.entries[0].definition, BenchmarkStatus::Completed);
    mismatchedEntrySettings.entries[0].result->measurementSettings = MeasurementSettings{4};
    bool mismatchedEntryRejected = false;
    try {
        static_cast<void>(BatchResultDocumentService{}.create(mismatchedEntrySettings));
    } catch (const std::invalid_argument&) {
        mismatchedEntryRejected = true;
    }
    require(mismatchedEntryRejected, "mismatched batch entry settings were accepted");
}

} // namespace

int main()
{
    try {
        testInitialAndSuccessfulBatchMapping();
        testMappingAndFieldMatrix();
        testCancelledAndNotStartedMapping();
        testFailedBatchErrorAndInvalidState();
        testImpossibleEntryCombinationRejected();
        testMismatchedCanonicalResultRejected();
        testMeasurementProvenanceRejected();
        std::cout << "PASS BatchResultDocumentService\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchResultDocumentService: " << error.what() << '\n';
        return 1;
    }
}