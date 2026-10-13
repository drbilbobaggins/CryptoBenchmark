#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchController.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkController.h>
#include <cryptobench/application/ResultJsonMapping.h>

#include "BackendIntegrationTestSupport.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QEventLoop>
#include <QTemporaryDir>
#include <QTimer>

#include <chrono>
#include <array>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace cryptobench;

namespace {

using application::BatchController;
using application::BatchDefinition;
using application::BatchExecutionState;
using application::BatchInputParser;
using application::BatchStatus;
using application::WriteResult;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

BatchDefinition parseDefinition(QTemporaryDir& directory, const QByteArray& input)
{
    require(directory.isValid(), "temporary directory is invalid");
    const auto path = directory.filePath("batch-input.json");
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch input could not be opened");
    require(file.write(input) == input.size(), "batch input could not be written");
    file.close();

    const auto parsed = BatchInputParser{}.parseFile(path);
    require(parsed.issues.empty() && parsed.definition.has_value(), "batch input was rejected");
    return *parsed.definition;
}

BatchDefinition naturalDefinition(QTemporaryDir& directory)
{
    return parseDefinition(
        directory,
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"hash","profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":64}},)"
        R"({"id":"aead","profileId":"aes-128-gcm","operation":"encrypt","iterationsPerRun":2,"runs":2,"parameters":{"plaintextSizeBytes":64}},)"
        R"({"id":"key-establishment","profileId":"x25519","operation":"derive","iterationsPerRun":2,"runs":2,"parameters":{}},)"
        R"({"id":"signature","profileId":"ed25519","operation":"sign","iterationsPerRun":2,"runs":2,"parameters":{"inputMode":"message","messageSizeBytes":64}}]})");
}

BatchDefinition cancellationDefinition(QTemporaryDir& directory)
{
    return parseDefinition(
        directory,
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"cancelled","profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":64}},)"
        R"({"id":"must-not-start","profileId":"aes-128-gcm","operation":"encrypt","iterationsPerRun":2,"runs":2,"parameters":{"plaintextSizeBytes":64}}]})");
}

struct PersistenceObserver {
    std::vector<QByteArray> payloads;
    std::vector<QString> targets;

    WriteResult operator()(const QString& target, const QByteArray& payload)
    {
        payloads.push_back(payload);
        targets.push_back(target);
        return application::AtomicFileWriter{}.writeAtomically(target, payload);
    }
};

QJsonObject persistedRoot(const QByteArray& payload)
{
    const auto document = QJsonDocument::fromJson(payload);
    require(!document.isNull() && document.isObject(), "persisted snapshot is not a JSON object");
    return document.object();
}

const char* exportedStatus(application::BatchEntryStatus status)
{
    switch (status) {
    case application::BatchEntryStatus::NotStarted:
        return "notStarted";
    case application::BatchEntryStatus::Completed:
        return "completed";
    case application::BatchEntryStatus::Failed:
        return "failed";
    case application::BatchEntryStatus::Cancelled:
        return "cancelled";
    }
    throw std::runtime_error("unsupported batch entry status");
}

application::BatchEntryStatus batchStatusFor(core::BenchmarkStatus status)
{
    switch (status) {
    case core::BenchmarkStatus::Completed:
        return application::BatchEntryStatus::Completed;
    case core::BenchmarkStatus::Failed:
        return application::BatchEntryStatus::Failed;
    case core::BenchmarkStatus::Cancelled:
        return application::BatchEntryStatus::Cancelled;
    }
    throw std::runtime_error("unsupported benchmark status");
}

void requireExportedEntry(const QJsonObject& value,
                          const application::BatchEntryState& expected,
                          application::BatchEntryStatus expectedStatus)
{
    require(value.value("entryIndex").toInt() == static_cast<int>(expected.definition.entryIndex),
            "snapshot entry index changed");
    require(value.value("status").toString() == exportedStatus(expectedStatus),
            "snapshot entry status changed");
    require(value.value("config").toObject() ==
                application::benchmarkConfigToJson(expected.definition.config),
            "snapshot entry config changed");
    require(value.value("structuralCharacteristics").toObject() ==
                application::structuralCharacteristicsToJson(expected.definition.characteristics),
            "snapshot entry characteristics changed");
    if (expected.definition.id.has_value()) {
        require(value.value("id").toString().toStdString() == *expected.definition.id,
                "snapshot entry identity changed");
    } else {
        require(!value.contains("id"), "snapshot emitted an absent entry identity");
    }

    if (expectedStatus == application::BatchEntryStatus::NotStarted) {
        require(!value.contains("environment") && !value.contains("statistics") &&
                    !value.contains("error"),
                "not-started entry contains completed-result data");
        return;
    }

    require(expected.result.has_value(), "terminal entry has no canonical result");
    const auto& result = *expected.result;
    require(batchStatusFor(result.status) == expectedStatus,
            "in-memory and exported entry statuses differ");
    require(value.value("environment").toObject() ==
                application::environmentInfoToJson(result.environment),
            "snapshot entry environment changed");

    if (expectedStatus == application::BatchEntryStatus::Completed) {
        require(result.statistics.has_value() && !result.error.has_value(),
                "completed result has invalid optional fields");
        require(value.value("statistics").toObject() ==
                    application::benchmarkStatisticsToJson(*result.statistics),
                "snapshot completed statistics changed");
        require(!value.contains("error"), "completed entry contains an error");
    } else if (expectedStatus == application::BatchEntryStatus::Failed) {
        require(!result.statistics.has_value() && result.error.has_value(),
                "failed result has invalid optional fields");
        require(value.value("error").toObject() ==
                    application::errorInfoToJson(*result.error),
                "snapshot failed error changed");
        require(!value.contains("statistics"), "failed entry contains statistics");
    } else {
        require(!result.statistics.has_value() && !result.error.has_value(),
                "cancelled result has invalid optional fields");
        require(!value.contains("statistics") && !value.contains("error"),
                "cancelled entry contains completed-result data");
    }
}

void requireBatchSnapshot(const QByteArray& payload, const BatchExecutionState& finalState,
                          const char* expectedTopLevelStatus,
                          const std::array<application::BatchEntryStatus, 4>& expectedStatuses)
{
    const auto root = persistedRoot(payload);
    require(root.value("format").toString() == "cryptobenchmark-result",
            "snapshot has the wrong format");
    require(root.value("schemaVersion").toInt() == 2, "snapshot has the wrong schema version");
    require(root.value("mode").toString() == "batch", "snapshot has the wrong mode");
    require(root.value("status").toString() == expectedTopLevelStatus,
            "snapshot has the wrong top-level status");
    require(!root.contains("batchError"), "normal snapshot contains a batch error");

    const auto entries = root.value("entries").toArray();
    require(entries.size() == static_cast<qsizetype>(finalState.entries.size()),
            "snapshot has the wrong entry count");
    for (qsizetype index = 0; index < entries.size(); ++index) {
        requireExportedEntry(entries.at(index).toObject(), finalState.entries.at(index),
                             expectedStatuses.at(static_cast<std::size_t>(index)));
    }
}

void waitForBatch(BatchController& controller, std::size_t& finishCount,
                  std::optional<BatchExecutionState>& finishedState)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&controller, &BatchController::batchFinished,
                     &loop, [&](const BatchExecutionState& state) {
                         ++finishCount;
                         finishedState = state;
                         loop.quit();
                     });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(30'000);
    loop.exec();
    timeout.stop();
    require(finishedState.has_value(), "batch timed out without a terminal state");
    require(finishCount == 1, "batch emitted more than one terminal state");
    require(!controller.isBusy(), "batch controller remained busy after completion");
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(finishCount == 1, "batch emitted a late duplicate terminal state");
}

void requireCompletedEntries(const BatchExecutionState& state)
{
    require(state.status == BatchStatus::Completed, "natural batch did not complete");
    require(!state.batchError.has_value(), "natural batch contains a batch error");
    require(state.entries.size() == 4, "natural batch has the wrong entry count");
    for (const auto& entry : state.entries) {
        require(entry.status == application::BatchEntryStatus::Completed,
                "natural batch contains a non-completed entry");
        require(entry.result.has_value(), "completed batch entry has no result");
        const auto now = std::chrono::system_clock::now();
        test_support::assertCompletedResult(entry.result.value(), entry.definition.config,
                                            now - std::chrono::minutes(1), now);
    }
}

void testNaturalBatch()
{
    QTemporaryDir directory;
    const auto definition = naturalDefinition(directory);
    const auto target = directory.filePath("natural-result.json");
    PersistenceObserver observer;
    auto persister = [&observer](const QString& path, const QByteArray& payload) {
        return observer(path, payload);
    };
    BatchController controller(std::make_unique<application::BenchmarkController>(), persister, {},
                               core::MeasurementSettings{5});
    std::size_t finishCount = 0;
    std::optional<BatchExecutionState> finishedState;

    controller.start(definition, target);
    waitForBatch(controller, finishCount, finishedState);
    requireCompletedEntries(*finishedState);
    require(observer.payloads.size() == 5, "natural batch did not persist five snapshots");
    require(observer.targets.size() == observer.payloads.size(),
            "persistence observer target count mismatch");
    const std::array expectedTopLevelStatuses{"inProgress", "inProgress", "inProgress",
                                               "inProgress", "completed"};
    for (std::size_t snapshotIndex = 0; snapshotIndex < observer.payloads.size(); ++snapshotIndex) {
        require(observer.targets[snapshotIndex] == target, "snapshot was written to the wrong target");
        std::array<application::BatchEntryStatus, 4> expectedStatuses{};
        for (std::size_t entryIndex = 0; entryIndex < expectedStatuses.size(); ++entryIndex) {
            expectedStatuses[entryIndex] = entryIndex < snapshotIndex
                ? application::BatchEntryStatus::Completed
                : application::BatchEntryStatus::NotStarted;
        }
        requireBatchSnapshot(observer.payloads[snapshotIndex], *finishedState,
                             expectedTopLevelStatuses[snapshotIndex], expectedStatuses);
    }

    const std::array expectedProfiles{
        core::AlgorithmProfileId::Sha256, core::AlgorithmProfileId::Aes128Gcm,
        core::AlgorithmProfileId::X25519, core::AlgorithmProfileId::Ed25519};
    const std::array expectedOperations{
        core::BenchmarkOperation::Hash, core::BenchmarkOperation::Encrypt,
        core::BenchmarkOperation::Derive, core::BenchmarkOperation::Sign};
    for (std::size_t index = 0; index < expectedProfiles.size(); ++index) {
        const auto& config = finishedState->entries[index].definition.config;
        require(config.profile == expectedProfiles[index] && config.operation == expectedOperations[index],
                "final in-memory entry identity changed");
    }
    require(finishedState->status == BatchStatus::Completed && !finishedState->batchError.has_value(),
            "final natural batch state has invalid terminal fields");

    QFile output(target);
    require(output.open(QIODevice::ReadOnly), "natural output could not be opened");
    const auto onDiskPayload = output.readAll();
    require(onDiskPayload == observer.payloads.back(),
        "natural output differs from the final atomic snapshot");
    const std::array<application::BatchEntryStatus, 4> completedStatuses{
        application::BatchEntryStatus::Completed, application::BatchEntryStatus::Completed,
        application::BatchEntryStatus::Completed, application::BatchEntryStatus::Completed};
    requireBatchSnapshot(onDiskPayload, *finishedState, "completed", completedStatuses);
}

void testCancellationAndReuse()
{
    QTemporaryDir directory;
    const auto definition = cancellationDefinition(directory);
    const auto cancelledTarget = directory.filePath("cancelled-result.json");
    const auto reuseTarget = directory.filePath("reuse-result.json");
    PersistenceObserver observer;
    auto persister = [&observer](const QString& path, const QByteArray& payload) {
        return observer(path, payload);
    };
    BatchController controller(std::make_unique<application::BenchmarkController>(), persister, {},
                               core::MeasurementSettings{5});
    bool cancelArmed = true;
    bool secondEntryObserved = false;
    QObject::connect(&controller, &BatchController::progressChanged,
                     [&](const application::BatchProgress& progress) {
                         if (progress.currentEntryIndex == 2) secondEntryObserved = true;
                         if (cancelArmed && progress.currentEntryIndex == 1 &&
                             progress.currentProgress.has_value()) {
                             cancelArmed = false;
                             controller.requestCancel();
                         }
                     });

    std::size_t finishCount = 0;
    std::optional<BatchExecutionState> finishedState;
    controller.start(definition, cancelledTarget);
    waitForBatch(controller, finishCount, finishedState);
    require(!cancelArmed, "real-worker cancellation was not observed during the first entry");
    require(finishedState->status == BatchStatus::Cancelled,
            "cancelled batch did not reach the cancelled state");
    require(finishedState->entries.size() == 2, "cancelled batch has the wrong entry count");
    require(finishedState->entries[1].status == application::BatchEntryStatus::NotStarted,
            "cancellation started a later batch entry");
        require(!secondEntryObserved, "cancellation advanced to the second batch entry");
    require(finishedState->entries[0].result.has_value(),
            "cancelled active entry has no terminal result");
        const auto activeStatus = finishedState->entries[0].result->status;
        require(activeStatus == core::BenchmarkStatus::Completed ||
            activeStatus == core::BenchmarkStatus::Failed ||
            activeStatus == core::BenchmarkStatus::Cancelled,
            "active real-worker entry did not return a canonical terminal status");
        require(finishedState->entries[0].status == batchStatusFor(activeStatus),
            "cancelled batch entry status does not match its canonical result");
    require(observer.payloads.size() == 2, "cancellation did not persist initial and final snapshots");
        const auto cancelledRoot = persistedRoot(observer.payloads.back());
        require(cancelledRoot.value("status").toString() == "cancelled",
            "cancelled final snapshot has the wrong status");
        require(!cancelledRoot.contains("batchError"), "cancelled final snapshot has a batch error");
        const auto cancelledEntries = cancelledRoot.value("entries").toArray();
        require(cancelledEntries.size() == 2, "cancelled final snapshot has the wrong entry count");
        requireExportedEntry(cancelledEntries.at(0).toObject(), finishedState->entries[0],
                 finishedState->entries[0].status);
        requireExportedEntry(cancelledEntries.at(1).toObject(), finishedState->entries[1],
                 application::BatchEntryStatus::NotStarted);

    cancelArmed = false;
    const auto reuseDefinition = parseDefinition(
        directory,
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"reuse","profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":64}}]})");
    finishCount = 0;
    finishedState.reset();
    controller.start(reuseDefinition, reuseTarget);
    waitForBatch(controller, finishCount, finishedState);
    require(finishedState->status == BatchStatus::Completed,
            "controller could not be reused after real-worker cancellation");
    require(finishedState->entries.size() == 1 &&
                finishedState->entries[0].status == application::BatchEntryStatus::Completed,
            "reused controller did not complete its new entry");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testNaturalBatch();
        testCancellationAndReuse();
        std::cout << "PASS BatchControllerIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchControllerIntegration: " << error.what() << '\n';
        return 1;
    }
}
