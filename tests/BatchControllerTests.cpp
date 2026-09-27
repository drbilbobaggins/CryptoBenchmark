#include <cryptobench/application/BatchController.h>
#include <cryptobench/application/BatchInputParser.h>

#include <QCoreApplication>
#include <QJsonArray>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <chrono>
#include <algorithm>
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

BatchDefinition definition(std::size_t entryCount)
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory is invalid");
    const auto path = directory.filePath("batch.json");
    require(entryCount >= 1 && entryCount <= 3, "unsupported batch fixture size");
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch fixture could not be opened");
    const QByteArray first =
        R"({"id":"first","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})";
    const QByteArray second =
        R"({"id":"second","profileId":"sha3-256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})";
    const QByteArray third =
        R"({"id":"third","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})";
    QByteArray input = R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)";
    input += first;
    if (entryCount >= 2) {
        input += ',';
        input += second;
    }
    if (entryCount >= 3) {
        input += ',';
        input += third;
    }
    input += "]}";
    require(file.write(input) == input.size(), "batch fixture could not be written");
    file.close();
    const auto parsed = BatchInputParser{}.parseFile(path);
    require(parsed.issues.empty() && parsed.definition.has_value(), "batch fixture was rejected");
    return *parsed.definition;
}

BenchmarkResult resultFor(const BatchEntryDefinition& entry, BenchmarkStatus status)
{
    const auto error = status == BenchmarkStatus::Failed
        ? std::optional<ErrorInfo>{ErrorInfo{ErrorCode::CryptoOperationFailed,
                                              FailureStage::Measurement,
                                              3,
                                              "scripted failure",
                                              std::string{"library detail"}}}
        : std::nullopt;
    const auto statistics = status == BenchmarkStatus::Completed
        ? std::optional<BenchmarkStatistics>{BenchmarkStatistics{
              {1.0, 1.1, 0.9, 1.2, 0.1},
              {2.0, 2.1, 1.9, 2.2, 0.2},
              {3.0, 3.1, 2.9, 3.2, 0.3}}}
        : std::nullopt;
    return {entry.config,
            {},
            statistics,
            entry.characteristics,
            {"test", "commit", "openssl", "Windows", "amd64", "Debug",
             std::chrono::system_clock::time_point{}},
            status,
            error};
}

class FakeExecutor final : public BenchmarkSessionExecutor {
public:
    FakeExecutor(std::vector<BenchmarkStatus> script, std::vector<std::string>& events)
        : script_(std::move(script)), events_(events)
    {
    }

    void start(const BenchmarkConfig& config) override
    {
        require(!busy_, "fake executor received a concurrent start");
        require(startIndex_ < script_.size(), "fake executor script was exhausted");
        busy_ = true;
        ++activeSessions_;
        maxActiveSessions_ = std::max(maxActiveSessions_, activeSessions_);
        starts_.push_back(config.profile);
        events_.push_back("start " + std::to_string(startIndex_ + 1));
        emit progressChanged({BenchmarkPhase::Preparing, std::nullopt, config.runs});
        pendingResult_ = resultFor((*definitions_)[startIndex_], script_[startIndex_]);
        ++startIndex_;
        if (!deferTerminal_) emitPendingTerminal();
    }

    void requestCancel() override
    {
        ++cancelRequests_;
        events_.push_back("cancel");
        if (throwOnCancel_) throw std::runtime_error("scripted cancellation failure");
        if (synchronousCancel_) emitPendingTerminal();
    }
    bool isBusy() const noexcept override { return busy_; }

    void setDeferTerminal(bool value) { deferTerminal_ = value; }
    void setSynchronousCancel(bool value) { synchronousCancel_ = value; }
    void setThrowOnCancel(bool value) { throwOnCancel_ = value; }
    void emitPendingTerminal()
    {
        require(busy_ && pendingResult_.has_value(), "fake executor has no pending terminal");
        const auto result = *pendingResult_;
        pendingResult_.reset();
        --activeSessions_;
        busy_ = false;
        emit benchmarkFinished(result);
    }

    void setDefinitions(const std::vector<BatchEntryDefinition>* definitions)
    {
        definitions_ = definitions;
    }

    const std::vector<AlgorithmProfileId>& starts() const noexcept { return starts_; }
    std::size_t maxActiveSessions() const noexcept { return maxActiveSessions_; }
    std::size_t cancelRequests() const noexcept { return cancelRequests_; }

private:
    std::vector<BenchmarkStatus> script_;
    std::vector<std::string>& events_;
    const std::vector<BatchEntryDefinition>* definitions_ = nullptr;
    std::vector<AlgorithmProfileId> starts_;
    std::size_t startIndex_ = 0;
    std::size_t activeSessions_ = 0;
    std::size_t maxActiveSessions_ = 0;
    std::size_t cancelRequests_ = 0;
    bool busy_ = false;
    bool deferTerminal_ = false;
    bool synchronousCancel_ = false;
    bool throwOnCancel_ = false;
    std::optional<BenchmarkResult> pendingResult_;
};

struct RunResult {
    BatchExecutionState state;
    std::vector<std::string> events;
    std::vector<QJsonObject> snapshots;
    std::vector<AlgorithmProfileId> starts;
    std::size_t maxActiveSessions = 0;
    std::vector<BatchProgress> progress;
    std::size_t finishCount = 0;
};

RunResult runBatch(
    const std::vector<BenchmarkStatus>& script,
    std::optional<std::size_t> failingPersistCall = std::nullopt,
    bool preparationFailure = false)
{
    QCoreApplication::processEvents();
    const auto batchDefinition = definition(script.size());
    std::vector<std::string> events;
    std::vector<QJsonObject> snapshots;
    auto executor = std::make_unique<FakeExecutor>(script, events);
    auto* executorPointer = executor.get();
    executorPointer->setDefinitions(&batchDefinition.entries());
    std::size_t persistCall = 0;
    auto persister = [&](const QString&, const QByteArray& payload) {
        ++persistCall;
        events.push_back("persist " + std::to_string(persistCall));
        const auto parsed = QJsonDocument::fromJson(payload);
        require(!parsed.isNull(), "snapshot was not valid JSON");
        snapshots.push_back(parsed.object());
        if (failingPersistCall == persistCall) {
            return WriteResult{false, QStringLiteral("scripted persistence failure")};
        }
        events.push_back("commit " + std::to_string(persistCall));
        return WriteResult{true, {}};
    };

    std::size_t preparationCall = 0;
    BatchController::SnapshotSerializer serializer;
    if (preparationFailure) {
        serializer = [&preparationCall](const ResultDocument& document) -> QByteArray {
            if (++preparationCall == 2) {
                throw std::runtime_error("scripted snapshot preparation failure");
            }
            return JsonResultExportService{}.serialize(document);
        };
    }
    BatchController controller(std::move(executor), persister, std::move(serializer));
    std::vector<BatchProgress> progress;
    std::size_t finishCount = 0;
    QObject::connect(&controller, &BatchController::progressChanged,
                     [&](const BatchProgress& value) { progress.push_back(value); });
    QObject::connect(&controller, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++finishCount; });

    controller.start(batchDefinition, QStringLiteral("batch-result.json"));
    for (int iteration = 0; iteration < 20 && controller.isBusy(); ++iteration) {
        QCoreApplication::processEvents();
    }
    require(!controller.isBusy(), "batch controller did not reach a terminal state");
    require(finishCount == 1, "batch terminal signal count was not exactly one");
    return {controller.state(), std::move(events), std::move(snapshots),
            executorPointer->starts(), executorPointer->maxActiveSessions(), std::move(progress),
            finishCount};
}

void testCompletedChainAndOrdering()
{
    const auto result = runBatch({BenchmarkStatus::Completed, BenchmarkStatus::Completed},
                                 std::nullopt);
    require(result.state.status == BatchStatus::Completed, "completed chain did not complete");
    require(result.starts == std::vector<AlgorithmProfileId>{AlgorithmProfileId::Sha256,
                                                               AlgorithmProfileId::Sha3_256},
            "entry start order was not preserved");
    require(result.maxActiveSessions == 1, "more than one benchmark session was active");
    require(result.state.entries[0].status == BatchEntryStatus::Completed &&
                result.state.entries[1].status == BatchEntryStatus::Completed,
            "completed chain entry statuses are incorrect");
    require(result.events == std::vector<std::string>{
                "persist 1", "commit 1", "start 1", "persist 2", "commit 2", "start 2",
                "persist 3", "commit 3"},
            "checkpoint ordering was not preserved");
    const auto entries = result.snapshots.back()["entries"].toArray();
    require(result.snapshots.back()["status"] == "completed" && entries.size() == 2 &&
                entries[0].toObject()["status"] == "completed" &&
                entries[1].toObject()["status"] == "completed",
            "final completed snapshot is incorrect");

    require(result.progress.size() >= 10, "insufficient batch progress observations");
    const auto& initial = result.progress.front();
    require(initial.persistenceInProgress && !initial.currentEntryIndex.has_value() &&
                initial.completedCount == 0 && initial.failedCount == 0 &&
                initial.cancelledCount == 0 && initial.notStartedCount == 2 &&
                !initial.currentProgress.has_value(),
            "initial persistence progress context is incorrect");

    const auto running = std::find_if(result.progress.begin(), result.progress.end(),
                                      [](const BatchProgress& value) {
                                          return value.currentProgress.has_value();
                                      });
    require(running != result.progress.end() && running->currentEntryIndex == 1 &&
                running->currentProfile == AlgorithmProfileId::Sha256 &&
                running->currentOperation == BenchmarkOperation::Hash &&
                running->currentProgress->phase == BenchmarkPhase::Preparing &&
                running->currentProgress->totalRuns == 1 &&
                !running->persistenceInProgress,
            "running-entry progress context is incorrect");

    const auto checkpoint = std::find_if(result.progress.begin(), result.progress.end(),
                                         [](const BatchProgress& value) {
                                             return value.persistenceInProgress &&
                                                 value.completedCount == 1 &&
                                                 value.notStartedCount == 1;
                                         });
    require(checkpoint != result.progress.end() && checkpoint->currentEntryIndex == 1 &&
                checkpoint->currentProfile == AlgorithmProfileId::Sha256 &&
                checkpoint->currentOperation == BenchmarkOperation::Hash &&
                !checkpoint->currentProgress.has_value(),
            "checkpoint progress context is incorrect");
    const auto checkpointEvent = std::find(result.events.begin(), result.events.end(),
                                           "persist 2");
    const auto secondStartEvent = std::find(result.events.begin(), result.events.end(),
                                            "start 2");
    require(checkpointEvent != result.events.end() && secondStartEvent != result.events.end() &&
                checkpointEvent < secondStartEvent,
            "checkpoint was not observed before the next start");

    const auto& terminal = result.progress.back();
    require(!terminal.persistenceInProgress && terminal.notStartedCount == 0 &&
                terminal.completedCount + terminal.failedCount + terminal.cancelledCount ==
                    terminal.totalEntries && terminal.totalEntries == 2,
            "natural completion progress context is incorrect");
}

void testPreparationFailureClassification()
{
    const auto result = runBatch({BenchmarkStatus::Completed}, std::nullopt, true);
    require(result.state.status == BatchStatus::Failed && result.state.batchError.has_value() &&
                result.state.batchError->code == BatchErrorCode::InternalError &&
                result.state.batchError->stage == BatchErrorStage::Orchestration &&
                result.state.entries[0].result->status == BenchmarkStatus::Completed,
            "snapshot preparation failure was classified as an output failure");
    require(result.events == std::vector<std::string>{"persist 1", "commit 1", "start 1"},
            "snapshot preparation failure crossed the persistence boundary");
}

void testUnexpectedCancelledResultFailsBatch()
{
    const auto middle = runBatch({BenchmarkStatus::Completed, BenchmarkStatus::Cancelled,
                                  BenchmarkStatus::Completed});
    require(middle.state.status == BatchStatus::Failed && middle.state.batchError.has_value() &&
                middle.state.batchError->code == BatchErrorCode::InternalError &&
                middle.state.batchError->stage == BatchErrorStage::Orchestration &&
                middle.state.entries[1].status == BatchEntryStatus::Cancelled &&
                middle.state.entries[1].result->status == BenchmarkStatus::Cancelled &&
                middle.state.entries[2].status == BatchEntryStatus::NotStarted &&
                middle.finishCount == 1,
            "unexpected middle cancellation did not fail the batch exactly once");
    require(middle.starts.size() == 2 &&
                middle.events == std::vector<std::string>{
                    "persist 1", "commit 1", "start 1", "persist 2", "commit 2", "start 2"},
            "unexpected middle cancellation started a later entry or persisted a checkpoint");

    const auto final = runBatch({BenchmarkStatus::Cancelled});
    require(final.state.status == BatchStatus::Failed && final.state.entries[0].status ==
                BatchEntryStatus::Cancelled && final.state.entries[0].result->status ==
                BenchmarkStatus::Cancelled && final.finishCount == 1,
            "unexpected final cancellation was mistaken for natural completion");
}

void testContinueAfterFailure()
{
    const auto result = runBatch({BenchmarkStatus::Completed, BenchmarkStatus::Failed,
                                  BenchmarkStatus::Completed});
    require(result.state.status == BatchStatus::CompletedWithFailures,
            "mixed chain did not complete with failures");
    require(result.state.entries[1].result->status == BenchmarkStatus::Failed &&
                result.state.entries[1].result->error->technicalMessage == "scripted failure" &&
                result.state.entries[1].result->error->libraryDetails == "library detail",
            "canonical failed result was not preserved");
    require(result.events == std::vector<std::string>{
                "persist 1", "commit 1", "start 1", "persist 2", "commit 2", "start 2",
                "persist 3", "commit 3", "start 3", "persist 4", "commit 4"},
            "continue-on-failure ordering was not preserved");
    require(result.snapshots.back()["status"] == "completedWithFailures",
            "final mixed snapshot status is incorrect");
}

void testRepeatedFailureAndPersistenceSafety()
{
    const auto repeated = runBatch({BenchmarkStatus::Failed, BenchmarkStatus::Failed,
                                    BenchmarkStatus::Completed});
    require(repeated.state.status == BatchStatus::CompletedWithFailures,
            "repeated failures did not continue to completion");

    const auto initialFailure = runBatch({BenchmarkStatus::Completed}, 1);
    require(initialFailure.state.status == BatchStatus::Failed &&
                initialFailure.state.batchError->code == BatchErrorCode::OutputInitializationFailed,
            "initial persistence failure was not fatal initialization failure");
    require(initialFailure.events == std::vector<std::string>{"persist 1"} &&
                initialFailure.state.entries[0].status == BatchEntryStatus::NotStarted,
            "initial persistence failure started an entry");

    const auto checkpointFailure = runBatch({BenchmarkStatus::Completed,
                                              BenchmarkStatus::Completed}, 2);
    require(checkpointFailure.state.status == BatchStatus::Failed &&
                checkpointFailure.state.batchError->code == BatchErrorCode::OutputWriteFailed &&
                checkpointFailure.state.entries[0].result->status == BenchmarkStatus::Completed &&
                checkpointFailure.state.entries[1].status == BatchEntryStatus::NotStarted,
            "intermediate persistence failure did not preserve canonical state");
    require(checkpointFailure.events == std::vector<std::string>{
                "persist 1", "commit 1", "start 1", "persist 2"},
            "intermediate persistence failure allowed a later start");

    const auto finalFailure = runBatch({BenchmarkStatus::Completed}, 2);
    require(finalFailure.state.status == BatchStatus::Failed &&
                finalFailure.state.batchError->code == BatchErrorCode::OutputWriteFailed &&
                finalFailure.state.entries[0].result->status == BenchmarkStatus::Completed,
            "final persistence failure was not terminal");
    require(finalFailure.events == std::vector<std::string>{
                "persist 1", "commit 1", "start 1", "persist 2"},
            "final persistence failure triggered a restart");
}

void testActiveCancellationRaces()
{
    for (const auto status : {BenchmarkStatus::Cancelled, BenchmarkStatus::Completed,
                              BenchmarkStatus::Failed}) {
        const auto batchDefinition = definition(2);
        std::vector<std::string> events;
        auto executor = std::make_unique<FakeExecutor>(std::vector<BenchmarkStatus>{status,
                                                                                       BenchmarkStatus::Completed}, events);
        auto* executorPointer = executor.get();
        executorPointer->setDefinitions(&batchDefinition.entries());
        executorPointer->setDeferTerminal(true);
        executorPointer->setSynchronousCancel(status == BenchmarkStatus::Cancelled);
        std::vector<QJsonObject> snapshots;
        auto persister = [&](const QString&, const QByteArray& payload) {
            snapshots.push_back(QJsonDocument::fromJson(payload).object());
            return WriteResult{true, {}};
        };
        BatchController controller(std::move(executor), persister);
        std::size_t finishCount = 0;
        QObject::connect(&controller, &BatchController::batchFinished,
                         [&](const BatchExecutionState&) { ++finishCount; });
        controller.start(batchDefinition, QStringLiteral("batch-result.json"));
        QCoreApplication::processEvents();
        require(executorPointer->isBusy(), "deferred fake did not remain active");
        controller.requestCancel();
        controller.requestCancel();
        require(executorPointer->cancelRequests() == 1, "active cancellation was not idempotent");
        if (executorPointer->isBusy()) executorPointer->emitPendingTerminal();
        require(!controller.isBusy() && finishCount == 1, "active cancellation did not terminalize");
        require(controller.state().status == BatchStatus::Cancelled &&
                    controller.state().entries[0].result->status == status &&
                    controller.state().entries[1].status == BatchEntryStatus::NotStarted,
                "active cancellation did not preserve canonical terminal truth");
        require(snapshots.size() == 2 && snapshots.back()["status"] == "cancelled",
                "active cancellation did not persist its terminal snapshot");
    }
}

void testCancellationBetweenEntriesAndDuringPersistence()
{
    const auto betweenDefinition = definition(2);
    std::vector<std::string> betweenEvents;
    auto betweenExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed, BenchmarkStatus::Completed}, betweenEvents);
    auto* betweenExecutorPointer = betweenExecutor.get();
    betweenExecutorPointer->setDefinitions(&betweenDefinition.entries());
    std::size_t betweenPersists = 0;
    BatchController between(std::move(betweenExecutor),
        [&](const QString&, const QByteArray&) {
            ++betweenPersists;
            return WriteResult{true, {}};
        });
    between.start(betweenDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    require(between.isBusy(), "queued advancement did not leave controller active");
    between.requestCancel();
    QCoreApplication::processEvents();
    require(betweenExecutorPointer->starts().size() == 1 &&
                betweenExecutorPointer->cancelRequests() == 0 &&
                between.state().status == BatchStatus::Cancelled &&
                between.state().entries[0].status == BatchEntryStatus::Completed &&
                between.state().entries[1].status == BatchEntryStatus::NotStarted &&
                betweenPersists == 3,
            "between-entry cancellation started or cancelled an executor");

    const auto initialDefinition = definition(1);
    std::vector<QJsonObject> initialSnapshots;
    BatchController* initialController = nullptr;
    auto initialExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, betweenEvents);
    auto* initialExecutorPointer = initialExecutor.get();
    initialExecutorPointer->setDefinitions(&initialDefinition.entries());
    int initialDepth = 0;
    BatchController initial(std::move(initialExecutor),
        [&](const QString&, const QByteArray& payload) {
            require(++initialDepth == 1, "initial persistence overlapped");
            initialSnapshots.push_back(QJsonDocument::fromJson(payload).object());
            if (initialSnapshots.size() == 1) initialController->requestCancel();
            --initialDepth;
            return WriteResult{true, {}};
        });
    initialController = &initial;
    std::size_t initialFinished = 0;
    QObject::connect(&initial, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++initialFinished; });
    initial.start(initialDefinition, QStringLiteral("batch-result.json"));
    require(initial.state().status == BatchStatus::Cancelled && initialFinished == 1 &&
                initialExecutorPointer->starts().empty() && initialSnapshots.size() == 2 &&
                initialSnapshots[0]["status"] == "inProgress" &&
                initialSnapshots[1]["status"] == "cancelled",
            "initial persistence cancellation did not produce the required snapshots");

    const auto checkpointDefinition = definition(2);
    std::vector<QJsonObject> checkpointSnapshots;
    std::size_t checkpointDepth = 0;
    std::size_t checkpointCalls = 0;
    BatchController* checkpointController = nullptr;
    auto checkpointExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed, BenchmarkStatus::Completed}, betweenEvents);
    auto* checkpointExecutorPointer = checkpointExecutor.get();
    checkpointExecutorPointer->setDefinitions(&checkpointDefinition.entries());
    BatchController checkpoint(std::move(checkpointExecutor),
        [&](const QString&, const QByteArray& payload) {
            require(++checkpointDepth == 1, "checkpoint persistence overlapped");
            ++checkpointCalls;
            checkpointSnapshots.push_back(QJsonDocument::fromJson(payload).object());
            if (checkpointCalls == 2) checkpointController->requestCancel();
            --checkpointDepth;
            return WriteResult{true, {}};
        });
    checkpointController = &checkpoint;
    std::size_t checkpointFinished = 0;
    QObject::connect(&checkpoint, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++checkpointFinished; });
    checkpoint.start(checkpointDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    require(checkpoint.state().status == BatchStatus::Cancelled && checkpointFinished == 1 &&
                checkpointExecutorPointer->starts().size() == 1 &&
                checkpointExecutorPointer->cancelRequests() == 0 &&
                checkpoint.state().entries[0].status == BatchEntryStatus::Completed &&
                checkpoint.state().entries[1].status == BatchEntryStatus::NotStarted &&
                checkpointSnapshots.size() == 3 && checkpointSnapshots.back()["status"] == "cancelled",
            "checkpoint persistence cancellation did not preserve the committed entry");

    const auto finalDefinition = definition(1);
    std::vector<QJsonObject> finalSnapshots;
    std::size_t finalDepth = 0;
    std::size_t finalCalls = 0;
    BatchController* finalController = nullptr;
    auto finalExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, betweenEvents);
    auto* finalExecutorPointer = finalExecutor.get();
    finalExecutorPointer->setDefinitions(&finalDefinition.entries());
    BatchController naturalFinal(std::move(finalExecutor),
        [&](const QString&, const QByteArray& payload) {
            require(++finalDepth == 1, "natural-final persistence overlapped");
            ++finalCalls;
            finalSnapshots.push_back(QJsonDocument::fromJson(payload).object());
            if (finalCalls == 2) finalController->requestCancel();
            --finalDepth;
            return WriteResult{true, {}};
        });
    finalController = &naturalFinal;
    std::size_t finalFinished = 0;
    QObject::connect(&naturalFinal, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++finalFinished; });
    naturalFinal.start(finalDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    require(naturalFinal.state().status == BatchStatus::Cancelled && finalFinished == 1 &&
                finalExecutorPointer->starts().size() == 1 && finalSnapshots.size() == 3 &&
                finalSnapshots[0]["status"] == "inProgress" &&
                finalSnapshots[1]["status"] == "completed" &&
                finalSnapshots[2]["status"] == "cancelled",
            "natural-final persistence cancellation did not honor the latch");
}

void testCancelAfterTerminal()
{
    const auto batchDefinition = definition(1);
    std::vector<std::string> events;
    auto executor = std::make_unique<FakeExecutor>(std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, events);
    auto* executorPointer = executor.get();
    executorPointer->setDefinitions(&batchDefinition.entries());
    std::size_t persistCount = 0;
    BatchController controller(std::move(executor),
        [&](const QString&, const QByteArray&) {
            ++persistCount;
            return WriteResult{true, {}};
        });
    std::size_t finishCount = 0;
    QObject::connect(&controller, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++finishCount; });
    controller.start(batchDefinition, QStringLiteral("batch-result.json"));
    for (int iteration = 0; iteration < 20 && controller.isBusy(); ++iteration) {
        QCoreApplication::processEvents();
    }
    const auto before = controller.state();
    controller.requestCancel();
    require(controller.state().status == before.status && controller.state().entries[0].status == before.entries[0].status &&
                persistCount == 2 && executorPointer->cancelRequests() == 0 &&
                executorPointer->starts().size() == 1 && finishCount == 1,
            "cancel after terminal was not a no-op");
}

void testSaveAsRecovery()
{
    const auto batchDefinition = definition(1);
    std::vector<std::string> events;
    auto executor = std::make_unique<FakeExecutor>(std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, events);
    auto* executorPointer = executor.get();
    executorPointer->setDefinitions(&batchDefinition.entries());
    std::vector<QJsonObject> recoverySnapshots;
    std::size_t executionPersists = 0;
    BatchController failed(std::move(executor),
        [&](const QString& target, const QByteArray& payload) {
            if (++executionPersists == 2)
                return WriteResult{false, QStringLiteral("natural final failure")};
            if (target == QStringLiteral("recovery.json"))
                recoverySnapshots.push_back(QJsonDocument::fromJson(payload).object());
            if (target == QStringLiteral("bad.json"))
                return WriteResult{false, QStringLiteral("Save As failure")};
            return WriteResult{true, {}};
        });
    failed.start(batchDefinition, QStringLiteral("batch-result.json"));
    for (int iteration = 0; iteration < 20 && failed.isBusy(); ++iteration) {
        QCoreApplication::processEvents();
    }
    require(failed.state().entries.size() == 1, "Save As fixture did not create one entry");
    require(failed.state().status == BatchStatus::Failed, "Save As fixture did not reach Failed");
    require(failed.state().entries[0].status == BatchEntryStatus::Completed,
            "Save As fixture did not preserve Completed entry");
    require(failed.state().batchError.has_value() &&
                failed.state().batchError->code == BatchErrorCode::OutputWriteFailed &&
                failed.state().batchError->stage == BatchErrorStage::SnapshotPersistence,
            "Save As fixture did not fail at natural-final persistence");
    const auto originalError = failed.state().batchError;
    const auto originalTarget = failed.state().outputTarget;
    const auto originalResult = failed.state().entries[0].result;
    bool emptyRejected = false;
    try { (void)failed.saveAs(QString{}); }
    catch (const std::invalid_argument&) { emptyRejected = true; }
    require(emptyRejected, "Save As accepted an empty target");
    require(!failed.saveAs(QStringLiteral("bad.json")).success, "Save As failure was not reported");
    require(failed.state().batchError->technicalMessage == originalError->technicalMessage,
            "failed Save As changed the in-memory error");
    const auto recovered = failed.saveAs(QStringLiteral("recovery.json"));
    require(recovered.success && recoverySnapshots.size() == 1 &&
                recoverySnapshots[0]["status"] == "failed" &&
                recoverySnapshots[0]["batchError"].toObject()["code"] == "outputWriteFailed" &&
                recoverySnapshots[0]["batchError"].toObject()["stage"] == "snapshotPersistence" &&
                recoverySnapshots[0]["entries"].toArray()[0].toObject()["status"] == "completed" &&
                failed.state().status == BatchStatus::Failed && failed.state().batchError.has_value() &&
                originalError.has_value() && failed.state().batchError->code == originalError->code &&
                failed.state().batchError->stage == originalError->stage &&
                failed.state().batchError->technicalMessage == originalError->technicalMessage &&
                failed.state().entries[0].result.has_value() && originalResult.has_value() &&
                failed.state().entries[0].result->status == originalResult->status &&
                failed.state().outputTarget == originalTarget &&
                executorPointer->starts().size() == 1,
            "Save As recovery did not preserve the latest failed state");

    auto completedExecutor = std::make_unique<FakeExecutor>(std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, events);
    auto* completedPointer = completedExecutor.get();
    completedPointer->setDefinitions(&batchDefinition.entries());
    BatchController completed(std::move(completedExecutor),
        [](const QString&, const QByteArray&) { return WriteResult{true, {}}; });
    completed.start(batchDefinition, QStringLiteral("completed.json"));
    for (int iteration = 0; iteration < 20 && completed.isBusy(); ++iteration) {
        QCoreApplication::processEvents();
    }
    bool terminalNonFailedRejected = false;
    try { (void)completed.saveAs(QStringLiteral("copy.json")); }
    catch (const std::logic_error&) { terminalNonFailedRejected = true; }
    require(terminalNonFailedRejected && completedPointer->starts().size() == 1,
            "Save As accepted a terminal non-failed batch");
}

void testFatalDrain()
{
    const auto batchDefinition = definition(2);
    std::vector<std::string> events;
    auto executor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed, BenchmarkStatus::Completed}, events);
    auto* executorPointer = executor.get();
    executorPointer->setDefinitions(&batchDefinition.entries());
    executorPointer->setDeferTerminal(true);
    executorPointer->setThrowOnCancel(true);
    BatchController controller(std::move(executor),
        [](const QString&, const QByteArray&) { return WriteResult{true, {}}; });
    std::size_t finishCount = 0;
    QObject::connect(&controller, &BatchController::batchFinished,
                     [&](const BatchExecutionState&) { ++finishCount; });
    controller.start(batchDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    controller.requestCancel();
    require(executorPointer->isBusy() && finishCount == 0 && controller.isBusy(),
            "fatal drain terminalized while the executor was busy");
    executorPointer->emitPendingTerminal();
    require(!executorPointer->isBusy() && !controller.isBusy() && finishCount == 1 &&
                controller.state().status == BatchStatus::Failed && controller.state().batchError->code ==
                    BatchErrorCode::InternalError && controller.state().batchError->stage ==
                    BatchErrorStage::Orchestration && controller.state().entries[0].status == BatchEntryStatus::Completed &&
                executorPointer->starts().size() == 1,
            "fatal drain did not preserve the terminal result and fail exactly once");
}

void testCancellationPersistenceFailurePrecedence()
{
    const auto initialDefinition = definition(1);
    std::vector<std::string> initialEvents;
    auto initialExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed}, initialEvents);
    auto* initialExecutorPointer = initialExecutor.get();
    initialExecutorPointer->setDefinitions(&initialDefinition.entries());
    BatchController* initialController = nullptr;
    BatchController initial(std::move(initialExecutor),
        [&](const QString&, const QByteArray&) {
            initialController->requestCancel();
            return WriteResult{false, QStringLiteral("initial failure")};
        });
    initialController = &initial;
    initial.start(initialDefinition, QStringLiteral("batch-result.json"));
    require(initial.state().status == BatchStatus::Failed &&
                initial.state().batchError->code == BatchErrorCode::OutputInitializationFailed &&
                initialExecutorPointer->starts().empty(),
            "initial persistence failure did not take precedence over cancellation");

    const auto checkpointDefinition = definition(2);
    std::vector<std::string> checkpointEvents;
    auto checkpointExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Completed, BenchmarkStatus::Completed}, checkpointEvents);
    auto* checkpointExecutorPointer = checkpointExecutor.get();
    checkpointExecutorPointer->setDefinitions(&checkpointDefinition.entries());
    std::size_t checkpointCalls = 0;
    BatchController* checkpointController = nullptr;
    BatchController checkpoint(std::move(checkpointExecutor),
        [&](const QString&, const QByteArray&) {
            ++checkpointCalls;
            if (checkpointCalls == 2) {
                checkpointController->requestCancel();
                return WriteResult{false, QStringLiteral("checkpoint failure")};
            }
            return WriteResult{true, {}};
        });
    checkpointController = &checkpoint;
    checkpoint.start(checkpointDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    require(checkpoint.state().status == BatchStatus::Failed &&
                checkpoint.state().batchError->code == BatchErrorCode::OutputWriteFailed &&
                checkpoint.state().entries[0].result->status == BenchmarkStatus::Completed &&
                checkpoint.state().entries[1].status == BatchEntryStatus::NotStarted &&
                checkpointExecutorPointer->starts().size() == 1,
            "checkpoint persistence failure did not take precedence over cancellation");

    const auto terminalDefinition = definition(1);
    std::vector<std::string> terminalEvents;
    auto terminalExecutor = std::make_unique<FakeExecutor>(
        std::vector<BenchmarkStatus>{BenchmarkStatus::Cancelled}, terminalEvents);
    auto* terminalExecutorPointer = terminalExecutor.get();
    terminalExecutorPointer->setDefinitions(&terminalDefinition.entries());
    terminalExecutorPointer->setDeferTerminal(true);
    std::size_t terminalCalls = 0;
    BatchController* terminalController = nullptr;
    BatchController terminal(std::move(terminalExecutor),
        [&](const QString&, const QByteArray&) {
            ++terminalCalls;
            if (terminalCalls == 2) return WriteResult{false, QStringLiteral("cancelled final failure")};
            return WriteResult{true, {}};
        });
    terminalController = &terminal;
    terminal.start(terminalDefinition, QStringLiteral("batch-result.json"));
    QCoreApplication::processEvents();
    terminal.requestCancel();
    terminalExecutorPointer->emitPendingTerminal();
    require(terminal.state().status == BatchStatus::Failed &&
                terminal.state().batchError->code == BatchErrorCode::OutputWriteFailed &&
                terminal.state().entries[0].status == BatchEntryStatus::Cancelled &&
                terminalExecutorPointer->starts().size() == 1,
            "cancelled-final persistence failure did not preserve canonical entry state");
    (void)terminalController;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testCompletedChainAndOrdering();
        testPreparationFailureClassification();
        testUnexpectedCancelledResultFailsBatch();
        testContinueAfterFailure();
        testRepeatedFailureAndPersistenceSafety();
        testActiveCancellationRaces();
        testCancellationBetweenEntriesAndDuringPersistence();
        testCancelAfterTerminal();
        testSaveAsRecovery();
        testCancellationPersistenceFailurePrecedence();
        testFatalDrain();
        std::cout << "PASS BatchController\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchController: " << error.what() << '\n';
        return 1;
    }
}
