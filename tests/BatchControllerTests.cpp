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
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch fixture could not be opened");
    const QByteArray input = entryCount == 2
        ? QByteArray{R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
                       R"({"id":"first","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}},)"
                       R"({"id":"second","profileId":"sha3-256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}}]})"}
        : QByteArray{R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
                       R"({"id":"first","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}},)"
                       R"({"id":"second","profileId":"sha3-256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}},)"
                       R"({"id":"third","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}}]})"};
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
        emit benchmarkFinished(resultFor((*definitions_)[startIndex_], script_[startIndex_]));
        --activeSessions_;
        busy_ = false;
        ++startIndex_;
    }

    void requestCancel() override {}
    bool isBusy() const noexcept override { return busy_; }

    void setDefinitions(const std::vector<BatchEntryDefinition>* definitions)
    {
        definitions_ = definitions;
    }

    const std::vector<AlgorithmProfileId>& starts() const noexcept { return starts_; }
    std::size_t maxActiveSessions() const noexcept { return maxActiveSessions_; }

private:
    std::vector<BenchmarkStatus> script_;
    std::vector<std::string>& events_;
    const std::vector<BatchEntryDefinition>* definitions_ = nullptr;
    std::vector<AlgorithmProfileId> starts_;
    std::size_t startIndex_ = 0;
    std::size_t activeSessions_ = 0;
    std::size_t maxActiveSessions_ = 0;
    bool busy_ = false;
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
        std::cout << "PASS BatchController\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchController: " << error.what() << '\n';
        return 1;
    }
}
