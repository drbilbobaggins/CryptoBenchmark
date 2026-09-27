#include <cryptobench/application/BatchController.h>

#include <cryptobench/application/BenchmarkController.h>

#include <QMetaObject>

#include <stdexcept>
#include <utility>

namespace cryptobench::application {

BatchController::BatchController(QObject* parent)
    : BatchController(std::make_unique<BenchmarkController>(), {}, {}, parent)
{
}

BatchController::BatchController(
    std::unique_ptr<BenchmarkSessionExecutor> executor,
    SnapshotPersister persister,
    SnapshotSerializer serializer,
    QObject* parent)
    : QObject(parent), executor_(std::move(executor)), persister_(std::move(persister)),
      serializer_(std::move(serializer))
{
    if (!executor_) throw std::invalid_argument("BatchController requires an executor");
    if (!serializer_) {
        serializer_ = [this](const ResultDocument& document) {
            return exportService_.serialize(document);
        };
    }

    connect(executor_.get(), &BenchmarkSessionExecutor::progressChanged,
            this, &BatchController::onExecutorProgress);
    connect(executor_.get(), &BenchmarkSessionExecutor::benchmarkFinished,
            this, &BatchController::onExecutorFinished);
}

bool BatchController::isBusy() const noexcept
{
    return state_ != State::Idle && state_ != State::Terminal;
}

const BatchExecutionState& BatchController::state() const noexcept
{
    return batchState_;
}

BatchProgress BatchController::progress() const
{
    auto value = deriveBatchProgress(batchState_, currentProgress_);
    value.persistenceInProgress = state_ == State::InitializingOutput ||
                                  state_ == State::PersistingSnapshot;
    return value;
}

void BatchController::start(const BatchDefinition& definition, const QString& outputTarget)
{
    if (isBusy() || executor_->isBusy()) throw std::logic_error("BatchController is already running");
    if (definition.entries().empty()) throw std::invalid_argument("batch definition is empty");

    batchState_ = createBatchExecutionState(definition, outputTarget);
    startedPositions_.assign(batchState_.entries.size(), false);
    nextPosition_ = 0;
    activePosition_.reset();
    currentProgress_.reset();
    requiredSnapshotCommitted_ = false;
    terminalEmitted_ = false;
    state_ = State::InitializingOutput;
    emitProgress();
    persistSnapshot(true);
}

void BatchController::advance()
{
    if (state_ != State::ReadyToAdvance || batchState_.status != BatchStatus::InProgress ||
        activePosition_.has_value() || !requiredSnapshotCommitted_) {
        return;
    }

    if (!nextPosition_.has_value()) {
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                  "batch ended without a natural terminal status");
        return;
    }

    const auto position = *nextPosition_;
    if (!nextEntryGate(position)) {
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                  "batch entry gate rejected the next entry");
        return;
    }

    auto& entry = batchState_.entries[position];
    activePosition_ = position;
    nextPosition_ = position + 1 < batchState_.entries.size()
        ? std::optional<std::size_t>{position + 1}
        : std::nullopt;
    batchState_.currentEntryIndex = entry.definition.entryIndex;
    startedPositions_[position] = true;
    requiredSnapshotCommitted_ = false;
    currentProgress_.reset();
    state_ = State::RunningEntry;
    emitProgress();

    try {
        executor_->start(entry.definition.config);
    } catch (const std::exception& error) {
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration, error.what());
    }
}

void BatchController::onExecutorProgress(const core::ProgressInfo& progress)
{
    if (state_ != State::RunningEntry || !activePosition_.has_value()) return;
    currentProgress_ = progress;
    emitProgress();
}

void BatchController::onExecutorFinished(const core::BenchmarkResult& result)
{
    if (state_ != State::RunningEntry || !activePosition_.has_value()) return;

    const auto position = *activePosition_;
    auto& entry = batchState_.entries[position];
    entry.result = result;
    switch (result.status) {
    case core::BenchmarkStatus::Completed:
        entry.status = BatchEntryStatus::Completed;
        break;
    case core::BenchmarkStatus::Failed:
        entry.status = BatchEntryStatus::Failed;
        break;
    case core::BenchmarkStatus::Cancelled:
        entry.status = BatchEntryStatus::Cancelled;
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                  "unexpected cancelled benchmark result in M12-B");
        break;
    }

    if (result.status == core::BenchmarkStatus::Cancelled) return;

    if (const auto finalStatus = naturalFinalStatus(); finalStatus.has_value()) {
        batchState_.status = *finalStatus;
    }

    activePosition_.reset();
    currentProgress_.reset();
    state_ = State::PersistingSnapshot;
    emitProgress();
    persistSnapshot(false);
}

void BatchController::persistSnapshot(bool initialSnapshot)
{
    QByteArray payload;
    try {
        const auto document = documentService_.create(batchState_);
        payload = serializer_(document);
    } catch (const std::exception& error) {
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration, error.what());
        return;
    }

    try {
        const auto result = persister_
            ? persister_(batchState_.outputTarget, payload)
            : fileWriter_.writeAtomically(batchState_.outputTarget, payload);
        if (!result.success) {
            failBatch(
                initialSnapshot ? BatchErrorCode::OutputInitializationFailed
                                : BatchErrorCode::OutputWriteFailed,
                initialSnapshot ? BatchErrorStage::OutputInitialization
                                : BatchErrorStage::SnapshotPersistence,
                result.technicalMessage.toStdString());
            return;
        }
    } catch (const std::exception& error) {
        failBatch(
            initialSnapshot ? BatchErrorCode::OutputInitializationFailed
                            : BatchErrorCode::OutputWriteFailed,
            initialSnapshot ? BatchErrorStage::OutputInitialization
                            : BatchErrorStage::SnapshotPersistence,
            error.what());
        return;
    }

    requiredSnapshotCommitted_ = true;
    if (initialSnapshot) {
        state_ = State::ReadyToAdvance;
        emitProgress();
        QMetaObject::invokeMethod(this, &BatchController::advance, Qt::QueuedConnection);
        return;
    }

    if (batchState_.status != BatchStatus::InProgress) {
        state_ = State::Terminal;
        emitProgress();
        finishTerminal();
        return;
    }

    state_ = State::ReadyToAdvance;
    emitProgress();
    QMetaObject::invokeMethod(this, &BatchController::advance, Qt::QueuedConnection);
}

void BatchController::failBatch(BatchErrorCode code, BatchErrorStage stage, std::string message)
{
    if (state_ == State::Terminal) return;
    activePosition_.reset();
    requiredSnapshotCommitted_ = false;
    batchState_.status = BatchStatus::Failed;
    batchState_.batchError = BatchError{
        code,
        stage,
        batchState_.currentEntryIndex,
        std::move(message)
    };
    state_ = State::Terminal;
    emitProgress();
    finishTerminal();
}

void BatchController::finishTerminal()
{
    if (terminalEmitted_) return;
    terminalEmitted_ = true;
    emit batchFinished(batchState_);
}

void BatchController::emitProgress()
{
    emit progressChanged(progress());
}

bool BatchController::nextEntryGate(std::size_t position) const
{
    if (position >= batchState_.entries.size() || executor_->isBusy() || startedPositions_[position]) {
        return false;
    }
    const auto& entry = batchState_.entries[position];
    if (entry.status != BatchEntryStatus::NotStarted || entry.result.has_value()) return false;
    for (std::size_t index = 0; index < position; ++index) {
        if (batchState_.entries[index].status == BatchEntryStatus::NotStarted ||
            !batchState_.entries[index].result.has_value()) {
            return false;
        }
    }
    return true;
}

std::optional<BatchStatus> BatchController::naturalFinalStatus() const
{
    bool allTerminal = true;
    bool hasFailure = false;
    bool hasCancellation = false;
    for (const auto& entry : batchState_.entries) {
        allTerminal = allTerminal && entry.status != BatchEntryStatus::NotStarted;
        hasFailure = hasFailure || entry.status == BatchEntryStatus::Failed;
        hasCancellation = hasCancellation || entry.status == BatchEntryStatus::Cancelled;
    }
    if (!allTerminal || hasCancellation) return std::nullopt;
    return hasFailure ? BatchStatus::CompletedWithFailures : BatchStatus::Completed;
}

} // namespace cryptobench::application
