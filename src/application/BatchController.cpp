#include <cryptobench/application/BatchController.h>

#include <cryptobench/application/BenchmarkController.h>

#include <QMetaObject>

#include <stdexcept>
#include <utility>

namespace cryptobench::application {

BatchController::BatchController(QObject* parent)
    : QObject(parent),
      executorFactory_([](const core::MeasurementSettings& settings) {
          return std::make_unique<BenchmarkController>(nullptr, QString{},
                                                       WorkerRunSessionTestHooks{}, settings);
      }),
      settingsProvider_([] { return core::defaultMeasurementSettings(); })
{
    serializer_ = [this](const ResultDocument& document) {
        return exportService_.serialize(document);
    };
}

BatchController::BatchController(MeasurementSettingsProvider settingsProvider, QObject* parent)
    : BatchController(parent)
{
    if (!settingsProvider) {
        throw std::invalid_argument("BatchController requires a measurement settings provider");
    }
    settingsProvider_ = std::move(settingsProvider);
}

BatchController::BatchController(
    std::unique_ptr<BenchmarkSessionExecutor> executor,
    SnapshotPersister persister,
    SnapshotSerializer serializer,
    core::MeasurementSettings executorSettings,
    QObject* parent)
        : QObject(parent), executor_(BenchmarkSessionExecutor::adopt(std::move(executor))),
            persister_(std::move(persister)),
      serializer_(std::move(serializer)), fixedExecutorSettings_(executorSettings)
{
    if (!executor_) throw std::invalid_argument("BatchController requires an executor");
    if (!core::isValidMeasurementSettings(*fixedExecutorSettings_)) {
        throw std::invalid_argument("BatchController executor settings are invalid");
    }
    executor_->setParent(nullptr);
    if (!serializer_) {
        serializer_ = [this](const ResultDocument& document) {
            return exportService_.serialize(document);
        };
    }
    executor_->setEmissionLifetimeOwner(executor_);
    connectExecutor();
}

BatchController::BatchController(
    ExecutorFactory executorFactory,
    SnapshotPersister persister,
    SnapshotSerializer serializer,
    MeasurementSettingsProvider settingsProvider,
    QObject* parent)
    : QObject(parent), executorFactory_(std::move(executorFactory)),
      settingsProvider_(std::move(settingsProvider)), persister_(std::move(persister)),
      serializer_(std::move(serializer))
{
    if (!executorFactory_) throw std::invalid_argument("BatchController requires an executor factory");
    if (!serializer_) {
        serializer_ = [this](const ResultDocument& document) {
            return exportService_.serialize(document);
        };
    }

}

bool BatchController::isBusy() const noexcept
{
    return state_ != State::Idle && state_ != State::Terminal;
}

void BatchController::requestCancel()
{
    if (!isBusy() || batchState_.cancelRequested) return;

    batchState_.cancelRequested = true;
    if (state_ == State::RunningEntry) {
        state_ = State::CancellingEntry;
        emitProgress();
        try {
            executor_->requestCancel();
        } catch (const std::exception& error) {
            failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                      error.what());
        }
        return;
    }

    if (state_ == State::ReadyToAdvance) {
        batchState_.status = BatchStatus::Cancelled;
        state_ = State::PersistingSnapshot;
        persistenceIntent_ = PersistenceIntent::CancelledFinal;
        emitProgress();
        persistSnapshot(PersistenceIntent::CancelledFinal);
        return;
    }

    emitProgress();
}

WriteResult BatchController::saveAs(const QString& newTarget)
{
    if (state_ != State::Terminal || batchState_.status != BatchStatus::Failed) {
        throw std::logic_error("Save As requires a terminal failed batch");
    }
    if (newTarget.isEmpty()) throw std::invalid_argument("Save As target is empty");

    try {
        const auto document = documentService_.create(batchState_);
        const auto payload = serializer_(document);
        return persister_ ? persister_(newTarget, payload)
                          : fileWriter_.writeAtomically(newTarget, payload);
    } catch (const std::exception& error) {
        return {false, QString::fromUtf8(error.what())};
    }
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
    if (isBusy() || (executor_ && executor_->isBusy())) {
        throw std::logic_error("BatchController is already running");
    }
    if (definition.entries().empty()) throw std::invalid_argument("batch definition is empty");

    if (!settingsProvider_ && !fixedExecutorSettings_) {
        throw std::invalid_argument("BatchController has no measurement settings provider");
    }
    const auto measurementSettings = settingsProvider_
        ? settingsProvider_()
        : *fixedExecutorSettings_;
    if (!core::isValidMeasurementSettings(measurementSettings)) {
        throw std::invalid_argument("BatchController measurement settings are invalid");
    }

    std::unique_ptr<BenchmarkSessionExecutor> nextExecutor;
    if (executorFactory_) {
        nextExecutor = executorFactory_(measurementSettings);
        if (!nextExecutor) throw std::invalid_argument("BatchController executor factory returned null");
    } else if (!executor_) {
        throw std::logic_error("BatchController has no executor");
    }

    if (nextExecutor) {
        retireExecutor();
        nextExecutor->setParent(nullptr);
        executor_ = BenchmarkSessionExecutor::adopt(std::move(nextExecutor));
        executor_->setEmissionLifetimeOwner(executor_);
        connectExecutor();
    }

    batchState_ = createBatchExecutionState(definition, outputTarget);
    batchState_.measurementSettings = measurementSettings;
    startedPositions_.assign(batchState_.entries.size(), false);
    nextPosition_ = 0;
    activePosition_.reset();
    currentProgress_.reset();
    requiredSnapshotCommitted_ = false;
    terminalEmitted_ = false;
    state_ = State::InitializingOutput;
    emitProgress();
    persistSnapshot(PersistenceIntent::Initial);
}

void BatchController::connectExecutor()
{
    auto* executor = executor_.get();
    connect(executor, &BenchmarkSessionExecutor::progressChanged, this,
            [this, executor](const core::ProgressInfo& progress) {
                if (executor_.get() == executor) onExecutorProgress(progress);
            });
    connect(executor, &BenchmarkSessionExecutor::benchmarkFinished, this,
            [this, executor](const core::BenchmarkResult& result) {
                if (executor_.get() == executor) onExecutorFinished(result);
            });
}

void BatchController::retireExecutor()
{
    if (!executor_) return;
    retiredExecutors_.push_back(std::move(executor_));
    QMetaObject::invokeMethod(this, [this] { retiredExecutors_.clear(); },
                              Qt::QueuedConnection);
}

void BatchController::advance()
{
    if (state_ != State::ReadyToAdvance || batchState_.status != BatchStatus::InProgress ||
        batchState_.cancelRequested || activePosition_.has_value() || !requiredSnapshotCommitted_) {
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
    if (state_ == State::DrainingFatalEntry) {
        if (activePosition_.has_value()) {
            auto& entry = batchState_.entries[*activePosition_];
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
                break;
            }
        }
        finalizePendingFatal();
        return;
    }
    if ((state_ != State::RunningEntry && state_ != State::CancellingEntry) ||
        !activePosition_.has_value()) return;

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
        break;
    }

    activePosition_.reset();
    currentProgress_.reset();

    if (result.status == core::BenchmarkStatus::Cancelled && !batchState_.cancelRequested) {
        failBatch(BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                  "unexpected cancelled benchmark result in M12-B");
        return;
    }

    if (batchState_.cancelRequested) {
        batchState_.status = BatchStatus::Cancelled;
        state_ = State::PersistingSnapshot;
        persistenceIntent_ = PersistenceIntent::CancelledFinal;
        emitProgress();
        persistSnapshot(PersistenceIntent::CancelledFinal);
        return;
    }

    const auto finalStatus = naturalFinalStatus();
    if (finalStatus.has_value()) {
        batchState_.status = *finalStatus;
    }

    state_ = State::PersistingSnapshot;
    persistenceIntent_ = finalStatus.has_value()
        ? PersistenceIntent::NaturalFinal
        : PersistenceIntent::EntryCheckpoint;
    emitProgress();
    persistSnapshot(persistenceIntent_);
}

void BatchController::persistSnapshot(PersistenceIntent intent)
{
    persistenceIntent_ = intent;
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
                intent == PersistenceIntent::Initial
                    ? BatchErrorCode::OutputInitializationFailed
                    : BatchErrorCode::OutputWriteFailed,
                intent == PersistenceIntent::Initial
                    ? BatchErrorStage::OutputInitialization
                    : BatchErrorStage::SnapshotPersistence,
                result.technicalMessage.toStdString());
            return;
        }
    } catch (const std::exception& error) {
        failBatch(
            intent == PersistenceIntent::Initial
                ? BatchErrorCode::OutputInitializationFailed
                : BatchErrorCode::OutputWriteFailed,
            intent == PersistenceIntent::Initial
                ? BatchErrorStage::OutputInitialization
                : BatchErrorStage::SnapshotPersistence,
            error.what());
        return;
    }

    requiredSnapshotCommitted_ = true;
    if (batchState_.cancelRequested && intent != PersistenceIntent::CancelledFinal) {
        batchState_.status = BatchStatus::Cancelled;
        state_ = State::PersistingSnapshot;
        persistSnapshot(PersistenceIntent::CancelledFinal);
        return;
    }

    if (intent == PersistenceIntent::Initial) {
        state_ = State::ReadyToAdvance;
        emitProgress();
        QMetaObject::invokeMethod(this, &BatchController::advance, Qt::QueuedConnection);
        return;
    }

    if (intent == PersistenceIntent::CancelledFinal ||
        batchState_.status != BatchStatus::InProgress) {
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

    const BatchError error{code, stage, batchState_.currentEntryIndex, std::move(message)};
    if (activePosition_.has_value() && executor_->isBusy()) {
        pendingFatalError_ = error;
        batchState_.cancelRequested = true;
        state_ = State::DrainingFatalEntry;
        emitProgress();
        try {
            executor_->requestCancel();
        } catch (const std::exception& drainError) {
            pendingFatalError_ = BatchError{
                BatchErrorCode::InternalError,
                BatchErrorStage::Orchestration,
                batchState_.currentEntryIndex,
                drainError.what()};
            if (!executor_->isBusy()) finalizePendingFatal();
        }
        return;
    }

    activePosition_.reset();
    requiredSnapshotCommitted_ = false;
    batchState_.status = BatchStatus::Failed;
    batchState_.batchError = error;
    state_ = State::Terminal;
    emitProgress();
    finishTerminal();
}

void BatchController::finalizePendingFatal()
{
    if (!pendingFatalError_ || executor_->isBusy()) return;
    activePosition_.reset();
    currentProgress_.reset();
    requiredSnapshotCommitted_ = false;
    batchState_.status = BatchStatus::Failed;
    batchState_.batchError = *pendingFatalError_;
    pendingFatalError_.reset();
    state_ = State::Terminal;
    emitProgress();
    finishTerminal();
}

void BatchController::finishTerminal()
{
    if (terminalEmitted_) return;
    terminalEmitted_ = true;
    const auto terminalState = batchState_;
    emit batchFinished(terminalState);
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
