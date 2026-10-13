#include <cryptobench/application/BenchmarkController.h>

#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <QMetaObject>

#include <stdexcept>
#include <string>
#include <utility>

namespace cryptobench::application {

BenchmarkController::BenchmarkController(
    QObject* parent,
    QString workerExecutablePath,
    WorkerRunSessionTestHooks sessionTestHooks,
    core::MeasurementSettings measurementSettings)
    : BenchmarkSessionExecutor(parent),
      measurementSettings_(measurementSettings),
      workerExecutablePath_(std::move(workerExecutablePath)),
      sessionTestHooks_(std::move(sessionTestHooks))
{
    if (!core::isValidMeasurementSettings(measurementSettings_)) {
        throw std::invalid_argument("BenchmarkController measurement settings are invalid");
    }
}

BenchmarkController::~BenchmarkController()
{
    if (!currentSession_) return;

    auto* session = currentSession_.release();
    session->setParent(nullptr);
    if (!session->isActive()) {
        QMetaObject::invokeMethod(session, &QObject::deleteLater, Qt::QueuedConnection);
        return;
    }

    const auto deleteSession = [session](auto&&...) { session->deleteLater(); };
    connect(session, &WorkerRunSession::completed, session, deleteSession);
    connect(session, &WorkerRunSession::failed, session, deleteSession);
    connect(session, &WorkerRunSession::cancelled, session, deleteSession);
    session->cancel();
}

bool BenchmarkController::isBusy() const noexcept
{
    return state_ != State::Idle;
}

void BenchmarkController::requestCancel()
{
    if (!isBusy()) return;

    cancelRequested_ = true;
    if (state_ == State::Terminalizing || state_ == State::BetweenRuns) return;
    state_ = State::Cancelling;
    if (currentSession_ && currentSession_->isActive()) currentSession_->cancel();
}

void BenchmarkController::start(const core::BenchmarkConfig& config)
{
    if (isBusy()) throw std::logic_error("BenchmarkController is already running");

    core::ValidationResult validation;
    if (!core::ConfigValidator{}.validateAndCreate(config, validation)) {
        const auto message = validation.errors.empty()
            ? "benchmark configuration is invalid"
            : validation.errors.front().technicalMessage;
        throw std::invalid_argument(message);
    }
    const auto* profile = core::AlgorithmRegistry::find(config.profile);
    if (profile == nullptr) {
        throw std::invalid_argument("benchmark configuration references an unknown profile");
    }
    if (!core::isValidMeasurementSettings(measurementSettings_)) {
        throw std::invalid_argument("BenchmarkController measurement settings are invalid");
    }

    config_ = config;
    characteristics_ = profile->characteristics;
    environment_ = collectEnvironmentInfo();
    expectedRunIndex_ = 0;
    completedRuns_.clear();
    cancelRequested_ = false;
    pendingTerminalKind_ = PendingTerminalKind::None;
    pendingRun_.reset();
    pendingError_.reset();
    ++generation_;
    state_ = State::StartingRun;
    startRun();
}

void BenchmarkController::startRun()
{
    if (cancelRequested_ || state_ == State::Cancelling || state_ == State::Terminalizing) {
        finishCancelled();
        return;
    }
    if (!config_ || !characteristics_ || !environment_ ||
        expectedRunIndex_ >= config_->runs || currentSession_) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        "BenchmarkController cannot start the next logical run",
                                        expectedRunIndex_);
        pendingTerminalKind_ = PendingTerminalKind::Failed;
        finishFailed();
        return;
    }

    const auto generation = generation_;
    std::unique_ptr<WorkerRunSession> session;
    try {
        session = std::make_unique<WorkerRunSession>(this, workerExecutablePath_, sessionTestHooks_);
    } catch (const std::exception& error) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        error.what(), expectedRunIndex_);
        pendingTerminalKind_ = PendingTerminalKind::Failed;
        finishFailed();
        return;
    }
    auto* sessionPointer = session.get();
    currentSession_ = std::move(session);
    state_ = State::StartingRun;
    if (sessionTestHooks_.sessionCreated) sessionTestHooks_.sessionCreated(sessionPointer);

    connect(sessionPointer, &WorkerRunSession::progressChanged, this,
            [this, sessionPointer, generation](const core::ProgressInfo& progress) {
                onSessionProgress(sessionPointer, generation, progress);
            });
    connect(sessionPointer, &WorkerRunSession::completed, this,
            [this, sessionPointer, generation](const WorkerRunSessionResult& result) {
                onSessionCompleted(sessionPointer, generation, result);
            });
    connect(sessionPointer, &WorkerRunSession::failed, this,
            [this, sessionPointer, generation](const core::ErrorInfo& error) {
                onSessionFailed(sessionPointer, generation, error);
            });
    connect(sessionPointer, &WorkerRunSession::cancelled, this,
            [this, sessionPointer, generation] {
                onSessionCancelled(sessionPointer, generation);
            });

    try {
        currentSession_->start(*config_, expectedRunIndex_, measurementSettings_);
    } catch (const std::exception& error) {
        pendingError_ = controllerError(core::ErrorCode::WorkerStartupFailed,
                                        core::FailureStage::WorkerStartup,
                                        error.what(), expectedRunIndex_);
        pendingTerminalKind_ = PendingTerminalKind::Failed;
        queueTerminalContinuation(sessionPointer, generation);
    }
}

void BenchmarkController::onSessionProgress(
    WorkerRunSession* session, std::uint64_t generation,
    const core::ProgressInfo& progress)
{
    if (generation != generation_ || currentSession_.get() != session || !config_ ||
        state_ == State::Cancelling || state_ == State::Terminalizing) return;
    if (progress.totalRuns != config_->runs || !progress.runIndex ||
        *progress.runIndex != expectedRunIndex_) return;
    emit progressChanged(progress);
}

void BenchmarkController::onSessionCompleted(
    WorkerRunSession* session, std::uint64_t generation,
    const WorkerRunSessionResult& result)
{
    if (generation != generation_ || currentSession_.get() != session || !config_ ||
        pendingTerminalKind_ != PendingTerminalKind::None) return;
    try {
        if (result.logicalRunIndex != expectedRunIndex_ ||
            result.workerMeasurement.runIndex != expectedRunIndex_) {
            throw core::ResultAssemblyError("WorkerRunSession returned an unexpected logical run");
        }
        pendingRun_ = core::ResultAssembler::assembleRun(
            result.workerMeasurement, result.memory, expectedRunIndex_,
            config_->iterationsPerRun);
        pendingTerminalKind_ = PendingTerminalKind::Completed;
    } catch (const std::exception& error) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        error.what(), expectedRunIndex_);
        pendingTerminalKind_ = PendingTerminalKind::Failed;
    }
    queueTerminalContinuation(session, generation);
}

void BenchmarkController::onSessionFailed(
    WorkerRunSession* session, std::uint64_t generation, const core::ErrorInfo& error)
{
    if (generation != generation_ || currentSession_.get() != session ||
        pendingTerminalKind_ != PendingTerminalKind::None) return;
    pendingError_ = error;
    pendingTerminalKind_ = PendingTerminalKind::Failed;
    queueTerminalContinuation(session, generation);
}

void BenchmarkController::onSessionCancelled(WorkerRunSession* session, std::uint64_t generation)
{
    if (generation != generation_ || currentSession_.get() != session ||
        pendingTerminalKind_ != PendingTerminalKind::None) return;
    pendingTerminalKind_ = PendingTerminalKind::Cancelled;
    queueTerminalContinuation(session, generation);
}

void BenchmarkController::queueTerminalContinuation(
    WorkerRunSession* session, std::uint64_t generation)
{
    if (pendingTerminalKind_ == PendingTerminalKind::None) return;
    state_ = State::Terminalizing;
    if (sessionTestHooks_.terminalContinuationQueued) {
        sessionTestHooks_.terminalContinuationQueued();
    }
    QMetaObject::invokeMethod(this, [this, session, generation] {
        if (generation != generation_ || currentSession_.get() != session ||
            pendingTerminalKind_ == PendingTerminalKind::None) return;

        const auto terminalKind = pendingTerminalKind_;
        const auto pendingRun = pendingRun_;
        const auto pendingError = pendingError_;
        currentSession_.reset();
        pendingRun_.reset();
        pendingError_.reset();
        pendingTerminalKind_ = PendingTerminalKind::None;

        if (terminalKind == PendingTerminalKind::Completed && pendingRun.has_value()) {
            completedRuns_.push_back(*pendingRun);
            ++expectedRunIndex_;
        }

        if (terminalKind == PendingTerminalKind::Failed || pendingError.has_value()) {
            pendingError_ = pendingError;
            finishFailed();
        } else if (cancelRequested_ || terminalKind == PendingTerminalKind::Cancelled) {
            finishCancelled();
        } else if (config_ && expectedRunIndex_ == config_->runs) {
            finishCompleted();
        } else {
            state_ = State::BetweenRuns;
            const auto nextGeneration = generation_;
            QMetaObject::invokeMethod(this, [this, nextGeneration] {
                if (nextGeneration != generation_ ||
                    (state_ != State::BetweenRuns && state_ != State::Cancelling)) return;
                if (state_ == State::Cancelling) {
                    finishCancelled();
                    return;
                }
                state_ = State::StartingRun;
                startRun();
            }, Qt::QueuedConnection);
        }
    }, Qt::QueuedConnection);
}

void BenchmarkController::finishCompleted()
{
    if (!config_ || !characteristics_ || !environment_ ||
        completedRuns_.size() != config_->runs) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        "BenchmarkController completed with an incomplete run set");
        finishFailed();
        return;
    }
    try {
        const auto result = core::ResultAssembler::completed(
            *config_, completedRuns_, *characteristics_, *environment_);
        auto stampedResult = result;
        stampedResult.measurementSettings = measurementSettings_;
        state_ = State::Idle;
        emitBenchmarkFinished(stampedResult);
    } catch (const std::exception& error) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        error.what());
        finishFailed();
    }
}

void BenchmarkController::finishFailed()
{
    if (!config_ || !characteristics_ || !environment_ || !pendingError_) return;
    const auto error = *pendingError_;
    try {
        const auto result = core::ResultAssembler::failed(
            *config_, completedRuns_, *characteristics_, *environment_, error);
        auto stampedResult = result;
        stampedResult.measurementSettings = measurementSettings_;
        pendingError_.reset();
        state_ = State::Idle;
        emitBenchmarkFinished(stampedResult);
    } catch (const std::exception& assemblyError) {
        const auto fallbackError = controllerError(
            core::ErrorCode::InternalError, core::FailureStage::ResultAssembly,
            assemblyError.what());
        pendingError_.reset();
        state_ = State::Idle;
        core::BenchmarkResult fallbackResult{*config_, completedRuns_, std::nullopt,
                             *characteristics_, *environment_,
                             core::BenchmarkStatus::Failed, fallbackError};
        fallbackResult.measurementSettings = measurementSettings_;
        emitBenchmarkFinished(fallbackResult);
    }
}

void BenchmarkController::finishCancelled()
{
    if (!config_ || !characteristics_ || !environment_) return;
    try {
        const auto result = core::ResultAssembler::cancelled(
            *config_, completedRuns_, *characteristics_, *environment_);
        auto stampedResult = result;
        stampedResult.measurementSettings = measurementSettings_;
        state_ = State::Idle;
        emitBenchmarkFinished(stampedResult);
    } catch (const std::exception& error) {
        pendingError_ = controllerError(core::ErrorCode::InternalError,
                                        core::FailureStage::ResultAssembly,
                                        error.what());
        finishFailed();
    }
}

core::ErrorInfo BenchmarkController::controllerError(
    core::ErrorCode code, core::FailureStage stage, std::string message,
    std::optional<std::uint32_t> runIndex)
{
    return {code, stage, runIndex, std::move(message), std::nullopt};
}

} // namespace cryptobench::application