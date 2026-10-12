#include <cryptobench/application/WorkerRunSession.h>

#include <cryptobench/core/ConfigValidator.h>

#include <QUuid>

#include <stdexcept>
#include <string>
#include <utility>

namespace cryptobench::application {

namespace {
constexpr int kTechnicalTimeoutMilliseconds = 10'000;
constexpr int kWorkerExitTimeoutMilliseconds = 10'000;
constexpr int kFinalDrainTimeoutMilliseconds = 250;
constexpr int kWorkerFailureGraceTimeoutMilliseconds = 250;
constexpr int kCleanupTimeoutMilliseconds = 10'000;

bool isNormalExit(int exitCode, QProcess::ExitStatus exitStatus)
{
    return exitStatus == QProcess::NormalExit && exitCode == 0;
}

std::string validationMessage(const core::ValidationResult& validation)
{
    if (validation.errors.empty()) return "benchmark configuration is invalid";
    return validation.errors.front().technicalMessage;
}
}

WorkerRunSession::WorkerRunSession(QObject* parent,
                                                                     QString workerExecutablePath,
                                                                     WorkerRunSessionTestHooks testHooks)
        : QObject(parent),
            workerExecutablePath_(std::move(workerExecutablePath)),
            testHooks_(std::move(testHooks))
{
    technicalTimer_.setSingleShot(true);
    connect(&technicalTimer_, &QTimer::timeout, this, &WorkerRunSession::onTechnicalTimeout);
    workerExitTimer_.setSingleShot(true);
    connect(&workerExitTimer_, &QTimer::timeout, this, &WorkerRunSession::onWorkerExitTimeout);
    finalDrainTimer_.setSingleShot(true);
    connect(&finalDrainTimer_, &QTimer::timeout, this, &WorkerRunSession::onFinalDrainTimeout);
    workerFailureGraceTimer_.setSingleShot(true);
    connect(&workerFailureGraceTimer_, &QTimer::timeout,
            this, &WorkerRunSession::onWorkerFailureGraceTimeout);
    cleanupTimer_.setSingleShot(true);
    connect(&cleanupTimer_, &QTimer::timeout, this, &WorkerRunSession::onCleanupTimeout);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::connected, this, [this] {
        if (state_ != State::WaitingForWorkerReady) return;
        armTechnicalTimeout();
    });
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerReadyReceived,
            this, &WorkerRunSession::onWorkerReady);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::progressReceived,
            this, &WorkerRunSession::onProgress);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::baselineReadyReceived,
            this, &WorkerRunSession::onBaselineReady);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::algorithmReadyReceived,
            this, &WorkerRunSession::onAlgorithmReady);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::measurementFinishedReceived,
            this, &WorkerRunSession::onMeasurementFinished);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerRunMeasurementReceived,
            this, &WorkerRunSession::onWorkerMeasurement);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerOutcomeReceived,
            this, &WorkerRunSession::onWorkerOutcome);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::transportError,
            this, &WorkerRunSession::onTransportError);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::disconnected,
            this, &WorkerRunSession::onDisconnected);
    connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::errorOccurred,
            this, &WorkerRunSession::onProcessError);
    connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::finished,
            this, &WorkerRunSession::onProcessFinished);
    connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::started, this, [this] {
        if (testHooks_.workerStarted) testHooks_.workerStarted(workerProcess_.processId());
    });
}

WorkerRunSession::~WorkerRunSession()
{
    cleanup();
    workerProcess_.kill();
}

void WorkerRunSession::start(const core::BenchmarkConfig& config,
                             std::uint32_t logicalRunIndex,
                             const core::MeasurementSettings& settings)
{
    if (state_ != State::Idle) throw std::logic_error("WorkerRunSession is already active");
    if (!core::isValidMeasurementSettings(settings)) {
        throw std::invalid_argument("WorkerRunSession measurement settings are invalid");
    }
    core::ValidationResult validation;
    if (!core::ConfigValidator{}.validateAndCreate(config, validation)) {
        throw std::invalid_argument(validationMessage(validation));
    }

    config_ = config;
    if (logicalRunIndex >= config.runs) {
        throw std::invalid_argument("WorkerRunSession logical run index is out of range");
    }
    settings_ = settings;
    logicalRunIndex_ = logicalRunIndex;
    requestSent_ = false;
    workerLaunchAttempted_ = false;
    processFinished_ = false;
    processExitObserved_ = false;
    normalExit_ = false;
    processFailurePending_ = false;
    workerOutcomeCompleted_ = false;
    workerFailureGracePending_ = false;
    finalDrainExpired_ = false;
    cleanupEscalated_ = false;
    terminalSignalled_ = false;
    terminalKind_ = TerminalKind::None;
    terminalError_.reset();
    terminalResult_.reset();
    memory_.reset();
    workerMeasurement_.reset();

    const auto name = endpoint();
    try {
        state_ = State::WaitingForWorkerReady;
        ipcChannel_.startListeningV2(name);
        armTechnicalTimeout();
        workerLaunchAttempted_ = true;
        workerProcess_.startV2(name, workerExecutablePath_);
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::WorkerStartupFailed,
                          core::FailureStage::WorkerStartup,
                          QString::fromUtf8(error.what())));
    }
}

void WorkerRunSession::cancel()
{
    if (!isActive()) return;
    finishCancellation();
}

bool WorkerRunSession::isActive() const noexcept
{
    return state_ != State::Idle && state_ != State::Terminal;
}

void WorkerRunSession::onWorkerReady(const ipc::WorkerReady& value)
{
    if (state_ != State::WaitingForWorkerReady) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("WorkerReady arrived in an invalid session state")));
        return;
    }
    if (value.protocolVersion != ipc::kProtocolVersionV2 || !config_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("worker protocol version is unsupported")));
        return;
    }
    try {
        state_ = State::WaitingForBaselineReady;
        requestSent_ = true;
        ipcChannel_.sendBenchmarkRunRequest({logicalRunIndex_, *config_});
        stopTechnicalTimeout();
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QString::fromUtf8(error.what())));
    }
}

void WorkerRunSession::onProgress(const ipc::Progress& value)
{
    if (!isActive() || !config_) return;
    if (!requestSent_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("Progress arrived before BenchmarkRunRequest")));
        return;
    }
    const bool expectedTotal = value.totalRuns == config_->runs;
    const bool expectedRun = value.runIndex && *value.runIndex == logicalRunIndex_;
    const bool legalPhase = state_ == State::Preparing &&
        value.phase == core::BenchmarkPhase::Warmup;
    if (!expectedTotal || !expectedRun || !legalPhase) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("Progress did not match the active v2 session")));
    }
}

void WorkerRunSession::onBaselineReady(std::uint32_t runIndex)
{
    if (state_ != State::WaitingForBaselineReady || runIndex != logicalRunIndex_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("BaselineReady did not match the expected logical run")));
        return;
    }
    const auto processId = workerProcess_.processId();
    if (processId <= 0 || static_cast<std::uint64_t>(processId) > UINT32_MAX) {
        fail(sessionError(core::ErrorCode::WorkerStartupFailed,
                  core::FailureStage::WorkerStartup,
                  QStringLiteral("worker process ID is invalid")));
        return;
    }
    stopTechnicalTimeout();
    try {
        state_ = State::Preparing;
        startSamplerV2(static_cast<std::uint32_t>(processId));
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::MemoryMeasurementFailed,
                          core::FailureStage::MemoryMeasurement,
                          QString::fromUtf8(error.what())));
        return;
    }
    try {
        ipcChannel_.sendStartAlgorithmPreparation(runIndex);
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QString::fromUtf8(error.what())));
    }
}

void WorkerRunSession::onAlgorithmReady(std::uint32_t runIndex)
{
    if (state_ != State::Preparing || runIndex != logicalRunIndex_ || !samplerIsActive()) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("AlgorithmReady did not match the preparation state")));
        return;
    }
    try {
        state_ = State::Measuring;
        markSamplerExecutionBoundaryV2();
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::MemoryMeasurementFailed,
                          core::FailureStage::MemoryMeasurement,
                          QString::fromUtf8(error.what())));
        return;
    }
    try {
        ipcChannel_.sendStartMeasurement(runIndex);
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QString::fromUtf8(error.what())));
    }
}

void WorkerRunSession::onMeasurementFinished(std::uint32_t runIndex)
{
    if (state_ != State::Measuring || runIndex != logicalRunIndex_ || !samplerIsActive()) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("MeasurementFinished did not match the active logical run")));
        return;
    }
    try {
        state_ = State::WaitingForWorkerMeasurement;
        memory_ = stopAndCollectSamplerV2();
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::MemoryMeasurementFailed,
                          core::FailureStage::MemoryMeasurement,
                          QString::fromUtf8(error.what())));
        return;
    }
    try {
        ipcChannel_.sendMemoryWindowClosed(runIndex);
        armTechnicalTimeout();
    } catch (const std::exception& error) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QString::fromUtf8(error.what())));
    }
}

void WorkerRunSession::onWorkerMeasurement(const core::WorkerRunMeasurement& value)
{
    if (state_ != State::WaitingForWorkerMeasurement || value.runIndex != logicalRunIndex_ || !memory_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("WorkerRunMeasurement did not match the closed memory window")));
        return;
    }
    workerMeasurement_ = value;
    state_ = State::WaitingForWorkerOutcome;
}

void WorkerRunSession::onWorkerOutcome(const ipc::WorkerOutcome& value)
{
    if (!isActive()) return;
    if (!requestSent_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("WorkerOutcome arrived before BenchmarkRunRequest")));
        return;
    }
    if (value.status == ipc::WorkerOutcomeStatus::Failed) {
        workerFailureGracePending_ = true;
        fail(value.error.value_or(sessionError(
            core::ErrorCode::CryptoOperationFailed,
            core::FailureStage::Measurement,
            QStringLiteral("worker reported an unspecified failure"))));
        return;
    }

    if (state_ != State::WaitingForWorkerOutcome || !workerMeasurement_ || !memory_ ||
        workerOutcomeCompleted_ || value.error) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("WorkerOutcome arrived before the run result was ready")));
        return;
    }

    workerOutcomeCompleted_ = true;
    state_ = State::WaitingForWorkerExit;
    stopTechnicalTimeout();
    if (processFinished_) {
        if (finalDrainExpired_) {
            onFinalDrainTimeout();
        } else {
            armFinalDrainTimeout();
        }
    } else {
        armWorkerExitTimeout();
    }
}

void WorkerRunSession::onTransportError(const QString& message)
{
    if (isActive() && state_ != State::CleaningUp) {
        const bool startupFailure = !workerLaunchAttempted_ &&
            state_ == State::WaitingForWorkerReady;
        fail(sessionError(startupFailure
                              ? core::ErrorCode::WorkerStartupFailed
                              : core::ErrorCode::WorkerCommunicationFailed,
                          startupFailure
                              ? core::FailureStage::WorkerStartup
                              : core::FailureStage::WorkerCommunication,
                          message));
    }
}

void WorkerRunSession::onDisconnected()
{
    if (!isActive() || state_ == State::CleaningUp) return;
    armFinalDrainTimeout();
}

void WorkerRunSession::onProcessError(QProcess::ProcessError error, const QString& message)
{
    if (!isActive() || state_ == State::CleaningUp) return;
    if (error == QProcess::FailedToStart) {
        processExitObserved_ = true;
    }
    const auto code = error == QProcess::FailedToStart
        ? core::ErrorCode::WorkerStartupFailed
        : core::ErrorCode::WorkerCommunicationFailed;
    const auto stage = error == QProcess::FailedToStart
        ? core::FailureStage::WorkerStartup
        : core::FailureStage::WorkerCommunication;
    fail(sessionError(code, stage, message));
}

void WorkerRunSession::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    processFinished_ = true;
    processExitObserved_ = true;
    normalExit_ = isNormalExit(exitCode, exitStatus);
    processFailurePending_ = !normalExit_;
    stopTechnicalTimeout();
    stopWorkerExitTimeout();
    if (state_ == State::CleaningUp) {
        workerFailureGraceTimer_.stop();
        cleanupTimer_.stop();
        finalizeTerminal();
        return;
    }
    if (isActive()) {
        if (finalDrainExpired_) {
            onFinalDrainTimeout();
        } else {
            armFinalDrainTimeout();
        }
    }
}

void WorkerRunSession::onWorkerFailureGraceTimeout()
{
    if (state_ != State::CleaningUp || !workerFailureGracePending_) return;
    workerFailureGracePending_ = false;
    if (processExitObserved_ && !workerProcess_.isRunning()) {
        finalizeTerminal();
        return;
    }
    if (!workerProcess_.isRunning()) {
        armCleanupTimeout();
        return;
    }
    workerProcess_.kill();
    armCleanupTimeout();
}

void WorkerRunSession::onTechnicalTimeout()
{
    if (!isActive() || state_ == State::CleaningUp) return;
    if (state_ == State::WaitingForWorkerExit && workerOutcomeCompleted_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("worker did not exit after completed outcome")));
        return;
    }
    fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                      core::FailureStage::WorkerCommunication,
                      QStringLiteral("worker session technical timeout")));
}

void WorkerRunSession::onWorkerExitTimeout()
{
    if (!isActive() || state_ == State::CleaningUp || processFinished_) return;
    fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                      core::FailureStage::WorkerCommunication,
                      QStringLiteral("worker did not exit after IPC final-frame drain")));
}

void WorkerRunSession::onFinalDrainTimeout()
{
    if (!isActive() || state_ == State::CleaningUp) return;
    finalDrainExpired_ = true;
    if (processFailurePending_) {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("worker exited abnormally")));
    } else if (workerOutcomeCompleted_ && workerMeasurement_ && memory_ && processFinished_) {
        beginCompletion();
    } else if (!processFinished_) {
        stopTechnicalTimeout();
        armWorkerExitTimeout();
    } else {
        fail(sessionError(core::ErrorCode::WorkerCommunicationFailed,
                          core::FailureStage::WorkerCommunication,
                          QStringLiteral("worker exited before the required final IPC frames")));
    }
}

void WorkerRunSession::onCleanupTimeout()
{
    if (state_ != State::CleaningUp) return;
    if (workerProcess_.isRunning()) {
        cleanupEscalated_ = true;
        cleanupTimer_.stop();
        return;
    }
    if (workerLaunchAttempted_ && !processExitObserved_) {
        cleanupTimer_.start(kCleanupTimeoutMilliseconds);
        return;
    }
    finalizeTerminal();
}

void WorkerRunSession::fail(core::ErrorInfo error)
{
    if (terminalKind_ != TerminalKind::None || state_ == State::Terminal) return;
    terminalKind_ = TerminalKind::Failed;
    terminalError_ = std::move(error);
    beginCleanup();
}

void WorkerRunSession::finishCancellation()
{
    if (terminalKind_ != TerminalKind::None || state_ == State::Terminal) return;
    terminalKind_ = TerminalKind::Cancelled;
    beginCleanup();
}

void WorkerRunSession::beginCompletion()
{
    if (terminalKind_ != TerminalKind::None || !processFinished_ || !normalExit_ ||
        !workerOutcomeCompleted_ || !workerMeasurement_ || !memory_) {
        return;
    }
    terminalKind_ = TerminalKind::Completed;
    terminalResult_ = WorkerRunSessionResult{logicalRunIndex_, *workerMeasurement_, *memory_};
    beginCleanup();
}

void WorkerRunSession::beginCleanup()
{
    if (state_ == State::CleaningUp || state_ == State::Terminal) return;
    state_ = State::CleaningUp;
    stopTechnicalTimeout();
    stopWorkerExitTimeout();
    finalDrainTimer_.stop();
    workerFailureGraceTimer_.stop();
    cleanupTimer_.stop();
    cleanup();
    if (workerProcess_.isRunning()) {
        if (workerFailureGracePending_) {
            workerFailureGraceTimer_.start(kWorkerFailureGraceTimeoutMilliseconds);
            return;
        }
        workerProcess_.kill();
        armCleanupTimeout();
        return;
    }
    if (workerLaunchAttempted_ && !processExitObserved_) {
        armCleanupTimeout();
        return;
    }
    finalizeTerminal();
}

void WorkerRunSession::finalizeTerminal()
{
    if (terminalSignalled_) return;
    if (workerProcess_.isRunning() ||
        (workerLaunchAttempted_ && !processExitObserved_)) return;
    terminalSignalled_ = true;
    state_ = State::Terminal;
    switch (terminalKind_) {
        case TerminalKind::Completed:
            emit completed(*terminalResult_);
            return;
        case TerminalKind::Failed:
            emit failed(*terminalError_);
            return;
        case TerminalKind::Cancelled:
            emit cancelled();
            return;
        case TerminalKind::None:
            return;
    }
}

core::ErrorInfo WorkerRunSession::sessionError(core::ErrorCode code,
                                               core::FailureStage stage,
                                               const QString& message) const
{
    return {code, stage, requestSent_ ? std::optional<std::uint32_t>(logicalRunIndex_) : std::nullopt,
            message.toStdString(), std::nullopt};
}

void WorkerRunSession::cleanup() noexcept
{
    stopTechnicalTimeout();
    stopWorkerExitTimeout();
    finalDrainTimer_.stop();
    workerFailureGraceTimer_.stop();
    cleanupTimer_.stop();
    stopAndDiscardSampler();
    ipcChannel_.close();
    if (state_ == State::Terminal || state_ == State::Idle) workerProcess_.kill();
}

void WorkerRunSession::armTechnicalTimeout()
{
    technicalTimer_.start(kTechnicalTimeoutMilliseconds);
}

void WorkerRunSession::stopTechnicalTimeout()
{
    technicalTimer_.stop();
}

void WorkerRunSession::armWorkerExitTimeout()
{
    if (!workerExitTimer_.isActive()) {
        workerExitTimer_.start(kWorkerExitTimeoutMilliseconds);
    }
}

void WorkerRunSession::stopWorkerExitTimeout()
{
    workerExitTimer_.stop();
}

void WorkerRunSession::armFinalDrainTimeout()
{
    if (!finalDrainExpired_) finalDrainTimer_.start(kFinalDrainTimeoutMilliseconds);
}

void WorkerRunSession::armCleanupTimeout()
{
    cleanupTimer_.start(kCleanupTimeoutMilliseconds);
}

void WorkerRunSession::startSamplerV2(std::uint32_t processId)
{
    if (testHooks_.startSampler) {
        testHooks_.startSampler(processId, settings_);
        return;
    }
    memorySampler_.startV2(processId, settings_);
}

void WorkerRunSession::markSamplerExecutionBoundaryV2()
{
    if (testHooks_.markExecutionBoundary) {
        testHooks_.markExecutionBoundary();
        return;
    }
    memorySampler_.markExecutionBoundaryV2();
}

core::MemoryV2RawObservations WorkerRunSession::stopAndCollectSamplerV2()
{
    if (testHooks_.stopAndCollectSampler) {
        return testHooks_.stopAndCollectSampler();
    }
    return memorySampler_.stopAndCollectV2();
}

void WorkerRunSession::stopAndDiscardSampler() noexcept
{
    if (testHooks_.stopAndDiscardSampler) {
        testHooks_.stopAndDiscardSampler();
        return;
    }
    memorySampler_.stopAndDiscard();
}

bool WorkerRunSession::samplerIsActive() const noexcept
{
    if (testHooks_.samplerIsActive) {
        return testHooks_.samplerIsActive();
    }
    return memorySampler_.isActive();
}

QString WorkerRunSession::endpoint() const
{
    if (testHooks_.endpointFactory) return testHooks_.endpointFactory();
    return QStringLiteral("CryptoBenchmark_M17_4_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

} // namespace cryptobench::application
