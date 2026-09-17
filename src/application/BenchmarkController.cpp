#include <cryptobench/application/BenchmarkController.h>

#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/ipc/WireProtocol.h>

#include <QUuid>

#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace cryptobench::application {
namespace {

constexpr int kTechnicalTimeoutMilliseconds = 10'000;

std::string validationMessage(const core::ValidationResult& validation)
{
    if (validation.errors.empty()) return "benchmark configuration is invalid";
    return validation.errors.front().technicalMessage;
}

core::ErrorInfo parentError(
    core::ErrorCode code,
    core::FailureStage stage,
    std::string message,
    std::optional<std::uint32_t> runIndex = std::nullopt)
{
    return {code, stage, runIndex, std::move(message), std::nullopt};
}

} // namespace

BenchmarkController::BenchmarkController(QObject* parent)
    : QObject(parent)
{
    technicalTimer_.setSingleShot(true);
    connect(&technicalTimer_, &QTimer::timeout, this, &BenchmarkController::onTimeout);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerReadyReceived,
            this, &BenchmarkController::onWorkerReady);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::progressReceived,
            this, &BenchmarkController::onProgress);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::measurementReadyReceived,
            this, &BenchmarkController::onMeasurementReady);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::measurementFinishedReceived,
            this, &BenchmarkController::onMeasurementFinished);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerRunMeasurementReceived,
            this, &BenchmarkController::onWorkerRunMeasurement);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::workerOutcomeReceived,
            this, &BenchmarkController::onWorkerOutcome);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::transportError,
            this, &BenchmarkController::onTransportError);
    connect(&ipcChannel_, &ipc::ParentIpcChannel::disconnected,
            this, &BenchmarkController::onDisconnected);
    connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::errorOccurred,
            this, &BenchmarkController::onWorkerError);
    connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::finished,
            this, &BenchmarkController::onWorkerFinished);
}

BenchmarkController::~BenchmarkController()
{
    technicalTimer_.stop();
    memorySampler_.stopAndDiscard();
    workerProcess_.kill();
    ipcChannel_.close();
}

bool BenchmarkController::isBusy() const noexcept
{
    return state_ != State::Idle;
}

void BenchmarkController::start(const core::BenchmarkConfig& config)
{
    if (isBusy()) throw std::logic_error("BenchmarkController is already running");

    core::ValidationResult validation;
    if (!core::ConfigValidator{}.validateAndCreate(config, validation)) {
        throw std::invalid_argument(validationMessage(validation));
    }

    const auto* profile = core::AlgorithmRegistry::find(config.profile);
    if (profile == nullptr) {
        throw std::invalid_argument("benchmark configuration references an unknown profile");
    }

    config_ = config;
    characteristics_ = profile->characteristics;
    environment_ = collectEnvironmentInfo();
    expectedRunIndex_ = 0;
    completedRuns_.clear();
    pendingMemory_.reset();
    terminalResultEmitted_ = false;
    processExited_ = false;
    sessionActive_ = true;

    const auto endpoint = QStringLiteral("CryptoBenchmark_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    try {
        ipcChannel_.startListening(endpoint);
        state_ = State::WaitingForWorkerReady;
        armTimeout();
        workerProcess_.start(endpoint);
    } catch (const std::exception& error) {
        enterFailure(parentError(
            core::ErrorCode::WorkerStartupFailed,
            core::FailureStage::WorkerStartup,
            error.what()));
    }
}

void BenchmarkController::onWorkerReady(const ipc::WorkerReady& value)
{
    if (!sessionActive_) return;
    if (state_ != State::WaitingForWorkerReady) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "WorkerReady arrived in an invalid session state"));
        return;
    }
    if (value.protocolVersion != ipc::kProtocolVersion) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Worker protocol version is unsupported"));
        return;
    }

    try {
        ipcChannel_.sendBenchmarkRequest({*config_});
        state_ = State::WaitingForMeasurementReady;
        technicalTimer_.stop();
    } catch (const std::exception& error) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 error.what()));
    }
}

void BenchmarkController::onProgress(const core::ProgressInfo& value)
{
    if (!sessionActive_) return;
    if (state_ == State::Measuring) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Progress arrived during a measured memory window",
                                 expectedRunIndex_));
        return;
    }
    if (config_ && value.totalRuns != config_->runs) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Progress total does not match the configured run count"));
        return;
    }
    if (value.runIndex && config_ && *value.runIndex >= config_->runs) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Progress run index is outside the configured run range"));
        return;
    }
    emit progressChanged(value);
}

void BenchmarkController::onMeasurementReady(std::uint32_t runIndex)
{
    if (!sessionActive_) return;
    if (state_ != State::WaitingForMeasurementReady || !config_ ||
        runIndex != expectedRunIndex_ || runIndex >= config_->runs) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "MeasurementReady did not match the expected run",
                                 runIndex));
        return;
    }

    const auto processId = workerProcess_.processId();
    if (processId <= 0 || static_cast<std::uint64_t>(processId) >
                              std::numeric_limits<std::uint32_t>::max()) {
        enterFailure(parentError(core::ErrorCode::MemoryMeasurementFailed,
                                 core::FailureStage::MemoryMeasurement,
                                 "Worker process ID is invalid", runIndex));
        return;
    }

    try {
        memorySampler_.start(static_cast<std::uint32_t>(processId), runIndex);
        state_ = State::Measuring;
        ipcChannel_.sendStartMeasurement(runIndex);
    } catch (const std::exception& error) {
        enterFailure(parentError(core::ErrorCode::MemoryMeasurementFailed,
                                 core::FailureStage::MemoryMeasurement,
                                 error.what(), runIndex));
    }
}

void BenchmarkController::onMeasurementFinished(std::uint32_t runIndex)
{
    if (!sessionActive_) return;
    if (state_ != State::Measuring || runIndex != expectedRunIndex_ ||
        !memorySampler_.isActive()) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "MeasurementFinished did not match the active run",
                                 runIndex));
        return;
    }

    try {
        pendingMemory_ = memorySampler_.stopAndCollect();
        if (pendingMemory_->runIndex != runIndex) {
            throw std::logic_error("parent memory measurement run index mismatch");
        }
        ipcChannel_.sendMemoryWindowClosed(runIndex);
        state_ = State::WaitingForWorkerRunMeasurement;
        armTimeout();
    } catch (const std::exception& error) {
        enterFailure(parentError(core::ErrorCode::MemoryMeasurementFailed,
                                 core::FailureStage::MemoryMeasurement,
                                 error.what(), runIndex));
    }
}

void BenchmarkController::onWorkerRunMeasurement(const core::WorkerRunMeasurement& value)
{
    if (!sessionActive_) return;
    if (state_ != State::WaitingForWorkerRunMeasurement || !config_ ||
        !pendingMemory_ || value.runIndex != expectedRunIndex_ ||
        pendingMemory_->runIndex != value.runIndex) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Worker run measurement did not match the pending run",
                                 value.runIndex));
        return;
    }

    try {
        completedRuns_.push_back(core::ResultAssembler::assembleRun(
            value, *pendingMemory_, config_->iterationsPerRun));
        pendingMemory_.reset();
        ++expectedRunIndex_;
        if (expectedRunIndex_ < config_->runs) {
            if (processExited_) {
                enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                         core::FailureStage::WorkerCommunication,
                                         "Worker exited before the final run was assembled",
                                         value.runIndex));
                return;
            }
            state_ = State::WaitingForMeasurementReady;
            technicalTimer_.stop();
        } else {
            state_ = State::WaitingForWorkerOutcome;
            if (processExited_) {
                armTimeout();
            } else {
                technicalTimer_.stop();
            }
        }
    } catch (const std::exception& error) {
        enterFailure(parentError(core::ErrorCode::InternalError,
                                 core::FailureStage::ResultAssembly,
                                 error.what(), value.runIndex));
    }
}

void BenchmarkController::onWorkerOutcome(const ipc::WorkerOutcome& value)
{
    if (!sessionActive_) return;
    if (value.status == ipc::WorkerOutcomeStatus::Failed) {
        if (!value.error) {
            enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                     core::FailureStage::WorkerCommunication,
                                     "Worker failure outcome did not contain ErrorInfo"));
        } else {
            enterFailure(*value.error);
        }
        return;
    }
    if (state_ != State::WaitingForWorkerOutcome || !config_ ||
        expectedRunIndex_ != config_->runs || completedRuns_.size() != config_->runs ||
        pendingMemory_ || memorySampler_.isActive() || value.error) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Completed outcome arrived before the session was complete"));
        return;
    }
    if (processExited_) {
        finishSuccessfully();
        return;
    }
    state_ = State::WaitingForWorkerExit;
    armTimeout();
}

void BenchmarkController::onTransportError(const QString& message)
{
    if (sessionActive_ && state_ != State::Aborting) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 message.toStdString()));
    }
}

void BenchmarkController::onDisconnected()
{
    if (!sessionActive_ || state_ == State::WaitingForWorkerExit || state_ == State::Aborting) return;
    enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                             core::FailureStage::WorkerCommunication,
                             "Worker IPC channel disconnected unexpectedly"));
}

void BenchmarkController::onWorkerError(QProcess::ProcessError, const QString& message)
{
    if (sessionActive_ && state_ != State::Aborting) {
        const auto startupFailure = state_ == State::WaitingForWorkerReady;
        enterFailure(parentError(startupFailure
                                     ? core::ErrorCode::WorkerStartupFailed
                                     : core::ErrorCode::WorkerCommunicationFailed,
                                 startupFailure
                                     ? core::FailureStage::WorkerStartup
                                     : core::FailureStage::WorkerCommunication,
                                 message.toStdString()));
    }
}

void BenchmarkController::onWorkerFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (!sessionActive_ || state_ == State::Aborting) return;
    if (exitStatus != QProcess::NormalExit || exitCode != 0) {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Worker did not exit normally"));
        return;
    }
    processExited_ = true;
    if (state_ == State::WaitingForWorkerExit) {
        finishSuccessfully();
    } else if (state_ == State::WaitingForWorkerRunMeasurement ||
               state_ == State::WaitingForWorkerOutcome) {
        armTimeout();
    } else {
        enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                                 core::FailureStage::WorkerCommunication,
                                 "Worker exited before the terminal IPC drain"));
    }
}

void BenchmarkController::onTimeout()
{
    if (!sessionActive_) return;
    enterFailure(parentError(core::ErrorCode::WorkerCommunicationFailed,
                             core::FailureStage::WorkerCommunication,
                             "Worker session timed out", expectedRunIndex_));
}

void BenchmarkController::armTimeout()
{
    if (state_ == State::WaitingForWorkerReady ||
        state_ == State::WaitingForWorkerRunMeasurement ||
        state_ == State::WaitingForWorkerOutcome ||
        state_ == State::WaitingForWorkerExit) {
        technicalTimer_.start(kTechnicalTimeoutMilliseconds);
    } else {
        technicalTimer_.stop();
    }
}

void BenchmarkController::enterFailure(core::ErrorInfo error)
{
    if (!sessionActive_ || state_ == State::Aborting || terminalResultEmitted_) return;
    state_ = State::Aborting;
    technicalTimer_.stop();
    memorySampler_.stopAndDiscard();
    pendingMemory_.reset();
    workerProcess_.kill();
    ipcChannel_.close();

    terminalResultEmitted_ = true;
    const auto result = core::ResultAssembler::failed(
        *config_, completedRuns_, *characteristics_, *environment_, std::move(error));
    sessionActive_ = false;
    state_ = State::Idle;
    emit benchmarkFinished(result);
}

void BenchmarkController::finishSuccessfully()
{
    if (!sessionActive_ || terminalResultEmitted_) return;
    core::BenchmarkResult result;
    try {
        result = core::ResultAssembler::completed(
            *config_, completedRuns_, *characteristics_, *environment_);
    } catch (const std::exception& error) {
        enterFailure(parentError(core::ErrorCode::InternalError,
                                 core::FailureStage::ResultAssembly,
                                 error.what()));
        return;
    }
    terminalResultEmitted_ = true;
    technicalTimer_.stop();
    ipcChannel_.close();
    sessionActive_ = false;
    state_ = State::Idle;
    emit benchmarkFinished(result);
}

} // namespace cryptobench::application
