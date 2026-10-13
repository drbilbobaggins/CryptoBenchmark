#pragma once

#include <cstdint>
#include <functional>
#include <optional>

#include <QObject>
#include <QTimer>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/core/WorkerRunMeasurement.h>
#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>

namespace cryptobench::application {

class WorkerRunSession;

struct WorkerRunSessionResult {
    std::uint32_t logicalRunIndex;
    core::WorkerRunMeasurement workerMeasurement;
    core::MemoryV2RawObservations memory;
};

struct WorkerRunSessionTestHooks {
    std::function<void(qint64)> workerStarted;
    std::function<void(WorkerRunSession*)> sessionCreated;
    std::function<void()> terminalContinuationQueued;
    std::function<QString()> endpointFactory;
    std::function<void(std::uint32_t, const core::MeasurementSettings&)> startSampler;
    std::function<void()> markExecutionBoundary;
    std::function<core::MemoryV2RawObservations()> stopAndCollectSampler;
    std::function<void()> stopAndDiscardSampler;
    std::function<bool()> samplerIsActive;
    std::function<QProcess::ProcessState()> processState;
    std::function<void()> cleanupStarted;
    std::function<void()> killProcess;
    std::function<void()> cleanupTimeoutArmed;
    std::function<int()> cleanupTimeoutMilliseconds;
};

// The caller retains this single-use object until a terminal signal confirms
// sampler cleanup and observed worker termination. Destroying an active
// session is outside the supported lifecycle contract.
class WorkerRunSession final : public QObject {
    Q_OBJECT

public:
    explicit WorkerRunSession(QObject* parent = nullptr,
                              QString workerExecutablePath = {},
                              WorkerRunSessionTestHooks testHooks = {});
    ~WorkerRunSession() override;

    WorkerRunSession(const WorkerRunSession&) = delete;
    WorkerRunSession& operator=(const WorkerRunSession&) = delete;

    void start(const core::BenchmarkConfig& config,
               std::uint32_t logicalRunIndex,
               const core::MeasurementSettings& settings = core::defaultMeasurementSettings());
    void cancel();
    bool isActive() const noexcept;

signals:
    void progressChanged(const cryptobench::core::ProgressInfo& progress);
    void completed(const cryptobench::application::WorkerRunSessionResult& result);
    void failed(const cryptobench::core::ErrorInfo& error);
    void cancelled();

private:
    enum class State {
        Idle,
        WaitingForWorkerReady,
        WaitingForBaselineReady,
        Preparing,
        Measuring,
        WaitingForMeasurementFinished,
        WaitingForWorkerMeasurement,
        WaitingForWorkerOutcome,
        WaitingForWorkerExit,
        CleaningUp,
        Terminal
    };

    enum class TerminalKind {
        None,
        Completed,
        Failed,
        Cancelled
    };

    void onWorkerReady(const ipc::WorkerReady& value);
    void onProgress(const ipc::Progress& value);
    void onBaselineReady(std::uint32_t runIndex);
    void onAlgorithmReady(std::uint32_t runIndex);
    void onMeasurementFinished(std::uint32_t runIndex);
    void onWorkerMeasurement(const core::WorkerRunMeasurement& value);
    void onWorkerOutcome(const ipc::WorkerOutcome& value);
    void onTransportError(const QString& message);
    void onDisconnected();
    void onProcessError(QProcess::ProcessError error, const QString& message);
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onTechnicalTimeout();
    void onWorkerExitTimeout();
    void onFinalDrainTimeout();
    void onWorkerFailureGraceTimeout();
private slots:
    void onCleanupTimeout();

private:
    void fail(core::ErrorInfo error);
    void finishCancellation();
    void beginCompletion();
    void beginCleanup();
    void finalizeTerminal();
    core::ErrorInfo sessionError(core::ErrorCode code,
                                 core::FailureStage stage,
                                 const QString& message) const;
    void cleanup() noexcept;
    void armTechnicalTimeout();
    void stopTechnicalTimeout();
    void armWorkerExitTimeout();
    void stopWorkerExitTimeout();
    void armFinalDrainTimeout();
    void armCleanupTimeout();
    void startSamplerV2(std::uint32_t processId);
    void markSamplerExecutionBoundaryV2();
    core::MemoryV2RawObservations stopAndCollectSamplerV2();
    void stopAndDiscardSampler() noexcept;
    bool samplerIsActive() const noexcept;
    bool processIsRunning() const noexcept;
    void refreshProcessExitObservation() noexcept;
    void killWorkerProcess();
    void queueCleanupReevaluation();
    QString endpoint() const;

    State state_ = State::Idle;
    bool terminalSignalled_ = false;
    bool requestSent_ = false;
    bool workerLaunchAttempted_ = false;
    bool processFinished_ = false;
    bool processExitObserved_ = false;
    bool normalExit_ = false;
    bool processFailurePending_ = false;
    bool workerOutcomeCompleted_ = false;
    bool workerFailureGracePending_ = false;
    bool finalDrainExpired_ = false;
    std::uint32_t logicalRunIndex_ = 0;
    std::optional<core::BenchmarkConfig> config_;
    core::MeasurementSettings settings_ = core::defaultMeasurementSettings();
    std::optional<core::MemoryV2RawObservations> memory_;
    std::optional<core::WorkerRunMeasurement> workerMeasurement_;
    std::optional<core::ErrorInfo> terminalError_;
    std::optional<WorkerRunSessionResult> terminalResult_;
    TerminalKind terminalKind_ = TerminalKind::None;
    QString workerExecutablePath_;
    WorkerRunSessionTestHooks testHooks_;

    ipc::ParentIpcChannel ipcChannel_;
    platform::windows::WindowsWorkerProcess workerProcess_;
    platform::windows::WorkerMemorySampler memorySampler_;
    QTimer technicalTimer_;
    QTimer workerExitTimer_;
    QTimer finalDrainTimer_;
    QTimer workerFailureGraceTimer_;
    QTimer cleanupTimer_;
};

} // namespace cryptobench::application

Q_DECLARE_METATYPE(cryptobench::application::WorkerRunSessionResult)
