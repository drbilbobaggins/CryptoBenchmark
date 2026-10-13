#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <QObject>
#include <cryptobench/application/BenchmarkSessionExecutor.h>
#include <cryptobench/application/WorkerRunSession.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/core/ResultAssembler.h>

namespace cryptobench::application {

class BenchmarkController final : public BenchmarkSessionExecutor {
    Q_OBJECT

public:
    explicit BenchmarkController(
        QObject* parent = nullptr,
        QString workerExecutablePath = {},
        WorkerRunSessionTestHooks sessionTestHooks = {},
        core::MeasurementSettings measurementSettings = core::defaultMeasurementSettings());
    ~BenchmarkController() override;

    void start(const core::BenchmarkConfig& config) override;
    void requestCancel() override;
    bool isBusy() const noexcept override;

private:
    enum class State {
        Idle,
        StartingRun,
        BetweenRuns,
        Cancelling,
        Terminalizing
    };

    enum class PendingTerminalKind {
        None,
        Completed,
        Failed,
        Cancelled
    };

    void startRun();
    void onSessionProgress(WorkerRunSession* session, std::uint64_t generation,
                           const core::ProgressInfo& progress);
    void onSessionCompleted(WorkerRunSession* session, std::uint64_t generation,
                            const WorkerRunSessionResult& result);
    void onSessionFailed(WorkerRunSession* session, std::uint64_t generation,
                         const core::ErrorInfo& error);
    void onSessionCancelled(WorkerRunSession* session, std::uint64_t generation);
    void queueTerminalContinuation(WorkerRunSession* session, std::uint64_t generation);
    void finishCompleted();
    void finishFailed();
    void finishCancelled();
    static core::ErrorInfo controllerError(core::ErrorCode code,
                                           core::FailureStage stage,
                                           std::string message,
                                           std::optional<std::uint32_t> runIndex = std::nullopt);

    State state_ = State::Idle;
    bool cancelRequested_ = false;
    std::uint64_t generation_ = 0;
    std::uint32_t expectedRunIndex_ = 0;
    std::optional<core::BenchmarkConfig> config_;
    std::optional<core::StructuralCharacteristics> characteristics_;
    std::optional<core::EnvironmentInfo> environment_;
    core::MeasurementSettings measurementSettings_ = core::defaultMeasurementSettings();
    QString workerExecutablePath_;
    WorkerRunSessionTestHooks sessionTestHooks_;
    std::unique_ptr<WorkerRunSession> currentSession_;
    std::vector<core::RunResult> completedRuns_;
    PendingTerminalKind pendingTerminalKind_ = PendingTerminalKind::None;
    std::optional<core::RunResult> pendingRun_;
    std::optional<core::ErrorInfo> pendingError_;
};

} // namespace cryptobench::application
