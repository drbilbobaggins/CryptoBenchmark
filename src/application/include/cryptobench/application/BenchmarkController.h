#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <QObject>
#include <QTimer>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/core/ResultAssembler.h>
#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>

namespace cryptobench::application {

class BenchmarkController final : public QObject {
    Q_OBJECT

public:
    explicit BenchmarkController(QObject* parent = nullptr);
    ~BenchmarkController() override;

    void start(const core::BenchmarkConfig& config);
    bool isBusy() const noexcept;

signals:
    void progressChanged(const cryptobench::core::ProgressInfo& progress);
    void benchmarkFinished(const cryptobench::core::BenchmarkResult& result);

private:
    enum class State {
        Idle,
        WaitingForWorkerReady,
        WaitingForMeasurementReady,
        Measuring,
        WaitingForWorkerRunMeasurement,
        WaitingForWorkerOutcome,
        WaitingForWorkerExit,
        Aborting
    };

    void onWorkerReady(const ipc::WorkerReady& value);
    void onProgress(const core::ProgressInfo& value);
    void onMeasurementReady(std::uint32_t runIndex);
    void onMeasurementFinished(std::uint32_t runIndex);
    void onWorkerRunMeasurement(const core::WorkerRunMeasurement& value);
    void onWorkerOutcome(const ipc::WorkerOutcome& value);
    void onTransportError(const QString& message);
    void onDisconnected();
    void onWorkerError(QProcess::ProcessError error, const QString& message);
    void onWorkerFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onTimeout();

    void armTimeout();
    void enterFailure(core::ErrorInfo error);
    void finishSuccessfully();

    State state_ = State::Idle;
    bool sessionActive_ = false;
    bool terminalResultEmitted_ = false;
    bool processExited_ = false;
    std::optional<core::BenchmarkConfig> config_;
    std::optional<core::StructuralCharacteristics> characteristics_;
    std::optional<core::EnvironmentInfo> environment_;
    std::uint32_t expectedRunIndex_ = 0;
    std::vector<core::RunResult> completedRuns_;
    std::optional<core::ParentRunMemoryMeasurement> pendingMemory_;

    ipc::ParentIpcChannel ipcChannel_;
    platform::windows::WindowsWorkerProcess workerProcess_;
    platform::windows::WorkerMemorySampler memorySampler_;
    QTimer technicalTimer_;
};

} // namespace cryptobench::application
