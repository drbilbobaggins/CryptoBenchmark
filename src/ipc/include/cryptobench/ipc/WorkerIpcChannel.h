#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <QLocalSocket>

#include <cryptobench/core/ProgressSink.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>

namespace cryptobench::ipc {

enum class WorkerIpcMode : std::uint8_t {
    LegacyV1,
    SingleRunV2
};

class BenchmarkRequestDecodeError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class WorkerIpcChannel final
    : public core::ProgressSink
    , public core::RunMeasurementCoordinator {
public:
    explicit WorkerIpcChannel(
        int timeoutMilliseconds = 10'000,
        WorkerIpcMode mode = WorkerIpcMode::LegacyV1);
    ~WorkerIpcChannel() override;

    void connectToServer(const QString& endpoint);
    void sendWorkerReady();
    BenchmarkRequest receiveBenchmarkRequest();
    BenchmarkRunRequest receiveBenchmarkRunRequest();
    void sendWorkerOutcome(const WorkerOutcome& outcome);

    void reportProgress(const core::ProgressInfo& info) override;
    void beginAlgorithmPreparation(std::uint32_t runIndex);
    void finishAlgorithmPreparation(std::uint32_t runIndex);
    void beforeMeasurement(std::uint32_t runIndex) override;
    void afterMeasurement(const core::WorkerRunMeasurement& measurement) override;

private:
    void sendFrame(MessageType type, const QByteArray& payload);
    Frame receiveFrame();
    Frame receiveExpected(MessageType expected);
    std::uint32_t receiveRunIndex(MessageType expectedType);
    void requireConnected() const;

    QLocalSocket socket_;
    FrameParser parser_;
    int timeoutMilliseconds_;
    WorkerIpcMode mode_;
    std::uint32_t nextRunIndex_ = 0;
    std::optional<std::uint32_t> activeRunIndex_;
    std::optional<std::uint32_t> preparationRunIndex_;
    std::optional<std::uint32_t> algorithmReadyRunIndex_;
};

} // namespace cryptobench::ipc
