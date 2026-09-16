#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <QLocalSocket>

#include <cryptobench/core/ProgressSink.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>

namespace cryptobench::ipc {

class WorkerIpcChannel final
    : public core::ProgressSink
    , public core::RunMeasurementCoordinator {
public:
    explicit WorkerIpcChannel(int timeoutMilliseconds = 10'000);
    ~WorkerIpcChannel() override;

    void connectToServer(const QString& endpoint);
    void sendWorkerReady();
    BenchmarkRequest receiveBenchmarkRequest();
    void sendWorkerOutcome(const WorkerOutcome& outcome);

    void reportProgress(const core::ProgressInfo& info) override;
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
    std::uint32_t nextRunIndex_ = 0;
    std::optional<std::uint32_t> activeRunIndex_;
};

} // namespace cryptobench::ipc
