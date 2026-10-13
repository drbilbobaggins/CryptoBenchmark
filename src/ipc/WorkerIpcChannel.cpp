#include <cryptobench/ipc/WorkerIpcChannel.h>

#include <QElapsedTimer>

#include <stdexcept>

namespace cryptobench::ipc {

WorkerIpcChannel::WorkerIpcChannel(int timeoutMilliseconds, WorkerIpcMode mode)
    : timeoutMilliseconds_(timeoutMilliseconds), mode_(mode)
{
    if (timeoutMilliseconds_ <= 0) {
        throw std::invalid_argument("WorkerIpcChannel timeout must be positive");
    }
}

WorkerIpcChannel::~WorkerIpcChannel()
{
    if (socket_.state() != QLocalSocket::UnconnectedState) {
        socket_.disconnectFromServer();
    }
}

void WorkerIpcChannel::connectToServer(const QString& endpoint)
{
    if (socket_.state() != QLocalSocket::UnconnectedState) {
        throw std::logic_error("WorkerIpcChannel is already connected");
    }
    socket_.connectToServer(endpoint);
    if (!socket_.waitForConnected(timeoutMilliseconds_)) {
        throw std::runtime_error("WorkerIpcChannel connection failed: " + socket_.errorString().toStdString());
    }
}

void WorkerIpcChannel::sendWorkerReady()
{
    sendFrame(
        MessageType::WorkerReady,
        encodeWorkerReady({mode_ == WorkerIpcMode::SingleRunV2 ? kProtocolVersionV2 : kProtocolVersion}));
}

BenchmarkRequest WorkerIpcChannel::receiveBenchmarkRequest()
{
    const auto frame = receiveExpected(MessageType::BenchmarkRequest);
    try {
        return decodeBenchmarkRequest(frame.payload);
    } catch (const std::invalid_argument& error) {
        throw BenchmarkRequestDecodeError(error.what());
    }
}

BenchmarkRunRequest WorkerIpcChannel::receiveBenchmarkRunRequest()
{
    const auto frame = receiveExpected(MessageType::BenchmarkRunRequest);
    try {
        return decodeBenchmarkRunRequest(frame.payload);
    } catch (const std::invalid_argument& error) {
        throw BenchmarkRequestDecodeError(error.what());
    }
}

void WorkerIpcChannel::sendWorkerOutcome(const WorkerOutcome& outcome)
{
    sendFrame(MessageType::WorkerOutcome, encodeWorkerOutcome(outcome));
}

void WorkerIpcChannel::reportProgress(const core::ProgressInfo& info)
{
    sendFrame(MessageType::Progress, encodeProgress(info));
}

void WorkerIpcChannel::beginAlgorithmPreparation(std::uint32_t runIndex)
{
    if (mode_ != WorkerIpcMode::SingleRunV2 || preparationRunIndex_ || algorithmReadyRunIndex_ || activeRunIndex_) {
        throw std::logic_error("invalid WorkerIpcChannel algorithm preparation sequence");
    }
    sendFrame(MessageType::BaselineReady, encodeRunIndexPayload(runIndex));
    const auto receivedRunIndex = receiveRunIndex(MessageType::StartAlgorithmPreparation);
    if (receivedRunIndex != runIndex) {
        throw std::runtime_error("StartAlgorithmPreparation runIndex mismatch");
    }
    preparationRunIndex_ = runIndex;
}

void WorkerIpcChannel::finishAlgorithmPreparation(std::uint32_t runIndex)
{
    if (mode_ != WorkerIpcMode::SingleRunV2 || !preparationRunIndex_ || *preparationRunIndex_ != runIndex || algorithmReadyRunIndex_ || activeRunIndex_) {
        throw std::logic_error("invalid WorkerIpcChannel algorithm preparation completion sequence");
    }
    sendFrame(MessageType::AlgorithmReady, encodeRunIndexPayload(runIndex));
    algorithmReadyRunIndex_ = runIndex;
    preparationRunIndex_.reset();
}

void WorkerIpcChannel::beforeMeasurement(std::uint32_t runIndex)
{
    if (mode_ == WorkerIpcMode::SingleRunV2) {
        if (!algorithmReadyRunIndex_ || *algorithmReadyRunIndex_ != runIndex || activeRunIndex_) {
            throw std::logic_error("invalid WorkerIpcChannel v2 measurement sequence");
        }
        const auto receivedRunIndex = receiveRunIndex(MessageType::StartMeasurement);
        if (receivedRunIndex != runIndex) {
            throw std::runtime_error("StartMeasurement runIndex mismatch");
        }
        activeRunIndex_ = runIndex;
        return;
    }
    if (activeRunIndex_ || runIndex != nextRunIndex_) {
        throw std::logic_error("invalid WorkerIpcChannel beforeMeasurement sequence");
    }
    sendFrame(MessageType::MeasurementReady, encodeRunIndexPayload(runIndex));
    const auto receivedRunIndex = receiveRunIndex(MessageType::StartMeasurement);
    if (receivedRunIndex != runIndex) {
        throw std::runtime_error("StartMeasurement runIndex mismatch");
    }
    activeRunIndex_ = runIndex;
}

void WorkerIpcChannel::afterMeasurement(const core::WorkerRunMeasurement& measurement)
{
    if (!activeRunIndex_ || *activeRunIndex_ != measurement.runIndex) {
        throw std::logic_error("invalid WorkerIpcChannel afterMeasurement sequence");
    }
    sendFrame(MessageType::MeasurementFinished, encodeRunIndexPayload(measurement.runIndex));
    const auto receivedRunIndex = receiveRunIndex(MessageType::MemoryWindowClosed);
    if (receivedRunIndex != measurement.runIndex) {
        throw std::runtime_error("MemoryWindowClosed runIndex mismatch");
    }
    sendFrame(MessageType::WorkerRunMeasurement, encodeWorkerRunMeasurement(measurement));
    activeRunIndex_.reset();
    if (mode_ == WorkerIpcMode::SingleRunV2) {
        algorithmReadyRunIndex_.reset();
        return;
    }
    ++nextRunIndex_;
}

void WorkerIpcChannel::sendFrame(MessageType type, const QByteArray& payload)
{
    requireConnected();
    const auto frame = encodeFrame(type, payload);
    if (socket_.write(frame) != frame.size()) {
        throw std::runtime_error("WorkerIpcChannel write failed: " + socket_.errorString().toStdString());
    }

    QElapsedTimer deadline;
    deadline.start();
    while (socket_.bytesToWrite() != 0) {
        const auto remaining = timeoutMilliseconds_ - static_cast<int>(deadline.elapsed());
        if (remaining <= 0 || !socket_.waitForBytesWritten(remaining)) {
            throw std::runtime_error("WorkerIpcChannel write failed: " + socket_.errorString().toStdString());
        }
    }
}

Frame WorkerIpcChannel::receiveFrame()
{
    requireConnected();
    QElapsedTimer deadline;
    deadline.start();
    while (true) {
        const auto frames = parser_.append(socket_.readAll());
        if (frames.size() > 1) {
            throw std::runtime_error("WorkerIpcChannel received multiple pending frames");
        }
        if (!frames.empty()) return frames.front();
        const auto remaining = timeoutMilliseconds_ - static_cast<int>(deadline.elapsed());
        if (remaining <= 0 || !socket_.waitForReadyRead(remaining)) {
            throw std::runtime_error("WorkerIpcChannel read failed: " + socket_.errorString().toStdString());
        }
    }
}

Frame WorkerIpcChannel::receiveExpected(MessageType expected)
{
    const auto frame = receiveFrame();
    if (frame.messageType != expected) {
        throw std::runtime_error("WorkerIpcChannel received unexpected message type");
    }
    return frame;
}

std::uint32_t WorkerIpcChannel::receiveRunIndex(MessageType expectedType)
{
    return decodeRunIndexPayload(receiveExpected(expectedType).payload);
}

void WorkerIpcChannel::requireConnected() const
{
    if (socket_.state() != QLocalSocket::ConnectedState) {
        throw std::logic_error("WorkerIpcChannel is not connected");
    }
}

} // namespace cryptobench::ipc
