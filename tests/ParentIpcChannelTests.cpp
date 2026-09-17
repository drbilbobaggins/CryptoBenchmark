#include <cryptobench/ipc/ParentIpcChannel.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QUuid>

#include <functional>
#include <deque>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M05_1_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

void waitUntil(const std::function<bool()>& condition, const char* message)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < 5'000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(condition(), message);
}

std::unique_ptr<QLocalSocket> connectWorker(ipc::ParentIpcChannel& channel, const QString& name)
{
    auto socket = std::make_unique<QLocalSocket>();
    socket->connectToServer(name);
    require(socket->waitForConnected(5'000), "test worker failed to connect");
    waitUntil([&] { return channel.isConnected(); }, "parent did not report connection");
    return socket;
}

void sendBytes(QLocalSocket& socket, const QByteArray& bytes)
{
    require(socket.write(bytes) == bytes.size(), "test worker write failed");
    socket.flush();
}

struct FrameReader {
    ipc::FrameParser parser;
    std::deque<ipc::Frame> pending;
};

ipc::Frame receiveFrame(QLocalSocket& socket, FrameReader& reader)
{
    while (reader.pending.empty()) {
        for (auto& candidate : reader.parser.append(socket.readAll())) reader.pending.push_back(std::move(candidate));
        if (!reader.pending.empty()) break;
        require(socket.waitForReadyRead(5'000), "test worker did not receive a complete frame");
    }
    auto frame = std::move(reader.pending.front());
    reader.pending.pop_front();
    return frame;
}

void testConnectionAndParentMessages()
{
    ipc::ParentIpcChannel channel;
    bool connected = false;
    channel.connect(&channel, &ipc::ParentIpcChannel::connected, [&] { connected = true; });
    const auto name = endpoint();
    channel.startListening(name);
    require(channel.isListening(), "parent did not start listening");

    auto socket = connectWorker(channel, name);
    require(connected && !channel.isListening(), "parent listener remained active after first worker");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        3,
        core::HashConfig{8}
    };
    channel.sendBenchmarkRequest({config});
    channel.sendStartMeasurement(7);
    channel.sendMemoryWindowClosed(7);

    FrameReader reader;
    const auto first = receiveFrame(*socket, reader);
    const auto second = receiveFrame(*socket, reader);
    const auto third = receiveFrame(*socket, reader);
    require(first.messageType == ipc::MessageType::BenchmarkRequest, "BenchmarkRequest type mismatch");
    require(ipc::decodeBenchmarkRequest(first.payload).config.runs == 3, "BenchmarkRequest payload mismatch");
    require(second.messageType == ipc::MessageType::StartMeasurement && ipc::decodeRunIndexPayload(second.payload) == 7,
            "StartMeasurement payload mismatch");
    require(third.messageType == ipc::MessageType::MemoryWindowClosed && ipc::decodeRunIndexPayload(third.payload) == 7,
            "MemoryWindowClosed payload mismatch");

    auto extra = std::make_unique<QLocalSocket>();
    extra->connectToServer(name);
    require(!extra->waitForConnected(200), "parent accepted a second worker connection");
    channel.close();
}

void testWorkerMessagesAndStreamHandling()
{
    ipc::ParentIpcChannel channel;
    const auto name = endpoint();
    channel.startListening(name);
    auto socket = connectWorker(channel, name);

    int readyCount = 0;
    std::vector<std::uint32_t> measurementReady;
    std::vector<std::uint32_t> measurementFinished;
    std::vector<ipc::Progress> progress;
    std::vector<ipc::WorkerRunMeasurement> measurements;
    std::vector<ipc::WorkerOutcome> outcomes;
    channel.connect(&channel, &ipc::ParentIpcChannel::workerReadyReceived, [&](const ipc::WorkerReady& value) {
        require(value.protocolVersion == 1, "WorkerReady payload mismatch");
        ++readyCount;
    });
    channel.connect(&channel, &ipc::ParentIpcChannel::progressReceived, [&](const ipc::Progress& value) { progress.push_back(value); });
    channel.connect(&channel, &ipc::ParentIpcChannel::measurementReadyReceived, [&](std::uint32_t value) { measurementReady.push_back(value); });
    channel.connect(&channel, &ipc::ParentIpcChannel::measurementFinishedReceived, [&](std::uint32_t value) { measurementFinished.push_back(value); });
    channel.connect(&channel, &ipc::ParentIpcChannel::workerRunMeasurementReceived, [&](const ipc::WorkerRunMeasurement& value) { measurements.push_back(value); });
    channel.connect(&channel, &ipc::ParentIpcChannel::workerOutcomeReceived, [&](const ipc::WorkerOutcome& value) { outcomes.push_back(value); });

    const auto readyFrame = ipc::encodeFrame(ipc::MessageType::WorkerReady, ipc::encodeWorkerReady({1}));
    const auto progressFrame = ipc::encodeFrame(ipc::MessageType::Progress, ipc::encodeProgress({core::BenchmarkPhase::Preparing, std::nullopt, 2}));
    sendBytes(*socket, readyFrame.left(2));
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    require(readyCount == 0, "partial frame was delivered too early");
    sendBytes(*socket, readyFrame.mid(2));
    waitUntil([&] { return readyCount == 1; }, "WorkerReady was not delivered");

    auto combined = progressFrame;
    combined.append(ipc::encodeFrame(ipc::MessageType::MeasurementReady, ipc::encodeRunIndexPayload(2)));
    combined.append(ipc::encodeFrame(ipc::MessageType::MeasurementFinished, ipc::encodeRunIndexPayload(2)));
    combined.append(ipc::encodeFrame(ipc::MessageType::WorkerRunMeasurement, ipc::encodeWorkerRunMeasurement({2, 11, 22})));
    combined.append(ipc::encodeFrame(ipc::MessageType::WorkerOutcome, ipc::encodeWorkerOutcome({ipc::WorkerOutcomeStatus::Completed, std::nullopt})));
    sendBytes(*socket, combined);
    waitUntil([&] { return progress.size() == 1 && measurementReady.size() == 1 && measurementFinished.size() == 1 && measurements.size() == 1 && outcomes.size() == 1; },
              "coalesced worker frames were not all delivered");
    require(progress.front().phase == core::BenchmarkPhase::Preparing, "Progress payload mismatch");
    require(measurementReady.front() == 2 && measurementFinished.front() == 2, "run-index event mismatch");
    require(measurements.front().elapsedNanoseconds == 11, "WorkerRunMeasurement payload mismatch");
    require(outcomes.front().status == ipc::WorkerOutcomeStatus::Completed, "WorkerOutcome payload mismatch");
    channel.close();
}

void testWrongDirectionIsObservableError()
{
    ipc::ParentIpcChannel channel;
    const auto name = endpoint();
    channel.startListening(name);
    auto socket = connectWorker(channel, name);
    QString error;
    channel.connect(&channel, &ipc::ParentIpcChannel::transportError, [&](const QString& value) { error = value; });

    sendBytes(*socket, ipc::encodeFrame(ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0)));
    waitUntil([&] { return !error.isEmpty(); }, "wrong-direction frame did not report an error");
    require(error.contains(QStringLiteral("parent-originating")), "wrong-direction error was not descriptive");
    channel.close();
}

void testRemoteDisconnectCanCloseReentrantly()
{
    ipc::ParentIpcChannel channel;
    const auto name = endpoint();
    channel.startListening(name);
    auto socket = connectWorker(channel, name);
    bool disconnected = false;
    channel.connect(&channel, &ipc::ParentIpcChannel::disconnected, [&] {
        disconnected = true;
        channel.close();
    });

    socket->disconnectFromServer();
    waitUntil([&] { return disconnected; }, "parent did not report remote disconnect");
    require(!channel.isListening() && !channel.isConnected(), "re-entrant close left stale channel state");
    channel.close();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testConnectionAndParentMessages();
        testWorkerMessagesAndStreamHandling();
        testWrongDirectionIsObservableError();
        testRemoteDisconnectCanCloseReentrantly();
        std::cout << "Parent IPC channel tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Parent IPC channel tests failed: " << error.what() << '\n';
        return 1;
    }
}
