#include <cryptobench/ipc/WorkerIpcChannel.h>

#include <QLocalServer>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>
#include <QUuid>

#include <deque>
#include <future>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

using namespace cryptobench;

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M04_2_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

QString startServer(QLocalServer& server)
{
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");
    return name;
}

QLocalSocket* accept(QLocalServer& server)
{
    require(server.waitForNewConnection(10'000), "parent did not accept worker connection");
    return server.nextPendingConnection();
}

void disconnectCleanly(QLocalSocket& socket)
{
    if (socket.state() == QLocalSocket::UnconnectedState) return;
    socket.disconnectFromServer();
    if (socket.state() != QLocalSocket::UnconnectedState) {
        socket.waitForDisconnected(2000);
    }
}

// Test-only: waits for the worker thread's channel operation to complete and
// reports whether it failed, without attempting any protocol recovery.
void requireWorkerFails(std::future<void>& future, const char* message)
{
    bool failed = false;
    try {
        future.get();
    } catch (const std::exception&) {
        failed = true;
    }
    require(failed, message);
}

// Test-only: buffers frames the M04.1 parser already decoded so none are dropped
// when a single socket read coalesces more than one complete frame.
struct TestFrameReader {
    ipc::FrameParser parser;
    std::deque<ipc::Frame> pending;
};

ipc::Frame receiveFrame(QLocalSocket& socket, TestFrameReader& reader, const char* label)
{
    QElapsedTimer deadline;
    deadline.start();
    while (true) {
        if (!reader.pending.empty()) {
            auto frame = std::move(reader.pending.front());
            reader.pending.pop_front();
            return frame;
        }
        for (auto& frame : reader.parser.append(socket.readAll())) {
            reader.pending.push_back(std::move(frame));
        }
        if (!reader.pending.empty()) continue;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        if (deadline.elapsed() >= 10'000) {
            throw std::runtime_error(
                "parent read timed out: " + socket.errorString().toStdString() +
                ", state=" + std::to_string(static_cast<int>(socket.state())) +
                ", phase=" + label);
        }
    }
}

void sendFrame(QLocalSocket& socket, ipc::MessageType type, const QByteArray& payload)
{
    const auto frame = ipc::encodeFrame(type, payload);
    require(socket.write(frame) == frame.size(), "parent write failed");
    socket.flush();
}

// Splits one canonical frame across two socket writes to exercise the
// production FrameParser's fragmented-payload reassembly.
void sendFrameFragmented(QLocalSocket& socket, ipc::MessageType type, const QByteArray& payload)
{
    const auto frame = ipc::encodeFrame(type, payload);
    const auto splitPoint = frame.size() / 2;
    require(socket.write(frame.left(splitPoint)) == splitPoint, "fragmented parent write (part 1) failed");
    socket.flush();
    QThread::msleep(20);
    require(socket.write(frame.mid(splitPoint)) == frame.size() - splitPoint, "fragmented parent write (part 2) failed");
    socket.flush();
}

void testReadyRequestAndProgress()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.sendWorkerReady();
        const auto request = channel.receiveBenchmarkRequest();
        require(request.config.profile == core::AlgorithmProfileId::Sha256, "request profile mismatch");
        channel.reportProgress({core::BenchmarkPhase::Warmup, 0, 2});
        for (std::uint32_t runIndex = 0; runIndex < 2; ++runIndex) {
            channel.beforeMeasurement(runIndex);
            channel.afterMeasurement({runIndex, 100 + runIndex, 200 + runIndex});
        }
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = ipc::decodeWorkerReady(receiveFrame(*socket, parser, "WorkerReady").payload);
    require(ready.protocolVersion == 1, "WorkerReady version mismatch");
    const core::BenchmarkConfig config{core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash, 3, 2, core::HashConfig{64}};
    sendFrame(*socket, ipc::MessageType::BenchmarkRequest, ipc::encodeBenchmarkRequest({config}));
    const auto progress = ipc::decodeProgress(receiveFrame(*socket, parser, "Progress").payload);
    require(progress.phase == core::BenchmarkPhase::Warmup && progress.runIndex == 0, "Progress mismatch");
    for (std::uint32_t runIndex = 0; runIndex < 2; ++runIndex) {
        const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
        require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == runIndex, "MeasurementReady mismatch");
        sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(runIndex));
        const auto finished = receiveFrame(*socket, parser, "MeasurementFinished");
        require(finished.messageType == ipc::MessageType::MeasurementFinished, "MeasurementFinished missing");
        require(!socket->bytesAvailable(), "measurement was sent before MemoryWindowClosed");
        sendFrame(*socket, ipc::MessageType::MemoryWindowClosed, ipc::encodeRunIndexPayload(runIndex));
        const auto measurement = ipc::decodeWorkerRunMeasurement(receiveFrame(*socket, parser, "WorkerRunMeasurement").payload);
        require(measurement.runIndex == runIndex && measurement.elapsedNanoseconds == 100 + runIndex, "WorkerRunMeasurement mismatch");
    }
    future.get();
    disconnectCleanly(*socket);
    server.close();
}

void testBenchmarkRequestRejectsWrongMessageType()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.sendWorkerReady();
        static_cast<void>(channel.receiveBenchmarkRequest());
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    receiveFrame(*socket, parser, "WorkerReady");
    sendFrame(*socket, ipc::MessageType::Progress,
              ipc::encodeProgress({core::BenchmarkPhase::Preparing, std::nullopt, 1}));
    requireWorkerFails(future, "worker accepted wrong message type while awaiting BenchmarkRequest");
    disconnectCleanly(*socket);
    server.close();
}

void testStartMeasurementRejectsWrongMessageType()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrame(*socket, ipc::MessageType::MeasurementFinished, ipc::encodeRunIndexPayload(0));
    requireWorkerFails(future, "worker accepted wrong message type while awaiting StartMeasurement");
    disconnectCleanly(*socket);
    server.close();
}

void testStartMeasurementRejectsMismatchingRunIndex()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(7));
    requireWorkerFails(future, "worker accepted mismatching StartMeasurement runIndex");
    disconnectCleanly(*socket);
    server.close();
}

void testMemoryWindowClosedRejectsWrongMessageType()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
        channel.afterMeasurement({0, 100, 200});
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0));
    const auto finished = receiveFrame(*socket, parser, "MeasurementFinished");
    require(finished.messageType == ipc::MessageType::MeasurementFinished, "MeasurementFinished missing");
    sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0));
    requireWorkerFails(future, "worker accepted wrong message type while awaiting MemoryWindowClosed");
    disconnectCleanly(*socket);
    server.close();
}

void testMemoryWindowClosedRejectsMismatchingRunIndex()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
        channel.afterMeasurement({0, 100, 200});
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0));
    const auto finished = receiveFrame(*socket, parser, "MeasurementFinished");
    require(finished.messageType == ipc::MessageType::MeasurementFinished, "MeasurementFinished missing");
    sendFrame(*socket, ipc::MessageType::MemoryWindowClosed, ipc::encodeRunIndexPayload(9));
    requireWorkerFails(future, "worker accepted mismatching MemoryWindowClosed runIndex");
    disconnectCleanly(*socket);
    server.close();
}

void testSkippedInitialRunIndexRejected()
{
    ipc::WorkerIpcChannel channel;
    bool rejected = false;
    try {
        channel.beforeMeasurement(1);
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "skipped initial run index was accepted");
}

void testAfterMeasurementWithoutActiveRunRejected()
{
    ipc::WorkerIpcChannel channel;
    bool rejected = false;
    try {
        channel.afterMeasurement({0, 100, 200});
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "afterMeasurement without an active run was accepted");
}

void testDuplicateRunIndexAfterCompletionRejected()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
        channel.afterMeasurement({0, 100, 200});
        channel.beforeMeasurement(0);
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrame(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0));
    const auto finished = receiveFrame(*socket, parser, "MeasurementFinished");
    require(finished.messageType == ipc::MessageType::MeasurementFinished, "MeasurementFinished missing");
    sendFrame(*socket, ipc::MessageType::MemoryWindowClosed, ipc::encodeRunIndexPayload(0));
    receiveFrame(*socket, parser, "WorkerRunMeasurement");
    requireWorkerFails(future, "duplicate run index after completion was accepted");
    disconnectCleanly(*socket);
    server.close();
}

void testFragmentedControlDelivery()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.beforeMeasurement(0);
        channel.afterMeasurement({0, 111, 222});
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto ready = receiveFrame(*socket, parser, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady && ipc::decodeRunIndexPayload(ready.payload) == 0,
            "MeasurementReady mismatch");
    sendFrameFragmented(*socket, ipc::MessageType::StartMeasurement, ipc::encodeRunIndexPayload(0));
    const auto finished = receiveFrame(*socket, parser, "MeasurementFinished");
    require(finished.messageType == ipc::MessageType::MeasurementFinished, "MeasurementFinished missing");
    require(!socket->bytesAvailable(), "measurement was sent before MemoryWindowClosed");
    sendFrameFragmented(*socket, ipc::MessageType::MemoryWindowClosed, ipc::encodeRunIndexPayload(0));
    const auto measurement = ipc::decodeWorkerRunMeasurement(receiveFrame(*socket, parser, "WorkerRunMeasurement").payload);
    require(measurement.runIndex == 0 && measurement.elapsedNanoseconds == 111 && measurement.processCpuNanoseconds == 222,
            "WorkerRunMeasurement mismatch");
    future.get();
    disconnectCleanly(*socket);
    server.close();
}

void testReceiveTimesOutOnIncompleteFrame()
{
    QLocalServer server;
    const auto name = startServer(server);
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel(200);
        channel.connectToServer(name);
        static_cast<void>(channel.receiveBenchmarkRequest());
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    // Never completes the frame; the worker must time out instead of waiting indefinitely.
    const QByteArray incompleteHeader(3, '\0');
    require(socket->write(incompleteHeader) == incompleteHeader.size(), "parent write failed");
    socket->flush();
    requireWorkerFails(future, "worker did not enforce its total receive timeout budget");
    disconnectCleanly(*socket);
    server.close();
}

void testWorkerOutcomeSending()
{
    QLocalServer server;
    const auto name = startServer(server);
    const core::ErrorInfo error{core::ErrorCode::CryptoOperationFailed, core::FailureStage::Measurement, 2, "boom", "details"};
    auto future = std::async(std::launch::async, [&] {
        ipc::WorkerIpcChannel channel;
        channel.connectToServer(name);
        channel.sendWorkerOutcome({ipc::WorkerOutcomeStatus::Completed, std::nullopt});
        channel.sendWorkerOutcome({ipc::WorkerOutcomeStatus::Failed, error});
    });
    std::unique_ptr<QLocalSocket> socket(accept(server));
    TestFrameReader parser;
    const auto completedFrame = receiveFrame(*socket, parser, "WorkerOutcome(Completed)");
    require(completedFrame.messageType == ipc::MessageType::WorkerOutcome, "unexpected completed outcome message type");
    const auto completed = ipc::decodeWorkerOutcome(completedFrame.payload);
    require(completed.status == ipc::WorkerOutcomeStatus::Completed && !completed.error, "completed outcome mismatch");
    const auto failedFrame = receiveFrame(*socket, parser, "WorkerOutcome(Failed)");
    require(failedFrame.messageType == ipc::MessageType::WorkerOutcome, "unexpected failed outcome message type");
    const auto failed = ipc::decodeWorkerOutcome(failedFrame.payload);
    require(failed.status == ipc::WorkerOutcomeStatus::Failed
                && failed.error
                && failed.error->code == error.code
                && failed.error->stage == error.stage
                && failed.error->runIndex == error.runIndex
                && failed.error->technicalMessage == error.technicalMessage
                && failed.error->libraryDetails == error.libraryDetails,
            "failed outcome mismatch");
    future.get();
    disconnectCleanly(*socket);
    server.close();
}

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testReadyRequestAndProgress();
        testBenchmarkRequestRejectsWrongMessageType();
        testStartMeasurementRejectsWrongMessageType();
        testStartMeasurementRejectsMismatchingRunIndex();
        testMemoryWindowClosedRejectsWrongMessageType();
        testMemoryWindowClosedRejectsMismatchingRunIndex();
        testSkippedInitialRunIndexRejected();
        testAfterMeasurementWithoutActiveRunRejected();
        testDuplicateRunIndexAfterCompletionRejected();
        testFragmentedControlDelivery();
        testReceiveTimesOutOnIncompleteFrame();
        testWorkerOutcomeSending();
        std::cout << "PASS worker IPC total=12\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
