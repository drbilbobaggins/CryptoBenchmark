#include "../src/worker/WorkerSession.h"

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>
#include <cryptobench/ipc/WireDtos.h>
#include <cryptobench/ipc/WireProtocol.h>

#include <QCoreApplication>
#include <QLocalServer>
#include <QLocalSocket>
#include <QUuid>

#include <deque>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using namespace cryptobench;

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M04_5_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

void sendFrame(QLocalSocket& socket, ipc::MessageType type, const QByteArray& payload)
{
    const auto frame = ipc::encodeFrame(type, payload);
    require(socket.write(frame) == frame.size(), "parent write failed");
    require(socket.waitForBytesWritten(10'000), "parent write timed out");
}

struct FrameReader {
    ipc::FrameParser parser;
    std::deque<ipc::Frame> pending;
};

ipc::Frame receiveFrame(QLocalSocket& socket, FrameReader& reader)
{
    while (reader.pending.empty()) {
        if (socket.bytesAvailable() == 0) {
            require(socket.waitForReadyRead(10'000), "parent read timed out");
        }
        for (auto& frame : reader.parser.append(socket.readAll())) {
            reader.pending.push_back(std::move(frame));
        }
    }

    auto frame = std::move(reader.pending.front());
    reader.pending.pop_front();
    return frame;
}

std::unique_ptr<QLocalSocket> acceptConnection(QLocalServer& server)
{
    require(server.waitForNewConnection(10'000), "worker connection timed out");
    return std::unique_ptr<QLocalSocket>(server.nextPendingConnection());
}

void sendRequest(QLocalSocket& socket, const core::BenchmarkConfig& config)
{
    sendFrame(socket, ipc::MessageType::BenchmarkRequest,
              ipc::encodeBenchmarkRequest({config}));
}

void receiveReady(QLocalSocket& socket, FrameReader& reader)
{
    const auto frame = receiveFrame(socket, reader);
    require(frame.messageType == ipc::MessageType::WorkerReady, "WorkerReady missing");
    require(ipc::decodeWorkerReady(frame.payload).protocolVersion == 1,
            "WorkerReady protocol version mismatch");
}

void receivePhase(QLocalSocket& socket, FrameReader& reader, core::BenchmarkPhase phase,
                  std::optional<std::uint32_t> runIndex)
{
    const auto frame = receiveFrame(socket, reader);
    require(frame.messageType == ipc::MessageType::Progress, "Progress missing");
    const auto progress = ipc::decodeProgress(frame.payload);
    require(progress.phase == phase && progress.runIndex == runIndex,
            "Progress contents mismatch");
}

void receiveSuccessfulRun(QLocalSocket& socket, FrameReader& reader, std::uint32_t runIndex)
{
    receivePhase(socket, reader, core::BenchmarkPhase::Warmup, runIndex);

    const auto ready = receiveFrame(socket, reader);
    require(ready.messageType == ipc::MessageType::MeasurementReady,
            "MeasurementReady missing");
    require(ipc::decodeRunIndexPayload(ready.payload) == runIndex,
            "MeasurementReady run index mismatch");

    sendFrame(socket, ipc::MessageType::StartMeasurement,
              ipc::encodeRunIndexPayload(runIndex));

    const auto finished = receiveFrame(socket, reader);
    require(finished.messageType == ipc::MessageType::MeasurementFinished,
            "MeasurementFinished missing");
    require(ipc::decodeRunIndexPayload(finished.payload) == runIndex,
            "MeasurementFinished run index mismatch");

    sendFrame(socket, ipc::MessageType::MemoryWindowClosed,
              ipc::encodeRunIndexPayload(runIndex));

    const auto measurementFrame = receiveFrame(socket, reader);
    require(measurementFrame.messageType == ipc::MessageType::WorkerRunMeasurement,
            "WorkerRunMeasurement missing");
    const auto measurement = ipc::decodeWorkerRunMeasurement(measurementFrame.payload);
    require(measurement.runIndex == runIndex,
            "WorkerRunMeasurement run index mismatch");
    require(measurement.processCpuNanoseconds % 100U == 0,
            "process CPU nanoseconds do not match FILETIME resolution");
    require(measurement.elapsedNanoseconds > 0,
            "elapsed nanoseconds must be positive");
}

void testSuccessfulSha256Session()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        2,
        core::HashConfig{8}
    };

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSession(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    receiveReady(*socket, reader);
    sendRequest(*socket, config);

    receivePhase(*socket, reader, core::BenchmarkPhase::Preparing, std::nullopt);
    receiveSuccessfulRun(*socket, reader, 0);
    receiveSuccessfulRun(*socket, reader, 1);
    receivePhase(*socket, reader, core::BenchmarkPhase::Finalizing, std::nullopt);

    const auto outcomeFrame = receiveFrame(*socket, reader);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "completed WorkerOutcome missing");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Completed && !outcome.error,
            "successful session did not complete cleanly");
    require(future.get() == 0, "successful worker session returned failure");
    server.close();
}

void testInvalidConfigIsReportedByWorker()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{core::kMaxWorkloadBytes + 1}
    };

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSession(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    receiveReady(*socket, reader);
    sendRequest(*socket, config);

    const auto outcomeFrame = receiveFrame(*socket, reader);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "invalid config did not produce a WorkerOutcome frame");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
            "invalid config did not produce failed outcome");
    require(outcome.error->code == core::ErrorCode::InvalidConfiguration,
            "invalid config error code mismatch");
    require(outcome.error->stage == core::FailureStage::ConfigValidation,
            "invalid config failure stage mismatch");
    require(future.get() != 0, "invalid config returned success");
    server.close();
}

void testMalformedRequestIsReportedAsDeserializationFailure()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSession(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    receiveReady(*socket, reader);
    sendFrame(*socket, ipc::MessageType::BenchmarkRequest, QByteArrayLiteral("{"));

    const auto outcomeFrame = receiveFrame(*socket, reader);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "malformed request did not produce a WorkerOutcome frame");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
            "malformed request did not produce failed outcome");
    require(outcome.error->code == core::ErrorCode::WorkerCommunicationFailed,
            "malformed request error code mismatch");
    require(outcome.error->stage == core::FailureStage::ConfigDeserialization,
            "malformed request failure stage mismatch");
    require(!outcome.error->runIndex, "malformed request unexpectedly contained a run index");
    require(future.get() != 0, "malformed request returned success");
    require(reader.pending.empty() && socket->bytesAvailable() == 0,
            "malformed request started a measurement handshake");
    server.close();
}

void testFrameErrorRemainsWorkerCommunicationFailure()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSession(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    receiveReady(*socket, reader);

    const auto invalidTypeFrame = QByteArray::fromHex("000a00000000");
    require(socket->write(invalidTypeFrame) == invalidTypeFrame.size(),
            "invalid frame write failed");
    require(socket->waitForBytesWritten(10'000), "invalid frame write timed out");

    const auto outcomeFrame = receiveFrame(*socket, reader);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "frame error did not produce a WorkerOutcome frame");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
            "frame error did not produce failed outcome");
    require(outcome.error->code == core::ErrorCode::WorkerCommunicationFailed,
            "frame error code mismatch");
    require(outcome.error->stage == core::FailureStage::WorkerCommunication,
            "frame error failure stage mismatch");
    require(!outcome.error->runIndex, "frame error unexpectedly contained a run index");
    require(future.get() != 0, "frame error returned success");
    server.close();
}

void testUnsupportedStrategyIsReportedByWorker()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::SlhDsaSha2128S,
        core::BenchmarkOperation::Sign,
        1,
        1,
        core::SignatureConfig{core::MessageInput{1}}
    };

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSession(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    receiveReady(*socket, reader);
    sendRequest(*socket, config);

    const auto outcomeFrame = receiveFrame(*socket, reader);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "unsupported strategy did not produce a WorkerOutcome frame");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
            "unsupported strategy did not produce failed outcome");
    require(outcome.error->code == core::ErrorCode::UnknownExecutionStrategy,
            "unsupported strategy error code mismatch");
    require(outcome.error->stage == core::FailureStage::TaskCreation,
            "unsupported strategy failure stage mismatch");
    require(future.get() != 0, "unsupported strategy returned success");
    server.close();
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    try {
        testSuccessfulSha256Session();
        testInvalidConfigIsReportedByWorker();
        testMalformedRequestIsReportedAsDeserializationFailure();
        testFrameErrorRemainsWorkerCommunicationFailure();
        testUnsupportedStrategyIsReportedByWorker();
        std::cout << "WorkerSessionTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WorkerSessionTests failed: " << error.what() << '\n';
        return 1;
    }
}
