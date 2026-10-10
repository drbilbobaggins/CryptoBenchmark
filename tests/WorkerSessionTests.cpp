#include "../src/worker/WorkerSession.h"

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>
#include <cryptobench/ipc/WireDtos.h>
#include <cryptobench/ipc/WireProtocol.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QLocalServer>
#include <QLocalSocket>
#include <QUuid>

#include <deque>
#include <chrono>
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

void collectFrames(QLocalSocket& socket, FrameReader& reader)
{
        for (auto& frame : reader.parser.append(socket.readAll())) {
                reader.pending.push_back(std::move(frame));
        }
}

bool noFrameFor(QLocalSocket& socket, FrameReader& reader, int milliseconds = 100)
{
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < milliseconds) {
                collectFrames(socket, reader);
                if (!reader.pending.empty() || socket.bytesAvailable() != 0) return false;
                QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        }
        collectFrames(socket, reader);
        return reader.pending.empty() && socket.bytesAvailable() == 0;
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

core::BenchmarkConfig v2HashConfig(std::uint32_t runs = 3)
{
        return {
                core::AlgorithmProfileId::Sha256,
                core::BenchmarkOperation::Hash,
                1,
                runs,
                core::HashConfig{8}
        };
}

void sendV2Request(QLocalSocket& socket, std::uint32_t runIndex,
                                   const core::BenchmarkConfig& config)
{
        sendFrame(socket, ipc::MessageType::BenchmarkRunRequest,
                          ipc::encodeBenchmarkRunRequest({runIndex, config}));
}

ipc::WorkerOutcome receiveFailedOutcome(QLocalSocket& socket, FrameReader& reader,
                                                                                const char* message)
{
        const auto frame = receiveFrame(socket, reader);
        require(frame.messageType == ipc::MessageType::WorkerOutcome, message);
        const auto outcome = ipc::decodeWorkerOutcome(frame.payload);
        require(outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
                        "v2 failure did not contain an error");
        return outcome;
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

void testV2SingleLogicalRun()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        4,
        core::HashConfig{8}
    };

    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSessionV2(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    const auto ready = receiveFrame(*socket, reader);
    require(ready.messageType == ipc::MessageType::WorkerReady, "v2 WorkerReady missing");
    require(ipc::decodeWorkerReady(ready.payload).protocolVersion == 2,
            "v2 WorkerReady protocol version mismatch");

        sendFrame(*socket, ipc::MessageType::BenchmarkRunRequest,
              ipc::encodeBenchmarkRunRequest({0, config}));
    const auto baseline = receiveFrame(*socket, reader);
    require(baseline.messageType == ipc::MessageType::BaselineReady,
            "v2 BaselineReady missing");
    require(ipc::decodeRunIndexPayload(baseline.payload) == 0,
            "v2 BaselineReady run index mismatch");
    require(noFrameFor(*socket, reader), "v2 worker crossed B0 before the start command");

        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
              ipc::encodeRunIndexPayload(0));
    receivePhase(*socket, reader, core::BenchmarkPhase::Warmup, 0);
    const auto algorithmReady = receiveFrame(*socket, reader);
    require(algorithmReady.messageType == ipc::MessageType::AlgorithmReady,
            "v2 AlgorithmReady missing");
    require(ipc::decodeRunIndexPayload(algorithmReady.payload) == 0,
            "v2 AlgorithmReady run index mismatch");
    require(noFrameFor(*socket, reader),
            "v2 worker crossed B1 before the start command");

        sendFrame(*socket, ipc::MessageType::StartMeasurement,
              ipc::encodeRunIndexPayload(0));
    const auto finished = receiveFrame(*socket, reader);
    require(finished.messageType == ipc::MessageType::MeasurementFinished,
            "v2 MeasurementFinished missing");
    require(ipc::decodeRunIndexPayload(finished.payload) == 0,
            "v2 MeasurementFinished run index mismatch");
    require(noFrameFor(*socket, reader), "v2 result was sent before MemoryWindowClosed");

        sendFrame(*socket, ipc::MessageType::MemoryWindowClosed,
              ipc::encodeRunIndexPayload(0));
    const auto measurement = receiveFrame(*socket, reader);
    require(measurement.messageType == ipc::MessageType::WorkerRunMeasurement,
            "v2 WorkerRunMeasurement missing");
        require(ipc::decodeWorkerRunMeasurement(measurement.payload).runIndex == 0,
            "v2 measurement run index mismatch");
    const auto outcomeFrame = receiveFrame(*socket, reader);
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome &&
                outcome.status == ipc::WorkerOutcomeStatus::Completed && !outcome.error,
            "v2 worker did not complete cleanly");
    require(future.get() == 0, "v2 worker returned failure");
    server.close();
}

void testV2WrongPreparationIndexFailsBeforeAlgorithmReady()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto name = endpoint();
    require(server.listen(name), "test server listen failed");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        1,
        3,
        core::HashConfig{8}
    };
    auto future = std::async(std::launch::async, [&] {
        return worker::runWorkerSessionV2(name);
    });
    auto socket = acceptConnection(server);
    FrameReader reader;
    const auto ready = receiveFrame(*socket, reader);
    require(ipc::decodeWorkerReady(ready.payload).protocolVersion == 2,
            "v2 WorkerReady protocol version mismatch");
        sendFrame(*socket, ipc::MessageType::BenchmarkRunRequest,
              ipc::encodeBenchmarkRunRequest({1, config}));
    const auto baseline = receiveFrame(*socket, reader);
    require(baseline.messageType == ipc::MessageType::BaselineReady,
            "v2 BaselineReady missing");
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
              ipc::encodeRunIndexPayload(2));
    const auto outcomeFrame = receiveFrame(*socket, reader);
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome &&
                outcome.status == ipc::WorkerOutcomeStatus::Failed && outcome.error,
            "wrong v2 preparation index did not fail");
    require(outcome.error->runIndex == 1,
            "wrong v2 preparation index failure context mismatch");
    require(future.get() != 0, "wrong v2 preparation index returned success");
    server.close();
}

void receiveV2Ready(QLocalSocket& socket, FrameReader& reader)
{
        const auto ready = receiveFrame(socket, reader);
        require(ready.messageType == ipc::MessageType::WorkerReady,
                        "v2 WorkerReady missing");
        require(ipc::decodeWorkerReady(ready.payload).protocolVersion == 2,
                        "v2 WorkerReady protocol version mismatch");
}

void receiveV2Baseline(QLocalSocket& socket, FrameReader& reader, std::uint32_t runIndex)
{
        const auto baseline = receiveFrame(socket, reader);
        require(baseline.messageType == ipc::MessageType::BaselineReady,
                        "v2 BaselineReady missing");
        require(ipc::decodeRunIndexPayload(baseline.payload) == runIndex,
                        "v2 BaselineReady run index mismatch");
}

void requireFailedFuture(std::future<int>& future)
{
        require(future.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
                        "v2 worker did not terminate after parent disconnect");
        require(future.get() != 0, "v2 worker returned success after parent disconnect");
}

void testV2WrongStartMeasurementIndexFailsWithoutMeasurement()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
                          ipc::encodeRunIndexPayload(1));
        receivePhase(*socket, reader, core::BenchmarkPhase::Warmup, 1);
        const auto algorithmReady = receiveFrame(*socket, reader);
        require(algorithmReady.messageType == ipc::MessageType::AlgorithmReady,
                        "v2 AlgorithmReady missing");

        sendFrame(*socket, ipc::MessageType::StartMeasurement,
                          ipc::encodeRunIndexPayload(0));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "wrong StartMeasurement index did not fail");
        require(outcome.error->stage == core::FailureStage::WorkerCommunication &&
                                outcome.error->runIndex == 1,
                        "wrong StartMeasurement failure context mismatch");
        require(noFrameFor(*socket, reader),
                        "wrong StartMeasurement index produced a measurement or completion");
        require(future.get() != 0, "wrong StartMeasurement index returned success");
        server.close();
}

void testV2WrongMemoryWindowIndexFailsWithoutResult()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
                          ipc::encodeRunIndexPayload(1));
        receivePhase(*socket, reader, core::BenchmarkPhase::Warmup, 1);
        static_cast<void>(receiveFrame(*socket, reader));
        sendFrame(*socket, ipc::MessageType::StartMeasurement,
                          ipc::encodeRunIndexPayload(1));
        const auto finished = receiveFrame(*socket, reader);
        require(finished.messageType == ipc::MessageType::MeasurementFinished,
                        "v2 MeasurementFinished missing");

        sendFrame(*socket, ipc::MessageType::MemoryWindowClosed,
                          ipc::encodeRunIndexPayload(0));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "wrong MemoryWindowClosed index did not fail");
        require(outcome.error->stage == core::FailureStage::WorkerCommunication &&
                                outcome.error->runIndex == 1,
                        "wrong MemoryWindowClosed failure context mismatch");
        require(noFrameFor(*socket, reader),
                        "wrong MemoryWindowClosed index produced a result or completion");
        require(future.get() != 0, "wrong MemoryWindowClosed index returned success");
        server.close();
}

void testV2MalformedRequestFailsBeforeBaseline()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendFrame(*socket, ipc::MessageType::BenchmarkRunRequest, QByteArrayLiteral("{"));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "malformed v2 request did not fail");
        require(outcome.error->code == core::ErrorCode::WorkerCommunicationFailed &&
                                outcome.error->stage == core::FailureStage::ConfigDeserialization,
                        "malformed v2 request classification mismatch");
        require(noFrameFor(*socket, reader), "malformed v2 request emitted BaselineReady");
        require(future.get() != 0, "malformed v2 request returned success");
        server.close();
}

void testV2InvalidConfigFailsBeforeBaseline()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        auto config = v2HashConfig();
        config.parameters = core::HashConfig{core::kMaxWorkloadBytes + 1};
        sendV2Request(*socket, 1, config);
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "invalid v2 config did not fail");
        require(outcome.error->code == core::ErrorCode::InvalidConfiguration &&
                                outcome.error->stage == core::FailureStage::ConfigValidation,
                        "invalid v2 config classification mismatch");
        require(noFrameFor(*socket, reader), "invalid v2 config emitted BaselineReady");
        require(future.get() != 0, "invalid v2 config returned success");
        server.close();
}

void testV2WrongModeRequestFailsBeforeBaseline()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendFrame(*socket, ipc::MessageType::BenchmarkRequest,
                          ipc::encodeBenchmarkRequest({v2HashConfig()}));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "wrong-mode v1 request did not fail");
        require(outcome.error->stage == core::FailureStage::WorkerCommunication,
                        "wrong-mode request classification mismatch");
        require(noFrameFor(*socket, reader), "wrong-mode request emitted BaselineReady");
        require(future.get() != 0, "wrong-mode request returned success");
        server.close();
}

void testV2InvalidControlPayloadLengthFails()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation, QByteArray(3, '\0'));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "invalid control payload length did not fail");
        require(outcome.error->stage == core::FailureStage::WorkerCommunication,
                        "invalid control payload classification mismatch");
        require(noFrameFor(*socket, reader), "invalid control payload emitted AlgorithmReady");
        require(future.get() != 0, "invalid control payload returned success");
        server.close();
}

void testV2PrematureStartMeasurementIsRejected()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        sendFrame(*socket, ipc::MessageType::StartMeasurement,
                          ipc::encodeRunIndexPayload(1));
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
                          ipc::encodeRunIndexPayload(1));
        const auto outcome = receiveFailedOutcome(*socket, reader,
                                                                                          "premature StartMeasurement was accepted");
        require(outcome.error->stage == core::FailureStage::WorkerCommunication,
                        "premature StartMeasurement classification mismatch");
        require(noFrameFor(*socket, reader),
                        "premature StartMeasurement reached algorithm preparation");
        require(future.get() != 0, "premature StartMeasurement returned success");
        server.close();
}

void testV2DisconnectAtB0FailsBoundedly()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        socket->disconnectFromServer();
        requireFailedFuture(future);
        server.close();
}

void testV2DisconnectAtB1FailsBoundedly()
{
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        const auto name = endpoint();
        require(server.listen(name), "test server listen failed");
        auto future = std::async(std::launch::async, [&] {
                return worker::runWorkerSessionV2(name);
        });
        auto socket = acceptConnection(server);
        FrameReader reader;
        receiveV2Ready(*socket, reader);
        sendV2Request(*socket, 1, v2HashConfig());
        receiveV2Baseline(*socket, reader, 1);
        sendFrame(*socket, ipc::MessageType::StartAlgorithmPreparation,
                          ipc::encodeRunIndexPayload(1));
        receivePhase(*socket, reader, core::BenchmarkPhase::Warmup, 1);
        static_cast<void>(receiveFrame(*socket, reader));
        socket->disconnectFromServer();
        requireFailedFuture(future);
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
        testV2SingleLogicalRun();
        testV2WrongPreparationIndexFailsBeforeAlgorithmReady();
        testV2WrongStartMeasurementIndexFailsWithoutMeasurement();
        testV2WrongMemoryWindowIndexFailsWithoutResult();
        testV2MalformedRequestFailsBeforeBaseline();
        testV2InvalidConfigFailsBeforeBaseline();
        testV2WrongModeRequestFailsBeforeBaseline();
        testV2InvalidControlPayloadLengthFails();
        testV2PrematureStartMeasurementIsRejected();
        testV2DisconnectAtB0FailsBoundedly();
        testV2DisconnectAtB1FailsBoundedly();
        std::cout << "WorkerSessionTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WorkerSessionTests failed: " << error.what() << '\n';
        return 1;
    }
}
