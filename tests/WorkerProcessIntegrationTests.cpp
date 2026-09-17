#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>
#include <cryptobench/ipc/WireDtos.h>
#include <cryptobench/ipc/WireProtocol.h>

#include <QCoreApplication>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QUuid>

#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

using namespace cryptobench;

namespace {

constexpr int kTimeoutMilliseconds = 10'000;

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

struct FrameReader {
    ipc::FrameParser parser;
    std::deque<ipc::Frame> pending;
};

class WorkerCleanup final {
public:
    explicit WorkerCleanup(QProcess& process) : process_(process) {}

    ~WorkerCleanup()
    {
        if (process_.state() == QProcess::NotRunning) return;
        process_.kill();
        process_.waitForFinished(2'000);
    }

private:
    QProcess& process_;
};

QString makeEndpoint()
{
    return QStringLiteral("CryptoBenchmark_M04_6_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

ipc::Frame receiveFrame(QLocalSocket& socket, FrameReader& reader, const char* phase)
{
    while (reader.pending.empty()) {
        if (socket.bytesAvailable() == 0) {
            require(socket.waitForReadyRead(kTimeoutMilliseconds),
                    std::string("timed out waiting for ") + phase + ": " + socket.errorString().toStdString());
        }
        for (auto& frame : reader.parser.append(socket.readAll())) {
            reader.pending.push_back(std::move(frame));
        }
    }

    auto frame = std::move(reader.pending.front());
    reader.pending.pop_front();
    return frame;
}

void sendFrame(QLocalSocket& socket, ipc::MessageType type, const QByteArray& payload)
{
    const auto frame = ipc::encodeFrame(type, payload);
    require(socket.write(frame) == frame.size(), "parent failed to write a complete frame");
    require(socket.waitForBytesWritten(kTimeoutMilliseconds),
            "parent timed out writing a frame");
}

void requireProgress(QLocalSocket& socket, FrameReader& reader, core::BenchmarkPhase phase,
                     std::optional<std::uint32_t> runIndex)
{
    const auto frame = receiveFrame(socket, reader, "Progress");
    require(frame.messageType == ipc::MessageType::Progress, "expected Progress");
    const auto progress = ipc::decodeProgress(frame.payload);
    require(progress.phase == phase && progress.runIndex == runIndex,
            "Progress contents did not match the expected phase or run index");
}

void completeRun(QLocalSocket& socket, FrameReader& reader, std::uint32_t runIndex)
{
    requireProgress(socket, reader, core::BenchmarkPhase::Warmup, runIndex);

    const auto ready = receiveFrame(socket, reader, "MeasurementReady");
    require(ready.messageType == ipc::MessageType::MeasurementReady,
            "expected MeasurementReady");
    require(ipc::decodeRunIndexPayload(ready.payload) == runIndex,
            "MeasurementReady run index mismatch");

    sendFrame(socket, ipc::MessageType::StartMeasurement,
              ipc::encodeRunIndexPayload(runIndex));

    const auto finished = receiveFrame(socket, reader, "MeasurementFinished");
    require(finished.messageType == ipc::MessageType::MeasurementFinished,
            "expected MeasurementFinished");
    require(ipc::decodeRunIndexPayload(finished.payload) == runIndex,
            "MeasurementFinished run index mismatch");

    sendFrame(socket, ipc::MessageType::MemoryWindowClosed,
              ipc::encodeRunIndexPayload(runIndex));

    const auto measurementFrame = receiveFrame(socket, reader, "WorkerRunMeasurement");
    require(measurementFrame.messageType == ipc::MessageType::WorkerRunMeasurement,
            "expected WorkerRunMeasurement");
    const auto measurement = ipc::decodeWorkerRunMeasurement(measurementFrame.payload);
    require(measurement.runIndex == runIndex, "WorkerRunMeasurement run index mismatch");
    require(measurement.elapsedNanoseconds > 0,
            "WorkerRunMeasurement elapsed time must be positive");
    require(measurement.processCpuNanoseconds % 100U == 0,
            "WorkerRunMeasurement CPU time is not FILETIME-aligned");
}

void testRealWorkerProcess()
{
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto endpoint = makeEndpoint();
    require(server.listen(endpoint), "test parent failed to listen on the local endpoint");

    QProcess worker;
    WorkerCleanup cleanup(worker);
    const auto workerPath = QCoreApplication::applicationDirPath() + QStringLiteral("/CryptoBenchmarkWorker.exe");
    require(QFileInfo::exists(workerPath),
            "CryptoBenchmarkWorker.exe was not found beside the integration test executable");

    worker.start(workerPath, {QStringLiteral("--ipc-endpoint"), endpoint});
    require(worker.waitForStarted(kTimeoutMilliseconds),
            "CryptoBenchmarkWorker failed to start: " + worker.errorString().toStdString());
    require(worker.processId() != 0, "CryptoBenchmarkWorker did not expose a valid process ID");
    require(worker.processId() != QCoreApplication::applicationPid(),
            "CryptoBenchmarkWorker unexpectedly shares the parent process ID");

    require(server.waitForNewConnection(kTimeoutMilliseconds),
            "CryptoBenchmarkWorker did not connect to the local endpoint");
    std::unique_ptr<QLocalSocket> socket(server.nextPendingConnection());
    require(socket != nullptr, "local server accepted a null worker socket");
    server.close();

    FrameReader reader;
    const auto readyFrame = receiveFrame(*socket, reader, "WorkerReady");
    require(readyFrame.messageType == ipc::MessageType::WorkerReady,
            "first worker message was not WorkerReady");
    require(ipc::decodeWorkerReady(readyFrame.payload).protocolVersion == 1,
            "worker protocol version was not 1");

    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        2,
        core::HashConfig{8}
    };
    sendFrame(*socket, ipc::MessageType::BenchmarkRequest,
              ipc::encodeBenchmarkRequest({config}));

    requireProgress(*socket, reader, core::BenchmarkPhase::Preparing, std::nullopt);
    completeRun(*socket, reader, 0);
    completeRun(*socket, reader, 1);
    requireProgress(*socket, reader, core::BenchmarkPhase::Finalizing, std::nullopt);

    const auto outcomeFrame = receiveFrame(*socket, reader, "WorkerOutcome");
    require(outcomeFrame.messageType == ipc::MessageType::WorkerOutcome,
            "terminal worker message was not WorkerOutcome");
    const auto outcome = ipc::decodeWorkerOutcome(outcomeFrame.payload);
    require(outcome.status == ipc::WorkerOutcomeStatus::Completed && !outcome.error,
            "worker did not report a successful outcome");

    require(worker.waitForFinished(kTimeoutMilliseconds),
            "worker did not exit after reporting Completed");
    require(worker.exitStatus() == QProcess::NormalExit,
            "worker did not exit normally");
    require(worker.exitCode() == 0, "worker exit code was not zero");
}

} // namespace


int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testRealWorkerProcess();
        std::cout << "Worker process integration test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Worker process integration test failed: " << error.what() << '\n';
        return 1;
    }
}
