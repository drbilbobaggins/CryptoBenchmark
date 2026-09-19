#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QLocalSocket>
#include <QTimer>

#include <windows.h>

#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>
#include <cryptobench/ipc/WireDtos.h>

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

using namespace cryptobench;
using namespace cryptobench::ipc;

void sendFrame(QLocalSocket& socket, MessageType type, const QByteArray& payload)
{
    const auto frame = encodeFrame(type, payload);
    if (socket.write(frame) != frame.size() || !socket.waitForBytesWritten(5'000)) {
        throw std::runtime_error("scripted worker write failed");
    }
}

Frame receiveFrame(QLocalSocket& socket, FrameParser& parser)
{
    QElapsedTimer timer;
    timer.start();
    while (true) {
        const auto frames = parser.append(socket.readAll());
        if (!frames.empty()) return frames.front();
        const auto remaining = 5'000 - static_cast<int>(timer.elapsed());
        if (remaining <= 0 || !socket.waitForReadyRead(remaining)) {
            throw std::runtime_error("scripted worker read failed");
        }
    }
}

void receiveExpected(QLocalSocket& socket, FrameParser& parser, MessageType expected)
{
    const auto frame = receiveFrame(socket, parser);
    if (frame.messageType != expected) throw std::runtime_error("scripted worker received an unexpected frame");
}

void signalMarker(const QByteArray& value)
{
    const auto* pathValue = std::getenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE");
    if (pathValue == nullptr) return;

    QFile signalFile(QString::fromLocal8Bit(pathValue));
    if (!signalFile.open(QIODevice::WriteOnly | QIODevice::Append)) {
        throw std::runtime_error("scripted worker signal file could not be opened");
    }
    signalFile.write(value + '\n');
    signalFile.close();
}

void signalMeasurementStarted(std::uint32_t runIndex)
{
    signalMarker(QByteArray("started ") + QByteArray::number(runIndex));
}

void waitForCancellation(QLocalSocket& socket)
{
    QElapsedTimer timer;
    timer.start();
    while (socket.state() != QLocalSocket::UnconnectedState && timer.elapsed() < 60'000) {
        socket.waitForReadyRead(1'000);
    }
}

void sendProgressAndMeasurementReady(
    QLocalSocket& socket,
    std::uint32_t runIndex,
    std::uint32_t totalRuns)
{
    sendFrame(socket, MessageType::Progress,
              encodeProgress({core::BenchmarkPhase::Preparing, std::nullopt, totalRuns}));
    sendFrame(socket, MessageType::MeasurementReady, encodeRunIndexPayload(runIndex));
}

void sendFailureOutcome(QLocalSocket& socket, std::uint32_t runIndex, const char* message)
{
    sendFrame(socket, MessageType::WorkerOutcome,
              encodeWorkerOutcome({
                  WorkerOutcomeStatus::Failed,
                  core::ErrorInfo{
                      core::ErrorCode::CryptoOperationFailed,
                      core::FailureStage::Measurement,
                      runIndex,
                      message,
                      std::string("scripted-library-details")
                  }
              }));
}

void completeRun(
    QLocalSocket& socket,
    FrameParser& parser,
    std::uint32_t runIndex,
    std::uint32_t totalRuns)
{
    sendProgressAndMeasurementReady(socket, runIndex, totalRuns);
    receiveExpected(socket, parser, MessageType::StartMeasurement);
    signalMeasurementStarted(runIndex);
    sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(runIndex));
    receiveExpected(socket, parser, MessageType::MemoryWindowClosed);
    sendFrame(socket, MessageType::WorkerRunMeasurement,
              encodeWorkerRunMeasurement({runIndex, 1'000, 1'000}));
}

QString argumentValue(int argc, char* argv[], int index)
{
    return index < argc && argv[index] != nullptr
        ? QString::fromLocal8Bit(argv[index])
        : QStringLiteral("<missing>");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);

    if (argc != 3 || argumentValue(argc, argv, 1) != QStringLiteral("--ipc-endpoint") ||
        argumentValue(argc, argv, 2).isEmpty() || argumentValue(argc, argv, 2) == QStringLiteral("<missing>")) {
        return 2;
    }

    const auto* scenarioValue = std::getenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
    const auto scenario = scenarioValue == nullptr
        ? QString{}
        : QString::fromLocal8Bit(scenarioValue);
    QLocalSocket socket;
    const auto endpoint = argumentValue(argc, argv, 2);
    try {
        if (scenario == QStringLiteral("wait")) {
            QTimer::singleShot(60'000, &application, &QCoreApplication::quit);
            return application.exec();
        }

        socket.connectToServer(endpoint);
        if (!socket.waitForConnected(5'000)) {
            return 3;
        }

        FrameParser parser;
        sendFrame(socket, ipc::MessageType::WorkerReady, encodeWorkerReady({kProtocolVersion}));
        signalMarker(QByteArray("pid ") + QByteArray::number(GetCurrentProcessId()));
        const auto request = receiveFrame(socket, parser);
        if (request.messageType != MessageType::BenchmarkRequest) {
            return 4;
        }
        const auto config = decodeBenchmarkRequest(request.payload).config;

        if (scenario == QStringLiteral("failed-before-measurement") ||
            scenario == QStringLiteral("failed-immediately") ||
            scenario == QStringLiteral("failed-disconnect-immediately")) {
            sendFailureOutcome(socket, 0, "scripted worker failure");
            if (scenario == QStringLiteral("failed-disconnect-immediately")) {
                socket.disconnectFromServer();
                socket.waitForDisconnected(1'000);
            }
            return 9;
        }

        if (scenario == QStringLiteral("failed-during-measurement")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            sendFailureOutcome(socket, 0, "scripted active-measurement failure");
            return 9;
        }

        if (scenario == QStringLiteral("failed-after-memory-window-closed")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(0));
            receiveExpected(socket, parser, MessageType::MemoryWindowClosed);
            sendFailureOutcome(socket, 0, "scripted pending-memory failure");
            return 9;
        }

        if (scenario == QStringLiteral("final-run-no-outcome") ||
            scenario == QStringLiteral("completed-no-exit")) {
            for (std::uint32_t runIndex = 0; runIndex < config.runs; ++runIndex) {
                completeRun(socket, parser, runIndex, config.runs);
            }
            if (scenario == QStringLiteral("completed-no-exit")) {
                sendFrame(socket, MessageType::WorkerOutcome,
                          encodeWorkerOutcome({WorkerOutcomeStatus::Completed, std::nullopt}));
            }
            waitForCancellation(socket);
            return 0;
        }

        if (scenario == QStringLiteral("completed")) {
            for (std::uint32_t runIndex = 0; runIndex < config.runs; ++runIndex) {
                completeRun(socket, parser, runIndex, config.runs);
            }
            sendFrame(socket, MessageType::WorkerOutcome,
                      encodeWorkerOutcome({WorkerOutcomeStatus::Completed, std::nullopt}));
            return 0;
        }

        if (scenario == QStringLiteral("crash-during-measurement")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            return 9;
        }

        if (scenario == QStringLiteral("actual-crash-during-measurement")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
            return 9;
        }

        if (scenario == QStringLiteral("unexpected-disconnect")) {
            sendFrame(socket, MessageType::Progress,
                      encodeProgress({core::BenchmarkPhase::Preparing, std::nullopt, config.runs}));
            socket.disconnectFromServer();
            socket.waitForDisconnected(1'000);
            return 0;
        }

        if (scenario == QStringLiteral("protocol-error")) {
            sendFrame(socket, MessageType::BenchmarkRequest, {});
            return 9;
        }

        if (scenario == QStringLiteral("wait-before-measurement")) {
            sendFrame(socket, MessageType::Progress,
                      encodeProgress({core::BenchmarkPhase::Preparing, std::nullopt, config.runs}));
            waitForCancellation(socket);
            return 0;
        }

        if (scenario == QStringLiteral("wait-during-measurement")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            waitForCancellation(socket);
            return 0;
        }

        if (scenario == QStringLiteral("complete-one-run-then-wait-during-next")) {
            sendProgressAndMeasurementReady(socket, 0, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(0);
            sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(0));
            receiveExpected(socket, parser, MessageType::MemoryWindowClosed);
            sendFrame(socket, MessageType::WorkerRunMeasurement,
                      encodeWorkerRunMeasurement({0, 1'000, 1'000}));
            sendProgressAndMeasurementReady(socket, 1, config.runs);
            receiveExpected(socket, parser, MessageType::StartMeasurement);
            signalMeasurementStarted(1);
            waitForCancellation(socket);
            return 0;
        }

        signalMarker("unknown-scenario");
        return 5;
    } catch (const std::exception&) {
        return 6;
    }
}
