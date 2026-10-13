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

void receiveExpectedRun(
    QLocalSocket& socket,
    FrameParser& parser,
    MessageType expected,
    std::uint32_t runIndex)
{
    const auto frame = receiveFrame(socket, parser);
    if (frame.messageType != expected || decodeRunIndexPayload(frame.payload) != runIndex) {
        throw std::runtime_error("scripted worker received an unexpected run command");
    }
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
    receiveExpectedRun(socket, parser, MessageType::StartMeasurement, runIndex);
    signalMeasurementStarted(runIndex);
    sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed, runIndex);
    sendFrame(socket, MessageType::WorkerRunMeasurement,
              encodeWorkerRunMeasurement({runIndex, 1'000, 1'000}));
}

void completeV2Run(
    QLocalSocket& socket,
    FrameParser& parser,
    std::uint32_t runIndex,
    std::uint32_t totalRuns)
{
    sendFrame(socket, MessageType::BaselineReady, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation, runIndex);
    sendFrame(socket, MessageType::Progress,
              encodeProgress({core::BenchmarkPhase::Warmup, runIndex, totalRuns}));
    sendFrame(socket, MessageType::AlgorithmReady, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::StartMeasurement, runIndex);
    sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed, runIndex);
    sendFrame(socket, MessageType::WorkerRunMeasurement,
              encodeWorkerRunMeasurement({runIndex, 1'000, 1'000}));
    sendFrame(socket, MessageType::WorkerOutcome,
              encodeWorkerOutcome({WorkerOutcomeStatus::Completed, std::nullopt}));
}

void completeV2RunAfterPreparation(
    QLocalSocket& socket,
    FrameParser& parser,
    std::uint32_t runIndex,
    std::uint32_t totalRuns)
{
    sendFrame(socket, MessageType::Progress,
              encodeProgress({core::BenchmarkPhase::Warmup, runIndex, totalRuns}));
    sendFrame(socket, MessageType::AlgorithmReady, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::StartMeasurement, runIndex);
    sendFrame(socket, MessageType::MeasurementFinished, encodeRunIndexPayload(runIndex));
    receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed, runIndex);
    sendFrame(socket, MessageType::WorkerRunMeasurement,
              encodeWorkerRunMeasurement({runIndex, 1'000, 1'000}));
    sendFrame(socket, MessageType::WorkerOutcome,
              encodeWorkerOutcome({WorkerOutcomeStatus::Completed, std::nullopt}));
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

    const bool v2 = argc == 4 && argumentValue(argc, argv, 3) == QStringLiteral("--ipc-v2");
    if ((!v2 && argc != 3) || (v2 && argc != 4) ||
        argumentValue(argc, argv, 1) != QStringLiteral("--ipc-endpoint") ||
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
        if (v2 && scenario == QStringLiteral("unsupported-protocol")) {
            signalMarker(QByteArray("pid ") + QByteArray::number(GetCurrentProcessId()));
            signalMarker("unsupported-protocol-ready");
            sendFrame(socket, ipc::MessageType::WorkerReady,
                      encodeWorkerReady({kProtocolVersionV2 + 1}));
            QElapsedTimer timer;
            timer.start();
            while (socket.state() != QLocalSocket::UnconnectedState && timer.elapsed() < 60'000) {
                if (socket.waitForReadyRead(1'000)) {
                    signalMarker("unexpected-benchmark-request");
                    socket.readAll();
                }
            }
            return 0;
        }
        sendFrame(socket, ipc::MessageType::WorkerReady,
                  encodeWorkerReady({v2 ? kProtocolVersionV2 : kProtocolVersion}));
        signalMarker(QByteArray("pid ") + QByteArray::number(GetCurrentProcessId()));
        const auto request = receiveFrame(socket, parser);
        if (v2) {
            if (request.messageType != MessageType::BenchmarkRunRequest) return 4;
            const auto runRequest = decodeBenchmarkRunRequest(request.payload);
            if (scenario == QStringLiteral("silent-baseline")) {
                signalMarker("baseline-silent");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("long-preparation")) {
                signalMarker("long-preparation-delay-started");
                int exitCode = 0;
                QTimer::singleShot(2'200, &application, [&] {
                    try {
                        sendFrame(socket, MessageType::BaselineReady,
                                  encodeRunIndexPayload(runRequest.logicalRunIndex));
                        signalMarker("long-preparation-baseline-ready");
                        receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                           runRequest.logicalRunIndex);
                        completeV2RunAfterPreparation(
                            socket, parser, runRequest.logicalRunIndex, runRequest.config.runs);
                    } catch (const std::exception&) {
                        exitCode = 6;
                    }
                    application.quit();
                });
                application.exec();
                return exitCode;
            }
            if (scenario == QStringLiteral("early-exit-missing-final")) {
                return 0;
            }
            if (scenario == QStringLiteral("failed-during-measurement-v2")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::Progress,
                          encodeProgress({core::BenchmarkPhase::Warmup,
                                          runRequest.logicalRunIndex,
                                          runRequest.config.runs}));
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                sendFailureOutcome(socket, runRequest.logicalRunIndex,
                                   "scripted v2 measurement failure");
                return 9;
            }
            if (scenario == QStringLiteral("failed-after-memory-window-closed-v2")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::Progress,
                          encodeProgress({core::BenchmarkPhase::Warmup,
                                          runRequest.logicalRunIndex,
                                          runRequest.config.runs}));
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::MeasurementFinished,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed,
                                   runRequest.logicalRunIndex);
                sendFailureOutcome(socket, runRequest.logicalRunIndex,
                                   "scripted v2 post-window failure");
                return 9;
            }
            if (scenario == QStringLiteral("completed-abnormal-exit-v2")) {
                completeV2Run(socket, parser, runRequest.logicalRunIndex,
                              runRequest.config.runs);
                return 9;
            }
            if (scenario == QStringLiteral("missing-final-outcome-v2")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::Progress,
                          encodeProgress({core::BenchmarkPhase::Warmup,
                                          runRequest.logicalRunIndex,
                                          runRequest.config.runs}));
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::MeasurementFinished,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::WorkerRunMeasurement,
                          encodeWorkerRunMeasurement({runRequest.logicalRunIndex, 1'000, 1'000}));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("complete-prefix-then-fail-v2") &&
                runRequest.logicalRunIndex == 0) {
                completeV2Run(socket, parser, runRequest.logicalRunIndex,
                              runRequest.config.runs);
                return 0;
            }
            if (scenario == QStringLiteral("complete-prefix-then-fail-v2")) {
                sendFailureOutcome(socket, runRequest.logicalRunIndex,
                                   "scripted v2 prefix failure");
                return 9;
            }
            if (scenario == QStringLiteral("complete-prefix-then-wait-v2") &&
                runRequest.logicalRunIndex == 0) {
                completeV2Run(socket, parser, runRequest.logicalRunIndex,
                              runRequest.config.runs);
                return 0;
            }
            if (scenario == QStringLiteral("complete-prefix-then-wait-v2")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                signalMarker("prefix-next-preparing");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("failed-before-measurement") ||
                scenario == QStringLiteral("failed-immediately") ||
                scenario == QStringLiteral("failed-graceful") ||
                scenario == QStringLiteral("failed-stays-alive") ||
                scenario == QStringLiteral("failed-disconnect-immediately-v2")) {
                sendFailureOutcome(socket, runRequest.logicalRunIndex, "scripted v2 worker failure");
                if (scenario == QStringLiteral("failed-disconnect-immediately-v2")) {
                    socket.disconnectFromServer();
                    socket.waitForDisconnected(1'000);
                    return 9;
                }
                if (scenario == QStringLiteral("failed-graceful")) {
                    QTimer::singleShot(100, &application, &QCoreApplication::quit);
                    application.exec();
                }
                if (scenario == QStringLiteral("failed-stays-alive")) {
                    signalMarker("failure-sent");
                    QTimer::singleShot(60'000, &application, &QCoreApplication::quit);
                    application.exec();
                }
                return scenario == QStringLiteral("failed-graceful") ? 0 : 9;
            }
            if (scenario == QStringLiteral("crash-before-outcome")) return 9;
            if (scenario == QStringLiteral("invalid-progress-before-preparation")) {
                sendFrame(socket, MessageType::Progress,
                          encodeProgress({core::BenchmarkPhase::Preparing,
                                          runRequest.logicalRunIndex,
                                          1}));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("invalid-progress-during-measurement")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpected(socket, parser, MessageType::StartAlgorithmPreparation);
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpected(socket, parser, MessageType::StartMeasurement);
                sendFrame(socket, MessageType::Progress,
                          encodeProgress({core::BenchmarkPhase::Measuring,
                                          runRequest.logicalRunIndex,
                                          1}));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("wrong-baseline-index")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex + 1));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("duplicate-baseline")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("v2-measurement-ready")) {
                sendFrame(socket, MessageType::MeasurementReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("wrong-direction")) {
                sendFrame(socket, MessageType::StartMeasurement,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("malformed-boundary")) {
                sendFrame(socket, MessageType::BaselineReady, QByteArray("\x01", 1));
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("observe-b0-command")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                signalMarker("baseline-ready");
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                signalMarker("start-preparation-sent");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("observe-b1-command")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                signalMarker("start-measurement-sent");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("observe-e-command")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::MeasurementFinished,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed,
                                   runRequest.logicalRunIndex);
                signalMarker("memory-window-closed-sent");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("wait-after-memory-window-closed")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartAlgorithmPreparation,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::StartMeasurement,
                                   runRequest.logicalRunIndex);
                sendFrame(socket, MessageType::MeasurementFinished,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpectedRun(socket, parser, MessageType::MemoryWindowClosed,
                                   runRequest.logicalRunIndex);
                signalMarker("memory-window-closed-received");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("wait-preparing")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpected(socket, parser, MessageType::StartAlgorithmPreparation);
                signalMarker("preparing");
                waitForCancellation(socket);
                return 0;
            }
            if (scenario == QStringLiteral("wait-measuring")) {
                sendFrame(socket, MessageType::BaselineReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpected(socket, parser, MessageType::StartAlgorithmPreparation);
                sendFrame(socket, MessageType::AlgorithmReady,
                          encodeRunIndexPayload(runRequest.logicalRunIndex));
                receiveExpected(socket, parser, MessageType::StartMeasurement);
                signalMarker("measuring");
                waitForCancellation(socket);
                return 0;
            }
            completeV2Run(socket, parser, runRequest.logicalRunIndex, runRequest.config.runs);
            if (scenario == QStringLiteral("completed-before-exit")) {
                QTimer::singleShot(100, &application, &QCoreApplication::quit);
                application.exec();
            }
            if (scenario == QStringLiteral("exit-before-final-queued")) {
                socket.disconnectFromServer();
                socket.waitForDisconnected(1'000);
            }
            if (scenario == QStringLiteral("completed-disconnect-stays-alive")) {
                signalMarker("disconnected-alive");
                socket.disconnectFromServer();
                socket.waitForDisconnected(1'000);
                QTimer::singleShot(60'000, &application, &QCoreApplication::quit);
                application.exec();
            }
            if (scenario == QStringLiteral("duplicate-outcome")) {
                sendFrame(socket, MessageType::WorkerOutcome,
                          encodeWorkerOutcome({WorkerOutcomeStatus::Completed, std::nullopt}));
            }
            return 0;
        }
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
