#pragma once

#include <cstdint>

#include <QObject>
#include <QPointer>
#include <QLocalServer>
#include <QLocalSocket>

#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>
#include <cryptobench/ipc/WireDtos.h>

namespace cryptobench::ipc {

class ParentIpcChannel final : public QObject {
    Q_OBJECT

public:
    explicit ParentIpcChannel(QObject* parent = nullptr);
    ~ParentIpcChannel() override;

    void startListening(const QString& endpoint);
    void startListeningV2(const QString& endpoint);
    void close();

    bool isListening() const;
    bool isConnected() const;

    void sendBenchmarkRequest(const BenchmarkRequest& request);
    void sendBenchmarkRunRequest(const BenchmarkRunRequest& request);
    void sendStartAlgorithmPreparation(std::uint32_t runIndex);
    void sendStartMeasurement(std::uint32_t runIndex);
    void sendMemoryWindowClosed(std::uint32_t runIndex);

signals:
    void connected();
    void disconnected();
    void transportError(const QString& message);

    void workerReadyReceived(const cryptobench::ipc::WorkerReady& value);
    void progressReceived(const cryptobench::ipc::Progress& value);
    void baselineReadyReceived(std::uint32_t runIndex);
    void algorithmReadyReceived(std::uint32_t runIndex);
    void measurementReadyReceived(std::uint32_t runIndex);
    void measurementFinishedReceived(std::uint32_t runIndex);
    void workerRunMeasurementReceived(const cryptobench::ipc::WorkerRunMeasurement& value);
    void workerOutcomeReceived(const cryptobench::ipc::WorkerOutcome& value);

private:
    void acceptConnection();
    void handleReadyRead();
    void handleSocketError(QLocalSocket::LocalSocketError error);
    void handleDisconnected();
    void dispatchFrame(const Frame& frame);
    void sendFrame(MessageType type, const QByteArray& payload);
    void reportTransportError(const QString& message);
    void requireConnected() const;

    QLocalServer server_;
    QPointer<QLocalSocket> socket_;
    FrameParser parser_;
    bool v2Mode_ = false;
};

} // namespace cryptobench::ipc
