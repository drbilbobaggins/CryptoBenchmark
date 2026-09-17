#include <cryptobench/ipc/ParentIpcChannel.h>

#include <stdexcept>

namespace cryptobench::ipc {

ParentIpcChannel::ParentIpcChannel(QObject* parent)
    : QObject(parent)
{
    connect(&server_, &QLocalServer::newConnection, this, &ParentIpcChannel::acceptConnection);
}

ParentIpcChannel::~ParentIpcChannel()
{
    close();
}

void ParentIpcChannel::startListening(const QString& endpoint)
{
    if (server_.isListening() || socket_) {
        throw std::logic_error("ParentIpcChannel is already active");
    }
    if (endpoint.isEmpty()) {
        throw std::invalid_argument("ParentIpcChannel endpoint must not be empty");
    }

    server_.setSocketOptions(QLocalServer::UserAccessOption);
    if (!server_.listen(endpoint)) {
        const auto message = QStringLiteral("ParentIpcChannel listen failed: ") + server_.errorString();
        reportTransportError(message);
        throw std::runtime_error(message.toStdString());
    }
}

void ParentIpcChannel::close()
{
    server_.close();
    if (socket_) {
        QObject::disconnect(socket_, nullptr, this, nullptr);
        socket_->disconnectFromServer();
        socket_->deleteLater();
        socket_ = nullptr;
    }
    parser_ = FrameParser{};
}

bool ParentIpcChannel::isListening() const
{
    return server_.isListening();
}

bool ParentIpcChannel::isConnected() const
{
    return socket_ && socket_->state() == QLocalSocket::ConnectedState;
}

void ParentIpcChannel::sendBenchmarkRequest(const BenchmarkRequest& request)
{
    sendFrame(MessageType::BenchmarkRequest, encodeBenchmarkRequest(request));
}

void ParentIpcChannel::sendStartMeasurement(std::uint32_t runIndex)
{
    sendFrame(MessageType::StartMeasurement, encodeRunIndexPayload(runIndex));
}

void ParentIpcChannel::sendMemoryWindowClosed(std::uint32_t runIndex)
{
    sendFrame(MessageType::MemoryWindowClosed, encodeRunIndexPayload(runIndex));
}

void ParentIpcChannel::acceptConnection()
{
    if (socket_) {
        while (server_.hasPendingConnections()) {
            auto* extra = server_.nextPendingConnection();
            if (extra) extra->disconnectFromServer();
            if (extra) extra->deleteLater();
        }
        reportTransportError(QStringLiteral("ParentIpcChannel received an extra worker connection"));
        return;
    }

    auto accepted = server_.nextPendingConnection();
    if (!accepted) {
        reportTransportError(QStringLiteral("ParentIpcChannel accepted a null worker socket"));
        return;
    }

    server_.close();
    socket_ = accepted;
    socket_->setParent(this);
    connect(socket_, &QLocalSocket::readyRead, this, &ParentIpcChannel::handleReadyRead);
    connect(socket_, &QLocalSocket::errorOccurred, this, &ParentIpcChannel::handleSocketError);
    connect(socket_, &QLocalSocket::disconnected, this, &ParentIpcChannel::handleDisconnected);
    emit connected();
}

void ParentIpcChannel::handleReadyRead()
{
    try {
        for (const auto& frame : parser_.append(socket_->readAll())) {
            dispatchFrame(frame);
        }
    } catch (const std::exception& error) {
        reportTransportError(QStringLiteral("ParentIpcChannel protocol error: ") + QString::fromUtf8(error.what()));
        if (socket_) socket_->disconnectFromServer();
    }
}

void ParentIpcChannel::handleSocketError(QLocalSocket::LocalSocketError)
{
    if (socket_) {
        reportTransportError(QStringLiteral("ParentIpcChannel socket error: ") + socket_->errorString());
    }
}

void ParentIpcChannel::handleDisconnected()
{
    emit disconnected();
}

void ParentIpcChannel::dispatchFrame(const Frame& frame)
{
    switch (frame.messageType) {
        case MessageType::WorkerReady:
            emit workerReadyReceived(decodeWorkerReady(frame.payload));
            return;
        case MessageType::Progress:
            emit progressReceived(decodeProgress(frame.payload));
            return;
        case MessageType::MeasurementReady:
            emit measurementReadyReceived(decodeRunIndexPayload(frame.payload));
            return;
        case MessageType::MeasurementFinished:
            emit measurementFinishedReceived(decodeRunIndexPayload(frame.payload));
            return;
        case MessageType::WorkerRunMeasurement:
            emit workerRunMeasurementReceived(decodeWorkerRunMeasurement(frame.payload));
            return;
        case MessageType::WorkerOutcome:
            emit workerOutcomeReceived(decodeWorkerOutcome(frame.payload));
            return;
        case MessageType::BenchmarkRequest:
        case MessageType::StartMeasurement:
        case MessageType::MemoryWindowClosed:
            throw std::invalid_argument("ParentIpcChannel received a parent-originating message");
    }
    throw std::invalid_argument("ParentIpcChannel received an unsupported message");
}

void ParentIpcChannel::sendFrame(MessageType type, const QByteArray& payload)
{
    requireConnected();
    const auto frame = encodeFrame(type, payload);
    if (socket_->write(frame) != frame.size()) {
        const auto message = QStringLiteral("ParentIpcChannel write failed: ") + socket_->errorString();
        reportTransportError(message);
        throw std::runtime_error(message.toStdString());
    }
    socket_->flush();
}

void ParentIpcChannel::reportTransportError(const QString& message)
{
    emit transportError(message);
}

void ParentIpcChannel::requireConnected() const
{
    if (!isConnected()) {
        throw std::logic_error("ParentIpcChannel is not connected");
    }
}

} // namespace cryptobench::ipc
