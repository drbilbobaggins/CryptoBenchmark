#include <cryptobench/ipc/FrameCodec.h>

#include <stdexcept>

namespace cryptobench::ipc {
namespace {

void append16(QByteArray& bytes, std::uint16_t value)
{
    bytes.append(static_cast<char>(value >> 8));
    bytes.append(static_cast<char>(value));
}

void append32(QByteArray& bytes, std::uint32_t value)
{
    for (int shift = 24; shift >= 0; shift -= 8) bytes.append(static_cast<char>(value >> shift));
}

std::uint16_t read16(const char* data)
{
    return (static_cast<std::uint16_t>(static_cast<unsigned char>(data[0])) << 8) |
           static_cast<std::uint16_t>(static_cast<unsigned char>(data[1]));
}

std::uint32_t read32(const char* data)
{
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index) value = (value << 8) | static_cast<unsigned char>(data[index]);
    return value;
}

MessageType parseType(std::uint16_t value)
{
    if (value < 1 || value > 9) throw std::runtime_error("unknown IPC message type");
    return static_cast<MessageType>(value);
}

void validateType(MessageType value)
{
    switch (value) {
        case MessageType::WorkerReady:
        case MessageType::BenchmarkRequest:
        case MessageType::Progress:
        case MessageType::MeasurementReady:
        case MessageType::StartMeasurement:
        case MessageType::MeasurementFinished:
        case MessageType::MemoryWindowClosed:
        case MessageType::WorkerRunMeasurement:
        case MessageType::WorkerOutcome:
            return;
    }
    throw std::invalid_argument("unsupported IPC message type");
}

} // namespace

QByteArray encodeFrame(MessageType messageType, const QByteArray& payload)
{
    validateType(messageType);
    if (payload.size() > static_cast<qsizetype>(kMaxIpcPayload)) {
        throw std::invalid_argument("IPC payload exceeds maximum size");
    }
    QByteArray result;
    result.reserve(static_cast<int>(kFrameHeaderSize) + payload.size());
    append16(result, static_cast<std::uint16_t>(messageType));
    append32(result, static_cast<std::uint32_t>(payload.size()));
    result.append(payload);
    return result;
}

Frame decodeFrame(const QByteArray& frame)
{
    if (frame.size() < static_cast<int>(kFrameHeaderSize)) throw std::invalid_argument("incomplete IPC frame header");
    const auto length = read32(frame.constData() + 2);
    if (length > kMaxIpcPayload) throw std::invalid_argument("IPC payload exceeds maximum size");
    if (frame.size() != static_cast<int>(kFrameHeaderSize + length)) throw std::invalid_argument("incomplete IPC frame");
    return {parseType(read16(frame.constData())), frame.mid(static_cast<int>(kFrameHeaderSize), static_cast<int>(length))};
}

QByteArray encodeRunIndexPayload(std::uint32_t runIndex)
{
    QByteArray result;
    append32(result, runIndex);
    return result;
}

std::uint32_t decodeRunIndexPayload(const QByteArray& payload)
{
    if (payload.size() != 4) throw std::invalid_argument("IPC control payload must be 4 bytes");
    return read32(payload.constData());
}

std::vector<Frame> FrameParser::append(const QByteArray& bytes)
{
    buffer_.append(bytes);
    std::vector<Frame> frames;
    while (buffer_.size() >= static_cast<int>(kFrameHeaderSize)) {
        const auto length = read32(buffer_.constData() + 2);
        if (length > kMaxIpcPayload) throw std::invalid_argument("IPC payload exceeds maximum size");
        const auto frameSize = kFrameHeaderSize + length;
        if (buffer_.size() < static_cast<int>(frameSize)) break;
        frames.push_back(decodeFrame(buffer_.left(static_cast<int>(frameSize))));
        buffer_.remove(0, static_cast<int>(frameSize));
    }
    return frames;
}

} // namespace cryptobench::ipc
