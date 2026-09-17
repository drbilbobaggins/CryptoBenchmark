#pragma once

#include <cstdint>
#include <vector>

#include <QByteArray>

#include <cryptobench/ipc/WireProtocol.h>

namespace cryptobench::ipc {

struct Frame {
    MessageType messageType;
    QByteArray payload;
};

QByteArray encodeFrame(MessageType messageType, const QByteArray& payload);
Frame decodeFrame(const QByteArray& frame);

QByteArray encodeRunIndexPayload(std::uint32_t runIndex);
std::uint32_t decodeRunIndexPayload(const QByteArray& payload);

class FrameParser {
public:
    std::vector<Frame> append(const QByteArray& bytes);

private:
    QByteArray buffer_;
};

} // namespace cryptobench::ipc
