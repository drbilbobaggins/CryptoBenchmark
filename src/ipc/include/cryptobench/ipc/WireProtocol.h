#pragma once

#include <cstddef>
#include <cstdint>

namespace cryptobench::ipc {

constexpr std::uint32_t kProtocolVersion = 1;
constexpr std::uint32_t kProtocolVersionV2 = 2;
constexpr std::uint32_t kMaxIpcPayload = 1024U * 1024U;
constexpr std::size_t kFrameHeaderSize = 6;

enum class MessageType : std::uint16_t {
    WorkerReady = 1,
    BenchmarkRequest = 2,
    Progress = 3,
    MeasurementReady = 4,
    StartMeasurement = 5,
    MeasurementFinished = 6,
    MemoryWindowClosed = 7,
    WorkerRunMeasurement = 8,
    WorkerOutcome = 9,
    BenchmarkRunRequest = 10,
    BaselineReady = 11,
    StartAlgorithmPreparation = 12,
    AlgorithmReady = 13
};

} // namespace cryptobench::ipc
