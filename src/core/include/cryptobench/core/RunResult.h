#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <variant>

#include <cryptobench/core/MemoryRunMeasurement.h>
#include <cryptobench/core/MemoryV2.h>

namespace cryptobench::core {

using RunDuration = std::chrono::nanoseconds;
using MeanOperationDuration = std::chrono::duration<double, std::nano>;

struct RunResult {
    std::uint32_t runIndex;

    RunDuration totalElapsedTime;
    MeanOperationDuration meanElapsedTimePerOperation;

    RunDuration totalCpuTime;
    MeanOperationDuration meanCpuTimePerOperation;

    std::variant<MemoryRunMeasurement, MemoryV2RunMeasurement> memory;
};

} // namespace cryptobench::core
