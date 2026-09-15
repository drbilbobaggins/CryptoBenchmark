#pragma once

#include <chrono>
#include <cstdint>

#include <cryptobench/core/MemoryRunMeasurement.h>

namespace cryptobench::core {

using RunDuration = std::chrono::nanoseconds;
using MeanOperationDuration = std::chrono::duration<double, std::nano>;

struct RunResult {
    std::uint32_t runIndex;

    RunDuration totalElapsedTime;
    MeanOperationDuration meanElapsedTimePerOperation;

    RunDuration totalCpuTime;
    MeanOperationDuration meanCpuTimePerOperation;

    MemoryRunMeasurement memory;
};

} // namespace cryptobench::core
