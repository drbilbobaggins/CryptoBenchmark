#pragma once

#include <cstdint>

namespace cryptobench::core {

struct WorkerRunMeasurement {
    std::uint32_t runIndex;
    std::uint64_t elapsedNanoseconds;
    std::uint64_t processCpuNanoseconds;
};

} // namespace cryptobench::core
