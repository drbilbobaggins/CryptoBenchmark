#pragma once

#include <cstdint>

namespace cryptobench::core {

struct MemoryRunMeasurement {
    std::uint64_t baselineBytes;
    std::uint64_t peakSampledBytes;
    std::uint64_t peakDeltaBytes;
};

struct ParentRunMemoryMeasurement {
    std::uint32_t runIndex;
    MemoryRunMeasurement memory;
};

} // namespace cryptobench::core
