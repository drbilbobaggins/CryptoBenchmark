#pragma once

#include <cstdint>
#include <optional>

namespace cryptobench::core {

struct MemoryV2RawObservations {
    std::uint64_t baselinePrivateUsageBytes = 0;
    std::uint64_t readyPrivateUsageBytes = 0;
    std::optional<std::uint64_t> preparationPeakSampledPrivateUsageBytes;
    std::optional<std::uint64_t> executionPeakSampledPrivateUsageBytes;
    std::uint64_t finalPrivateUsageBytes = 0;
    std::uint64_t preparationSampleCount = 0;
    std::uint64_t executionSampleCount = 0;
};

struct MemoryV2DerivedMetrics {
    std::int64_t readyStateDelta = 0;
    std::uint64_t preparationPeakDelta = 0;
    std::uint64_t executionPeakDelta = 0;
    std::uint64_t operationalPeakDelta = 0;
};

struct MemoryV2RunMeasurement {
    MemoryV2RawObservations raw;
    MemoryV2DerivedMetrics derived;
};

} // namespace cryptobench::core
