#pragma once

#include <cryptobench/core/MemoryV2.h>

#include <algorithm>
#include <cstdint>

namespace cryptobench::platform::windows {

enum class MemoryV2SamplePhase {
    Preparation,
    Execution
};

inline void recordMemoryV2Sample(
    core::MemoryV2RawObservations& observations,
    MemoryV2SamplePhase phase,
    std::uint64_t sample) noexcept
{
    if (phase == MemoryV2SamplePhase::Preparation) {
        ++observations.preparationSampleCount;
        if (!observations.preparationPeakSampledPrivateUsageBytes.has_value()) {
            observations.preparationPeakSampledPrivateUsageBytes = sample;
        } else {
            observations.preparationPeakSampledPrivateUsageBytes = std::max(
                *observations.preparationPeakSampledPrivateUsageBytes,
                sample);
        }
        return;
    }

    ++observations.executionSampleCount;
    if (!observations.executionPeakSampledPrivateUsageBytes.has_value()) {
        observations.executionPeakSampledPrivateUsageBytes = sample;
    } else {
        observations.executionPeakSampledPrivateUsageBytes = std::max(
            *observations.executionPeakSampledPrivateUsageBytes,
            sample);
    }
}

} // namespace cryptobench::platform::windows
