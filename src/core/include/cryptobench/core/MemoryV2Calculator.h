#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>

#include <cryptobench/core/MemoryV2.h>

namespace cryptobench::core {

inline std::optional<MemoryV2DerivedMetrics> calculateMemoryV2DerivedMetrics(
    const MemoryV2RawObservations& observations) noexcept
{
    const bool preparationPeakPresent = observations.preparationPeakSampledPrivateUsageBytes.has_value();
    if ((observations.preparationSampleCount == 0) == preparationPeakPresent) {
        return std::nullopt;
    }

    const bool executionPeakPresent = observations.executionPeakSampledPrivateUsageBytes.has_value();
    if ((observations.executionSampleCount == 0) == executionPeakPresent) {
        return std::nullopt;
    }

    std::int64_t readyStateDelta = 0;
    if (observations.readyPrivateUsageBytes >= observations.baselinePrivateUsageBytes) {
        const std::uint64_t positiveMagnitude =
            observations.readyPrivateUsageBytes - observations.baselinePrivateUsageBytes;
        if (positiveMagnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::nullopt;
        }
        readyStateDelta = static_cast<std::int64_t>(positiveMagnitude);
    } else {
        const std::uint64_t negativeMagnitude =
            observations.baselinePrivateUsageBytes - observations.readyPrivateUsageBytes;
        const auto maximumNegativeMagnitude =
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1U;
        if (negativeMagnitude > maximumNegativeMagnitude) {
            return std::nullopt;
        }
        readyStateDelta = negativeMagnitude == maximumNegativeMagnitude
            ? std::numeric_limits<std::int64_t>::min()
            : -static_cast<std::int64_t>(negativeMagnitude);
    }

    std::uint64_t preparationPeak = std::max(
        observations.baselinePrivateUsageBytes,
        observations.readyPrivateUsageBytes);
    if (observations.preparationPeakSampledPrivateUsageBytes.has_value()) {
        preparationPeak = std::max(
            preparationPeak,
            *observations.preparationPeakSampledPrivateUsageBytes);
    }

    std::uint64_t executionPeak = std::max(
        {observations.baselinePrivateUsageBytes,
         observations.readyPrivateUsageBytes,
         observations.finalPrivateUsageBytes});
    if (observations.executionPeakSampledPrivateUsageBytes.has_value()) {
        executionPeak = std::max(
            executionPeak,
            *observations.executionPeakSampledPrivateUsageBytes);
    }

    std::uint64_t operationalPeak = executionPeak;
    if (observations.preparationPeakSampledPrivateUsageBytes.has_value()) {
        operationalPeak = std::max(
            operationalPeak,
            *observations.preparationPeakSampledPrivateUsageBytes);
    }
    if (observations.executionPeakSampledPrivateUsageBytes.has_value()) {
        operationalPeak = std::max(
            operationalPeak,
            *observations.executionPeakSampledPrivateUsageBytes);
    }

    return MemoryV2DerivedMetrics{
        readyStateDelta,
        preparationPeak - observations.baselinePrivateUsageBytes,
        executionPeak - observations.baselinePrivateUsageBytes,
        operationalPeak - observations.baselinePrivateUsageBytes
    };
}

} // namespace cryptobench::core
