#pragma once

#include <cstdint>

namespace cryptobench::core {

struct MeasurementSettings {
    std::uint32_t memorySamplingIntervalMilliseconds;
};

inline constexpr std::uint32_t kDefaultMemorySamplingIntervalMilliseconds = 5;

constexpr MeasurementSettings defaultMeasurementSettings() noexcept
{
    return {kDefaultMemorySamplingIntervalMilliseconds};
}

constexpr bool isValidMeasurementSettings(const MeasurementSettings& settings) noexcept
{
    return settings.memorySamplingIntervalMilliseconds >= 1
        && settings.memorySamplingIntervalMilliseconds <= 5;
}

} // namespace cryptobench::core
