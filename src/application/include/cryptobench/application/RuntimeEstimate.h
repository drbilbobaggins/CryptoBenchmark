#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <cryptobench/application/RuntimeCalibrationProvider.h>

namespace cryptobench::application {

struct EntryRuntimeEstimate {
    std::uint32_t entryIndex;
    RuntimeDurationComponent estimatedMeasuredBlockDurationPerRun;
    RuntimeDurationComponent estimatedTotalEntryDuration;
};

enum class RuntimeEstimateAvailability {
    Available,
    Partial,
    Unavailable
};

struct RuntimeEstimate {
    std::vector<EntryRuntimeEstimate> perEntry;
    RuntimeDurationComponent estimatedTotalBatchDuration;
    RuntimeEstimateAvailability availability;
    std::size_t missingMeasuredBlockEntryCount;
    std::size_t missingTotalEntryCount;
    std::vector<std::uint32_t> shortRunEntryIndices;
};

} // namespace cryptobench::application
