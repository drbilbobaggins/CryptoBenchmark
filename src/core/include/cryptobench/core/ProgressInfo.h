#pragma once

#include <cstdint>
#include <optional>

namespace cryptobench::core {

enum class BenchmarkPhase {
    Preparing,
    Warmup,
    Measuring,
    Finalizing
};

struct ProgressInfo {
    BenchmarkPhase phase;
    std::optional<std::uint32_t> runIndex;
    std::uint32_t totalRuns;
};

} // namespace cryptobench::core
