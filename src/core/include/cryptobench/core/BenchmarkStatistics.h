#pragma once

#include <variant>

#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/Statistics.h>

namespace cryptobench::core {

struct MemoryV2Statistics {
    Statistics<double> readyStatePrivateUsageDeltaBytes;
    Statistics<double> preparationPeakPrivateUsageDeltaBytes;
    Statistics<double> executionPeakPrivateUsageDeltaBytes;
    Statistics<double> operationalPeakPrivateUsageDeltaBytes;
};

struct BenchmarkStatistics {
    Statistics<double> elapsedNanosecondsPerOperation;
    Statistics<double> cpuNanosecondsPerOperation;
    std::variant<Statistics<double>, MemoryV2Statistics> memory;
};

} // namespace cryptobench::core
