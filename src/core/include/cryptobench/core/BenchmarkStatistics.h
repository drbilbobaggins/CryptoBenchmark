#pragma once

#include <cryptobench/core/Statistics.h>

namespace cryptobench::core {

struct BenchmarkStatistics {
    Statistics<double> elapsedNanosecondsPerOperation;
    Statistics<double> cpuNanosecondsPerOperation;
    Statistics<double> peakDeltaBytes;
};

} // namespace cryptobench::core
