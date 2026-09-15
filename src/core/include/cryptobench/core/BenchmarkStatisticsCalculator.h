#pragma once

#include <span>

#include <cryptobench/core/BenchmarkStatistics.h>
#include <cryptobench/core/RunResult.h>

namespace cryptobench::core {

class BenchmarkStatisticsCalculator {
public:
    static BenchmarkStatistics calculate(std::span<const RunResult> runs);
};

} // namespace cryptobench::core
