#include <cryptobench/core/BenchmarkStatisticsCalculator.h>

#include <stdexcept>
#include <vector>

#include <cryptobench/core/StatisticsCalculator.h>

namespace cryptobench::core {

BenchmarkStatistics BenchmarkStatisticsCalculator::calculate(std::span<const RunResult> runs)
{
    if (runs.empty()) {
        throw std::invalid_argument("BenchmarkStatisticsCalculator requires at least one run");
    }

    std::vector<double> elapsedNanosecondsPerOperation;
    std::vector<double> cpuNanosecondsPerOperation;
    std::vector<double> peakDeltaBytes;
    elapsedNanosecondsPerOperation.reserve(runs.size());
    cpuNanosecondsPerOperation.reserve(runs.size());
    peakDeltaBytes.reserve(runs.size());

    for (const auto& run : runs) {
        elapsedNanosecondsPerOperation.push_back(run.meanElapsedTimePerOperation.count());
        cpuNanosecondsPerOperation.push_back(run.meanCpuTimePerOperation.count());
        peakDeltaBytes.push_back(static_cast<double>(run.memory.peakDeltaBytes));
    }

    return {
        StatisticsCalculator::calculate(elapsedNanosecondsPerOperation),
        StatisticsCalculator::calculate(cpuNanosecondsPerOperation),
        StatisticsCalculator::calculate(peakDeltaBytes)
    };
}

} // namespace cryptobench::core
