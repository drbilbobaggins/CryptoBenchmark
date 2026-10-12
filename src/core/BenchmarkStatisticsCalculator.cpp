#include <cryptobench/core/BenchmarkStatisticsCalculator.h>

#include <stdexcept>
#include <vector>

#include <cryptobench/core/MemoryV2Calculator.h>
#include <cryptobench/core/StatisticsCalculator.h>

namespace cryptobench::core {

BenchmarkStatistics BenchmarkStatisticsCalculator::calculate(std::span<const RunResult> runs)
{
    if (runs.empty()) {
        throw std::invalid_argument("BenchmarkStatisticsCalculator requires at least one run");
    }

    std::vector<double> elapsedNanosecondsPerOperation;
    std::vector<double> cpuNanosecondsPerOperation;
    std::vector<double> legacyPeakDeltaBytes;
    std::vector<double> readyStatePrivateUsageDeltaBytes;
    std::vector<double> preparationPeakPrivateUsageDeltaBytes;
    std::vector<double> executionPeakPrivateUsageDeltaBytes;
    std::vector<double> operationalPeakPrivateUsageDeltaBytes;
    const bool v2 = std::holds_alternative<MemoryV2RunMeasurement>(runs.front().memory);
    elapsedNanosecondsPerOperation.reserve(runs.size());
    cpuNanosecondsPerOperation.reserve(runs.size());
    legacyPeakDeltaBytes.reserve(runs.size());
    readyStatePrivateUsageDeltaBytes.reserve(runs.size());
    preparationPeakPrivateUsageDeltaBytes.reserve(runs.size());
    executionPeakPrivateUsageDeltaBytes.reserve(runs.size());
    operationalPeakPrivateUsageDeltaBytes.reserve(runs.size());

    for (const auto& run : runs) {
        if (std::holds_alternative<MemoryV2RunMeasurement>(run.memory) != v2) {
            throw std::invalid_argument("Benchmark statistics cannot mix legacy and Memory v2 runs");
        }
        if (v2) {
            const auto& memory = std::get<MemoryV2RunMeasurement>(run.memory);
            const auto derived = calculateMemoryV2DerivedMetrics(memory.raw);
            if (!derived.has_value() ||
                derived->readyStateDelta != memory.derived.readyStateDelta ||
                derived->preparationPeakDelta != memory.derived.preparationPeakDelta ||
                derived->executionPeakDelta != memory.derived.executionPeakDelta ||
                derived->operationalPeakDelta != memory.derived.operationalPeakDelta) {
                throw std::invalid_argument("Benchmark statistics contain invalid Memory v2 data");
            }
            readyStatePrivateUsageDeltaBytes.push_back(
                static_cast<double>(memory.derived.readyStateDelta));
            preparationPeakPrivateUsageDeltaBytes.push_back(
                static_cast<double>(memory.derived.preparationPeakDelta));
            executionPeakPrivateUsageDeltaBytes.push_back(
                static_cast<double>(memory.derived.executionPeakDelta));
            operationalPeakPrivateUsageDeltaBytes.push_back(
                static_cast<double>(memory.derived.operationalPeakDelta));
        } else {
            legacyPeakDeltaBytes.push_back(static_cast<double>(
                std::get<MemoryRunMeasurement>(run.memory).peakDeltaBytes));
        }
        elapsedNanosecondsPerOperation.push_back(run.meanElapsedTimePerOperation.count());
        cpuNanosecondsPerOperation.push_back(run.meanCpuTimePerOperation.count());
    }

    std::variant<Statistics<double>, MemoryV2Statistics> memoryStatistics;
    if (v2) {
        memoryStatistics = MemoryV2Statistics{
            StatisticsCalculator::calculate(readyStatePrivateUsageDeltaBytes),
            StatisticsCalculator::calculate(preparationPeakPrivateUsageDeltaBytes),
            StatisticsCalculator::calculate(executionPeakPrivateUsageDeltaBytes),
            StatisticsCalculator::calculate(operationalPeakPrivateUsageDeltaBytes)
        };
    } else {
        memoryStatistics = StatisticsCalculator::calculate(legacyPeakDeltaBytes);
    }

    BenchmarkStatistics result{
        StatisticsCalculator::calculate(elapsedNanosecondsPerOperation),
        StatisticsCalculator::calculate(cpuNanosecondsPerOperation),
        std::move(memoryStatistics)
    };
    return result;
}

} // namespace cryptobench::core
