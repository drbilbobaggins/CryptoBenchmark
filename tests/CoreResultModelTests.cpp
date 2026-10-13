#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/BenchmarkStatisticsCalculator.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireNear(double actual, double expected, std::string_view message)
{
    require(std::abs(actual - expected) <= 1e-12, message);
}

BenchmarkConfig validConfig()
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 3, 2, HashConfig{64}};
}

RunResult runResult(
    std::uint32_t runIndex,
    double elapsedNanosecondsPerOperation,
    double cpuNanosecondsPerOperation,
    std::uint64_t peakDeltaBytes)
{
    return {
        runIndex,
        RunDuration{static_cast<RunDuration::rep>(elapsedNanosecondsPerOperation * 3.0)},
        MeanOperationDuration{elapsedNanosecondsPerOperation},
        RunDuration{static_cast<RunDuration::rep>(cpuNanosecondsPerOperation * 3.0)},
        MeanOperationDuration{cpuNanosecondsPerOperation},
        MemoryRunMeasurement{1000, 1000 + peakDeltaBytes, peakDeltaBytes}
    };
}

void requireStatistics(
    const Statistics<double>& actual,
    double mean,
    double median,
    double minimum,
    double maximum,
    double stddev,
    std::string_view prefix)
{
    requireNear(actual.mean, mean, std::string(prefix) + " mean mismatch");
    requireNear(actual.median, median, std::string(prefix) + " median mismatch");
    requireNear(actual.min, minimum, std::string(prefix) + " minimum mismatch");
    requireNear(actual.max, maximum, std::string(prefix) + " maximum mismatch");
    requireNear(actual.stddev, stddev, std::string(prefix) + " standard deviation mismatch");
}

void testMemoryAndRunResultValueContract()
{
    const MemoryRunMeasurement memory{1000, 1450, 450};
    require(memory.baselineBytes == 1000, "memory baseline mismatch");
    require(memory.peakSampledBytes == 1450, "memory peak mismatch");
    require(memory.peakDeltaBytes == 450, "memory delta mismatch");

    const ParentRunMemoryMeasurement parentMemory{2, memory};
    require(parentMemory.runIndex == 2 && parentMemory.memory.peakDeltaBytes == 450,
            "parent memory measurement mismatch");

    const RunResult result = runResult(2, 100.5, 40.25, 450);
    require(result.runIndex == 2, "run result index mismatch");
    require(result.totalElapsedTime == RunDuration{301}, "run result elapsed duration mismatch");
    require(result.meanElapsedTimePerOperation.count() == 100.5, "fractional elapsed duration mismatch");
    require(result.totalCpuTime == RunDuration{120}, "run result CPU duration mismatch");
    require(result.meanCpuTimePerOperation.count() == 40.25, "fractional CPU duration mismatch");
        require(std::get<MemoryRunMeasurement>(result.memory).peakDeltaBytes == 450,
            "run result memory mismatch");
}

void testBenchmarkStatisticsFromRunMeans()
{
    const std::array runs{
        runResult(0, 10.0, 4.0, 100),
        runResult(1, 20.0, 8.0, 200),
        runResult(2, 30.0, 12.0, 300)
    };
    const auto statistics = BenchmarkStatisticsCalculator::calculate(runs);
    requireStatistics(statistics.elapsedNanosecondsPerOperation, 20.0, 20.0, 10.0, 30.0, std::sqrt(200.0 / 3.0), "elapsed");
    requireStatistics(statistics.cpuNanosecondsPerOperation, 8.0, 8.0, 4.0, 12.0, std::sqrt(32.0 / 3.0), "CPU");
    requireStatistics(std::get<Statistics<double>>(statistics.memory), 200.0, 200.0, 100.0, 300.0,
                      std::sqrt(20000.0 / 3.0), "memory");
}

void testSingleRunAndEmptyStatistics()
{
    const std::array singleRun{runResult(0, 12.5, 4.25, 75)};
    const auto statistics = BenchmarkStatisticsCalculator::calculate(singleRun);
    requireStatistics(statistics.elapsedNanosecondsPerOperation, 12.5, 12.5, 12.5, 12.5, 0.0, "single elapsed");
    requireStatistics(statistics.cpuNanosecondsPerOperation, 4.25, 4.25, 4.25, 4.25, 0.0, "single CPU");
    requireStatistics(std::get<Statistics<double>>(statistics.memory), 75.0, 75.0, 75.0, 75.0,
                      0.0, "single memory");

    bool rejected = false;
    try {
        static_cast<void>(BenchmarkStatisticsCalculator::calculate(std::span<const RunResult>{}));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "empty benchmark statistics input was accepted");
}

void testBenchmarkResultShapes()
{
    const auto* profile = AlgorithmRegistry::find(AlgorithmProfileId::Sha256);
    require(profile != nullptr, "result test profile was not found");
    const auto characteristics = profile->characteristics;
    const EnvironmentInfo environment{
        "0.1.0", "abc123", "3.6.4", "Windows", "x64", "Debug", std::chrono::system_clock::time_point{}
    };
    const auto completedRuns = std::vector<RunResult>{runResult(0, 10.0, 4.0, 100), runResult(1, 20.0, 8.0, 200)};
    const auto completedStatistics = BenchmarkStatisticsCalculator::calculate(completedRuns);
    const BenchmarkResult completed{
        validConfig(), completedRuns, completedStatistics, characteristics, environment,
        BenchmarkStatus::Completed, std::nullopt
    };
    require(completed.status == BenchmarkStatus::Completed && completed.runs.size() == 2,
            "completed result shape mismatch");
    require(completed.statistics.has_value() && !completed.error.has_value(),
            "completed result optional fields mismatch");

    const ErrorInfo error{ErrorCode::CryptoOperationFailed, FailureStage::Measurement, 1, "failed", std::nullopt};
    const BenchmarkResult failed{
        validConfig(), {completedRuns.front()}, std::nullopt, characteristics, environment,
        BenchmarkStatus::Failed, error
    };
    require(failed.status == BenchmarkStatus::Failed && failed.runs.size() == 1,
            "failed result shape mismatch");
    require(!failed.statistics.has_value() && failed.error.has_value(), "failed result optional fields mismatch");

    const BenchmarkResult cancelled{
        validConfig(), {completedRuns.front()}, std::nullopt, characteristics, environment,
        BenchmarkStatus::Cancelled, std::nullopt
    };
    require(cancelled.status == BenchmarkStatus::Cancelled && cancelled.runs.size() == 1,
            "cancelled result shape mismatch");
    require(!cancelled.statistics.has_value() && !cancelled.error.has_value(),
            "cancelled result optional fields mismatch");
}

void testEnvironmentInfoContract()
{
    const auto* profile = AlgorithmRegistry::find(AlgorithmProfileId::Sha256);
    require(profile != nullptr, "environment test profile was not found");
    const EnvironmentInfo environment{
        "0.1.0", "abc123", "3.6.4", "Windows", "x64", "Debug", std::chrono::system_clock::time_point{}
    };
    const BenchmarkResult result{
        validConfig(), {}, std::nullopt, profile->characteristics, environment,
        BenchmarkStatus::Cancelled, std::nullopt
    };
    require(result.environment.applicationVersion == "0.1.0", "environment version mismatch");
    require(result.environment.gitCommit == "abc123", "environment commit mismatch");
    require(result.environment.opensslVersion == "3.6.4", "environment OpenSSL mismatch");
    require(result.environment.operatingSystem == "Windows", "environment OS mismatch");
    require(result.environment.architecture == "x64", "environment architecture mismatch");
    require(result.environment.buildType == "Debug", "environment build type mismatch");
    require(result.environment.measuredAt == std::chrono::system_clock::time_point{}, "environment timestamp mismatch");
}

} // namespace

int runCoreResultModelTests()
{
    const auto tests = std::array{
        std::pair{"memory and RunResult value contract", &testMemoryAndRunResultValueContract},
        std::pair{"benchmark statistics from run means", &testBenchmarkStatisticsFromRunMeans},
        std::pair{"single-run and empty statistics", &testSingleRunAndEmptyStatistics},
        std::pair{"BenchmarkResult shapes", &testBenchmarkResultShapes},
        std::pair{"EnvironmentInfo contract", &testEnvironmentInfoContract}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS core result model total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
