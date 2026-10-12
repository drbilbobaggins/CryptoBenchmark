#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkStatisticsCalculator.h>
#include <cryptobench/core/ResultAssembler.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

void requireNear(double actual, double expected, std::string_view message)
{
    require(std::abs(actual - expected) <= 1e-12, message);
}

template <typename Function>
void requireAssemblyFailure(Function&& function, std::string_view message)
{
    bool rejected = false;
    try {
        static_cast<void>(function());
    } catch (const ResultAssemblyError&) {
        rejected = true;
    }
    require(rejected, message);
}

BenchmarkConfig validConfig(std::uint64_t iterations = 4, std::uint32_t runs = 3)
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, iterations, runs, HashConfig{64}};
}

EnvironmentInfo environment()
{
    return {"0.1.0", "abc123", "3.6.4", "Windows", "x64", "Debug", {}};
}

StructuralCharacteristics characteristics()
{
    return AlgorithmRegistry::find(AlgorithmProfileId::Sha256)->characteristics;
}

RunResult makeRun(std::uint32_t index, std::uint64_t elapsed, std::uint64_t cpu, std::uint64_t delta = 10)
{
    return ResultAssembler::assembleRun(
        {index, elapsed, cpu},
        {index, {100, 100 + delta, delta}},
        4);
}

MemoryV2RawObservations makeMemoryV2(
    std::uint64_t baseline,
    std::uint64_t ready,
    std::optional<std::uint64_t> preparationPeak,
    std::uint64_t preparationSamples,
    std::optional<std::uint64_t> executionPeak,
    std::uint64_t executionSamples,
    std::uint64_t finalValue)
{
    return {
        baseline,
        ready,
        preparationPeak,
        executionPeak,
        finalValue,
        preparationSamples,
        executionSamples
    };
}

RunResult makeV2Run(
    std::uint32_t index,
    std::uint64_t elapsed,
    std::uint64_t cpu,
    const MemoryV2RawObservations& memory)
{
    return ResultAssembler::assembleRun({index, elapsed, cpu}, memory, index, 4);
}

void testMatchingMergeAndFractionalMeans()
{
    const auto result = ResultAssembler::assembleRun({2, 10, 7}, {2, {100, 100, 0}}, 4);
    require(result.runIndex == 2, "assembled run index mismatch");
    require(result.totalElapsedTime == RunDuration{10}, "assembled elapsed mismatch");
    require(result.totalCpuTime == RunDuration{7}, "assembled CPU mismatch");
        require(std::get<MemoryRunMeasurement>(result.memory).peakDeltaBytes == 0,
            "zero memory delta was not preserved");
    require(result.meanElapsedTimePerOperation.count() == 2.5, "fractional elapsed mean mismatch");
    require(result.meanCpuTimePerOperation.count() == 1.75, "fractional CPU mean mismatch");
}

void testRunMergeRejectsMalformedInput()
{
    requireAssemblyFailure([] { return ResultAssembler::assembleRun({1, 10, 7}, {2, {100, 100, 0}}, 4); }, "run index mismatch was accepted");
    requireAssemblyFailure([] { return ResultAssembler::assembleRun({1, 10, 7}, {1, {100, 100, 0}}, 0); }, "zero iterations were accepted");
    requireAssemblyFailure([] { return ResultAssembler::assembleRun({1, 10, 7}, {1, {101, 100, 1}}, 4); }, "peak below baseline was accepted");
    requireAssemblyFailure([] { return ResultAssembler::assembleRun({1, 10, 7}, {1, {100, 110, 9}}, 4); }, "invalid peak delta was accepted");
    requireAssemblyFailure([] {
        return ResultAssembler::assembleRun(
            {1, static_cast<std::uint64_t>(std::numeric_limits<RunDuration::rep>::max()) + 1, 7},
            {1, {100, 100, 0}}, 4);
    }, "unrepresentable elapsed duration was accepted");
}

void testMemoryV2RunAssembly()
{
    const auto result = makeV2Run(
        2,
        10,
        7,
        makeMemoryV2(100, 80, 150, 1, 130, 1, 120));
    require(result.runIndex == 2, "Memory v2 run index mismatch");
    require(result.meanElapsedTimePerOperation.count() == 2.5,
            "Memory v2 fractional elapsed mean mismatch");
    require(result.meanCpuTimePerOperation.count() == 1.75,
            "Memory v2 fractional CPU mean mismatch");
        require(std::holds_alternative<MemoryV2RunMeasurement>(result.memory),
            "Memory v2 run did not retain v2 data");
        const auto& memory = std::get<MemoryV2RunMeasurement>(result.memory);
        require(memory.derived.readyStateDelta == -20,
            "Memory v2 signed ReadyState delta mismatch");
        require(memory.derived.preparationPeakDelta == 50 &&
            memory.derived.executionPeakDelta == 30 &&
            memory.derived.operationalPeakDelta == 50,
            "Memory v2 derived peak deltas mismatch");
}

void testMemoryV2RunRejectsMalformedInput()
{
    const auto valid = makeMemoryV2(100, 100, std::nullopt, 0, std::nullopt, 0, 100);
    requireAssemblyFailure(
        [&] { return ResultAssembler::assembleRun({2, 10, 7}, valid, 1, 4); },
        "unexpected Memory v2 run index was accepted");
    requireAssemblyFailure(
        [&] { return ResultAssembler::assembleRun({1, 10, 7}, valid, 1, 0); },
        "zero iterations were accepted for Memory v2");
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::assembleRun(
                {1, 10, 7}, makeMemoryV2(100, 100, 0, 0, std::nullopt, 0, 100), 1, 4);
        },
        "inconsistent preparation sample count was accepted");
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::assembleRun(
                {1, 10, 7},
                makeMemoryV2(0, std::numeric_limits<std::uint64_t>::max(), std::nullopt, 0,
                             std::nullopt, 0, 0),
                1,
                4);
        },
        "overflowing Memory v2 ReadyState delta was accepted");
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::assembleRun(
                {1, static_cast<std::uint64_t>(std::numeric_limits<RunDuration::rep>::max()) + 1, 7},
                valid,
                1,
                4);
        },
        "unrepresentable Memory v2 elapsed duration was accepted");
}

void testMemoryV2BoundaryOnlyNonzeroPeaks()
{
    const auto requireBoundaryCase = [](const MemoryV2RawObservations& observations,
                                        std::int64_t expectedReadyStateDelta,
                                        std::uint64_t expectedPreparationPeakDelta,
                                        std::uint64_t expectedExecutionPeakDelta,
                                        std::uint64_t expectedOperationalPeakDelta,
                                        std::string_view message) {
        const auto result = ResultAssembler::assembleRun(
            {0, 40, 8}, observations, 0, 4);
        const auto& memory = std::get<MemoryV2RunMeasurement>(result.memory);
        require(memory.raw.preparationSampleCount == 0 &&
                    memory.raw.executionSampleCount == 0 &&
                    !memory.raw.preparationPeakSampledPrivateUsageBytes.has_value() &&
                    !memory.raw.executionPeakSampledPrivateUsageBytes.has_value(),
                message);
        require(memory.derived.readyStateDelta == expectedReadyStateDelta &&
                    memory.derived.preparationPeakDelta == expectedPreparationPeakDelta &&
                    memory.derived.executionPeakDelta == expectedExecutionPeakDelta &&
                    memory.derived.operationalPeakDelta == expectedOperationalPeakDelta,
                message);
    };

    requireBoundaryCase(
        makeMemoryV2(100, 140, std::nullopt, 0, std::nullopt, 0, 120),
        40,
        40,
        40,
        40,
        "boundary-only case A mismatch");
    requireBoundaryCase(
        makeMemoryV2(100, 110, std::nullopt, 0, std::nullopt, 0, 160),
        10,
        10,
        60,
        60,
        "boundary-only case B mismatch");
}

void testMemoryV2CompletedStatistics()
{
    const std::array runs{
        makeV2Run(0, 40, 8, makeMemoryV2(100, 70, 120, 1, 130, 1, 110)),
        makeV2Run(1, 80, 16, makeMemoryV2(100, 80, 150, 1, 150, 1, 120)),
        makeV2Run(2, 120, 24, makeMemoryV2(100, 90, std::nullopt, 0, 160, 1, 105))
    };
    const auto result = ResultAssembler::completed(validConfig(), runs, characteristics(), environment());
        require(result.config.iterationsPerRun == 4 && result.config.runs == 3,
            "Memory v2 completed result changed configured N or M");
    require(result.statistics.has_value(), "Memory v2 completed result has no statistics");
    const auto& statistics = *result.statistics;
        require(std::holds_alternative<MemoryV2Statistics>(statistics.memory),
            "Memory v2 statistic families are incomplete");
        const auto& memory = std::get<MemoryV2Statistics>(statistics.memory);
        const auto& ready = memory.readyStatePrivateUsageDeltaBytes;
        require(ready.mean == -20.0 && ready.median == -20.0 && ready.min == -30.0 && ready.max == -10.0,
            "signed ReadyState statistics mismatch");
        requireNear(ready.stddev, std::sqrt(200.0 / 3.0), "signed ReadyState standard deviation mismatch");
    const auto& preparation = memory.preparationPeakPrivateUsageDeltaBytes;
        requireNear(preparation.mean, 70.0 / 3.0, "preparation mean mismatch");
        require(preparation.median == 20.0 && preparation.min == 0.0 && preparation.max == 50.0,
            "preparation peak statistics mismatch");
        requireNear(preparation.stddev, std::sqrt(11400.0 / 27.0),
            "preparation standard deviation mismatch");
    const auto& execution = memory.executionPeakPrivateUsageDeltaBytes;
        requireNear(execution.mean, 140.0 / 3.0, "execution mean mismatch");
        require(execution.median == 50.0 && execution.min == 30.0 && execution.max == 60.0,
            "execution peak statistics mismatch");
        requireNear(execution.stddev, std::sqrt(4200.0 / 27.0),
            "execution standard deviation mismatch");
    const auto& operational = memory.operationalPeakPrivateUsageDeltaBytes;
        requireNear(operational.mean, 140.0 / 3.0, "operational mean mismatch");
        require(operational.median == 50.0 && operational.min == 30.0 && operational.max == 60.0,
            "operational peak statistics mismatch");
        requireNear(operational.stddev, execution.stddev, "operational standard deviation mismatch");
        require(!std::holds_alternative<Statistics<double>>(statistics.memory),
            "Memory v2 statistics exposed a fabricated legacy peak family");

        requireAssemblyFailure(
            [&] {
                return ResultAssembler::completed(
                    validConfig(), std::array{runs[0], runs[2], runs[1]}, characteristics(), environment());
            },
            "out-of-order Memory v2 series was accepted");
}

void testMemoryV2SingleRunAndMixedSeriesRejection()
{
    const auto singleRun = makeV2Run(
        0,
        40,
        8,
        makeMemoryV2(100, 100, std::nullopt, 0, std::nullopt, 0, 100));
    const auto single = ResultAssembler::completed(
        validConfig(4, 1), std::array{singleRun}, characteristics(), environment());
    require(single.statistics.has_value(), "single Memory v2 run has no statistics");
    const auto& singleMemory = std::get<MemoryV2Statistics>(single.statistics->memory);
    require(singleMemory.readyStatePrivateUsageDeltaBytes.stddev == 0.0 &&
                singleMemory.preparationPeakPrivateUsageDeltaBytes.stddev == 0.0 &&
                singleMemory.executionPeakPrivateUsageDeltaBytes.stddev == 0.0 &&
                singleMemory.operationalPeakPrivateUsageDeltaBytes.stddev == 0.0,
            "single Memory v2 run did not produce zero standard deviation");
    const auto& boundaryMemory = std::get<MemoryV2RunMeasurement>(singleRun.memory);
    require(boundaryMemory.raw.preparationSampleCount == 0 &&
                boundaryMemory.raw.executionSampleCount == 0 &&
                !boundaryMemory.raw.preparationPeakSampledPrivateUsageBytes.has_value() &&
                !boundaryMemory.raw.executionPeakSampledPrivateUsageBytes.has_value(),
            "boundary-only Memory v2 run fabricated optional sampled peaks");

    const auto legacyRun = makeRun(1, 80, 16);
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::completed(
                validConfig(4, 2), std::array{singleRun, legacyRun}, characteristics(), environment());
        },
        "mixed legacy and Memory v2 series was accepted");
}

void testMemoryV2CompleteSeriesRejectsIncompleteDuplicateAndOutOfOrder()
{
    const std::array runs{
        makeV2Run(0, 40, 8, makeMemoryV2(100, 100, std::nullopt, 0, std::nullopt, 0, 100)),
        makeV2Run(1, 80, 16, makeMemoryV2(100, 110, std::nullopt, 0, std::nullopt, 0, 110)),
        makeV2Run(2, 120, 24, makeMemoryV2(100, 90, std::nullopt, 0, std::nullopt, 0, 120))
    };

    requireAssemblyFailure(
        [&] {
            return ResultAssembler::completed(
                validConfig(4, 3), std::array{runs[0], runs[1]}, characteristics(), environment());
        },
        "incomplete Memory v2 series was accepted");
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::completed(
                validConfig(4, 3), std::array{runs[0], runs[1], runs[1]}, characteristics(), environment());
        },
        "duplicate Memory v2 series was accepted");
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::completed(
                validConfig(4, 3), std::array{runs[0], runs[2], runs[1]}, characteristics(), environment());
        },
        "out-of-order Memory v2 series was accepted");
}

void testMemoryV2TamperedDerivedMetricsRejected()
{
    auto tampered = makeV2Run(
        0,
        40,
        8,
        makeMemoryV2(100, 90, std::nullopt, 0, std::nullopt, 0, 100));
    auto& derived = std::get<MemoryV2RunMeasurement>(tampered.memory).derived;
    ++derived.readyStateDelta;
    requireAssemblyFailure(
        [&] {
            return ResultAssembler::completed(
                validConfig(4, 1), std::array{tampered}, characteristics(), environment());
        },
        "tampered Memory v2 derived metrics were accepted");
}

void testMemoryV2FailedAndCancelledPrefixes()
{
    const auto run0 = makeV2Run(
        0, 40, 8, makeMemoryV2(100, 90, std::nullopt, 0, std::nullopt, 0, 100));
    const auto run1 = makeV2Run(
        1, 80, 16, makeMemoryV2(100, 80, 120, 1, std::nullopt, 0, 110));
    const ErrorInfo error{ErrorCode::CryptoOperationFailed, FailureStage::Measurement,
                          2, "failed", std::nullopt};
    const auto failed = ResultAssembler::failed(
        validConfig(), std::array{run0, run1}, characteristics(), environment(), error);
    require(failed.status == BenchmarkStatus::Failed && failed.runs.size() == 2 &&
                !failed.statistics.has_value(),
            "valid Memory v2 failed prefix was not preserved correctly");
    const auto cancelled = ResultAssembler::cancelled(
        validConfig(), std::array{run0, run1}, characteristics(), environment());
    require(cancelled.status == BenchmarkStatus::Cancelled && cancelled.runs.size() == 2 &&
                !cancelled.statistics.has_value(),
            "valid Memory v2 cancelled prefix was not preserved correctly");
}

void testCompletedAssembly()
{
    const std::array runs{makeRun(0, 40, 8, 10), makeRun(1, 80, 16, 20), makeRun(2, 120, 24, 30)};
    const auto result = ResultAssembler::completed(validConfig(), runs, characteristics(), environment());
    const auto expectedStatistics = BenchmarkStatisticsCalculator::calculate(runs);
    require(result.status == BenchmarkStatus::Completed, "completed status mismatch");
    require(result.config.runs == 3 && result.runs.size() == 3, "completed run count mismatch");
    require(result.statistics.has_value() && !result.error.has_value(), "completed optional fields mismatch");
    require(result.statistics->elapsedNanosecondsPerOperation.mean == expectedStatistics.elapsedNanosecondsPerOperation.mean,
            "completed statistics mismatch");
    require(std::holds_alternative<HashCharacteristics>(result.characteristics) &&
                std::get<HashCharacteristics>(result.characteristics).outputBytes ==
                    std::get<HashCharacteristics>(characteristics()).outputBytes,
            "completed characteristics mismatch");
    require(result.environment.gitCommit == "abc123", "completed environment mismatch");
}

void testCompletedAssemblyRejectsInvalidSequences()
{
    const auto run0 = makeRun(0, 40, 8);
    const auto run1 = makeRun(1, 80, 16);
    const auto run2 = makeRun(2, 120, 24);
    requireAssemblyFailure([&] { return ResultAssembler::completed(validConfig(), std::array{run0, run1}, characteristics(), environment()); }, "short completed result was accepted");
    requireAssemblyFailure([&] { return ResultAssembler::completed(validConfig(), std::array{run0, run1, run2, run2}, characteristics(), environment()); }, "long completed result was accepted");
    requireAssemblyFailure([&] { return ResultAssembler::completed(validConfig(), std::array{run0, run2, run1}, characteristics(), environment()); }, "out-of-order completed result was accepted");
    requireAssemblyFailure([&] { return ResultAssembler::completed(validConfig(0), std::array{run0, run1, run2}, characteristics(), environment()); }, "zero-iteration completed result was accepted");
}

void testFailedAndCancelledAssembly()
{
    const auto run0 = makeRun(0, 40, 8);
    const auto run1 = makeRun(1, 80, 16);
    const ErrorInfo error{ErrorCode::CryptoOperationFailed, FailureStage::Measurement, 2, "failed", std::nullopt};
    const auto failed = ResultAssembler::failed(validConfig(), std::array{run0, run1}, characteristics(), environment(), error);
    require(failed.status == BenchmarkStatus::Failed && failed.runs.size() == 2, "failed result mismatch");
    require(!failed.statistics.has_value() && failed.error.has_value() &&
                failed.error->code == error.code && failed.error->stage == error.stage &&
                failed.error->runIndex == error.runIndex &&
                failed.error->technicalMessage == error.technicalMessage,
            "failed optional fields mismatch");
        const auto failedWithoutRuns = ResultAssembler::failed(validConfig(), std::span<const RunResult>{}, characteristics(), environment(), error);
        require(failedWithoutRuns.status == BenchmarkStatus::Failed && failedWithoutRuns.runs.empty(), "empty failed result mismatch");
        require(!failedWithoutRuns.statistics.has_value() && failedWithoutRuns.error.has_value() &&
                    failedWithoutRuns.error->code == error.code && failedWithoutRuns.error->stage == error.stage &&
                    failedWithoutRuns.error->runIndex == error.runIndex &&
                    failedWithoutRuns.error->technicalMessage == error.technicalMessage,
            "empty failed result optional fields mismatch");
        requireAssemblyFailure([&] { return ResultAssembler::failed(validConfig(0), std::span<const RunResult>{}, characteristics(), environment(), error); }, "zero-iteration failed result was accepted");
        const auto cancelledPrefix = ResultAssembler::cancelled(validConfig(), std::array{run0, run1}, characteristics(), environment());
        require(cancelledPrefix.status == BenchmarkStatus::Cancelled && cancelledPrefix.runs.size() == 2,
            "cancelled prefix result mismatch");
        require(cancelledPrefix.runs[0].runIndex == 0 && cancelledPrefix.runs[1].runIndex == 1,
            "cancelled prefix runs were not preserved");
        require(!cancelledPrefix.statistics.has_value() && !cancelledPrefix.error.has_value(),
            "cancelled prefix optional fields mismatch");
        const auto cancelled = ResultAssembler::cancelled(validConfig(), std::span<const RunResult>{}, characteristics(), environment());
        require(cancelled.status == BenchmarkStatus::Cancelled && cancelled.runs.empty(), "cancelled result mismatch");
        require(!cancelled.statistics.has_value() && !cancelled.error.has_value(), "cancelled optional fields mismatch");
        requireAssemblyFailure([&] { return ResultAssembler::cancelled(validConfig(0), std::span<const RunResult>{}, characteristics(), environment()); }, "zero-iteration cancelled result was accepted");
    requireAssemblyFailure([&] { return ResultAssembler::failed(validConfig(), std::array{run0, run1, run0}, characteristics(), environment(), error); }, "invalid failed prefix was accepted");
    requireAssemblyFailure([&] { return ResultAssembler::cancelled(validConfig(), std::array{run1}, characteristics(), environment()); }, "invalid cancelled prefix was accepted");
}

} // namespace

int runResultAssemblerTests()
{
    const auto tests = std::array{
        std::pair{"matching run merge and fractional means", &testMatchingMergeAndFractionalMeans},
        std::pair{"run merge rejects malformed input", &testRunMergeRejectsMalformedInput},
        std::pair{"Memory v2 run assembly", &testMemoryV2RunAssembly},
        std::pair{"Memory v2 run rejects malformed input", &testMemoryV2RunRejectsMalformedInput},
        std::pair{"Memory v2 boundary-only nonzero peaks", &testMemoryV2BoundaryOnlyNonzeroPeaks},
        std::pair{"Memory v2 completed statistics", &testMemoryV2CompletedStatistics},
        std::pair{"Memory v2 single run and mixed series rejection", &testMemoryV2SingleRunAndMixedSeriesRejection},
        std::pair{"Memory v2 complete series rejection", &testMemoryV2CompleteSeriesRejectsIncompleteDuplicateAndOutOfOrder},
        std::pair{"Memory v2 tampered derived metrics rejection", &testMemoryV2TamperedDerivedMetricsRejected},
        std::pair{"Memory v2 failed and cancelled prefixes", &testMemoryV2FailedAndCancelledPrefixes},
        std::pair{"completed assembly", &testCompletedAssembly},
        std::pair{"completed assembly rejects invalid sequences", &testCompletedAssemblyRejectsInvalidSequences},
        std::pair{"failed and cancelled assembly", &testFailedAndCancelledAssembly}
    };
    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS result assembler total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
