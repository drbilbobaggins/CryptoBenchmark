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

void testMatchingMergeAndFractionalMeans()
{
    const auto result = ResultAssembler::assembleRun({2, 10, 7}, {2, {100, 100, 0}}, 4);
    require(result.runIndex == 2, "assembled run index mismatch");
    require(result.totalElapsedTime == RunDuration{10}, "assembled elapsed mismatch");
    require(result.totalCpuTime == RunDuration{7}, "assembled CPU mismatch");
    require(result.memory.peakDeltaBytes == 0, "zero memory delta was not preserved");
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
