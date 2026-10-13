#include <cryptobench/core/ResultAssembler.h>

#include <limits>
#include <string>
#include <type_traits>
#include <utility>

#include <cryptobench/core/BenchmarkStatisticsCalculator.h>
#include <cryptobench/core/MemoryV2Calculator.h>

namespace cryptobench::core {
namespace {

[[noreturn]] void fail(std::string message)
{
    throw ResultAssemblyError(std::move(message));
}

bool fitsRunDuration(std::uint64_t value)
{
    using Rep = RunDuration::rep;
    if constexpr (std::is_signed_v<Rep>) {
        return value <= static_cast<std::uintmax_t>(std::numeric_limits<Rep>::max());
    } else {
        return value <= static_cast<std::uintmax_t>(std::numeric_limits<Rep>::max()) &&
               std::numeric_limits<Rep>::max() >= value;
    }
}

void validateMemory(const MemoryRunMeasurement& memory)
{
    if (memory.peakSampledBytes < memory.baselineBytes) {
        fail("Peak sampled memory is below the baseline");
    }

    if (memory.peakDeltaBytes != memory.peakSampledBytes - memory.baselineBytes) {
        fail("Peak memory delta does not match baseline and peak memory");
    }
}

MemoryV2RunMeasurement validateMemoryV2(
    const MemoryV2RawObservations& raw,
    const MemoryV2DerivedMetrics* expectedDerived = nullptr)
{
    const auto derived = calculateMemoryV2DerivedMetrics(raw);
    if (!derived.has_value()) {
        fail("Memory v2 observations are invalid");
    }
    if (expectedDerived != nullptr &&
        (expectedDerived->readyStateDelta != derived->readyStateDelta ||
         expectedDerived->preparationPeakDelta != derived->preparationPeakDelta ||
         expectedDerived->executionPeakDelta != derived->executionPeakDelta ||
         expectedDerived->operationalPeakDelta != derived->operationalPeakDelta)) {
        fail("Memory v2 derived metrics do not match raw observations");
    }
    return {raw, *derived};
}

void validateConfig(const BenchmarkConfig& config)
{
    if (config.iterationsPerRun == 0) {
        fail("Iterations per run must be non-zero");
    }
}

void validateRunSequence(const BenchmarkConfig& config, std::span<const RunResult> runs)
{
    const bool v2 = !runs.empty() &&
        std::holds_alternative<MemoryV2RunMeasurement>(runs.front().memory);
    for (std::size_t position = 0; position < runs.size(); ++position) {
        const auto& run = runs[position];
        if (position >= config.runs || run.runIndex != position) {
            fail("Run results do not form a sequential configured prefix");
        }
        if (std::holds_alternative<MemoryV2RunMeasurement>(run.memory) != v2) {
            fail("Run results cannot mix legacy and Memory v2 measurements");
        }
        if (v2) {
            const auto& memory = std::get<MemoryV2RunMeasurement>(run.memory);
            static_cast<void>(validateMemoryV2(memory.raw, &memory.derived));
        } else {
            validateMemory(std::get<MemoryRunMeasurement>(run.memory));
        }
    }
}

} // namespace

RunResult ResultAssembler::assembleRun(
    const WorkerRunMeasurement& worker,
    const ParentRunMemoryMeasurement& memory,
    std::uint64_t iterationsPerRun)
{
    if (worker.runIndex != memory.runIndex) {
        fail("Worker and parent measurements have different run indices");
    }
    if (iterationsPerRun == 0) {
        fail("Iterations per run must be non-zero");
    }
    if (!fitsRunDuration(worker.elapsedNanoseconds) || !fitsRunDuration(worker.processCpuNanoseconds)) {
        fail("Worker duration does not fit RunDuration");
    }
    validateMemory(memory.memory);

    return {
        worker.runIndex,
        RunDuration{static_cast<RunDuration::rep>(worker.elapsedNanoseconds)},
        MeanOperationDuration{static_cast<double>(worker.elapsedNanoseconds) / static_cast<double>(iterationsPerRun)},
        RunDuration{static_cast<RunDuration::rep>(worker.processCpuNanoseconds)},
        MeanOperationDuration{static_cast<double>(worker.processCpuNanoseconds) / static_cast<double>(iterationsPerRun)},
        memory.memory
    };
}

RunResult ResultAssembler::assembleRun(
    const WorkerRunMeasurement& worker,
    const MemoryV2RawObservations& memory,
    std::uint32_t expectedLogicalRunIndex,
    std::uint64_t iterationsPerRun)
{
    if (worker.runIndex != expectedLogicalRunIndex) {
        fail("Worker measurement has an unexpected logical run index");
    }
    if (iterationsPerRun == 0) {
        fail("Iterations per run must be non-zero");
    }
    if (!fitsRunDuration(worker.elapsedNanoseconds) || !fitsRunDuration(worker.processCpuNanoseconds)) {
        fail("Worker duration does not fit RunDuration");
    }

    const auto memoryV2 = validateMemoryV2(memory);
    return {
        worker.runIndex,
        RunDuration{static_cast<RunDuration::rep>(worker.elapsedNanoseconds)},
        MeanOperationDuration{static_cast<double>(worker.elapsedNanoseconds) / static_cast<double>(iterationsPerRun)},
        RunDuration{static_cast<RunDuration::rep>(worker.processCpuNanoseconds)},
        MeanOperationDuration{static_cast<double>(worker.processCpuNanoseconds) / static_cast<double>(iterationsPerRun)},
        memoryV2
    };
}

BenchmarkResult ResultAssembler::completed(
    BenchmarkConfig config,
    std::span<const RunResult> runs,
    StructuralCharacteristics characteristics,
    EnvironmentInfo environment)
{
    validateConfig(config);
    if (runs.size() != config.runs) {
        fail("Completed result does not contain exactly the configured run count");
    }
    validateRunSequence(config, runs);
    if (runs.empty()) {
        fail("Completed result requires at least one run");
    }

    std::vector<RunResult> storedRuns(runs.begin(), runs.end());
    return {
        std::move(config),
        std::move(storedRuns),
        BenchmarkStatisticsCalculator::calculate(runs),
        std::move(characteristics),
        std::move(environment),
        BenchmarkStatus::Completed,
        std::nullopt
    };
}

BenchmarkResult ResultAssembler::failed(
    BenchmarkConfig config,
    std::span<const RunResult> runs,
    StructuralCharacteristics characteristics,
    EnvironmentInfo environment,
    ErrorInfo error)
{
    validateConfig(config);
    validateRunSequence(config, runs);
    return {
        std::move(config),
        std::vector<RunResult>(runs.begin(), runs.end()),
        std::nullopt,
        std::move(characteristics),
        std::move(environment),
        BenchmarkStatus::Failed,
        std::move(error)
    };
}

BenchmarkResult ResultAssembler::cancelled(
    BenchmarkConfig config,
    std::span<const RunResult> runs,
    StructuralCharacteristics characteristics,
    EnvironmentInfo environment)
{
    validateConfig(config);
    validateRunSequence(config, runs);
    return {
        std::move(config),
        std::vector<RunResult>(runs.begin(), runs.end()),
        std::nullopt,
        std::move(characteristics),
        std::move(environment),
        BenchmarkStatus::Cancelled,
        std::nullopt
    };
}

} // namespace cryptobench::core
