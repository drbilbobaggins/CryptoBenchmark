#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/RunnerFailure.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

using cryptobench::core::FailureStage;
using cryptobench::core::RunnerFailure;

[[noreturn]] void rethrowWithRunnerContext(
    FailureStage stage,
    std::optional<std::uint32_t> runIndex)
{
    try {
        throw;
    } catch (const RunnerFailure&) {
        throw;
    } catch (const std::exception& error) {
        std::throw_with_nested(RunnerFailure(stage, runIndex, error.what()));
    } catch (...) {
        std::throw_with_nested(RunnerFailure(
            stage,
            runIndex,
            "Unknown benchmark runner failure"));
    }
}

} // namespace

namespace cryptobench::core {

BenchmarkRunner::BenchmarkRunner(
    BenchmarkTask& task,
    ProgressSink& progressSink,
    RunMeasurementCoordinator& measurementCoordinator,
    ProcessCpuTimeSource& cpuTimeSource)
    : task_(task),
      progressSink_(progressSink),
      measurementCoordinator_(measurementCoordinator),
      cpuTimeSource_(cpuTimeSource)
{
}

void BenchmarkRunner::run()
{
    const auto& config = task_.config().value();

    try {
        progressSink_.reportProgress({BenchmarkPhase::Preparing, std::nullopt, config.runs});
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, std::nullopt);
    }
    prepareSeries(std::nullopt);

    for (std::uint32_t runIndex = 0; runIndex < config.runs; ++runIndex) {
        prepareRun(runIndex);
        static_cast<void>(measure(runIndex));
    }

    try {
        progressSink_.reportProgress({BenchmarkPhase::Finalizing, std::nullopt, config.runs});
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, std::nullopt);
    }
}

void BenchmarkRunner::validateLogicalRunIndex(std::uint32_t logicalRunIndex) const
{
    if (logicalRunIndex >= task_.config().value().runs) {
        throw std::invalid_argument("logicalRunIndex is outside benchmark runs");
    }
}

void BenchmarkRunner::prepareLogicalRun(std::uint32_t logicalRunIndex)
{
    validateLogicalRunIndex(logicalRunIndex);
    if (logicalRunIndex_ || logicalRunPrepared_) {
        throw std::logic_error("logical run preparation was already started");
    }

    logicalRunIndex_ = logicalRunIndex;
    prepareSeries(logicalRunIndex);
    prepareRun(logicalRunIndex);
    logicalRunPrepared_ = true;
}

WorkerRunMeasurement BenchmarkRunner::measureLogicalRun(std::uint32_t logicalRunIndex)
{
    validateLogicalRunIndex(logicalRunIndex);
    if (!logicalRunIndex_ || *logicalRunIndex_ != logicalRunIndex || !logicalRunPrepared_) {
        throw std::logic_error("logical run was not prepared");
    }
    if (logicalRunMeasurementStarted_) {
        throw std::logic_error("logical run measurement was already started");
    }

    logicalRunMeasurementStarted_ = true;
    return measure(logicalRunIndex);
}

void BenchmarkRunner::prepareSeries(std::optional<std::uint32_t> runIndex)
{
    try {
        task_.adapter().prepareSeries();
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::SeriesPreparation, runIndex);
    }
}

void BenchmarkRunner::prepareRun(std::uint32_t runIndex)
{
    const auto& config = task_.config().value();
    try {
        task_.adapter().prepareRun();
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::RunPreparation, runIndex);
    }
    try {
        progressSink_.reportProgress({BenchmarkPhase::Warmup, runIndex, config.runs});
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, runIndex);
    }
    try {
        task_.adapter().executeIteration();
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::Warmup, runIndex);
    }
}

WorkerRunMeasurement BenchmarkRunner::measure(std::uint32_t runIndex)
{
    const auto& config = task_.config().value();
    try {
        measurementCoordinator_.beforeMeasurement(runIndex);
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, runIndex);
    }

    WorkerRunMeasurement measurement{};
    try {
        const auto cpuBefore = cpuTimeSource_.currentProcessCpuTimeNanoseconds();
        const auto wallStart = std::chrono::steady_clock::now();
        for (std::uint64_t iteration = 0; iteration < config.iterationsPerRun; ++iteration) {
            task_.adapter().executeIteration();
        }
        const auto wallStop = std::chrono::steady_clock::now();
        const auto cpuAfter = cpuTimeSource_.currentProcessCpuTimeNanoseconds();

        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(wallStop - wallStart);
        measurement = {
            runIndex,
            static_cast<std::uint64_t>(elapsed.count()),
            cpuAfter - cpuBefore
        };
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::Measurement, runIndex);
    }

    try {
        measurementCoordinator_.afterMeasurement(measurement);
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, runIndex);
    }
    return measurement;
}

} // namespace cryptobench::core
