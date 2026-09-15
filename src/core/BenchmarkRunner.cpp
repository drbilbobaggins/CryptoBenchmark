#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/RunnerFailure.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
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
    auto& adapter = task_.adapter();

    try {
        progressSink_.reportProgress({BenchmarkPhase::Preparing, std::nullopt, config.runs});
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, std::nullopt);
    }
    try {
        adapter.prepareSeries();
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::SeriesPreparation, std::nullopt);
    }

    for (std::uint32_t runIndex = 0; runIndex < config.runs; ++runIndex) {
        try {
            adapter.prepareRun();
        } catch (...) {
            rethrowWithRunnerContext(FailureStage::RunPreparation, runIndex);
        }
        try {
            progressSink_.reportProgress({BenchmarkPhase::Warmup, runIndex, config.runs});
        } catch (...) {
            rethrowWithRunnerContext(FailureStage::WorkerCommunication, runIndex);
        }
        try {
            adapter.executeIteration();
        } catch (...) {
            rethrowWithRunnerContext(FailureStage::Warmup, runIndex);
        }

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
                adapter.executeIteration();
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
    }

    try {
        progressSink_.reportProgress({BenchmarkPhase::Finalizing, std::nullopt, config.runs});
    } catch (...) {
        rethrowWithRunnerContext(FailureStage::WorkerCommunication, std::nullopt);
    }
}

} // namespace cryptobench::core
