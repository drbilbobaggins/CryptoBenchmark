#include <cryptobench/core/BenchmarkRunner.h>

#include <chrono>
#include <cstdint>
#include <optional>

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

    progressSink_.reportProgress({BenchmarkPhase::Preparing, std::nullopt, config.runs});
    adapter.prepareSeries();

    for (std::uint32_t runIndex = 0; runIndex < config.runs; ++runIndex) {
        adapter.prepareRun();
        progressSink_.reportProgress({BenchmarkPhase::Warmup, runIndex, config.runs});
        adapter.executeIteration();

        measurementCoordinator_.beforeMeasurement(runIndex);
        const auto cpuBefore = cpuTimeSource_.currentProcessCpuTimeNanoseconds();
        const auto wallStart = std::chrono::steady_clock::now();
        for (std::uint64_t iteration = 0; iteration < config.iterationsPerRun; ++iteration) {
            adapter.executeIteration();
        }
        const auto wallStop = std::chrono::steady_clock::now();
        const auto cpuAfter = cpuTimeSource_.currentProcessCpuTimeNanoseconds();

        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(wallStop - wallStart);
        measurementCoordinator_.afterMeasurement({
            runIndex,
            static_cast<std::uint64_t>(elapsed.count()),
            cpuAfter - cpuBefore
        });
    }

    progressSink_.reportProgress({BenchmarkPhase::Finalizing, std::nullopt, config.runs});
}

} // namespace cryptobench::core
