#pragma once

#include <cstdint>
#include <optional>

#include <cryptobench/core/BenchmarkTask.h>
#include <cryptobench/core/ProcessCpuTimeSource.h>
#include <cryptobench/core/ProgressSink.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>

namespace cryptobench::core {

class BenchmarkRunner {
public:
    BenchmarkRunner(
        BenchmarkTask& task,
        ProgressSink& progressSink,
        RunMeasurementCoordinator& measurementCoordinator,
        ProcessCpuTimeSource& cpuTimeSource);

    void run();
    void prepareLogicalRun(std::uint32_t logicalRunIndex);
    WorkerRunMeasurement measureLogicalRun(std::uint32_t logicalRunIndex);

private:
    void validateLogicalRunIndex(std::uint32_t logicalRunIndex) const;
    void prepareSeries(std::optional<std::uint32_t> runIndex);
    void prepareRun(std::uint32_t runIndex);
    WorkerRunMeasurement measure(std::uint32_t runIndex);

    BenchmarkTask& task_;
    ProgressSink& progressSink_;
    RunMeasurementCoordinator& measurementCoordinator_;
    ProcessCpuTimeSource& cpuTimeSource_;
    std::optional<std::uint32_t> logicalRunIndex_;
    bool logicalRunPrepared_ = false;
    bool logicalRunMeasurementStarted_ = false;
};

} // namespace cryptobench::core
