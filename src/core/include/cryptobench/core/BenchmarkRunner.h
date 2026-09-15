#pragma once

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

private:
    BenchmarkTask& task_;
    ProgressSink& progressSink_;
    RunMeasurementCoordinator& measurementCoordinator_;
    ProcessCpuTimeSource& cpuTimeSource_;
};

} // namespace cryptobench::core
