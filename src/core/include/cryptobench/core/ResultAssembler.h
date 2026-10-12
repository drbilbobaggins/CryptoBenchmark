#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/MemoryRunMeasurement.h>
#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/WorkerRunMeasurement.h>

namespace cryptobench::core {

class ResultAssemblyError : public std::runtime_error {
public:
    explicit ResultAssemblyError(std::string message)
        : std::runtime_error(std::move(message))
    {
    }
};

class ResultAssembler {
public:
    static RunResult assembleRun(
        const WorkerRunMeasurement& worker,
        const ParentRunMemoryMeasurement& memory,
        std::uint64_t iterationsPerRun);

    static RunResult assembleRun(
        const WorkerRunMeasurement& worker,
        const MemoryV2RawObservations& memory,
        std::uint32_t expectedLogicalRunIndex,
        std::uint64_t iterationsPerRun);

    static BenchmarkResult completed(
        BenchmarkConfig config,
        std::span<const RunResult> runs,
        StructuralCharacteristics characteristics,
        EnvironmentInfo environment);

    static BenchmarkResult failed(
        BenchmarkConfig config,
        std::span<const RunResult> runs,
        StructuralCharacteristics characteristics,
        EnvironmentInfo environment,
        ErrorInfo error);

    static BenchmarkResult cancelled(
        BenchmarkConfig config,
        std::span<const RunResult> runs,
        StructuralCharacteristics characteristics,
        EnvironmentInfo environment);
};

} // namespace cryptobench::core
