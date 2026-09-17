#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/ProgressInfo.h>
#include <cryptobench/core/WorkerRunMeasurement.h>

namespace cryptobench::ipc {

struct WorkerReady {
    std::uint32_t protocolVersion;
};

struct BenchmarkRequest {
    core::BenchmarkConfig config;
};

using Progress = core::ProgressInfo;
using WorkerRunMeasurement = core::WorkerRunMeasurement;

enum class WorkerOutcomeStatus : std::uint8_t {
    Completed,
    Failed
};

struct WorkerOutcome {
    WorkerOutcomeStatus status;
    std::optional<core::ErrorInfo> error;
};

} // namespace cryptobench::ipc
