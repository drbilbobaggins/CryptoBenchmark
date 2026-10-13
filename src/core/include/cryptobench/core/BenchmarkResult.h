#pragma once

#include <optional>
#include <vector>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkStatistics.h>
#include <cryptobench/core/BenchmarkStatus.h>
#include <cryptobench/core/EnvironmentInfo.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/RunResult.h>
#include <cryptobench/core/StructuralCharacteristics.h>

namespace cryptobench::core {

struct BenchmarkResult {
    BenchmarkConfig config;
    std::vector<RunResult> runs;
    std::optional<BenchmarkStatistics> statistics;
    StructuralCharacteristics characteristics;
    EnvironmentInfo environment;
    BenchmarkStatus status;
    std::optional<ErrorInfo> error;
    std::optional<MeasurementSettings> measurementSettings;
};

} // namespace cryptobench::core
