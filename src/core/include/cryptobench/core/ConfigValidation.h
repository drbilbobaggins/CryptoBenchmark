#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <cryptobench/core/BenchmarkConfig.h>

namespace cryptobench::core {

constexpr std::uint64_t kMinIterationsPerRun = 1;
constexpr std::uint64_t kMaxIterationsPerRun = 1'000'000'000ULL;

constexpr std::uint32_t kMinRuns = 1;
constexpr std::uint32_t kMaxRuns = 1'000U;

constexpr std::uint64_t kMaxSeriesIterations = 1'000'000'000ULL;

constexpr WorkloadBytes kMaxWorkloadBytes =
    256ULL * 1024ULL * 1024ULL;

enum class ValidationErrorCode {
    UnsupportedOperation,
    PrimitiveConfigMismatch,
    SignatureInputMismatch,
    IterationsOutOfRange,
    RunsOutOfRange,
    SeriesIterationBudgetExceeded,
    WorkloadOutOfRange
};

enum class ValidationField {
    Operation,
    PrimitiveConfig,
    SignatureInput,
    MessageSize,
    PlaintextSize,
    HashInputSize,
    IterationsPerRun,
    Runs,
    SeriesIterationBudget
};

struct ValidationError {
    ValidationErrorCode code;
    ValidationField field;
    std::string technicalMessage;
};

struct ValidationResult {
    std::vector<ValidationError> errors;

    bool isValid() const noexcept
    {
        return errors.empty();
    }
};

class ConfigValidator;

class ValidatedBenchmarkConfig {
public:
    const BenchmarkConfig& value() const noexcept
    {
        return config_;
    }

private:
    explicit ValidatedBenchmarkConfig(BenchmarkConfig config)
        : config_(std::move(config))
    {
    }

    BenchmarkConfig config_;

    friend class ConfigValidator;
};

} // namespace cryptobench::core
