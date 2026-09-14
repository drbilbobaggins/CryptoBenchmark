#pragma once

#include <optional>

#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::core {

class ConfigValidator {
public:
    ValidationResult validate(const BenchmarkConfig& config) const;

    std::optional<ValidatedBenchmarkConfig> validateAndCreate(
        const BenchmarkConfig& config,
        ValidationResult& validation) const;
};

} // namespace cryptobench::core
