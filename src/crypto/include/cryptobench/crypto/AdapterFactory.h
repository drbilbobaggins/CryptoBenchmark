#pragma once

#include <memory>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/AlgorithmProfile.h>
#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::crypto {

class AdapterFactory {
public:
    std::unique_ptr<core::AlgorithmAdapter> create(
        const core::AlgorithmProfile& profile,
        core::BenchmarkOperation operation,
        const core::ValidatedBenchmarkConfig& config) const;
};

} // namespace cryptobench::crypto
