#pragma once

#include <memory>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/AlgorithmProfile.h>
#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::core {

class BenchmarkTask {
public:
    BenchmarkTask(
        ValidatedBenchmarkConfig config,
        const AlgorithmProfile& profile,
        std::unique_ptr<AlgorithmAdapter> adapter);

    BenchmarkTask(const BenchmarkTask&) = delete;
    BenchmarkTask& operator=(const BenchmarkTask&) = delete;
    BenchmarkTask(BenchmarkTask&&) = delete;
    BenchmarkTask& operator=(BenchmarkTask&&) = delete;

    const ValidatedBenchmarkConfig& config() const noexcept;
    const AlgorithmProfile& profile() const noexcept;
    AlgorithmAdapter& adapter() noexcept;
    const AlgorithmAdapter& adapter() const noexcept;

private:
    ValidatedBenchmarkConfig config_;
    const AlgorithmProfile* profile_;
    std::unique_ptr<AlgorithmAdapter> adapter_;
};

} // namespace cryptobench::core
