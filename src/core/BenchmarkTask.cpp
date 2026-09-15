#include <cryptobench/core/BenchmarkTask.h>

#include <stdexcept>
#include <utility>

namespace cryptobench::core {

BenchmarkTask::BenchmarkTask(
    ValidatedBenchmarkConfig config,
    const AlgorithmProfile& profile,
    std::unique_ptr<AlgorithmAdapter> adapter)
    : config_(std::move(config)),
      profile_(&profile),
      adapter_(std::move(adapter))
{
    if (adapter_ == nullptr) {
        throw std::invalid_argument("BenchmarkTask requires a non-null adapter");
    }

    if (profile_->id != config_.value().profile) {
        throw std::invalid_argument("BenchmarkTask profile does not match configuration");
    }
}

const ValidatedBenchmarkConfig& BenchmarkTask::config() const noexcept
{
    return config_;
}

const AlgorithmProfile& BenchmarkTask::profile() const noexcept
{
    return *profile_;
}

AlgorithmAdapter& BenchmarkTask::adapter() noexcept
{
    return *adapter_;
}

const AlgorithmAdapter& BenchmarkTask::adapter() const noexcept
{
    return *adapter_;
}

} // namespace cryptobench::core
