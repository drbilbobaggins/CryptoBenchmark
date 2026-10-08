#pragma once

#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include <cryptobench/core/AlgorithmProfile.h>
#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::core {

class CommonWorkload final {
public:
    CommonWorkload() = default;
    CommonWorkload(const CommonWorkload&) = delete;
    CommonWorkload& operator=(const CommonWorkload&) = delete;
    CommonWorkload(CommonWorkload&&) noexcept = default;
    CommonWorkload& operator=(CommonWorkload&&) noexcept = default;

    explicit CommonWorkload(std::vector<unsigned char>&& bytes) noexcept
        : bytes_(std::move(bytes))
    {
    }

    std::span<const unsigned char> bytes() const noexcept
    {
        return bytes_;
    }

    std::size_t size() const noexcept
    {
        return bytes_.size();
    }

    bool empty() const noexcept
    {
        return bytes_.empty();
    }

private:
    std::vector<unsigned char> bytes_;
};

CommonWorkload buildCommonWorkload(
    const ValidatedBenchmarkConfig& config,
    const AlgorithmProfile& profile);

} // namespace cryptobench::core
