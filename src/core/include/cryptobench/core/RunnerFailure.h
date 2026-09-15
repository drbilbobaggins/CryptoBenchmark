#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <cryptobench/core/ErrorInfo.h>

namespace cryptobench::core {

class RunnerFailure : public std::runtime_error {
public:
    RunnerFailure(
        FailureStage stage,
        std::optional<std::uint32_t> runIndex,
        std::string message)
        : std::runtime_error(std::move(message)),
          stage_(stage),
          runIndex_(runIndex)
    {
    }

    FailureStage stage() const noexcept
    {
        return stage_;
    }

    const std::optional<std::uint32_t>& runIndex() const noexcept
    {
        return runIndex_;
    }

private:
    FailureStage stage_;
    std::optional<std::uint32_t> runIndex_;
};

} // namespace cryptobench::core
