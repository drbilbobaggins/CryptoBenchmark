#pragma once

#include <span>

#include <cryptobench/core/AlgorithmProfile.h>

namespace cryptobench::core {

class AlgorithmRegistry {
public:
    static std::span<const AlgorithmProfile> all() noexcept;
    static const AlgorithmProfile* find(AlgorithmProfileId id) noexcept;
};

} // namespace cryptobench::core
