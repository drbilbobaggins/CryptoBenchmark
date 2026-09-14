#pragma once

#include <cstdint>
#include <initializer_list>

#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::core {

class SupportedOperations {
public:
    constexpr SupportedOperations() noexcept = default;

    SupportedOperations(std::initializer_list<BenchmarkOperation> operations) noexcept
    {
        for (const BenchmarkOperation operation : operations) {
            mask_ = static_cast<std::uint16_t>(mask_ | bitFor(operation));
        }
    }

    constexpr bool contains(BenchmarkOperation operation) const noexcept
    {
        const std::uint16_t bit = bitFor(operation);
        return bit != 0 && (mask_ & bit) != 0;
    }

    constexpr bool empty() const noexcept
    {
        return mask_ == 0;
    }

private:
    static constexpr std::uint16_t bitFor(BenchmarkOperation operation) noexcept
    {
        switch (operation) {
            case BenchmarkOperation::KeyGen: return 1u << 0;
            case BenchmarkOperation::Sign: return 1u << 1;
            case BenchmarkOperation::Verify: return 1u << 2;
            case BenchmarkOperation::Derive: return 1u << 3;
            case BenchmarkOperation::Encapsulate: return 1u << 4;
            case BenchmarkOperation::Decapsulate: return 1u << 5;
            case BenchmarkOperation::Encrypt: return 1u << 6;
            case BenchmarkOperation::Decrypt: return 1u << 7;
            case BenchmarkOperation::Hash: return 1u << 8;
            case BenchmarkOperation::Xof: return 1u << 9;
        }

        return 0;
    }

    std::uint16_t mask_ = 0;
};

} // namespace cryptobench::core
