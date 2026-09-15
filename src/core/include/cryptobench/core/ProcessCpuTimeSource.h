#pragma once

#include <cstdint>

namespace cryptobench::core {

class ProcessCpuTimeSource {
public:
    virtual ~ProcessCpuTimeSource() = default;

    virtual std::uint64_t currentProcessCpuTimeNanoseconds() = 0;
};

} // namespace cryptobench::core
