#pragma once

#include <cryptobench/core/ProcessCpuTimeSource.h>

#include <cstdint>

namespace cryptobench::platform::windows {

class WindowsProcessCpuTimeSource final : public core::ProcessCpuTimeSource {
public:
    std::uint64_t currentProcessCpuTimeNanoseconds() override;
};

} // namespace cryptobench::platform::windows
