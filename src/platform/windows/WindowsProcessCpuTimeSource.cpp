#include <cryptobench/platform/windows/WindowsProcessCpuTimeSource.h>

#include <windows.h>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

std::uint64_t fileTimeTo100NanosecondTicks(const FILETIME& fileTime)
{
    return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U)
        | static_cast<std::uint64_t>(fileTime.dwLowDateTime);
}

std::uint64_t checkedCpuTimeNanoseconds(
    const FILETIME& kernelTime,
    const FILETIME& userTime)
{
    const auto kernelTicks = fileTimeTo100NanosecondTicks(kernelTime);
    const auto userTicks = fileTimeTo100NanosecondTicks(userTime);
    constexpr auto maxValue = std::numeric_limits<std::uint64_t>::max();

    if (userTicks > maxValue - kernelTicks) {
        throw std::overflow_error("process CPU time tick sum overflow");
    }

    const auto totalTicks = kernelTicks + userTicks;
    if (totalTicks > maxValue / 100U) {
        throw std::overflow_error("process CPU time nanosecond conversion overflow");
    }

    return totalTicks * 100U;
}

} // namespace

namespace cryptobench::platform::windows {

std::uint64_t WindowsProcessCpuTimeSource::currentProcessCpuTimeNanoseconds()
{
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};

    if (!GetProcessTimes(
            GetCurrentProcess(),
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime)) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(
            "GetProcessTimes failed with error code " + std::to_string(errorCode));
    }

    return checkedCpuTimeNanoseconds(kernelTime, userTime);
}

} // namespace cryptobench::platform::windows
