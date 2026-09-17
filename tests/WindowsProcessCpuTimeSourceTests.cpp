#include <cryptobench/core/ProcessCpuTimeSource.h>
#include <cryptobench/platform/windows/WindowsProcessCpuTimeSource.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void performCpuWork()
{
    volatile std::uint64_t state = 0;
    for (std::uint64_t index = 0; index < 8'000'000; ++index) {
        state = state * 1'664'525U + index + 1'013'904'223U;
    }
}

void testInterfaceAndResolution()
{
    cryptobench::platform::windows::WindowsProcessCpuTimeSource concreteSource;
    cryptobench::core::ProcessCpuTimeSource& source = concreteSource;

    const auto reading = source.currentProcessCpuTimeNanoseconds();
    require(reading % 100U == 0, "CPU time is not based on 100 ns FILETIME resolution");
}

void testCumulativeReadingsAreMonotonic()
{
    cryptobench::platform::windows::WindowsProcessCpuTimeSource source;
    auto previous = source.currentProcessCpuTimeNanoseconds();

    for (int sample = 0; sample < 32; ++sample) {
        const auto current = source.currentProcessCpuTimeNanoseconds();
        require(current >= previous, "cumulative CPU time moved backwards");
        previous = current;
    }
}

void testCpuWorkAdvancesCumulativeTime()
{
    cryptobench::platform::windows::WindowsProcessCpuTimeSource source;
    const auto before = source.currentProcessCpuTimeNanoseconds();

    auto after = before;
    for (int attempt = 0; attempt < 3 && after <= before; ++attempt) {
        performCpuWork();
        after = source.currentProcessCpuTimeNanoseconds();
    }

    require(after > before, "bounded CPU work did not advance process CPU time");
}

} // namespace

int main()
{
    testInterfaceAndResolution();
    std::cout << "PASS interface and FILETIME resolution\n";
    testCumulativeReadingsAreMonotonic();
    std::cout << "PASS cumulative monotonicity\n";
    testCpuWorkAdvancesCumulativeTime();
    std::cout << "PASS CPU work progress\n";
    return 0;
}
