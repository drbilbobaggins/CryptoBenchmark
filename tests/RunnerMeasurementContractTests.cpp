#include <cryptobench/core/ProcessCpuTimeSource.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>
#include <cryptobench/core/WorkerRunMeasurement.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace cryptobench::tests {
namespace {

using namespace core;

static_assert(std::is_same_v<decltype(WorkerRunMeasurement::runIndex), std::uint32_t>);
static_assert(std::is_same_v<decltype(WorkerRunMeasurement::elapsedNanoseconds), std::uint64_t>);
static_assert(std::is_same_v<decltype(WorkerRunMeasurement::processCpuNanoseconds), std::uint64_t>);

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void testWorkerRunMeasurementDataContract()
{
    const WorkerRunMeasurement measurement{4, 1250000, 830000};
    require(measurement.runIndex == 4, "run index mismatch");
    require(measurement.elapsedNanoseconds == 1250000, "elapsed nanoseconds mismatch");
    require(measurement.processCpuNanoseconds == 830000, "process CPU nanoseconds mismatch");
}

class FakeCoordinator final : public RunMeasurementCoordinator {
public:
    void beforeMeasurement(std::uint32_t runIndex) override
    {
        beforeRunIndex = runIndex;
    }

    void afterMeasurement(const WorkerRunMeasurement& measurement) override
    {
        completedMeasurement = measurement;
    }

    std::uint32_t beforeRunIndex = 0;
    WorkerRunMeasurement completedMeasurement{};
};

void testCoordinatorPolymorphicContract()
{
    FakeCoordinator fake;
    RunMeasurementCoordinator& coordinator = fake;
    const WorkerRunMeasurement expected{7, 2400, 1700};

    coordinator.beforeMeasurement(expected.runIndex);
    coordinator.afterMeasurement(expected);

    require(fake.beforeRunIndex == expected.runIndex, "coordinator run index mismatch");
    require(fake.completedMeasurement.runIndex == expected.runIndex, "coordinator measurement run index mismatch");
    require(fake.completedMeasurement.elapsedNanoseconds == expected.elapsedNanoseconds, "coordinator elapsed value mismatch");
    require(fake.completedMeasurement.processCpuNanoseconds == expected.processCpuNanoseconds, "coordinator CPU value mismatch");
}

class FakeCpuTimeSource final : public ProcessCpuTimeSource {
public:
    explicit FakeCpuTimeSource(std::array<std::uint64_t, 2> values)
        : values_(values)
    {
    }

    std::uint64_t currentProcessCpuTimeNanoseconds() override
    {
        return values_[nextValue_++];
    }

private:
    std::array<std::uint64_t, 2> values_;
    std::size_t nextValue_ = 0;
};

void testCumulativeCpuTimeSourcePolymorphicContract()
{
    FakeCpuTimeSource fake({100000, 145000});
    ProcessCpuTimeSource& source = fake;

    require(source.currentProcessCpuTimeNanoseconds() == 100000, "first cumulative CPU value mismatch");
    require(source.currentProcessCpuTimeNanoseconds() == 145000, "second cumulative CPU value mismatch");
}

} // namespace

int runRunnerMeasurementContractTests()
{
    const auto tests = std::array{
        std::pair{"worker measurement data contract", &testWorkerRunMeasurementDataContract},
        std::pair{"measurement coordinator contract", &testCoordinatorPolymorphicContract},
        std::pair{"cumulative CPU time source contract", &testCumulativeCpuTimeSourcePolymorphicContract}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS runner measurement total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
