#include <cryptobench/core/MemoryV2Calculator.h>

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

MemoryV2RawObservations observations(
    std::uint64_t baseline,
    std::uint64_t ready,
    std::uint64_t finalValue,
    std::optional<std::uint64_t> preparationPeak = std::nullopt,
    std::uint64_t preparationSamples = 0,
    std::optional<std::uint64_t> executionPeak = std::nullopt,
    std::uint64_t executionSamples = 0)
{
    return {
        baseline,
        ready,
        preparationPeak,
        executionPeak,
        finalValue,
        preparationSamples,
        executionSamples
    };
}

MemoryV2DerivedMetrics calculate(const MemoryV2RawObservations& raw)
{
    const auto derived = calculateMemoryV2DerivedMetrics(raw);
    require(derived.has_value(), "valid raw observations were rejected");
    return *derived;
}

void requireInvalid(const MemoryV2RawObservations& raw, std::string_view message)
{
    require(!calculateMemoryV2DerivedMetrics(raw).has_value(), message);
}

void testReadyStateDeltaNormalCases()
{
    require(calculate(observations(100, 125, 100)).readyStateDelta == 25,
            "positive ready-state delta mismatch");
    require(calculate(observations(100, 100, 100)).readyStateDelta == 0,
            "zero ready-state delta mismatch");
    require(calculate(observations(125, 100, 100)).readyStateDelta == -25,
            "negative ready-state delta mismatch");
}

void testReadyStateDeltaBoundariesAndOverflow()
{
    const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    const auto minimumMagnitude = maximum + 1U;

    require(calculate(observations(0, maximum, 0)).readyStateDelta == std::numeric_limits<std::int64_t>::max(),
            "INT64_MAX ready-state delta mismatch");
    require(calculate(observations(minimumMagnitude, 0, 0)).readyStateDelta == std::numeric_limits<std::int64_t>::min(),
            "INT64_MIN ready-state delta mismatch");

    requireInvalid(observations(0, minimumMagnitude, 0),
                   "positive ready-state overflow was accepted");
    requireInvalid(observations(std::numeric_limits<std::uint64_t>::max(), 0, 0),
                   "negative ready-state overflow was accepted");
    requireInvalid(observations(0, std::numeric_limits<std::uint64_t>::max(), 0),
                   "UINT64_MAX positive ready-state overflow was accepted");
}

void testPreparationPeakDelta()
{
    require(calculate(observations(100, 120, 110)).preparationPeakDelta == 20,
            "absent preparation peak mismatch");
    require(calculate(observations(100, 120, 110, 80, 1)).preparationPeakDelta == 20,
            "preparation peak below boundaries lowered the maximum");
    require(calculate(observations(100, 120, 110, 150, 1)).preparationPeakDelta == 50,
            "preparation peak maximum mismatch");
    require(calculate(observations(100, 90, 80)).preparationPeakDelta == 0,
            "preparation delta became negative");
}

void testExecutionPeakDelta()
{
    require(calculate(observations(100, 120, 110)).executionPeakDelta == 20,
            "absent execution peak mismatch");
    require(calculate(observations(100, 150, 120)).executionPeakDelta == 50,
            "ready-state execution maximum mismatch");
    require(calculate(observations(100, 110, 160)).executionPeakDelta == 60,
            "final execution maximum mismatch");
    require(calculate(observations(100, 110, 120, std::nullopt, 0, 200, 1)).executionPeakDelta == 100,
            "execution peak maximum mismatch");
    require(calculate(observations(100, 90, 80, 70, 1, 60, 1)).executionPeakDelta == 0,
            "execution delta became negative");
}

void testOperationalPeakDeltaAndOrdering()
{
    const auto derived = calculate(observations(100, 110, 120, 180, 1, 160, 1));
    require(derived.operationalPeakDelta == 80, "operational maximum mismatch");
    require(derived.operationalPeakDelta >= derived.preparationPeakDelta,
            "operational delta was below preparation delta");
    require(derived.operationalPeakDelta >= derived.executionPeakDelta,
            "operational delta was below execution delta");

    require(calculate(observations(100, 130, 120)).operationalPeakDelta == 30,
            "absent optional peaks were not omitted from operational maximum");
    require(calculate(observations(100, 110, 120, std::nullopt, 0, 160, 1)).operationalPeakDelta == 60,
            "execution-only operational maximum mismatch");
    require(calculate(observations(100, 90, 80, 70, 1, 60, 1)).operationalPeakDelta == 0,
            "operational delta became negative");
}

void testRawPeakCountInvariants()
{
    require(calculateMemoryV2DerivedMetrics(observations(100, 100, 100)).has_value(),
            "zero preparation and execution counts should be valid");
    require(calculateMemoryV2DerivedMetrics(observations(100, 100, 100, 0, 1, 0, 1)).has_value(),
            "present zero sampled peaks should be valid");

    requireInvalid(observations(100, 100, 100, 0, 0),
                   "zero preparation count with present peak was accepted");
    requireInvalid(observations(100, 100, 100, std::nullopt, 1),
                   "nonzero preparation count with absent peak was accepted");
    requireInvalid(observations(100, 100, 100, std::nullopt, 0, 0, 0),
                   "zero execution count with present peak was accepted");
    requireInvalid(observations(100, 100, 100, std::nullopt, 0, std::nullopt, 1),
                   "nonzero execution count with absent peak was accepted");
    requireInvalid(observations(100, 100, 100, 0, 0, 0, 1),
                   "mixed invalid phase invariants were accepted");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testReadyStateDeltaNormalCases();
        cryptobench::tests::testReadyStateDeltaBoundariesAndOverflow();
        cryptobench::tests::testPreparationPeakDelta();
        cryptobench::tests::testExecutionPeakDelta();
        cryptobench::tests::testOperationalPeakDeltaAndOrdering();
        cryptobench::tests::testRawPeakCountInvariants();
        std::cout << "PASS Memory v2 calculator contracts\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
