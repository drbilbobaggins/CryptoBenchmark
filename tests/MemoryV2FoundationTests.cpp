#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/MemoryRunMeasurement.h>
#include <cryptobench/core/MemoryV2.h>

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void testMeasurementSettingsContract()
{
    require(
        defaultMeasurementSettings().memorySamplingIntervalMilliseconds == 5,
        "default measurement interval mismatch");

    for (const std::uint32_t interval : {1U, 2U, 3U, 4U, 5U}) {
        require(
            isValidMeasurementSettings({interval}),
            "valid measurement interval was rejected");
    }

    require(!isValidMeasurementSettings({0}), "zero measurement interval was accepted");
    require(!isValidMeasurementSettings({6}), "measurement interval above five was accepted");
    require(!isValidMeasurementSettings({std::numeric_limits<std::uint32_t>::max()}),
            "maximum measurement interval was accepted");
}

void testMemoryV2RawObservationContract()
{
    const MemoryV2RawObservations noSamples{
        100,
        110,
        std::nullopt,
        std::nullopt,
        120,
        0,
        0
    };
    require(!noSamples.preparationPeakSampledPrivateUsageBytes.has_value(),
            "absent preparation peak was not representable");
    require(!noSamples.executionPeakSampledPrivateUsageBytes.has_value(),
            "absent execution peak was not representable");
    require(noSamples.preparationSampleCount == 0 && noSamples.executionSampleCount == 0,
            "zero sample count mismatch");

    const MemoryV2RawObservations sampledZero{
        100,
        110,
        std::uint64_t{0},
        std::uint64_t{0},
        120,
        1,
        1
    };
    require(sampledZero.preparationPeakSampledPrivateUsageBytes.has_value(),
            "sampled zero preparation peak was treated as absent");
    require(sampledZero.executionPeakSampledPrivateUsageBytes.has_value(),
            "sampled zero execution peak was treated as absent");
    require(sampledZero.preparationPeakSampledPrivateUsageBytes.value() == 0,
            "sampled zero preparation peak value mismatch");
    require(sampledZero.executionPeakSampledPrivateUsageBytes.value() == 0,
            "sampled zero execution peak value mismatch");
}

void testMemoryV2DerivedAndLegacyContracts()
{
    static_assert(std::is_same_v<decltype(MemoryV2DerivedMetrics::readyStateDelta), std::int64_t>);
    static_assert(std::is_same_v<decltype(MemoryV2DerivedMetrics::preparationPeakDelta), std::uint64_t>);
    static_assert(std::is_same_v<decltype(MemoryV2DerivedMetrics::executionPeakDelta), std::uint64_t>);
    static_assert(std::is_same_v<decltype(MemoryV2DerivedMetrics::operationalPeakDelta), std::uint64_t>);

    const MemoryV2DerivedMetrics derived{-25, 0, 1, 2};
    require(derived.readyStateDelta == -25, "negative ready-state delta was not representable");
    require(derived.preparationPeakDelta == 0, "preparation peak delta mismatch");
    require(derived.executionPeakDelta == 1, "execution peak delta mismatch");
    require(derived.operationalPeakDelta == 2, "operational peak delta mismatch");

    const MemoryRunMeasurement legacy{100, 145, 45};
    require(legacy.baselineBytes == 100, "legacy baseline meaning changed");
    require(legacy.peakSampledBytes == 145, "legacy sampled peak meaning changed");
    require(legacy.peakDeltaBytes == 45, "legacy peak delta meaning changed");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testMeasurementSettingsContract();
        cryptobench::tests::testMemoryV2RawObservationContract();
        cryptobench::tests::testMemoryV2DerivedAndLegacyContracts();
        std::cout << "PASS Memory v2 foundation contracts\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
