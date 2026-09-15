#include "adapters/DigestAdapter.h"

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/BenchmarkTask.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/ProcessCpuTimeSource.h>
#include <cryptobench/core/ProgressSink.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::DigestAdapter;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::BenchmarkPhase;
using core::BenchmarkRunner;
using core::BenchmarkTask;
using core::ConfigValidator;
using core::DigestAlgorithm;
using core::DigestParameters;
using core::ProcessCpuTimeSource;
using core::ProgressInfo;
using core::ProgressSink;
using core::RunMeasurementCoordinator;
using core::WorkerRunMeasurement;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string hex(std::span<const unsigned char> bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void requireDigest(DigestAdapter& adapter, std::string_view expected)
{
    adapter.executeIteration();
    require(hex(adapter.output()) == expected, "SHA-256 digest mismatch");
}

void testEmptyInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 0);
    adapter.prepareSeries();
    requireDigest(adapter, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    require(adapter.output().size() == 32, "SHA-256 output length mismatch");
}

void testAbcInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void testRepeatedIterations()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

class NoOpProgressSink final : public ProgressSink {
public:
    void reportProgress(const ProgressInfo&) override
    {
    }
};

class RecordingMeasurementCoordinator final : public RunMeasurementCoordinator {
public:
    void beforeMeasurement(std::uint32_t) override
    {
    }

    void afterMeasurement(const WorkerRunMeasurement& measurement) override
    {
        measurements.push_back(measurement);
    }

    std::vector<WorkerRunMeasurement> measurements;
};

class DeterministicCpuTimeSource final : public ProcessCpuTimeSource {
public:
    std::uint64_t currentProcessCpuTimeNanoseconds() override
    {
        return values[nextValue++];
    }

private:
    const std::array<std::uint64_t, 4> values{1000, 1300, 2000, 2450};
    std::size_t nextValue = 0;
};

void testDigestAdapterRunsThroughBenchmarkRunner()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        3,
        2,
        core::HashConfig{64}
    };
    core::ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "SHA-256 integration config validation failed");

    const auto* profile = AlgorithmRegistry::find(config.profile);
    require(profile != nullptr && profile->id == core::AlgorithmProfileId::Sha256,
            "canonical SHA-256 profile resolution failed");
    const auto digestParameters = std::get<DigestParameters>(profile->parameters);
    const auto hashConfig = std::get<core::HashConfig>(validated->value().parameters);

    auto adapter = std::make_unique<DigestAdapter>(digestParameters, hashConfig.inputSize);
    BenchmarkTask task(std::move(*validated), *profile, std::move(adapter));
    NoOpProgressSink progress;
    RecordingMeasurementCoordinator coordinator;
    DeterministicCpuTimeSource cpuTime;
    BenchmarkRunner runner(task, progress, coordinator, cpuTime);

    runner.run();

    require(coordinator.measurements.size() == config.runs,
            "SHA-256 integration did not complete all configured runs");
    require(coordinator.measurements[0].runIndex == 0 && coordinator.measurements[1].runIndex == 1,
            "SHA-256 integration measurement indices are not ordered");
    require(coordinator.measurements[0].processCpuNanoseconds == 300,
            "SHA-256 integration run 0 CPU delta mismatch");
    require(coordinator.measurements[1].processCpuNanoseconds == 450,
            "SHA-256 integration run 1 CPU delta mismatch");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"empty input", &testEmptyInput},
            std::pair{"abc input", &testAbcInput},
            std::pair{"repeated iterations", &testRepeatedIterations},
            std::pair{"DigestAdapter through BenchmarkRunner", &testDigestAdapterRunsThroughBenchmarkRunner}
        };
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS digest adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
