#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/ConfigValidator.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

BenchmarkConfig validConfig(std::uint64_t iterations = 3, std::uint32_t runs = 2)
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, iterations, runs, HashConfig{64}};
}

BenchmarkTask makeTask(
    BenchmarkConfig config,
    std::unique_ptr<AlgorithmAdapter> adapter)
{
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "runner test config was not validated");
    const auto* profile = AlgorithmRegistry::find(config.profile);
    require(profile != nullptr, "runner test profile was not found");
    return BenchmarkTask(std::move(*validated), *profile, std::move(adapter));
}

struct TestState {
    std::vector<std::string> events;
    std::vector<WorkerRunMeasurement> measurements;
    std::array<std::uint64_t, 4> cpuValues{1000, 1300, 2000, 2450};
    std::size_t nextCpuValue = 0;
    bool failSeriesPreparation = false;
    std::size_t throwOnExecuteCall = 0;
    std::size_t executeCalls = 0;
};

class FakeAdapter final : public AlgorithmAdapter {
public:
    explicit FakeAdapter(TestState& state)
        : state_(state)
    {
    }

    void prepareSeries() override
    {
        state_.events.push_back("prepareSeries");
        if (state_.failSeriesPreparation) {
            throw std::runtime_error("prepare series failure");
        }
    }

    void prepareRun() override
    {
        state_.events.push_back("prepareRun");
    }

    void executeIteration() override
    {
        ++state_.executeCalls;
        state_.events.push_back("executeIteration");
        if (state_.throwOnExecuteCall != 0 && state_.executeCalls == state_.throwOnExecuteCall) {
            throw std::runtime_error("measured iteration failure");
        }
    }

private:
    TestState& state_;
};

class FakeProgressSink final : public ProgressSink {
public:
    explicit FakeProgressSink(TestState& state)
        : state_(state)
    {
    }

    void reportProgress(const ProgressInfo& info) override
    {
        if (info.phase == BenchmarkPhase::Preparing) {
            state_.events.push_back("progress:Preparing");
        } else if (info.phase == BenchmarkPhase::Warmup) {
            state_.events.push_back("progress:Warmup:" + std::to_string(*info.runIndex));
        } else if (info.phase == BenchmarkPhase::Finalizing) {
            state_.events.push_back("progress:Finalizing");
        } else {
            state_.events.push_back("progress:Measuring");
        }
    }

private:
    TestState& state_;
};

class FakeCoordinator final : public RunMeasurementCoordinator {
public:
    explicit FakeCoordinator(TestState& state)
        : state_(state)
    {
    }

    void beforeMeasurement(std::uint32_t runIndex) override
    {
        state_.events.push_back("beforeMeasurement:" + std::to_string(runIndex));
    }

    void afterMeasurement(const WorkerRunMeasurement& measurement) override
    {
        state_.events.push_back("afterMeasurement:" + std::to_string(measurement.runIndex));
        state_.measurements.push_back(measurement);
    }

private:
    TestState& state_;
};

class FakeCpuTimeSource final : public ProcessCpuTimeSource {
public:
    explicit FakeCpuTimeSource(TestState& state)
        : state_(state)
    {
    }

    std::uint64_t currentProcessCpuTimeNanoseconds() override
    {
        state_.events.push_back("cpuTime");
        return state_.cpuValues[state_.nextCpuValue++];
    }

private:
    TestState& state_;
};

void testSuccessfulLifecycleAndOrdering()
{
    TestState state;
    auto adapter = std::make_unique<FakeAdapter>(state);
    auto task = makeTask(validConfig(), std::move(adapter));
    FakeProgressSink progress(state);
    FakeCoordinator coordinator(state);
    FakeCpuTimeSource cpu(state);
    BenchmarkRunner runner(task, progress, coordinator, cpu);

    runner.run();

    const std::vector<std::string> expected{
        "progress:Preparing", "prepareSeries",
        "prepareRun", "progress:Warmup:0", "executeIteration", "beforeMeasurement:0",
        "cpuTime", "executeIteration", "executeIteration", "executeIteration", "cpuTime", "afterMeasurement:0",
        "prepareRun", "progress:Warmup:1", "executeIteration", "beforeMeasurement:1",
        "cpuTime", "executeIteration", "executeIteration", "executeIteration", "cpuTime", "afterMeasurement:1",
        "progress:Finalizing"
    };
    require(state.events == expected, "successful lifecycle ordering mismatch");
    require(state.executeCalls == 8, "unexpected total iteration count");
    require(state.measurements.size() == 2, "unexpected completed measurement count");
    require(state.measurements[0].runIndex == 0 && state.measurements[1].runIndex == 1,
            "measurement run indices are not ordered");
    require(state.measurements[0].processCpuNanoseconds == 300, "run 0 CPU delta mismatch");
    require(state.measurements[1].processCpuNanoseconds == 450, "run 1 CPU delta mismatch");
}

void testMeasuredFailureStopsImmediately()
{
    TestState state;
    state.throwOnExecuteCall = 6;
    auto task = makeTask(validConfig(3, 3), std::make_unique<FakeAdapter>(state));
    FakeProgressSink progress(state);
    FakeCoordinator coordinator(state);
    FakeCpuTimeSource cpu(state);
    BenchmarkRunner runner(task, progress, coordinator, cpu);

    bool propagated = false;
    try {
        runner.run();
    } catch (const std::runtime_error&) {
        propagated = true;
    }

    require(propagated, "measured iteration failure did not propagate");
    require(state.measurements.size() == 1 && state.measurements.front().runIndex == 0,
            "completed run 0 measurement was not preserved");
    require(std::count(state.events.begin(), state.events.end(), "beforeMeasurement:1") == 1,
            "run 1 did not reach its measurement boundary");
    require(std::count(state.events.begin(), state.events.end(), "afterMeasurement:1") == 0,
            "incomplete run 1 produced a measurement");
    require(state.events.back() == "executeIteration", "runner continued after measured failure");
    require(std::count(state.events.begin(), state.events.end(), "prepareRun") == 2,
            "runner started a later run after failure");
    require(std::count(state.events.begin(), state.events.end(), "progress:Warmup:2") == 0,
            "runner reported a later run after failure");
    require(std::count(state.events.begin(), state.events.end(), "progress:Finalizing") == 0,
            "runner finalized after measured failure");
}

void testSeriesPreparationFailureStopsImmediately()
{
    TestState state;
    state.failSeriesPreparation = true;
    auto task = makeTask(validConfig(), std::make_unique<FakeAdapter>(state));
    FakeProgressSink progress(state);
    FakeCoordinator coordinator(state);
    FakeCpuTimeSource cpu(state);
    BenchmarkRunner runner(task, progress, coordinator, cpu);

    bool propagated = false;
    try {
        runner.run();
    } catch (const std::runtime_error&) {
        propagated = true;
    }

    require(propagated, "series preparation failure did not propagate");
    require(state.events == std::vector<std::string>{"progress:Preparing", "prepareSeries"},
            "runner did not stop immediately after series preparation failure");
}

} // namespace

int runBenchmarkRunnerTests()
{
    const auto tests = std::array{
        std::pair{"successful lifecycle and ordering", &testSuccessfulLifecycleAndOrdering},
        std::pair{"measured failure fail-fast", &testMeasuredFailureStopsImmediately},
        std::pair{"series preparation failure", &testSeriesPreparationFailureStopsImmediately}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS benchmark runner total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
