#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/RunnerFailure.h>

#include <array>
#include <cstdint>
#include <exception>
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

BenchmarkConfig validConfig(std::uint64_t iterations = 2, std::uint32_t runs = 2)
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, iterations, runs, HashConfig{64}};
}

class FakeAdapter final : public AlgorithmAdapter {
public:
    enum class Failure { None, Series, RunPreparation, Warmup, Measurement };

    explicit FakeAdapter(Failure failure = Failure::None, std::uint32_t failingRun = 0)
        : failure_(failure),
          failingRun_(failingRun)
    {
    }

    void prepareSeries() override
    {
        if (failure_ == Failure::Series) throw std::logic_error("series diagnostic");
    }

    void prepareRun() override
    {
        if (hasPreparedRun_) {
            ++currentRun_;
        }
        hasPreparedRun_ = true;
        warmup_ = true;
        if (failure_ == Failure::RunPreparation && currentRun_ == failingRun_) {
            throw std::logic_error("run preparation diagnostic");
        }
    }

    void executeIteration() override
    {
        if (failure_ == Failure::Warmup && currentRun_ == failingRun_ && warmup_) {
            throw std::logic_error("warmup diagnostic");
        }
        if (failure_ == Failure::Measurement && currentRun_ == failingRun_ && !warmup_) {
            throw std::logic_error("measurement diagnostic");
        }
        warmup_ = false;
    }

private:
    Failure failure_;
    std::uint32_t failingRun_;
    std::uint32_t currentRun_ = 0;
    bool hasPreparedRun_ = false;
    bool warmup_ = true;
};

class FakeProgressSink final : public ProgressSink {
public:
    explicit FakeProgressSink(std::optional<BenchmarkPhase> failure = std::nullopt)
        : failure_(failure)
    {
    }

    void reportProgress(const ProgressInfo& info) override
    {
        if (failure_ == info.phase) throw std::logic_error("progress diagnostic");
    }

private:
    std::optional<BenchmarkPhase> failure_;
};

class FakeCoordinator final : public RunMeasurementCoordinator {
public:
    explicit FakeCoordinator(bool failAfter = false, bool failBefore = false)
        : failAfter_(failAfter),
          failBefore_(failBefore)
    {
    }

    void beforeMeasurement(std::uint32_t runIndex) override
    {
        ++beforeMeasurementCalls;
        if (failBefore_ && runIndex == 1) {
            throw std::logic_error("before measurement diagnostic");
        }
    }

    void afterMeasurement(const WorkerRunMeasurement&) override
    {
        if (failAfter_) throw std::logic_error("after measurement diagnostic");
    }

    std::uint32_t beforeMeasurementCalls = 0;

private:
    bool failAfter_;
    bool failBefore_;
};

class FakeCpuTimeSource final : public ProcessCpuTimeSource {
public:
    explicit FakeCpuTimeSource(bool fail = false)
        : fail_(fail)
    {
    }

    std::uint64_t currentProcessCpuTimeNanoseconds() override
    {
        if (fail_) throw std::logic_error("CPU diagnostic");
        return 100;
    }

private:
    bool fail_;
};

class RunnerFixture {
public:
    RunnerFixture(
        FakeAdapter::Failure adapterFailure = FakeAdapter::Failure::None,
        std::uint32_t failingRun = 0,
        std::optional<BenchmarkPhase> progressFailure = std::nullopt,
        bool cpuFailure = false,
        bool beforeFailure = false,
        bool afterFailure = false)
            : progress_(progressFailure),
          coordinator_(afterFailure, beforeFailure),
          cpu_(cpuFailure)
    {
        ValidationResult validation;
        auto validated = ConfigValidator{}.validateAndCreate(validConfig(), validation);
        require(validated.has_value() && validation.isValid(), "error test config was not validated");
        const auto* profile = AlgorithmRegistry::find(AlgorithmProfileId::Sha256);
        require(profile != nullptr, "error test profile was not found");
        task_ = std::make_unique<BenchmarkTask>(std::move(*validated), *profile,
                                                std::make_unique<FakeAdapter>(adapterFailure, failingRun));
    }

    void run()
    {
        BenchmarkRunner runner(*task_, progress_, coordinator_, cpu_);
        runner.run();
    }

    void prepare(std::uint32_t logicalRunIndex)
    {
        BenchmarkRunner runner(*task_, progress_, coordinator_, cpu_);
        runner.prepareLogicalRun(logicalRunIndex);
    }

    void prepareAndMeasure(std::uint32_t logicalRunIndex)
    {
        BenchmarkRunner runner(*task_, progress_, coordinator_, cpu_);
        runner.prepareLogicalRun(logicalRunIndex);
        static_cast<void>(runner.measureLogicalRun(logicalRunIndex));
    }

    std::uint32_t beforeMeasurementCalls() const
    {
        return coordinator_.beforeMeasurementCalls;
    }

private:
    FakeProgressSink progress_;
    FakeCoordinator coordinator_;
    FakeCpuTimeSource cpu_;
    std::unique_ptr<BenchmarkTask> task_;
};

void expectRunnerFailure(
    RunnerFixture& fixture,
    FailureStage stage,
    std::optional<std::uint32_t> runIndex,
    std::string_view message)
{
    try {
        fixture.run();
        throw std::runtime_error("runner did not fail");
    } catch (const RunnerFailure& failure) {
        require(failure.stage() == stage, message);
        require(failure.runIndex() == runIndex, "runner failure run index mismatch");
    }
}

template <typename Callable>
void expectExplicitRunnerFailure(
    Callable&& callable,
    FailureStage stage,
    std::optional<std::uint32_t> runIndex,
    std::string_view message)
{
    try {
        callable();
        throw std::runtime_error("runner did not fail");
    } catch (const RunnerFailure& failure) {
        require(failure.stage() == stage, message);
        require(failure.runIndex() == runIndex, "explicit runner failure run index mismatch");
    }
}

void testErrorInfoContract()
{
    const ErrorInfo detailed{
        ErrorCode::CryptoOperationFailed,
        FailureStage::Measurement,
        3,
        "operation failed",
        "library detail"
    };
    require(detailed.code == ErrorCode::CryptoOperationFailed, "error code mismatch");
    require(detailed.stage == FailureStage::Measurement, "error stage mismatch");
    require(detailed.runIndex == 3, "error run index mismatch");
    require(detailed.technicalMessage == "operation failed", "technical message mismatch");
    require(detailed.libraryDetails == "library detail", "library details mismatch");

    const ErrorInfo minimal{ErrorCode::InternalError, FailureStage::SeriesPreparation, std::nullopt, "failed", std::nullopt};
    require(!minimal.runIndex.has_value() && !minimal.libraryDetails.has_value(), "optional error fields mismatch");
}

void testAdapterStageContext()
{
    RunnerFixture series(FakeAdapter::Failure::Series);
    expectRunnerFailure(series, FailureStage::SeriesPreparation, std::nullopt, "series stage mismatch");
    RunnerFixture runPreparation(FakeAdapter::Failure::RunPreparation, 1);
    expectRunnerFailure(runPreparation, FailureStage::RunPreparation, 1, "run preparation stage mismatch");
    RunnerFixture warmup(FakeAdapter::Failure::Warmup, 1);
    expectRunnerFailure(warmup, FailureStage::Warmup, 1, "warmup stage mismatch");
    RunnerFixture measurement(FakeAdapter::Failure::Measurement, 1);
    expectRunnerFailure(measurement, FailureStage::Measurement, 1, "measurement stage mismatch");
}

void testDependencyStageContext()
{
    RunnerFixture before(FakeAdapter::Failure::None, 0, std::nullopt, false, true);
    expectRunnerFailure(before, FailureStage::WorkerCommunication, 1, "before stage mismatch");
    RunnerFixture cpu(FakeAdapter::Failure::None, 0, std::nullopt, true);
    expectRunnerFailure(cpu, FailureStage::Measurement, 0, "CPU stage mismatch");
    RunnerFixture after(FakeAdapter::Failure::None, 0, std::nullopt, false, false, true);
    expectRunnerFailure(after, FailureStage::WorkerCommunication, 0, "after stage mismatch");
}

void testNestedOriginalException()
{
    RunnerFixture fixture(FakeAdapter::Failure::Warmup, 0);
    try {
        fixture.run();
        throw std::runtime_error("runner did not fail");
    } catch (const RunnerFailure& failure) {
        require(failure.what() == std::string("warmup diagnostic"), "runner diagnostic was not preserved");
        bool nestedRecovered = false;
        try {
            std::rethrow_if_nested(failure);
        } catch (const std::logic_error& error) {
            nestedRecovered = true;
            require(std::string(error.what()) == "warmup diagnostic", "nested diagnostic mismatch");
        }
        require(nestedRecovered, "original nested exception was not recovered");
    }
}

void testProgressStageContext()
{
    RunnerFixture preparing(FakeAdapter::Failure::None, 0, BenchmarkPhase::Preparing);
    expectRunnerFailure(preparing, FailureStage::WorkerCommunication, std::nullopt, "preparing progress stage mismatch");
    RunnerFixture warmup(FakeAdapter::Failure::None, 0, BenchmarkPhase::Warmup);
    expectRunnerFailure(warmup, FailureStage::WorkerCommunication, 0, "warmup progress stage mismatch");
    require(warmup.beforeMeasurementCalls() == 0,
            "measurement began after warmup progress failure");
}

void testSingleLogicalRunErrorContext()
{
    RunnerFixture series(FakeAdapter::Failure::Series);
    expectExplicitRunnerFailure([&] { series.prepare(1); }, FailureStage::SeriesPreparation, 1,
                                "explicit series stage mismatch");
    RunnerFixture runPreparation(FakeAdapter::Failure::RunPreparation, 0);
    expectExplicitRunnerFailure([&] { runPreparation.prepare(1); }, FailureStage::RunPreparation, 1,
                                "explicit run preparation stage mismatch");
    RunnerFixture warmup(FakeAdapter::Failure::Warmup, 0);
    expectExplicitRunnerFailure([&] { warmup.prepare(1); }, FailureStage::Warmup, 1,
                                "explicit warmup stage mismatch");
    RunnerFixture before(FakeAdapter::Failure::None, 0, std::nullopt, false, true);
    expectExplicitRunnerFailure([&] { before.prepareAndMeasure(1); }, FailureStage::WorkerCommunication, 1,
                                "explicit before stage mismatch");
    RunnerFixture measurement(FakeAdapter::Failure::Measurement, 0);
    expectExplicitRunnerFailure([&] { measurement.prepareAndMeasure(1); }, FailureStage::Measurement, 1,
                                "explicit measurement stage mismatch");
    RunnerFixture cpu(FakeAdapter::Failure::None, 0, std::nullopt, true);
    expectExplicitRunnerFailure([&] { cpu.prepareAndMeasure(1); }, FailureStage::Measurement, 1,
                                "explicit CPU stage mismatch");
    RunnerFixture after(FakeAdapter::Failure::None, 0, std::nullopt, false, false, true);
    expectExplicitRunnerFailure([&] { after.prepareAndMeasure(1); }, FailureStage::WorkerCommunication, 1,
                                "explicit after stage mismatch");

    RunnerFixture nested(FakeAdapter::Failure::Warmup, 0);
    try {
        nested.prepare(1);
        throw std::runtime_error("runner did not fail");
    } catch (const RunnerFailure& failure) {
        bool nestedRecovered = false;
        try {
            std::rethrow_if_nested(failure);
        } catch (const std::logic_error& error) {
            nestedRecovered = true;
            require(std::string(error.what()) == "warmup diagnostic", "explicit nested diagnostic mismatch");
        }
        require(nestedRecovered, "explicit original nested exception was not recovered");
    }
}

} // namespace

int runRunnerErrorContextTests()
{
    const auto tests = std::array{
        std::pair{"canonical ErrorInfo contract", &testErrorInfoContract},
        std::pair{"adapter stage context", &testAdapterStageContext},
        std::pair{"dependency stage context", &testDependencyStageContext},
        std::pair{"nested original exception", &testNestedOriginalException},
        std::pair{"progress stage context", &testProgressStageContext},
        std::pair{"single logical run error context", &testSingleLogicalRunErrorContext}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS runner error context total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
