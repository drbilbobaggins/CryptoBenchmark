#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkTask.h>
#include <cryptobench/core/ConfigValidator.h>

#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace cryptobench::tests {
namespace {

using namespace core;

static_assert(!std::is_copy_constructible_v<BenchmarkTask>);
static_assert(!std::is_copy_assignable_v<BenchmarkTask>);
static_assert(!std::is_move_constructible_v<BenchmarkTask>);
static_assert(!std::is_move_assignable_v<BenchmarkTask>);

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

struct AdapterCounters {
    int prepareSeriesCalls = 0;
    int prepareRunCalls = 0;
    int executeIterationCalls = 0;
    int destructionCount = 0;
};

class FakeAdapter final : public AlgorithmAdapter {
public:
    explicit FakeAdapter(AdapterCounters& counters)
        : counters_(counters)
    {
    }

    ~FakeAdapter() override
    {
        ++counters_.destructionCount;
    }

    void prepareSeries() override
    {
        ++counters_.prepareSeriesCalls;
    }

    void prepareRun() override
    {
        ++counters_.prepareRunCalls;
    }

    void executeIteration() override
    {
        ++counters_.executeIterationCalls;
    }

private:
    AdapterCounters& counters_;
};

BenchmarkConfig validConfig()
{
    return {
        AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        2,
        3,
        HashConfig{64}
    };
}

std::optional<ValidatedBenchmarkConfig> validatedConfig(
    const BenchmarkConfig& config,
    ValidationResult& validation)
{
    return ConfigValidator{}.validateAndCreate(config, validation);
}

void testValidBindingAndAccess()
{
    const BenchmarkConfig raw = validConfig();
    ValidationResult validation;
    auto validated = validatedConfig(raw, validation);
    require(validated.has_value() && validation.isValid(), "valid config was not validated");

    const auto* canonicalProfile = AlgorithmRegistry::find(raw.profile);
    require(canonicalProfile != nullptr, "canonical profile was not found");

    AdapterCounters counters;
    auto adapter = std::make_unique<FakeAdapter>(counters);
    auto* adapterAddress = adapter.get();
    BenchmarkTask task(std::move(*validated), *canonicalProfile, std::move(adapter));

    require(task.config().value().profile == raw.profile, "task config profile mismatch");
    require(task.config().value().operation == raw.operation, "task config operation mismatch");
    require(task.config().value().iterationsPerRun == raw.iterationsPerRun, "task config iterations mismatch");
    require(task.config().value().runs == raw.runs, "task config runs mismatch");
    require(std::holds_alternative<HashConfig>(task.config().value().parameters), "task config payload type mismatch");
    require(std::get<HashConfig>(task.config().value().parameters).inputSize == 64, "task config workload mismatch");
    require(&task.profile() == canonicalProfile, "task canonical profile reference mismatch");
    require(task.profile().id == canonicalProfile->id, "task profile mismatch");
    require(task.profile().family == AlgorithmFamily::Sha2, "task profile family mismatch");
    require(&task.adapter() == adapterAddress, "task adapter reference mismatch");
    const BenchmarkTask& constTask = task;
    require(&constTask.adapter() == adapterAddress, "const task adapter reference mismatch");
}

void testConstructionDoesNotRunLifecycleAndOwnsAdapter()
{
    AdapterCounters counters;
    {
        const BenchmarkConfig raw = validConfig();
        ValidationResult validation;
        auto validated = validatedConfig(raw, validation);
        require(validated.has_value(), "valid config was not validated");
        const auto* canonicalProfile = AlgorithmRegistry::find(raw.profile);
        require(canonicalProfile != nullptr, "canonical profile was not found");
        BenchmarkTask task(
            std::move(*validated),
            *canonicalProfile,
            std::make_unique<FakeAdapter>(counters));

        require(counters.prepareSeriesCalls == 0, "construction called prepareSeries");
        require(counters.prepareRunCalls == 0, "construction called prepareRun");
        require(counters.executeIterationCalls == 0, "construction called executeIteration");
        require(counters.destructionCount == 0, "adapter was destroyed before task destruction");
    }
    require(counters.destructionCount == 1, "task did not own and destroy the adapter");
}

void testNullAdapterRejected()
{
    const BenchmarkConfig raw = validConfig();
    ValidationResult validation;
    auto validated = validatedConfig(raw, validation);
    require(validated.has_value(), "valid config was not validated");
    const auto* canonicalProfile = AlgorithmRegistry::find(raw.profile);
    require(canonicalProfile != nullptr, "canonical profile was not found");

    bool rejected = false;
    try {
        BenchmarkTask task(std::move(*validated), *canonicalProfile, nullptr);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "null adapter was accepted");
}

void testMismatchedProfileRejected()
{
    const BenchmarkConfig raw = validConfig();
    ValidationResult validation;
    auto validated = validatedConfig(raw, validation);
    require(validated.has_value(), "valid config was not validated");
    const auto* otherProfile = AlgorithmRegistry::find(AlgorithmProfileId::Sha512);
    require(otherProfile != nullptr, "comparison profile was not found");
    AdapterCounters counters;

    bool rejected = false;
    try {
        BenchmarkTask task(
            std::move(*validated),
            *otherProfile,
            std::make_unique<FakeAdapter>(counters));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "mismatched profile was accepted");
}

} // namespace

int runCoreExecutionContractTests()
{
    const auto tests = std::array{
        std::pair{"valid binding and access", &testValidBindingAndAccess},
        std::pair{"construction lifecycle and ownership", &testConstructionDoesNotRunLifecycleAndOwnsAdapter},
        std::pair{"null adapter rejection", &testNullAdapterRejected},
        std::pair{"mismatched profile rejection", &testMismatchedProfileRejected}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS core execution total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
