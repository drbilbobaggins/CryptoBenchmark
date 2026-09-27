#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BatchTypes.h>

#include <QFile>
#include <QTemporaryDir>

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using namespace cryptobench;
using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

BatchDefinition definition()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory is invalid");
    const auto path = directory.filePath("batch.json");
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch fixture could not be opened");
    const QByteArray input =
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"first","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}},)"
        R"({"profileId":"sha3-256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}}]})";
    require(file.write(input) == input.size(), "batch fixture could not be written");
    file.close();
    const auto parsed = BatchInputParser{}.parseFile(path);
    require(parsed.issues.empty() && parsed.definition.has_value(), "batch fixture was rejected");
    return *parsed.definition;
}

void testInitialStateAndOrdering()
{
    const auto state = createBatchExecutionState(definition(), "result.json");
    require(state.entries.size() == 2, "entry count mismatch");
    require(state.entries[0].definition.entryIndex == 1 && state.entries[1].definition.entryIndex == 2,
            "definition order was not preserved");
    require(state.entries[0].status == BatchEntryStatus::NotStarted &&
                !state.entries[0].result.has_value(),
            "initial entry state is not not-started");
    require(state.outputTarget == "result.json", "output target was not preserved");
}

void testStatusesAndInvariants()
{
    const auto state = createBatchExecutionState(definition(), {});
    const std::array statuses{BatchStatus::InProgress, BatchStatus::Completed,
                              BatchStatus::CompletedWithFailures, BatchStatus::Cancelled,
                              BatchStatus::Failed};
    for (const auto status : statuses) {
        auto copy = state;
        copy.status = status;
        require(toStableString(status) != "", "batch status is not representable");
    }

    auto invalid = state.entries.front();
    invalid.status = BatchEntryStatus::Completed;
    bool rejected = false;
    try {
        validateBatchEntryState(invalid);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "missing completed result was accepted");
}

void testDerivedCounts()
{
    auto state = createBatchExecutionState(definition(), {});
    state.entries[0].status = BatchEntryStatus::Completed;
    state.entries[0].result = core::BenchmarkResult{
        state.entries[0].definition.config,
        {},
        core::BenchmarkStatistics{
            core::Statistics<double>{1, 1, 1, 1, 0},
            core::Statistics<double>{1, 1, 1, 1, 0},
            core::Statistics<double>{1, 1, 1, 1, 0}
        },
        state.entries[0].definition.characteristics,
        {"0.1.0", "commit", "openssl", "Windows", "x64", "Debug",
         std::chrono::system_clock::time_point{}},
        BenchmarkStatus::Completed,
        std::nullopt
    };
    state.entries[1].status = BatchEntryStatus::NotStarted;
    state.currentEntryIndex = 2;
    const auto progress = deriveBatchProgress(state,
        ProgressInfo{BenchmarkPhase::Preparing, std::nullopt, 1});
    require(progress.totalEntries == 2 && progress.completedCount == 1 &&
                progress.failedCount == 0 && progress.cancelledCount == 0 &&
                progress.notStartedCount == 1,
            "derived progress counts are incorrect");
    require(progress.currentProfile == AlgorithmProfileId::Sha3_256 &&
                progress.currentOperation == BenchmarkOperation::Hash &&
                progress.currentProgress.has_value(),
            "current batch progress context was not derived");
}

} // namespace

int main()
{
    try {
        testInitialStateAndOrdering();
        testStatusesAndInvariants();
        testDerivedCounts();
        std::cout << "PASS BatchExecutionState\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchExecutionState: " << error.what() << '\n';
        return 1;
    }
}