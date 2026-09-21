#include <cryptobench/application/BenchmarkController.h>

#include <cryptobench/core/ConfigValidation.h>
#include "BackendIntegrationTestSupport.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

core::BenchmarkConfig validConfig()
{
    return {
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        2,
        core::HashConfig{8}
    };
}

void testInvalidPreflight()
{
    application::BenchmarkController controller;
    auto invalid = validConfig();
    invalid.parameters = core::HashConfig{core::kMaxWorkloadBytes + 1};

    bool rejected = false;
    try {
        controller.start(invalid);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }

    require(rejected, "invalid preflight configuration was accepted");
    require(!controller.isBusy(), "controller remained busy after invalid preflight");
}

void testSuccessfulSession()
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const auto config = validConfig();
    std::optional<core::BenchmarkResult> result;
    std::size_t finishCount = 0;
    bool progressObserved = false;
    bool terminal = false;
    std::size_t progressAfterTerminal = 0;
    std::vector<core::ProgressInfo> progress;

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
                     [&](const core::ProgressInfo& value) {
                         progressObserved = true;
                         if (terminal) ++progressAfterTerminal;
                         progress.push_back(value);
                     });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++finishCount;
                         result = value;
                         terminal = true;
                         loop.quit();
                     });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    const auto startedAt = std::chrono::system_clock::now();
    controller.start(config);
    bool concurrentStartRejected = false;
    try {
        controller.start(config);
    } catch (const std::logic_error&) {
        concurrentStartRejected = true;
    }
    require(concurrentStartRejected, "concurrent controller start was accepted");

    timeout.start(20'000);
    loop.exec();
    require(result.has_value(), "controller test timed out without a result");
    require(finishCount == 1, "controller emitted more than one final result");
    require(!controller.isBusy(), "controller remained busy after completion");
    test_support::assertCompletedResult(*result, config, startedAt,
                                        std::chrono::system_clock::now());
    require(progressObserved, "no progress was forwarded");
    QCoreApplication::processEvents();
    require(progressAfterTerminal == 0, "Measuring progress arrived after terminal result");

    std::vector<std::uint32_t> measuredRuns;
    std::optional<std::size_t> finalizingIndex;
    std::optional<std::size_t> lastMeasuringIndex;
    for (std::size_t index = 0; index < progress.size(); ++index) {
        const auto& value = progress[index];
        require(value.totalRuns == config.runs, "progress total does not match configured runs");
        if (value.phase == core::BenchmarkPhase::Measuring) {
            require(value.runIndex.has_value(), "Measuring progress has no run index");
            measuredRuns.push_back(*value.runIndex);
            require(index > 0 && progress[index - 1].phase == core::BenchmarkPhase::Warmup,
                    "Measuring progress was not preceded by warm-up");
            require(progress[index - 1].runIndex == value.runIndex,
                    "Measuring progress did not follow the matching warm-up run");
            lastMeasuringIndex = index;
        } else if (value.phase == core::BenchmarkPhase::Finalizing) {
            finalizingIndex = index;
        }
    }
    require(measuredRuns == std::vector<std::uint32_t>{0, 1},
            "unexpected Measuring progress sequence");
        require(finalizingIndex.has_value() && lastMeasuringIndex.has_value() &&
            *finalizingIndex > *lastMeasuringIndex,
            "Finalizing progress was not emitted after measured runs");

    const auto hashCharacteristics = std::get_if<core::HashCharacteristics>(&result->characteristics);
    require(hashCharacteristics != nullptr && hashCharacteristics->outputBytes == 32,
            "SHA-256 result characteristics are incorrect");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInvalidPreflight();
        testSuccessfulSession();
        std::cout << "PASS BenchmarkController\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BenchmarkController: " << error.what() << '\n';
        return 1;
    }
}
