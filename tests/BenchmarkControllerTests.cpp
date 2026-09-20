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

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
                     [&](const core::ProgressInfo&) { progressObserved = true; });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++finishCount;
                         result = value;
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
