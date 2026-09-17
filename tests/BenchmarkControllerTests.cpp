#include <cryptobench/application/BenchmarkController.h>

#include <cryptobench/core/ConfigValidation.h>

#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>

#include <iostream>
#include <variant>
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
    require(result->status == core::BenchmarkStatus::Completed, "session did not complete");
    require(!result->error.has_value(), "successful result contains an error");
    const auto* resultHash = std::get_if<core::HashConfig>(&result->config.parameters);
    const auto* expectedHash = std::get_if<core::HashConfig>(&config.parameters);
    require(result->config.profile == config.profile &&
                result->config.operation == config.operation &&
                result->config.iterationsPerRun == config.iterationsPerRun &&
                result->config.runs == config.runs &&
                resultHash != nullptr && expectedHash != nullptr &&
                resultHash->inputSize == expectedHash->inputSize,
            "completed result did not preserve the supplied config");
    require(result->runs.size() == 2, "completed result does not contain two runs");
    require(result->runs[0].runIndex == 0 && result->runs[1].runIndex == 1,
            "completed runs were not indexed sequentially");
    require(result->statistics.has_value(), "completed result has no statistics");
    require(progressObserved, "no progress was forwarded");
    require(!result->environment.applicationVersion.empty(), "environment version is empty");
    require(!result->environment.gitCommit.empty(), "environment git commit is empty");
    require(!result->environment.opensslVersion.empty(), "environment OpenSSL version is empty");
    require(!result->environment.operatingSystem.empty(), "environment operating system is empty");
    require(!result->environment.architecture.empty(), "environment architecture is empty");
    require(!result->environment.buildType.empty(), "environment build type is empty");

    for (const auto& run : result->runs) {
        require(run.memory.peakSampledBytes >= run.memory.baselineBytes,
                "run memory peak is below baseline");
        require(run.memory.peakDeltaBytes ==
                    run.memory.peakSampledBytes - run.memory.baselineBytes,
                "run memory delta is inconsistent");
    }
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
