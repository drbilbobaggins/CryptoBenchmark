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

class LifecycleHarness final {
public:
    LifecycleHarness()
    {
        QObject::connect(&controller_, &application::BenchmarkController::progressChanged,
                         [&](const core::ProgressInfo&) {
                             if (cancelArmed_ && controller_.isBusy()) {
                                 cancelArmed_ = false;
                                 controller_.requestCancel();
                             }
                         });
        QObject::connect(&controller_, &application::BenchmarkController::benchmarkFinished,
                         [&](const core::BenchmarkResult& result) {
                             ++terminalCount_;
                             result_ = result;
                             loop_.quit();
                         });
        QObject::connect(&timeout_, &QTimer::timeout, &loop_, &QEventLoop::quit);
        timeout_.setSingleShot(true);
    }

    const core::BenchmarkResult& run(
        std::string_view label,
        const core::BenchmarkConfig& config,
        bool cancelOnProgress = false)
    {
        label_ = label;
        result_.reset();
        terminalCount_ = 0;
        cancelArmed_ = cancelOnProgress;
        const auto startedAt = std::chrono::system_clock::now();

        controller_.start(config);
        if (!result_.has_value()) {
            timeout_.start(30'000);
            loop_.exec();
            timeout_.stop();
        }

        require(result_.has_value(), "session timed out without a terminal result");
        require(terminalCount_ == 1, "session emitted more than one terminal result");
        require(!controller_.isBusy(), "controller remained busy after terminal result");
        require(!cancelArmed_, "cancellation handler remained armed after the session");
        const auto completedAt = std::chrono::system_clock::now();
        if (result_->status == core::BenchmarkStatus::Completed) {
            test_support::assertCompletedResult(*result_, config, startedAt, completedAt);
        }

        QCoreApplication::processEvents(QEventLoop::AllEvents);
        require(terminalCount_ == 1, "session emitted a late duplicate terminal result");
        require(!controller_.isBusy(), "controller became busy after terminal result");
        return *result_;
    }

    void requireIdle(std::string_view message) const
    {
        require(!controller_.isBusy(), message);
    }

    void requestCancelWhileIdle()
    {
        controller_.requestCancel();
        require(!controller_.isBusy(), "idle cancellation changed controller state");
        require(terminalCount_ == 0, "idle cancellation emitted a terminal result");
    }

private:
    void require(bool condition, std::string_view message) const
    {
        if (!condition) {
            throw std::runtime_error(std::string(label_) + ": " + std::string(message));
        }
    }

    application::BenchmarkController controller_;
    QEventLoop loop_;
    QTimer timeout_;
    std::optional<core::BenchmarkResult> result_;
    std::size_t terminalCount_ = 0;
    bool cancelArmed_ = false;
    std::string_view label_ = "uninitialized session";
};

core::BenchmarkConfig sha256Config(core::WorkloadBytes inputSize)
{
    return {core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash, 2, 2,
            core::HashConfig{inputSize}};
}

void requireHashCharacteristics(const core::BenchmarkResult& result, core::ByteCount outputBytes)
{
    const auto* characteristics =
        std::get_if<core::HashCharacteristics>(&result.characteristics);
    if (characteristics == nullptr || characteristics->outputBytes != outputBytes) {
        throw std::runtime_error("hash result characteristics were incorrect");
    }
}

void requireAeadCharacteristics(const core::BenchmarkResult& result)
{
    const auto* characteristics =
        std::get_if<core::AeadCharacteristics>(&result.characteristics);
    if (characteristics == nullptr || characteristics->keyBytes != 16 ||
        characteristics->nonceBytes != 12 || characteristics->aadBytes != 32 ||
        characteristics->tagBytes != 16) {
        throw std::runtime_error("AES-128-GCM result characteristics were incorrect");
    }
}

void runLifecycle()
{
    LifecycleHarness harness;

    const auto completedA = sha256Config(8);
    const auto resultA = harness.run("Completed A", completedA);
    requireHashCharacteristics(resultA, 32);

    const core::BenchmarkConfig completedB{
        core::AlgorithmProfileId::Aes128Gcm, core::BenchmarkOperation::Encrypt, 2, 2,
        core::AeadConfig{1024}};
    const auto resultB = harness.run("Completed B", completedB);
    requireAeadCharacteristics(resultB);
    if (resultB.config.profile == resultA.config.profile ||
        resultB.config.operation == resultA.config.operation) {
        throw std::runtime_error("AES session reused the previous configuration");
    }

    const auto invalid = sha256Config(core::kMaxWorkloadBytes + 1);
    bool rejected = false;
    try {
        harness.run("invalid preflight", invalid);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    if (!rejected) throw std::runtime_error("invalid preflight was not rejected synchronously");
    harness.requireIdle("controller was not idle after invalid preflight");
    harness.requestCancelWhileIdle();

    const auto cancelledConfig = sha256Config(64);
    const auto cancelled = harness.run("Cancelled C", cancelledConfig, true);
    if (cancelled.status != core::BenchmarkStatus::Cancelled || cancelled.error.has_value() ||
        cancelled.statistics.has_value()) {
        throw std::runtime_error("real-worker cancellation result had incorrect terminal state");
    }
    if (cancelled.config.profile != cancelledConfig.profile ||
        cancelled.config.operation != cancelledConfig.operation ||
        cancelled.config.iterationsPerRun != cancelledConfig.iterationsPerRun ||
        cancelled.config.runs != cancelledConfig.runs) {
        throw std::runtime_error("cancelled result did not preserve its configuration");
    }
    const auto* cancelledHash = std::get_if<core::HashConfig>(&cancelled.config.parameters);
    const auto* expectedCancelledHash =
        std::get_if<core::HashConfig>(&cancelledConfig.parameters);
    if (cancelledHash == nullptr || expectedCancelledHash == nullptr ||
        cancelledHash->inputSize != expectedCancelledHash->inputSize) {
        throw std::runtime_error("cancelled result did not preserve its hash configuration");
    }
    if (cancelled.runs.size() > cancelledConfig.runs) {
        throw std::runtime_error("cancelled result retained too many completed runs");
    }
    for (std::size_t index = 0; index < cancelled.runs.size(); ++index) {
        if (cancelled.runs[index].runIndex != index) {
            throw std::runtime_error("cancelled result runs were not a sequential prefix");
        }
    }

    const core::BenchmarkConfig completedD{
        core::AlgorithmProfileId::Sha3_256, core::BenchmarkOperation::Hash, 2, 2,
        core::HashConfig{1024}};
    const auto resultD = harness.run("Completed D", completedD);
    requireHashCharacteristics(resultD, 32);
    if (resultD.config.profile == resultA.config.profile ||
        resultD.config.profile == resultB.config.profile) {
        throw std::runtime_error("SHA3 session reused a previous profile");
    }
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        runLifecycle();
        std::cout << "PASS BackendLifecycleIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendLifecycleIntegration: " << error.what() << '\n';
        return 1;
    }
}
