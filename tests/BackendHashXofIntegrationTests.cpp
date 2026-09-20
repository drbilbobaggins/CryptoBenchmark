#include <cryptobench/application/BenchmarkController.h>

#include "BackendIntegrationTestSupport.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>

#include <array>
#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

using namespace cryptobench;

namespace {

struct HashXofCase {
    const char* label;
    core::AlgorithmProfileId profile;
    core::BenchmarkOperation operation;
    core::WorkloadBytes inputSize;
    core::ByteCount outputBytes;
};

void runCase(const HashXofCase& testCase)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const core::BenchmarkConfig config{
        testCase.profile, testCase.operation, 2, 2, core::HashConfig{testCase.inputSize}};
    std::optional<core::BenchmarkResult> result;
    std::size_t finishCount = 0;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++finishCount;
                         result = value;
                         loop.quit();
                     });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    const auto startedAt = std::chrono::system_clock::now();
    timeout.start(30'000);
    controller.start(config);
    loop.exec();
    timeout.stop();

    test_support::require(result.has_value(), "session timed out without a result");
    test_support::require(finishCount == 1, "controller emitted more than one final result");
    test_support::require(!controller.isBusy(), "controller remained busy after completion");
    test_support::assertCompletedResult(*result, config, startedAt,
                                        std::chrono::system_clock::now());

    const auto* hashCharacteristics =
        std::get_if<core::HashCharacteristics>(&result->characteristics);
    test_support::require(hashCharacteristics != nullptr &&
                              hashCharacteristics->outputBytes == testCase.outputBytes,
                          "result output characteristics do not match the selected profile");
}

void runAllCases()
{
    constexpr std::array cases{
        HashXofCase{"SHA-3-256 empty input", core::AlgorithmProfileId::Sha3_256,
                    core::BenchmarkOperation::Hash, 0, 32},
        HashXofCase{"SHA-3-256 1024-byte input", core::AlgorithmProfileId::Sha3_256,
                    core::BenchmarkOperation::Hash, 1024, 32},
        HashXofCase{"SHAKE256-32B empty input", core::AlgorithmProfileId::Shake256_32B,
                    core::BenchmarkOperation::Xof, 0, 32},
        HashXofCase{"SHAKE256-256B 1024-byte input", core::AlgorithmProfileId::Shake256_256B,
                    core::BenchmarkOperation::Xof, 1024, 256}
    };

    for (const auto& testCase : cases) {
        try {
            runCase(testCase);
        } catch (const std::exception& error) {
            throw std::runtime_error(std::string(testCase.label) + ": " + error.what());
        }
    }
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        runAllCases();
        std::cout << "PASS BackendHashXofIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendHashXofIntegration: " << error.what() << '\n';
        return 1;
    }
}
