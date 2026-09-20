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

struct AeadCase {
    const char* label;
    core::AlgorithmProfileId profile;
    core::BenchmarkOperation operation;
    core::WorkloadBytes plaintextSize;
    core::ByteCount keyBytes;
};

void runCase(const AeadCase& testCase)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const core::BenchmarkConfig config{
        testCase.profile, testCase.operation, 2, 2, core::AeadConfig{testCase.plaintextSize}};
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

    const auto* characteristics =
        std::get_if<core::AeadCharacteristics>(&result->characteristics);
    test_support::require(characteristics != nullptr && characteristics->keyBytes == testCase.keyBytes &&
                              characteristics->nonceBytes == 12 && characteristics->aadBytes == 32 &&
                              characteristics->tagBytes == 16,
                          "result AEAD characteristics do not match the selected profile");
}

void runAllCases()
{
    constexpr std::array cases{
        AeadCase{"AES-128-GCM encrypt", core::AlgorithmProfileId::Aes128Gcm,
                 core::BenchmarkOperation::Encrypt, 1024, 16},
        AeadCase{"AES-128-GCM decrypt", core::AlgorithmProfileId::Aes128Gcm,
                 core::BenchmarkOperation::Decrypt, 1024, 16},
        AeadCase{"ChaCha20-Poly1305 encrypt", core::AlgorithmProfileId::ChaCha20Poly1305,
                 core::BenchmarkOperation::Encrypt, 1, 32},
        AeadCase{"ChaCha20-Poly1305 decrypt", core::AlgorithmProfileId::ChaCha20Poly1305,
                 core::BenchmarkOperation::Decrypt, 1024, 32}
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
        std::cout << "PASS BackendAeadIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendAeadIntegration: " << error.what() << '\n';
        return 1;
    }
}
