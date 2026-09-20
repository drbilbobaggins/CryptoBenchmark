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

struct KeyEstablishmentCase {
    const char* label;
    core::AlgorithmProfileId profile;
    core::BenchmarkOperation operation;
    core::ByteCount sharedSecretBytes;
};

void runCase(const KeyEstablishmentCase& testCase)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const core::BenchmarkConfig config{
        testCase.profile, testCase.operation, 2, 2, core::KeyEstablishmentConfig{}};
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
        std::get_if<core::KeyEstablishmentCharacteristics>(&result->characteristics);
    test_support::require(characteristics != nullptr &&
                              characteristics->sharedSecretBytes == testCase.sharedSecretBytes,
                          "result key-establishment characteristics do not match the selected profile");
}

void runAllCases()
{
    constexpr std::array cases{
        KeyEstablishmentCase{"ECDH P-256 key generation", core::AlgorithmProfileId::EcdhP256,
                             core::BenchmarkOperation::KeyGen, 32},
        KeyEstablishmentCase{"ECDH P-256 agreement", core::AlgorithmProfileId::EcdhP256,
                             core::BenchmarkOperation::Derive, 32},
        KeyEstablishmentCase{"X25519 key generation", core::AlgorithmProfileId::X25519,
                             core::BenchmarkOperation::KeyGen, 32},
        KeyEstablishmentCase{"X25519 agreement", core::AlgorithmProfileId::X25519,
                             core::BenchmarkOperation::Derive, 32},
        KeyEstablishmentCase{"ML-KEM-512 key generation", core::AlgorithmProfileId::MlKem512,
                             core::BenchmarkOperation::KeyGen, 32},
        KeyEstablishmentCase{"ML-KEM-512 encapsulation", core::AlgorithmProfileId::MlKem512,
                             core::BenchmarkOperation::Encapsulate, 32},
        KeyEstablishmentCase{"ML-KEM-512 decapsulation", core::AlgorithmProfileId::MlKem512,
                             core::BenchmarkOperation::Decapsulate, 32}
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
        std::cout << "PASS BackendKeyEstablishmentIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendKeyEstablishmentIntegration: " << error.what() << '\n';
        return 1;
    }
}
