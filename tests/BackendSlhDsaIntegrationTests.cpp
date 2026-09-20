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
#include <string_view>

using namespace cryptobench;

namespace {

struct SignatureCase {
    const char* label;
    core::AlgorithmProfileId profile;
    core::BenchmarkOperation operation;
    core::SignatureConfig signatureConfig;
    core::ByteCount signatureBytes;
    std::chrono::milliseconds watchdog;
};

void runCase(const SignatureCase& testCase)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const core::BenchmarkConfig config{
        testCase.profile, testCase.operation, 2, 2, testCase.signatureConfig};
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
    timeout.start(testCase.watchdog);
    controller.start(config);
    loop.exec();
    timeout.stop();

    test_support::require(result.has_value(), "session timed out without a result");
    test_support::require(finishCount == 1, "controller emitted more than one final result");
    test_support::require(!controller.isBusy(), "controller remained busy after completion");
    test_support::assertCompletedResult(*result, config, startedAt,
                                        std::chrono::system_clock::now());

    const auto* characteristics =
        std::get_if<core::SignatureCharacteristics>(&result->characteristics);
    test_support::require(characteristics != nullptr && characteristics->publicKeyBytes.has_value() &&
                              characteristics->privateKeyBytes.has_value() &&
                              characteristics->signatureSize.has_value() &&
                              *characteristics->publicKeyBytes == 32 &&
                              *characteristics->privateKeyBytes == 64 &&
                              characteristics->signatureSize->bytes == testCase.signatureBytes &&
                              characteristics->signatureSize->kind ==
                                  core::SignatureSizeReferenceKind::Fixed,
                          "result SLH-DSA characteristics do not match the selected profile");
}

void runFastCases()
{
    constexpr core::SignatureConfig noInput{core::NoSignatureInput{}};
    constexpr core::SignatureConfig message{core::MessageInput{1024}};
    constexpr auto watchdog = std::chrono::seconds{30};
    constexpr std::array cases{
        SignatureCase{"SLH-DSA SHA2-128f key generation", core::AlgorithmProfileId::SlhDsaSha2128F,
                      core::BenchmarkOperation::KeyGen, noInput, 17088, watchdog},
        SignatureCase{"SLH-DSA SHA2-128f message signing", core::AlgorithmProfileId::SlhDsaSha2128F,
                      core::BenchmarkOperation::Sign, message, 17088, watchdog},
        SignatureCase{"SLH-DSA SHA2-128f message verification", core::AlgorithmProfileId::SlhDsaSha2128F,
                      core::BenchmarkOperation::Verify, message, 17088, watchdog}
    };

    for (const auto& testCase : cases) {
        try {
            runCase(testCase);
        } catch (const std::exception& error) {
            throw std::runtime_error(std::string(testCase.label) + ": " + error.what());
        }
    }
}

void runSlowCase()
{
    constexpr core::SignatureConfig message{core::MessageInput{1024}};
    constexpr SignatureCase testCase{
        "SLH-DSA SHA2-128s message signing", core::AlgorithmProfileId::SlhDsaSha2128S,
        core::BenchmarkOperation::Sign, message, 7856, std::chrono::seconds{120}};
    try {
        runCase(testCase);
    } catch (const std::exception& error) {
        throw std::runtime_error(std::string(testCase.label) + ": " + error.what());
    }
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        const std::string_view mode = argc > 1 ? argv[1] : "";
        if (mode == "--fast") {
            runFastCases();
        } else if (mode == "--slow") {
            runSlowCase();
        } else {
            throw std::invalid_argument("expected --fast or --slow");
        }
        std::cout << "PASS BackendSlhDsaIntegration " << mode << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendSlhDsaIntegration: " << error.what() << '\n';
        return 1;
    }
}
