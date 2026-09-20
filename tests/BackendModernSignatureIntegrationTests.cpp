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

struct SignatureCase {
    const char* label;
    core::AlgorithmProfileId profile;
    core::BenchmarkOperation operation;
    core::SignatureConfig signatureConfig;
    core::ByteCount publicKeyBytes;
    core::ByteCount privateKeyBytes;
    core::ByteCount signatureBytes;
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
        std::get_if<core::SignatureCharacteristics>(&result->characteristics);
    test_support::require(characteristics != nullptr && characteristics->publicKeyBytes.has_value() &&
                              characteristics->privateKeyBytes.has_value() &&
                              characteristics->signatureSize.has_value() &&
                              *characteristics->publicKeyBytes == testCase.publicKeyBytes &&
                              *characteristics->privateKeyBytes == testCase.privateKeyBytes &&
                              characteristics->signatureSize->bytes == testCase.signatureBytes &&
                              characteristics->signatureSize->kind ==
                                  core::SignatureSizeReferenceKind::Fixed,
                          "result signature characteristics do not match the selected profile");
}

void runAllCases()
{
    constexpr core::SignatureConfig noInput{core::NoSignatureInput{}};
    constexpr core::SignatureConfig message{core::MessageInput{1024}};
    constexpr std::array cases{
        SignatureCase{"Ed25519 key generation", core::AlgorithmProfileId::Ed25519,
                      core::BenchmarkOperation::KeyGen, noInput, 32, 32, 64},
        SignatureCase{"Ed25519 message signing", core::AlgorithmProfileId::Ed25519,
                      core::BenchmarkOperation::Sign, message, 32, 32, 64},
        SignatureCase{"Ed25519 message verification", core::AlgorithmProfileId::Ed25519,
                      core::BenchmarkOperation::Verify, message, 32, 32, 64},
        SignatureCase{"ML-DSA-44 key generation", core::AlgorithmProfileId::MlDsa44,
                      core::BenchmarkOperation::KeyGen, noInput, 1312, 2560, 2420},
        SignatureCase{"ML-DSA-44 message signing", core::AlgorithmProfileId::MlDsa44,
                      core::BenchmarkOperation::Sign, message, 1312, 2560, 2420},
        SignatureCase{"ML-DSA-44 message verification", core::AlgorithmProfileId::MlDsa44,
                      core::BenchmarkOperation::Verify, message, 1312, 2560, 2420}
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
        std::cout << "PASS BackendModernSignatureIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendModernSignatureIntegration: " << error.what() << '\n';
        return 1;
    }
}
