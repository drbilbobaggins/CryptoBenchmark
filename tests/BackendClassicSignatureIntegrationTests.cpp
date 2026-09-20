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
    core::ByteCount signatureBytes;
    core::SignatureSizeReferenceKind signatureKind;
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
    test_support::require(characteristics != nullptr &&
                              !characteristics->publicKeyBytes.has_value() &&
                              !characteristics->privateKeyBytes.has_value() &&
                              characteristics->signatureSize.has_value() &&
                              characteristics->signatureSize->bytes == testCase.signatureBytes &&
                              characteristics->signatureSize->kind == testCase.signatureKind,
                          "result signature characteristics do not match the selected profile");
}

void runAllCases()
{
    constexpr core::SignatureConfig noInput{core::NoSignatureInput{}};
    constexpr core::SignatureConfig prehashed{core::PrehashedInput{}};
    constexpr core::SignatureConfig message{core::MessageInput{1024}};
    constexpr std::array cases{
        SignatureCase{"RSA-2048 key generation", core::AlgorithmProfileId::Rsa2048KeyGen,
                      core::BenchmarkOperation::KeyGen, noInput, 256,
                      core::SignatureSizeReferenceKind::Fixed},
        SignatureCase{"RSA-PSS prehashed signing", core::AlgorithmProfileId::RsaPss2048Sha256,
                      core::BenchmarkOperation::Sign, prehashed, 256,
                      core::SignatureSizeReferenceKind::Fixed},
        SignatureCase{"RSA-PSS prehashed verification", core::AlgorithmProfileId::RsaPss2048Sha256,
                      core::BenchmarkOperation::Verify, prehashed, 256,
                      core::SignatureSizeReferenceKind::Fixed},
        SignatureCase{"RSA-PSS message signing", core::AlgorithmProfileId::RsaPss2048Sha256,
                      core::BenchmarkOperation::Sign, message, 256,
                      core::SignatureSizeReferenceKind::Fixed},
        SignatureCase{"RSA-PSS message verification", core::AlgorithmProfileId::RsaPss2048Sha256,
                      core::BenchmarkOperation::Verify, message, 256,
                      core::SignatureSizeReferenceKind::Fixed},
        SignatureCase{"ECDSA P-256 key generation", core::AlgorithmProfileId::EcdsaP256KeyGen,
                      core::BenchmarkOperation::KeyGen, noInput, 72,
                      core::SignatureSizeReferenceKind::MaximumDerEncoded},
        SignatureCase{"ECDSA prehashed signing", core::AlgorithmProfileId::EcdsaP256Sha256,
                      core::BenchmarkOperation::Sign, prehashed, 72,
                      core::SignatureSizeReferenceKind::MaximumDerEncoded},
        SignatureCase{"ECDSA prehashed verification", core::AlgorithmProfileId::EcdsaP256Sha256,
                      core::BenchmarkOperation::Verify, prehashed, 72,
                      core::SignatureSizeReferenceKind::MaximumDerEncoded},
        SignatureCase{"ECDSA message signing", core::AlgorithmProfileId::EcdsaP256Sha256,
                      core::BenchmarkOperation::Sign, message, 72,
                      core::SignatureSizeReferenceKind::MaximumDerEncoded},
        SignatureCase{"ECDSA message verification", core::AlgorithmProfileId::EcdsaP256Sha256,
                      core::BenchmarkOperation::Verify, message, 72,
                      core::SignatureSizeReferenceKind::MaximumDerEncoded}
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
        std::cout << "PASS BackendClassicSignatureIntegration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BackendClassicSignatureIntegration: " << error.what() << '\n';
        return 1;
    }
}
