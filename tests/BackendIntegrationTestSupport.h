#pragma once

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkResult.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

namespace cryptobench::test_support {

inline void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

inline void requireNear(double actual, double expected, std::string_view message)
{
    require(std::isfinite(actual) && std::isfinite(expected), message);
    const auto tolerance = std::max(1e-9, std::max(std::abs(actual), std::abs(expected)) * 1e-12);
    require(std::abs(actual - expected) <= tolerance, message);
}

inline void requireOptionalByteCountEqual(const std::optional<core::ByteCount>& actual,
                                          const std::optional<core::ByteCount>& expected,
                                          std::string_view message)
{
    require(actual.has_value() == expected.has_value(), message);
    if (actual.has_value()) require(*actual == *expected, message);
}

inline void requireCharacteristicsMatch(const core::StructuralCharacteristics& actual,
                                        const core::StructuralCharacteristics& expected)
{
    require(actual.index() == expected.index(), "result characteristics have the wrong variant");

    if (const auto* actualValue = std::get_if<core::SignatureCharacteristics>(&actual)) {
        const auto& expectedValue = std::get<core::SignatureCharacteristics>(expected);
        requireOptionalByteCountEqual(actualValue->publicKeyBytes, expectedValue.publicKeyBytes,
                                       "signature public key characteristic mismatch");
        requireOptionalByteCountEqual(actualValue->privateKeyBytes, expectedValue.privateKeyBytes,
                                       "signature private key characteristic mismatch");
        require(actualValue->signatureSize.has_value() == expectedValue.signatureSize.has_value(),
                "signature size characteristic presence mismatch");
        if (actualValue->signatureSize.has_value()) {
            require(actualValue->signatureSize->bytes == expectedValue.signatureSize->bytes &&
                        actualValue->signatureSize->kind == expectedValue.signatureSize->kind,
                    "signature size characteristic mismatch");
        }
    } else if (const auto* keyActual =
                   std::get_if<core::KeyEstablishmentCharacteristics>(&actual)) {
        const auto& expectedValue = std::get<core::KeyEstablishmentCharacteristics>(expected);
        require(keyActual->sharedSecretBytes == expectedValue.sharedSecretBytes,
                "shared secret characteristic mismatch");
        requireOptionalByteCountEqual(keyActual->publicKeyBytes, expectedValue.publicKeyBytes,
                                       "key establishment public key characteristic mismatch");
        requireOptionalByteCountEqual(keyActual->privateKeyBytes, expectedValue.privateKeyBytes,
                                       "key establishment private key characteristic mismatch");
        requireOptionalByteCountEqual(keyActual->ciphertextBytes, expectedValue.ciphertextBytes,
                                       "ciphertext characteristic mismatch");
    } else if (const auto* aeadActual = std::get_if<core::AeadCharacteristics>(&actual)) {
        const auto& expectedValue = std::get<core::AeadCharacteristics>(expected);
        require(aeadActual->keyBytes == expectedValue.keyBytes &&
                    aeadActual->nonceBytes == expectedValue.nonceBytes &&
                    aeadActual->aadBytes == expectedValue.aadBytes &&
                    aeadActual->tagBytes == expectedValue.tagBytes,
                "AEAD characteristics mismatch");
    } else {
        const auto& hashActual = std::get<core::HashCharacteristics>(actual);
        const auto& expectedValue = std::get<core::HashCharacteristics>(expected);
        require(hashActual.outputBytes == expectedValue.outputBytes,
                "hash output characteristic mismatch");
    }
}

inline void requireTwoValueStatistics(const core::Statistics<double>& actual, double first,
                                      double second, std::string_view message)
{
    require(std::isfinite(first) && std::isfinite(second), message);
    const auto minimum = std::min(first, second);
    const auto maximum = std::max(first, second);
    const auto mean = (first + second) / 2.0;
    const auto standardDeviation = std::abs(first - second) / 2.0;
    requireNear(actual.mean, mean, message);
    requireNear(actual.median, mean, message);
    requireNear(actual.min, minimum, message);
    requireNear(actual.max, maximum, message);
    requireNear(actual.stddev, standardDeviation, message);
}

inline void assertCompletedResult(
    const core::BenchmarkResult& result, const core::BenchmarkConfig& expectedConfig,
    std::chrono::system_clock::time_point startedAt,
    std::chrono::system_clock::time_point completedAt)
{
    require(result.status == core::BenchmarkStatus::Completed, "session did not complete");
    require(!result.error.has_value(), "successful result contains an error");
    require(result.statistics.has_value(), "completed result has no statistics");

    const auto* resultHash = std::get_if<core::HashConfig>(&result.config.parameters);
    const auto* expectedHash = std::get_if<core::HashConfig>(&expectedConfig.parameters);
    require(result.config.profile == expectedConfig.profile &&
                result.config.operation == expectedConfig.operation &&
                result.config.iterationsPerRun == expectedConfig.iterationsPerRun &&
                result.config.runs == expectedConfig.runs && resultHash != nullptr &&
                expectedHash != nullptr && resultHash->inputSize == expectedHash->inputSize,
            "completed result did not preserve the supplied config");

    require(result.runs.size() == expectedConfig.runs, "completed result has the wrong run count");
    for (std::uint32_t index = 0; index < result.runs.size(); ++index) {
        require(result.runs[index].runIndex == index,
                "completed runs were not indexed sequentially");
    }

    require(!result.environment.applicationVersion.empty(), "environment version is empty");
    require(!result.environment.gitCommit.empty(), "environment git commit is empty");
    require(!result.environment.opensslVersion.empty(), "environment OpenSSL version is empty");
    require(!result.environment.operatingSystem.empty(), "environment operating system is empty");
    require(!result.environment.architecture.empty(), "environment architecture is empty");
    require(!result.environment.buildType.empty(), "environment build type is empty");
    require(result.environment.measuredAt >= startedAt && result.environment.measuredAt <= completedAt,
            "environment timestamp was not populated during the session");

    const auto* expectedProfile = core::AlgorithmRegistry::find(expectedConfig.profile);
    require(expectedProfile != nullptr, "configured algorithm profile is not registered");
    requireCharacteristicsMatch(result.characteristics, expectedProfile->characteristics);

    for (const auto& run : result.runs) {
        const auto expectedElapsed = static_cast<double>(run.totalElapsedTime.count()) /
                                     static_cast<double>(expectedConfig.iterationsPerRun);
        const auto expectedCpu = static_cast<double>(run.totalCpuTime.count()) /
                                 static_cast<double>(expectedConfig.iterationsPerRun);
        requireNear(run.meanElapsedTimePerOperation.count(), expectedElapsed,
                    "elapsed mean does not match total time");
        requireNear(run.meanCpuTimePerOperation.count(), expectedCpu,
                    "CPU mean does not match total time");
        require(run.memory.peakSampledBytes >= run.memory.baselineBytes,
                "run memory peak is below baseline");
        require(run.memory.peakDeltaBytes ==
                    run.memory.peakSampledBytes - run.memory.baselineBytes,
                "run memory delta is inconsistent");
    }

    const auto& statistics = *result.statistics;
    requireTwoValueStatistics(
        statistics.elapsedNanosecondsPerOperation,
        result.runs[0].meanElapsedTimePerOperation.count(),
        result.runs[1].meanElapsedTimePerOperation.count(), "elapsed statistics mismatch");
    requireTwoValueStatistics(
        statistics.cpuNanosecondsPerOperation,
        result.runs[0].meanCpuTimePerOperation.count(),
        result.runs[1].meanCpuTimePerOperation.count(), "CPU statistics mismatch");
    requireTwoValueStatistics(
        statistics.peakDeltaBytes, static_cast<double>(result.runs[0].memory.peakDeltaBytes),
        static_cast<double>(result.runs[1].memory.peakDeltaBytes), "memory statistics mismatch");
}

} // namespace cryptobench::test_support
