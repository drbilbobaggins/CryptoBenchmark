#include <cryptobench/application/ResultJsonMapping.h>

#include <array>
#include <chrono>
#include <cmath>
#include <iostream>
#include <initializer_list>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <QJsonObject>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireString(const QJsonObject& object, const char* key, std::string_view expected)
{
    const auto value = object.value(key);
    require(value.isString() && value.toString().toStdString() == expected, "JSON string field mismatch");
}

void requireNumber(const QJsonObject& object, const char* key, double expected)
{
    const auto value = object.value(key);
    require(value.isDouble() && value.toDouble() == expected, "JSON number field mismatch");
}

void requireKeys(const QJsonObject& object, std::initializer_list<const char*> keys)
{
    require(object.size() == static_cast<int>(keys.size()), "JSON object field count mismatch");
    for (const auto key : keys) {
        require(object.contains(key), "JSON object field missing");
    }
}

template <typename Enum>
void requireUnsupported(Enum value, std::string_view message)
{
    bool rejected = false;
    try {
        static_cast<void>(toStableString(value));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void testStableEnumStrings()
{
    require(toStableString(SignatureSizeReferenceKind::Fixed) == "fixed", "fixed kind mismatch");
    require(toStableString(SignatureSizeReferenceKind::MaximumDerEncoded) == "maximumDerEncoded",
            "maximum DER kind mismatch");
    requireUnsupported(static_cast<SignatureSizeReferenceKind>(99), "unsupported signature kind accepted");

    const std::array errorCodes{
        std::pair{ErrorCode::InvalidConfiguration, "invalidConfiguration"},
        std::pair{ErrorCode::UnknownExecutionStrategy, "unknownExecutionStrategy"},
        std::pair{ErrorCode::CryptoInitializationFailed, "cryptoInitializationFailed"},
        std::pair{ErrorCode::CryptoOperationFailed, "cryptoOperationFailed"},
        std::pair{ErrorCode::MemoryMeasurementFailed, "memoryMeasurementFailed"},
        std::pair{ErrorCode::WorkerStartupFailed, "workerStartupFailed"},
        std::pair{ErrorCode::WorkerCommunicationFailed, "workerCommunicationFailed"},
        std::pair{ErrorCode::InternalError, "internalError"}
    };
    for (const auto& [code, expected] : errorCodes) {
        require(toStableString(code) == expected, "error code string mismatch");
    }
    requireUnsupported(static_cast<ErrorCode>(99), "unsupported error code accepted");

    const std::array failureStages{
        std::pair{FailureStage::WorkerStartup, "workerStartup"},
        std::pair{FailureStage::ConfigDeserialization, "configDeserialization"},
        std::pair{FailureStage::ConfigValidation, "configValidation"},
        std::pair{FailureStage::TaskCreation, "taskCreation"},
        std::pair{FailureStage::SeriesPreparation, "seriesPreparation"},
        std::pair{FailureStage::RunPreparation, "runPreparation"},
        std::pair{FailureStage::Warmup, "warmup"},
        std::pair{FailureStage::Measurement, "measurement"},
        std::pair{FailureStage::MemoryMeasurement, "memoryMeasurement"},
        std::pair{FailureStage::WorkerCommunication, "workerCommunication"},
        std::pair{FailureStage::ResultAssembly, "resultAssembly"}
    };
    for (const auto& [stage, expected] : failureStages) {
        require(toStableString(stage) == expected, "failure stage string mismatch");
    }
    requireUnsupported(static_cast<FailureStage>(99), "unsupported failure stage accepted");
}

void testStructuralMappings()
{
    const SignatureCharacteristics completeSignature{
        ByteCount{1952}, ByteCount{4032}, SignatureSizeReference{ByteCount{3309}, SignatureSizeReferenceKind::Fixed}
    };
    const auto signature = structuralCharacteristicsToJson(completeSignature);
    requireKeys(signature, {"type", "publicKeyBytes", "privateKeyBytes", "signatureSize"});
    requireString(signature, "type", "signature");
    requireNumber(signature, "publicKeyBytes", 1952.0);
    requireNumber(signature, "privateKeyBytes", 4032.0);
    const auto signatureSize = signature.value("signatureSize").toObject();
    requireKeys(signatureSize, {"bytes", "kind"});
    requireNumber(signatureSize, "bytes", 3309.0);
    requireString(signatureSize, "kind", "fixed");

    const auto maximumSignature = structuralCharacteristicsToJson(SignatureCharacteristics{
        std::nullopt, std::nullopt,
        SignatureSizeReference{ByteCount{72}, SignatureSizeReferenceKind::MaximumDerEncoded}
    });
    requireKeys(maximumSignature, {"type", "signatureSize"});
    requireString(maximumSignature, "type", "signature");
    const auto maximumSignatureSize = maximumSignature.value("signatureSize").toObject();
    requireKeys(maximumSignatureSize, {"bytes", "kind"});
    requireNumber(maximumSignatureSize, "bytes", 72.0);
    requireString(maximumSignatureSize, "kind", "maximumDerEncoded");

    const auto emptySignature = structuralCharacteristicsToJson(SignatureCharacteristics{
        std::nullopt, std::nullopt, std::nullopt
    });
    requireKeys(emptySignature, {"type"});
    requireString(emptySignature, "type", "signature");
    require(!emptySignature.contains("publicKeyBytes") && !emptySignature.contains("privateKeyBytes")
                && !emptySignature.contains("signatureSize"),
            "absent signature optionals were emitted");

    const auto completeKeyEstablishment = structuralCharacteristicsToJson(KeyEstablishmentCharacteristics{
        ByteCount{32}, ByteCount{1184}, ByteCount{2400}, ByteCount{1088}
    });
    requireKeys(completeKeyEstablishment,
                {"type", "sharedSecretBytes", "publicKeyBytes", "privateKeyBytes", "ciphertextBytes"});
    requireString(completeKeyEstablishment, "type", "keyEstablishment");
    requireNumber(completeKeyEstablishment, "sharedSecretBytes", 32.0);
    requireNumber(completeKeyEstablishment, "publicKeyBytes", 1184.0);
    requireNumber(completeKeyEstablishment, "privateKeyBytes", 2400.0);
    requireNumber(completeKeyEstablishment, "ciphertextBytes", 1088.0);

    const auto emptyKeyEstablishment = structuralCharacteristicsToJson(KeyEstablishmentCharacteristics{
        ByteCount{32}, std::nullopt, std::nullopt, std::nullopt
    });
    requireKeys(emptyKeyEstablishment, {"type", "sharedSecretBytes"});
    require(!emptyKeyEstablishment.contains("publicKeyBytes") && !emptyKeyEstablishment.contains("privateKeyBytes")
                && !emptyKeyEstablishment.contains("ciphertextBytes"),
            "absent key-establishment optionals were emitted");

    const auto aead = structuralCharacteristicsToJson(AeadCharacteristics{32, 12, 32, 16});
    requireKeys(aead, {"type", "keyBytes", "nonceBytes", "aadBytes", "tagBytes"});
    requireString(aead, "type", "aead");
    requireNumber(aead, "keyBytes", 32.0);
    requireNumber(aead, "nonceBytes", 12.0);
    requireNumber(aead, "aadBytes", 32.0);
    requireNumber(aead, "tagBytes", 16.0);

    const auto hashXof = structuralCharacteristicsToJson(HashCharacteristics{64});
    requireKeys(hashXof, {"type", "outputBytes"});
    requireString(hashXof, "type", "hashXof");
    requireNumber(hashXof, "outputBytes", 64.0);
}

void testEnvironmentMapping()
{
    const auto measuredAt = std::chrono::system_clock::time_point{
        std::chrono::milliseconds{1790035200177LL}
    };
    const EnvironmentInfo environment{
        "1.2.3", "abc123", "3.6.4", "Windows 11", "x64", "Debug", measuredAt
    };
    const auto value = environmentInfoToJson(environment);
    requireKeys(value, {"applicationVersion", "gitCommit", "opensslVersion", "operatingSystem", "architecture", "buildType", "measuredAt"});
    requireString(value, "applicationVersion", "1.2.3");
    requireString(value, "gitCommit", "abc123");
    requireString(value, "opensslVersion", "3.6.4");
    requireString(value, "operatingSystem", "Windows 11");
    requireString(value, "architecture", "x64");
    requireString(value, "buildType", "Debug");
    requireString(value, "measuredAt", "2026-09-22T00:00:00.177Z");
}

void testStatisticsMapping()
{
    const BenchmarkStatistics statistics{
        Statistics<double>{1523.42, 1511.78, 1470.11, 1602.91, 42.31},
        Statistics<double>{1488.12, 1480.55, 1432.70, 1551.40, 37.82},
        Statistics<double>{65536.0, 65536.0, 65535.5, 65536.5, 0.25}
    };
    const auto value = benchmarkStatisticsToJson(statistics);
    requireKeys(value, {"wallClockNanosecondsPerOperation", "processCpuNanosecondsPerOperation",
                        "peakPrivateUsageDeltaBytes"});
    const auto wallClock = value.value("wallClockNanosecondsPerOperation").toObject();
    const auto processCpu = value.value("processCpuNanosecondsPerOperation").toObject();
    const auto peakPrivateUsage = value.value("peakPrivateUsageDeltaBytes").toObject();
    requireKeys(wallClock, {"mean", "median", "min", "max", "stddev"});
    requireKeys(processCpu, {"mean", "median", "min", "max", "stddev"});
    requireKeys(peakPrivateUsage, {"mean", "median", "min", "max", "stddev"});
    requireNumber(wallClock, "mean", 1523.42);
    requireNumber(wallClock, "median", 1511.78);
    requireNumber(wallClock, "min", 1470.11);
    requireNumber(wallClock, "max", 1602.91);
    requireNumber(wallClock, "stddev", 42.31);
    requireNumber(processCpu, "mean", 1488.12);
    requireNumber(processCpu, "median", 1480.55);
    requireNumber(processCpu, "min", 1432.70);
    requireNumber(processCpu, "max", 1551.40);
    requireNumber(processCpu, "stddev", 37.82);
    requireNumber(peakPrivateUsage, "mean", 65536.0);
    requireNumber(peakPrivateUsage, "median", 65536.0);
    requireNumber(peakPrivateUsage, "min", 65535.5);
    requireNumber(peakPrivateUsage, "max", 65536.5);
    requireNumber(peakPrivateUsage, "stddev", 0.25);
    require(!value.contains("elapsedNanosecondsPerOperation") && !value.contains("peakDeltaBytes"),
            "core statistics names leaked into JSON");
}

void requireNonFiniteRejected(BenchmarkStatistics statistics, std::string_view message)
{
    bool rejected = false;
    try {
        static_cast<void>(benchmarkStatisticsToJson(statistics));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

BenchmarkStatistics finiteStatistics()
{
    return {
        Statistics<double>{1.0, 2.0, 3.0, 4.0, 5.0},
        Statistics<double>{6.0, 7.0, 8.0, 9.0, 10.0},
        Statistics<double>{11.0, 12.0, 13.0, 14.0, 15.0}
    };
}

void testNonFiniteStatisticsRejected()
{
    auto nanStatistics = finiteStatistics();
    nanStatistics.elapsedNanosecondsPerOperation.mean = std::numeric_limits<double>::quiet_NaN();
    requireNonFiniteRejected(nanStatistics, "NaN statistics were accepted");

    auto positiveInfinityStatistics = finiteStatistics();
    positiveInfinityStatistics.cpuNanosecondsPerOperation.max = std::numeric_limits<double>::infinity();
    requireNonFiniteRejected(positiveInfinityStatistics, "positive infinity statistics were accepted");

    auto negativeInfinityStatistics = finiteStatistics();
    std::get<Statistics<double>>(negativeInfinityStatistics.memory).min =
        -std::numeric_limits<double>::infinity();
    requireNonFiniteRejected(negativeInfinityStatistics, "negative infinity statistics were accepted");
}

void testMemoryV2StatisticsRejectedBySchemaV1Mapping()
{
    const BenchmarkStatistics statistics{
        Statistics<double>{1.0, 1.0, 1.0, 1.0, 0.0},
        Statistics<double>{2.0, 2.0, 2.0, 2.0, 0.0},
        MemoryV2Statistics{
            Statistics<double>{-1.0, -1.0, -2.0, 0.0, 0.0},
            Statistics<double>{1.0, 1.0, 1.0, 1.0, 0.0},
            Statistics<double>{2.0, 2.0, 2.0, 2.0, 0.0},
            Statistics<double>{3.0, 3.0, 3.0, 3.0, 0.0}}
    };
    requireNonFiniteRejected(statistics, "Memory v2 statistics were serialized through schema v1");
}

void testErrorMappings()
{
    const ErrorInfo complete{
        ErrorCode::CryptoOperationFailed,
        FailureStage::Measurement,
        std::uint32_t{0},
        "technical message: exact",
        "library details: exact"
    };
    const auto completeValue = errorInfoToJson(complete);
    requireKeys(completeValue, {"code", "stage", "technicalMessage", "runIndex", "libraryDetails"});
    requireString(completeValue, "code", "cryptoOperationFailed");
    requireString(completeValue, "stage", "measurement");
    requireString(completeValue, "technicalMessage", "technical message: exact");
    requireNumber(completeValue, "runIndex", 0.0);
    requireString(completeValue, "libraryDetails", "library details: exact");

    const ErrorInfo withoutOptionals{
        ErrorCode::InternalError, FailureStage::ResultAssembly, std::nullopt, "message", std::nullopt
    };
    const auto minimalValue = errorInfoToJson(withoutOptionals);
    requireKeys(minimalValue, {"code", "stage", "technicalMessage"});
    require(!minimalValue.contains("runIndex") && !minimalValue.contains("libraryDetails"),
            "absent error optionals were emitted");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testStableEnumStrings();
        std::cout << "PASS stable enum strings\n";
        cryptobench::tests::testStructuralMappings();
        std::cout << "PASS structural mappings\n";
        cryptobench::tests::testEnvironmentMapping();
        std::cout << "PASS environment mapping\n";
        cryptobench::tests::testStatisticsMapping();
        std::cout << "PASS statistics mapping\n";
        cryptobench::tests::testNonFiniteStatisticsRejected();
        std::cout << "PASS non-finite statistics rejection\n";
        cryptobench::tests::testMemoryV2StatisticsRejectedBySchemaV1Mapping();
        std::cout << "PASS Memory v2 schema v1 rejection\n";
        cryptobench::tests::testErrorMappings();
        std::cout << "PASS error mappings\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL ResultJsonMapping: " << error.what() << '\n';
        return 1;
    }
}