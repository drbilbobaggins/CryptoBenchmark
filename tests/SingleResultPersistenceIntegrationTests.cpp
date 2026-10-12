#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/JsonResultExportService.h>
#include <cryptobench/application/SingleResultDocumentService.h>

#include <chrono>
#include <cmath>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QTemporaryDir>

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

BenchmarkConfig config(AlgorithmProfileId profile, std::uint64_t iterations, std::uint32_t runs,
                       std::uint32_t inputSize)
{
    return {profile, BenchmarkOperation::Hash, iterations, runs, HashConfig{inputSize}};
}

StructuralCharacteristics characteristics(std::uint32_t outputBytes)
{
    return HashCharacteristics{outputBytes};
}

EnvironmentInfo environment(std::string applicationVersion, std::string operatingSystem)
{
    return {std::move(applicationVersion), "commit-abc", "OpenSSL 3.6.4", std::move(operatingSystem),
            "x64", "Debug", std::chrono::system_clock::time_point{std::chrono::milliseconds{1790035200177LL}}};
}

BenchmarkStatistics statistics(double wallMean, double cpuMean, double peakMean)
{
    return {
        Statistics<double>{wallMean, wallMean + 0.25, wallMean - 0.25, wallMean + 0.5, 0.125},
        Statistics<double>{cpuMean, cpuMean + 0.25, cpuMean - 0.25, cpuMean + 0.5, 0.25},
        Statistics<double>{peakMean, peakMean + 0.5, peakMean - 0.5, peakMean + 1.0, 0.5}
    };
}

RunResult run(std::uint32_t index, std::uint64_t elapsed, std::uint64_t cpu, std::uint64_t peakDelta)
{
    return {index, std::chrono::nanoseconds{static_cast<std::int64_t>(elapsed)},
            MeanOperationDuration{static_cast<double>(elapsed) / 4.0},
            std::chrono::nanoseconds{static_cast<std::int64_t>(cpu)},
            MeanOperationDuration{static_cast<double>(cpu) / 4.0},
            MemoryRunMeasurement{100, 100 + peakDelta, peakDelta}};
}

BenchmarkResult completedResult(const BenchmarkConfig& benchmarkConfig,
                                const StructuralCharacteristics& benchmarkCharacteristics,
                                const EnvironmentInfo& benchmarkEnvironment,
                                const BenchmarkStatistics& benchmarkStatistics)
{
    return {benchmarkConfig, {run(0, 40, 8, 10), run(1, 80, 16, 20)}, benchmarkStatistics,
            benchmarkCharacteristics, benchmarkEnvironment, BenchmarkStatus::Completed, std::nullopt};
}

BenchmarkResult resultA()
{
    return completedResult(config(AlgorithmProfileId::Sha256, 64, 2, 128), characteristics(32),
                           environment("0.1.0", "Windows Mérés"), statistics(1.25, 2.75, 3.5));
}

BenchmarkResult resultB()
{
    return completedResult(config(AlgorithmProfileId::Sha3_256, 128, 2, 4096), characteristics(32),
                           environment("0.2.0", "Windows B"), statistics(11.25, 12.75, 13.5));
}

QByteArray readBytes(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not open persisted result");
    return file.readAll();
}

void writeInitialBytes(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "could not create initial target");
    require(file.write(bytes) == bytes.size(), "could not write initial target");
    file.close();
}

QJsonObject parseObject(const QByteArray& bytes)
{
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(bytes, &parseError);
    require(parseError.error == QJsonParseError::NoError, "persisted JSON did not parse");
    require(document.isObject(), "persisted JSON root is not an object");
    return document.object();
}

void requireNumber(const QJsonObject& object, const char* key, double expected)
{
    const auto value = object.value(key);
    require(value.isDouble() && value.toDouble() == expected, "JSON numeric field mismatch");
}

void requireString(const QJsonObject& object, const char* key, std::string_view expected)
{
    const auto value = object.value(key);
    require(value.isString() && value.toString().toUtf8().toStdString() == expected,
            "JSON string field mismatch");
}

QJsonObject singleEntry(const QByteArray& bytes)
{
    const auto root = parseObject(bytes);
    const auto entries = root.value("entries").toArray();
    require(entries.size() == 1, "serialized result does not contain exactly one entry");
    return entries.at(0).toObject();
}

void requireStatistics(const QJsonObject& entry, double wallMean, double cpuMean, double peakMean)
{
    const auto statisticsValue = entry.value("statistics");
    require(statisticsValue.isObject(), "statistics object is missing");
    const auto statisticsObject = statisticsValue.toObject();
    requireNumber(statisticsObject.value("wallClockNanosecondsPerOperation").toObject(), "mean", wallMean);
    requireNumber(statisticsObject.value("processCpuNanosecondsPerOperation").toObject(), "mean", cpuMean);
    requireNumber(statisticsObject.value("peakPrivateUsageDeltaBytes").toObject(), "mean", peakMean);
}

void requireEnvironment(const QJsonObject& entry, std::string_view applicationVersion,
                        std::string_view operatingSystem)
{
    const auto environmentValue = entry.value("environment");
    require(environmentValue.isObject(), "environment object is missing");
    const auto environmentObject = environmentValue.toObject();
    requireString(environmentObject, "applicationVersion", applicationVersion);
    requireString(environmentObject, "gitCommit", "commit-abc");
    requireString(environmentObject, "opensslVersion", "OpenSSL 3.6.4");
    requireString(environmentObject, "operatingSystem", operatingSystem);
    requireString(environmentObject, "architecture", "x64");
    requireString(environmentObject, "buildType", "Debug");
    requireString(environmentObject, "measuredAt", "2026-09-22T00:00:00.177Z");
}

QByteArray serializeResult(const BenchmarkResult& result)
{
    const auto document = SingleResultDocumentService{}.create(result);
    return JsonResultExportService{}.serialize(document);
}

void requireWriteSuccess(const WriteResult& result)
{
    require(result.success, "atomic persistence unexpectedly failed");
    require(result.technicalMessage.isEmpty(), "successful persistence has a diagnostic");
}

void requireSourceUnchanged(const BenchmarkResult& result, BenchmarkStatus status,
                            double statisticsMean, std::string_view operatingSystem)
{
    require(result.status == status && !result.error.has_value(), "benchmark status or error changed");
    require(result.config.profile == AlgorithmProfileId::Sha256 && result.config.iterationsPerRun == 64
                && result.config.runs == 2
                && std::get<HashConfig>(result.config.parameters).inputSize == 128,
            "benchmark config changed");
    require(result.runs.size() == 2 && result.runs[0].runIndex == 0 && result.runs[0].totalElapsedTime.count() == 40
                && result.runs[1].runIndex == 1
                && std::get<MemoryRunMeasurement>(result.runs[1].memory).peakDeltaBytes == 20,
            "benchmark runs changed");
    require(result.statistics.has_value()
                && result.statistics->elapsedNanosecondsPerOperation.mean == statisticsMean,
            "benchmark statistics changed");
    require(std::holds_alternative<HashCharacteristics>(result.characteristics)
                && std::get<HashCharacteristics>(result.characteristics).outputBytes == 32,
            "benchmark characteristics changed");
    require(result.environment.operatingSystem == operatingSystem
                && result.environment.measuredAt
                    == std::chrono::system_clock::time_point{std::chrono::milliseconds{1790035200177LL}},
            "benchmark environment changed");
}

void testNewTargetEndToEnd()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("single-result.json");
    const auto result = resultA();
    const auto payload = serializeResult(result);

    const auto writeResult = AtomicFileWriter{}.writeAtomically(target, payload);
    requireWriteSuccess(writeResult);
    const auto persisted = readBytes(target);
    require(persisted == payload, "persisted bytes differ from serialized payload");

    const auto root = parseObject(persisted);
    requireString(root, "format", "cryptobenchmark-result");
    requireNumber(root, "schemaVersion", 1.0);
    requireString(root, "mode", "single");
    requireString(root, "status", "completed");

    const auto entry = singleEntry(persisted);
    requireNumber(entry, "entryIndex", 1.0);
    requireString(entry, "status", "completed");
    require(!entry.contains("id") && !entry.contains("error") && !entry.contains("runs"),
            "single result contains an absent or run-level field");
    const auto configObject = entry.value("config").toObject();
    requireString(configObject, "profileId", "sha256");
    requireString(configObject, "operation", "hash");
    requireNumber(configObject, "iterationsPerRun", 64.0);
    requireNumber(configObject, "runs", 2.0);
    requireNumber(configObject.value("parameters").toObject(), "inputSizeBytes", 128.0);
    require(entry.value("structuralCharacteristics").toObject().value("type").toString() == "hashXof",
            "structural characteristics are missing");
    requireNumber(entry.value("structuralCharacteristics").toObject(), "outputBytes", 32.0);
    requireEnvironment(entry, "0.1.0", "Windows Mérés");
    requireStatistics(entry, 1.25, 2.75, 3.5);
    require(payload.contains(QByteArray::fromHex("4dc3a972c3a973")), "serialized payload lost non-ASCII bytes");
    requireString(entry.value("environment").toObject(), "operatingSystem", "Windows Mérés");
}

void testReplacementHasOnlySecondPayload()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("replacement.json");
    const auto payloadA = serializeResult(resultA());
    const auto payloadB = serializeResult(resultB());

    requireWriteSuccess(AtomicFileWriter{}.writeAtomically(target, payloadA));
    requireWriteSuccess(AtomicFileWriter{}.writeAtomically(target, payloadB));

    const auto persisted = readBytes(target);
    require(persisted == payloadB, "replacement file is not exactly result B");
    const auto entry = singleEntry(persisted);
    requireString(entry.value("config").toObject(), "profileId", "sha3-256");
    requireNumber(entry.value("config").toObject(), "iterationsPerRun", 128.0);
    requireNumber(entry.value("config").toObject().value("parameters").toObject(), "inputSizeBytes", 4096.0);
    requireNumber(entry.value("structuralCharacteristics").toObject(), "outputBytes", 32.0);
    requireStatistics(entry, 11.25, 12.75, 13.5);
    require(!persisted.contains(QByteArray("0.1.0")), "replacement retained result A data");
    require(!persisted.endsWith(QByteArray("\n")), "replacement contains trailing bytes");
}

void testSameResultCanWriteTwoTargets()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto firstTarget = directory.filePath("first.json");
    const auto secondTarget = directory.filePath("second.json");
    const auto payload = serializeResult(resultA());

    requireWriteSuccess(AtomicFileWriter{}.writeAtomically(firstTarget, payload));
    requireWriteSuccess(AtomicFileWriter{}.writeAtomically(secondTarget, payload));
    require(readBytes(firstTarget) == payload && readBytes(secondTarget) == payload,
            "same result did not persist byte-exactly to both targets");
}

void testSerializationFailureDoesNotWrite()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("valid-result.json");
    const auto validResult = resultA();
    const auto originalPayload = serializeResult(validResult);
    requireWriteSuccess(AtomicFileWriter{}.writeAtomically(target, originalPayload));

    auto invalidResult = validResult;
    invalidResult.statistics->elapsedNanosecondsPerOperation.mean = std::numeric_limits<double>::quiet_NaN();
    bool rejected = false;
    try {
        static_cast<void>(serializeResult(invalidResult));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }

    require(rejected, "serializer accepted non-finite statistics");
    require(readBytes(target) == originalPayload, "serialization failure changed the valid target");
    requireSourceUnchanged(validResult, BenchmarkStatus::Completed, 1.25, "Windows Mérés");
    require(invalidResult.status == BenchmarkStatus::Completed && !invalidResult.error.has_value(),
            "serialization failure mutated benchmark status or error");
}

void testInvalidChildPathFailureDoesNotMutateSource()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto parentFilePath = directory.filePath("ordinary-file");
    writeInitialBytes(parentFilePath, QByteArray("parent"));
    const auto target = parentFilePath + "/child.json";
    const auto result = resultA();
    const auto payload = serializeResult(result);

    const auto writeResult = AtomicFileWriter{}.writeAtomically(target, payload);
    require(!writeResult.success && !writeResult.technicalMessage.isEmpty(),
            "invalid child path did not return a diagnostic failure");
    require(!QFileInfo::exists(target), "invalid child target was created");
    requireSourceUnchanged(result, BenchmarkStatus::Completed, 1.25, "Windows Mérés");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testNewTargetEndToEnd();
        std::cout << "PASS new target end-to-end\n";
        cryptobench::tests::testReplacementHasOnlySecondPayload();
        std::cout << "PASS replacement without stale data\n";
        cryptobench::tests::testSameResultCanWriteTwoTargets();
        std::cout << "PASS independent targets\n";
        cryptobench::tests::testSerializationFailureDoesNotWrite();
        std::cout << "PASS serialization failure separation\n";
        cryptobench::tests::testInvalidChildPathFailureDoesNotMutateSource();
        std::cout << "PASS invalid child path failure\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL SingleResultPersistenceIntegration: " << error.what() << '\n';
        return 1;
    }
}
