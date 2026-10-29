#include <cryptobench/application/RuntimeCalibrationInventory.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>
#include <cryptobench/application/BuildInfo.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

namespace application = cryptobench::application;
using application::RuntimeCalibrationResourceStatus;

constexpr auto kProtocolId = "memory-v2-calibration-v1";
constexpr auto kTestOs = "test-os";
constexpr auto kTestArchitecture = "x86_64";
constexpr auto kTestBuildType = "Release";
constexpr auto kTestOpenSsl = "test-openssl";
constexpr auto kZeroHash =
    "0000000000000000000000000000000000000000000000000000000000000000";

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QByteArray digest(const QByteArray& bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
}

application::RuntimeCalibrationEnvironment expectedEnvironment()
{
    return {
        kProtocolId,
        kTestOs,
        kTestArchitecture,
        kTestBuildType,
        kTestOpenSsl};
}

QJsonObject sampleRecord()
{
    return {
        {"evidenceSubsetSha256", QLatin1String(kZeroHash)},
        {"holdoutSubsetSha256", QLatin1String(kZeroHash)},
        {"inputKind", QStringLiteral("message")},
        {"measuredModel", QJsonObject{
            {"kind", QStringLiteral("exactReference")},
            {"referenceMeasuredBlockNanoseconds", QStringLiteral("123")},
            {"referenceInputBytes", QStringLiteral("32")},
            {"referenceN", QStringLiteral("1")}}},
        {"modelQualificationStatus", QStringLiteral("unqualified")},
        {"operation", QStringLiteral("sign")},
        {"profileId", QStringLiteral("ed25519")},
        {"samplingIntervalMilliseconds", 5},
        {"validInputBytesMax", QStringLiteral("32")},
        {"validInputBytesMin", QStringLiteral("32")}};
}

QJsonObject validResource()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto inventorySha =
        application::runtimeCalibrationInventorySha256(inventory);
    return {
        {"architecture", QLatin1String(kTestArchitecture)},
        {"batchOverheadModels", QJsonArray{}},
        {"calibrationProtocolId", QLatin1String(kProtocolId)},
        {"campaignPlanSha256", QLatin1String(kZeroHash)},
        {"compilerId", QStringLiteral("synthetic-test-compiler")},
        {"datasetId", QStringLiteral("synthetic-m23-test-only")},
        {"datasetVersion", QStringLiteral("0.0.0-test")},
        {"format", QStringLiteral("cryptobenchmark-runtime-calibration")},
        {"generatedAtUtc", QStringLiteral("2026-10-28T00:00:00.000Z")},
        {"generatorVersion", QStringLiteral("m23-test-fixture")},
        {"holdoutReportSha256", QLatin1String(kZeroHash)},
        {"modelSchemaVersion", QStringLiteral("m23.1-provisional-1")},
        {"os", QLatin1String(kTestOs)},
        {"opensslVersion", QLatin1String(kTestOpenSsl)},
        {"powerPlan", QStringLiteral("synthetic test fixture")},
        {"qualificationStatus", QStringLiteral("unqualified")},
        {"qualificationSummary",
            QStringLiteral("Synthetic test fixture; not a qualified dataset")},
        {"qualifiedRuntimeContexts", QJsonArray{QJsonObject{
            {"architecture", QLatin1String(kTestArchitecture)},
            {"buildType", QLatin1String(kTestBuildType)},
            {"calibrationProtocolId", QLatin1String(kProtocolId)},
            {"opensslVersion", QLatin1String(kTestOpenSsl)},
            {"os", QLatin1String(kTestOs)},
            {"samplingIntervalMilliseconds", 5}}}},
        {"qtVersion", QStringLiteral("test-only")},
        {"rawEvidenceManifestSha256", QLatin1String(kZeroHash)},
        {"records", QJsonArray{sampleRecord()}},
        {"referenceAppSha256", QLatin1String(kZeroHash)},
        {"referenceAppVersion", QStringLiteral("test-only")},
        {"referenceBuildType", QLatin1String(kTestBuildType)},
        {"referenceCpu", QStringLiteral("synthetic test fixture")},
        {"referenceRamBytes", QStringLiteral("1")},
        {"referenceWorkerSha256", QLatin1String(kZeroHash)},
        {"registryInventorySha256", QString::fromLatin1(inventorySha)},
        {"schemaVersion", 1},
        {"sourceGitCommit", QString(40, QLatin1Char('0'))}};
}

void writeFile(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly | QIODevice::Truncate),
        "M23 synthetic resource could not be opened");
    require(file.write(bytes) == bytes.size(),
        "M23 synthetic resource write was incomplete");
    file.close();
}

QByteArray serialize(const QJsonObject& object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

RuntimeCalibrationResourceStatus loadBytes(
    const QString& path,
    const QByteArray& bytes,
    std::string_view expectedHash = {})
{
    writeFile(path, bytes);
    const auto expected = expectedHash.empty()
        ? digest(bytes).toStdString()
        : std::string(expectedHash);
    return application::loadRuntimeCalibrationResource(
        path, expected, expectedEnvironment()).status;
}

void expectCorrupt(
    QTemporaryDir& directory,
    std::string_view name,
    const QByteArray& bytes)
{
    const auto path = QDir(directory.path()).filePath(
        QString::fromUtf8(name.data(), static_cast<qsizetype>(name.size())));
    require(loadBytes(path, bytes) == RuntimeCalibrationResourceStatus::Corrupt,
        "invalid M23 resource was not rejected as corrupt");
}

void verifyValidAndUnavailableSemantics(QTemporaryDir& directory)
{
    const auto bytes = serialize(validResource());
    const auto path = QDir(directory.path()).filePath(QStringLiteral("valid.json"));
    require(loadBytes(path, bytes) == RuntimeCalibrationResourceStatus::Loaded,
        "valid synthetic M23 resource did not load");
    const auto loaded = application::loadRuntimeCalibrationResource(
        path, digest(bytes).toStdString(), expectedEnvironment());
    require(loaded.resource.has_value()
            && loaded.resource->qualificationStatus == "unqualified"
            && loaded.resource->records.size() == 1,
        "M23 resource did not preserve its explicitly unqualified status");

    const auto missingPath = QDir(directory.path()).filePath(QStringLiteral("missing.json"));
    require(application::loadRuntimeCalibrationResource(
                missingPath, kZeroHash, expectedEnvironment()).status
            == RuntimeCalibrationResourceStatus::Missing,
        "missing M23 resource did not have distinct unavailable status");

    require(application::loadRuntimeCalibrationResource(
                path, kZeroHash, expectedEnvironment()).status
            == RuntimeCalibrationResourceStatus::Corrupt,
        "wrong M23 resource checksum was not rejected");

    auto otherEnvironment = expectedEnvironment();
    otherEnvironment.buildType = "Debug";
    require(application::loadRuntimeCalibrationResource(
                path, digest(bytes).toStdString(), otherEnvironment).status
            == RuntimeCalibrationResourceStatus::Inapplicable,
        "valid but incompatible M23 context was not distinguished");

    auto changedRegistry = validResource();
    changedRegistry.insert("registryInventorySha256", QLatin1String(kZeroHash));
    const auto changedBytes = serialize(changedRegistry);
    require(loadBytes(
                QDir(directory.path()).filePath(QStringLiteral("registry.json")),
                changedBytes) == RuntimeCalibrationResourceStatus::Inapplicable,
        "valid resource for a different registry was not inapplicable");
}

void verifySchemaRejections(QTemporaryDir& directory)
{
    auto value = validResource();
    value.insert("schemaVersion", 2);
    expectCorrupt(directory, "version.json", serialize(value));

    value = validResource();
    auto fractionalVersion = serialize(value);
    fractionalVersion.replace(
        QByteArrayLiteral("\"schemaVersion\":1"),
        QByteArrayLiteral("\"schemaVersion\":1.0"));
    expectCorrupt(directory, "fractional-version.json", fractionalVersion);

    value = validResource();
    value.insert("modelSchemaVersion", QStringLiteral("future-model"));
    expectCorrupt(directory, "model-schema.json", serialize(value));

    value = validResource();
    value.insert("unexpected", true);
    expectCorrupt(directory, "unknown-field.json", serialize(value));

    value = validResource();
    value.insert("generatedAtUtc", QStringLiteral("not-a-date"));
    expectCorrupt(directory, "provenance-date.json", serialize(value));

    value = validResource();
    value.insert("referenceAppSha256", QStringLiteral("bad-hash"));
    expectCorrupt(directory, "provenance-hash.json", serialize(value));

    value = validResource();
    auto contexts = value.value(QStringLiteral("qualifiedRuntimeContexts")).toArray();
    auto context = contexts[0].toObject();
    context.insert("buildType", QStringLiteral("Debug"));
    contexts[0] = context;
    value.insert("qualifiedRuntimeContexts", contexts);
    expectCorrupt(directory, "inconsistent-context.json", serialize(value));

    value = validResource();
    value.insert("batchOverheadModels", QJsonArray{QJsonObject{
        {"kind", QStringLiteral("unselected-model")}}});
    expectCorrupt(directory, "pilot-gated-overhead.json", serialize(value));
}

void verifyCanonicalContextRejections(QTemporaryDir& directory)
{
    auto value = validResource();
    auto records = value.value(QStringLiteral("records")).toArray();
    auto record = records[0].toObject();
    record.insert("profileId", QStringLiteral("unknown-profile"));
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "unknown-profile.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    record.insert("inputKind", QStringLiteral("message-like"));
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "unknown-input-kind.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    records.append(records[0]);
    value.insert("records", records);
    expectCorrupt(directory, "duplicate-record.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    record.insert("samplingIntervalMilliseconds", 6);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "invalid-sampling.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    record.insert("validInputBytesMin", QStringLiteral("0"));
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "invalid-size-minimum.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    record.insert("validInputBytesMax", QStringLiteral("268435457"));
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "invalid-size-maximum.json", serialize(value));
}

void verifyIntegerAndModelRejections(QTemporaryDir& directory)
{
    auto value = validResource();
    auto records = value.value(QStringLiteral("records")).toArray();
    auto record = records[0].toObject();
    auto model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("referenceN", QStringLiteral("01"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "malformed-decimal.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("referenceN", QStringLiteral("18446744073709551616"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "overflow-decimal.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("referenceN", QStringLiteral("0"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "zero-reference-n.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("kind", QStringLiteral("future-model"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "unknown-measured-model.json", serialize(value));

    value = validResource();
    value.insert("qualificationStatus", QStringLiteral("qualified"));
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    record.insert("modelQualificationStatus", QStringLiteral("qualified"));
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "inconsistent-qualification.json", serialize(value));

    value = validResource();
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("referenceInputBytes", QStringLiteral("33"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "reference-size-mismatch.json", serialize(value));
}

void verifyByteAndJsonRejections(QTemporaryDir& directory)
{
    expectCorrupt(directory, "truncated.json", QByteArrayLiteral("{"));
    expectCorrupt(directory, "invalid-utf8.json", QByteArray("{\xff}", 3));
    expectCorrupt(
        directory,
        "duplicate-member.json",
        QByteArrayLiteral(
            "{\"format\":\"cryptobenchmark-runtime-calibration\","
            "\"format\":\"cryptobenchmark-runtime-calibration\"}"));

    const auto oversizedPath =
        QDir(directory.path()).filePath(QStringLiteral("oversized.json"));
    const QByteArray oversized(
        application::kMaximumRuntimeCalibrationResourceBytes + 1, ' ');
    writeFile(oversizedPath, oversized);
    require(application::loadRuntimeCalibrationResource(
                oversizedPath, kZeroHash, expectedEnvironment()).status
            == RuntimeCalibrationResourceStatus::Corrupt,
        "oversized M23 resource was not rejected");
}

void verifyExecutableRelativeAndRelocatedPath(QTemporaryDir& directory)
{
    const auto executable = QFileInfo(QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmark.exe"))).absoluteFilePath();
    require(QFileInfo::exists(executable),
        "CMake application executable is missing from build-*/bin");
    const auto buildResourcePath =
        application::runtimeCalibrationResourcePath(executable);
    const auto expectedBuildResourcePath = QDir(QFileInfo(executable).absolutePath())
        .filePath(QStringLiteral("calibration/runtime-calibration-v1.json"));
    require(QDir::cleanPath(buildResourcePath)
            == QDir::cleanPath(expectedBuildResourcePath),
        "build-tree calibration path is not application-executable-relative");
    require(!QFileInfo::exists(buildResourcePath),
        "synthetic calibration fixture was deployed beside the production executable");
    require(cryptobench::application::build_info::runtimeCalibrationResourceSha256.empty(),
        "M23 test fixture unexpectedly configured a production calibration hash");

    const auto stageOne = QDir(directory.path()).filePath(QStringLiteral("stage-one"));
    const auto stageTwo = QDir(directory.path()).filePath(QStringLiteral("stage-two"));
    require(QDir().mkpath(stageOne), "staged-directory test setup failed");
    const auto stagedExecutable =
        QDir(stageOne).filePath(QStringLiteral("CryptoBenchmark.exe"));
    writeFile(stagedExecutable, QByteArrayLiteral("test-only executable placeholder"));
    const auto stagedResourcePath =
        application::runtimeCalibrationResourcePath(stagedExecutable);
    const auto stagedResourceDirectory = QFileInfo(stagedResourcePath).absolutePath();
    require(QDir().mkpath(stagedResourceDirectory),
        "staged calibration directory could not be created");
    const auto fixtureBytes = serialize(validResource());
    writeFile(stagedResourcePath, fixtureBytes);
    const auto loaded = application::loadRuntimeCalibrationResource(
        stagedResourcePath, digest(fixtureBytes).toStdString(), expectedEnvironment());
    require(loaded.status == RuntimeCalibrationResourceStatus::Loaded,
        "staged synthetic calibration resource did not load");

    const auto originalCurrentDirectory = QDir::currentPath();
    require(QDir::setCurrent(directory.path()),
        "staged path test could not change working directory");
    require(application::runtimeCalibrationResourcePath(stagedExecutable)
            == stagedResourcePath,
        "staged calibration path depends on the working directory");
    require(QDir::setCurrent(originalCurrentDirectory),
        "staged path test could not restore working directory");
    require(QDir().rename(stageOne, stageTwo),
        "staged directory could not be relocated");
    const auto relocatedExecutable =
        QDir(stageTwo).filePath(QStringLiteral("CryptoBenchmark.exe"));
    const auto relocatedResourcePath =
        application::runtimeCalibrationResourcePath(relocatedExecutable);
    require(relocatedResourcePath
            == QDir(stageTwo).filePath(
                QStringLiteral("calibration/runtime-calibration-v1.json")),
        "staged resource path did not relocate with the executable");
    require(application::loadRuntimeCalibrationResource(
                relocatedResourcePath,
                digest(fixtureBytes).toStdString(),
                expectedEnvironment()).status
            == RuntimeCalibrationResourceStatus::Loaded,
        "relocated staged calibration resource did not load");
}

void runResourceTests()
{
    QTemporaryDir directory;
    require(directory.isValid(), "M23 resource test temporary directory failed");
    verifyValidAndUnavailableSemantics(directory);
    verifySchemaRejections(directory);
    verifyCanonicalContextRejections(directory);
    verifyIntegerAndModelRejections(directory);
    verifyByteAndJsonRejections(directory);
    verifyExecutableRelativeAndRelocatedPath(directory);
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        require(argc == 1,
            "M23 resource tests accept no arguments and never initiate measurements");
        runResourceTests();
        std::cout << "PASS M23 resource safety and executable-relative path tests\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL M23 resource tests: " << error.what() << '\n';
        return 1;
    }
}
