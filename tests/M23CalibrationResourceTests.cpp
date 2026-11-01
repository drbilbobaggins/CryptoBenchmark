#include <cryptobench/application/RuntimeCalibrationInventory.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>
#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/core/ConfigValidator.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

namespace application = cryptobench::application;
namespace core = cryptobench::core;
using application::RuntimeCalibrationResourceStatus;

constexpr auto kProtocolId = "memory-v2-calibration-v1";
constexpr auto kTestOs = "test-os";
constexpr auto kTestArchitecture = "x86_64";
constexpr auto kTestBuildType = "Release";
constexpr auto kTestOpenSsl = "test-openssl";
constexpr auto kApprovedPragmaticResourceSha256 =
    "d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129";
constexpr qsizetype kApprovedPragmaticResourceBytes = 92'881;
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

QJsonObject pragmaticRecord(
    const application::RuntimeCalibrationCase& calibrationCase)
{
    const auto inputKind = application::toStableString(calibrationCase.inputKind);
    const auto variableSize = calibrationCase.hasVariableInputSize;
    const auto minimumInputBytes =
        calibrationCase.inputKind == application::RuntimeCalibrationInputKind::HashXof
        ? std::uint64_t{0}
        : std::uint64_t{1};
    QJsonObject model;
    if (variableSize) {
        model = {
            {"anchorInputBytes", QString::number(minimumInputBytes)},
            {"anchorPicosecondsPerOperation", QStringLiteral("1200")},
            {"kind", QStringLiteral("anchoredAffinePerOperation")},
            {"slopePicosecondsPerBytePerOperation", QStringLiteral("2")}};
    } else {
        model = {
            {"kind", QStringLiteral("constantPerOperation")},
            {"picosecondsPerOperation", QStringLiteral("1200")}};
    }
    const auto operation = application::toStableOperationString(
        calibrationCase.operation);
    const auto profileId = core::toStableProfileId(calibrationCase.profileId);
    QJsonObject record{
        {"evidenceSubsetSha256", QLatin1String(kZeroHash)},
        {"inputKind", QString::fromUtf8(
            inputKind.data(), static_cast<qsizetype>(inputKind.size()))},
        {"measuredModel", model},
        {"modelQualificationStatus", variableSize
            ? QStringLiteral("perOperationReferenceFitSizeHoldoutOnly")
            : QStringLiteral("perOperationReferenceFitOnly")},
        {"operation", QString::fromUtf8(
            operation.data(), static_cast<qsizetype>(operation.size()))},
        {"profileId", QString::fromUtf8(
            profileId.data(), static_cast<qsizetype>(profileId.size()))},
        {"samplingIntervalMilliseconds", 5},
        {"holdoutSubsetSha256", QLatin1String(kZeroHash)}};
    if (variableSize) {
        record.insert("validInputBytesMin", QString::number(minimumInputBytes));
        record.insert(
            "validInputBytesMax",
            QString::number(core::kMaxWorkloadBytes));
    }
    return record;
}

QJsonObject validPragmaticResource()
{
    auto resource = validResource();
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    QJsonArray records;
    for (const auto& calibrationCase : inventory.cases) {
        records.append(pragmaticRecord(calibrationCase));
    }
    const QJsonObject missingReasons{
        {"referenceWorkerSha256", QStringLiteral("notRecordedInCampaignEvidence")},
        {"referenceAppSha256", QStringLiteral("notRecordedInCampaignEvidence")},
        {"qtVersion", QStringLiteral("notRecordedInCampaignEvidence")},
        {"compilerId", QStringLiteral("notRecordedInCampaignEvidence")},
        {"referenceCpu", QStringLiteral("notRecordedInCampaignEvidence")},
        {"referenceRamBytes", QStringLiteral("notRecordedInCampaignEvidence")},
        {"powerPlan", QStringLiteral("notRecordedInCampaignEvidence")}};
    const QJsonObject approximationPolicy{
        {"warmupOperationsPerLogicalRun", 1},
        {"fixedEntryOverhead", QJsonObject{
            {"nanoseconds", QStringLiteral("0")},
            {"status", QStringLiteral("assumedUnmeasured")}}},
        {"batchOverhead", QJsonObject{
            {"nanoseconds", QStringLiteral("0")},
            {"status", QStringLiteral("assumedUnmeasured")}}},
        {"samplingIntervalAssumptions", QJsonArray{
            QJsonObject{
                {"requestedIntervalMilliseconds", 1},
                {"sourceMeasuredIntervalMilliseconds", 5},
                {"status", QStringLiteral("assumedFrom5ms")}},
            QJsonObject{
                {"requestedIntervalMilliseconds", 2},
                {"sourceMeasuredIntervalMilliseconds", 5},
                {"status", QStringLiteral("assumedFrom5ms")}},
            QJsonObject{
                {"requestedIntervalMilliseconds", 3},
                {"sourceMeasuredIntervalMilliseconds", 5},
                {"status", QStringLiteral("assumedFrom5ms")}},
            QJsonObject{
                {"requestedIntervalMilliseconds", 4},
                {"sourceMeasuredIntervalMilliseconds", 5},
                {"status", QStringLiteral("assumedFrom5ms")}}}}};
    resource.insert("modelSchemaVersion", QStringLiteral("m23-pragmatic-1"));
    resource.insert("qualificationStatus", QStringLiteral("reducedScopeApproximate"));
    resource.insert(
        "qualificationSummary",
        QStringLiteral(
            "Per-operation size holdouts only; no end-to-end Batch qualification"));
    resource.insert("referenceWorkerSha256", QJsonValue(QJsonValue::Null));
    resource.insert("referenceAppSha256", QJsonValue(QJsonValue::Null));
    resource.insert("qtVersion", QJsonValue(QJsonValue::Null));
    resource.insert("compilerId", QJsonValue(QJsonValue::Null));
    resource.insert("referenceCpu", QJsonValue(QJsonValue::Null));
    resource.insert("referenceRamBytes", QJsonValue(QJsonValue::Null));
    resource.insert("powerPlan", QJsonValue(QJsonValue::Null));
    resource.insert("provenanceMissingReasons", missingReasons);
    resource.insert("sourceEvidenceSha256", QJsonObject{
        {"nightResultSha256", QLatin1String(kZeroHash)},
        {"supplementalResultSha256", QLatin1String(kZeroHash)},
        {"splitManifestSha256", QLatin1String(kZeroHash)}});
    resource.insert("approximationPolicy", approximationPolicy);
    resource.insert("records", records);
    return resource;
}

qsizetype findPragmaticRecord(
    const QJsonArray& records,
    const QString& inputKind)
{
    for (qsizetype index = 0; index < records.size(); ++index) {
        if (records[index].toObject().value(QStringLiteral("inputKind")).toString()
            == inputKind) {
            return index;
        }
    }
    throw std::runtime_error("pragmatic synthetic fixture is missing an input kind");
}

template <typename Mutator>
QJsonObject mutatePragmaticRecord(
    QJsonObject resource,
    const QString& inputKind,
    Mutator mutate)
{
    auto records = resource.value(QStringLiteral("records")).toArray();
    const auto index = findPragmaticRecord(records, inputKind);
    auto record = records[index].toObject();
    mutate(record);
    records[index] = record;
    resource.insert("records", records);
    return resource;
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
            && loaded.resource->dialect
                == application::RuntimeCalibrationResourceDialect::M23_1Provisional
            && loaded.resource->records.size() == 1
            && loaded.resource->records[0].modelKind
                == application::RuntimeCalibrationMeasuredModelKind::ExactReference
            && !loaded.resource->records[0].pragmaticModel
            && loaded.resource->records[0].evidenceStatus
                == application::RuntimeCalibrationRecordEvidenceStatus::Unqualified
            && loaded.diagnostic
                == "resource integrity and provisional schema validation passed",
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

void verifyPragmaticValidAndHashSemantics(QTemporaryDir& directory)
{
    const auto bytes = serialize(validPragmaticResource());
    const auto path = QDir(directory.path()).filePath(
        QStringLiteral("pragmatic-valid.json"));
    require(loadBytes(path, bytes) == RuntimeCalibrationResourceStatus::Loaded,
        "valid pragmatic resource did not load");
    const auto loaded = application::loadRuntimeCalibrationResource(
        path, digest(bytes).toStdString(), expectedEnvironment());
    require(loaded.resource.has_value()
            && loaded.resource->dialect
                == application::RuntimeCalibrationResourceDialect::M23Pragmatic
            && loaded.resource->qualificationStatus == "reducedScopeApproximate"
            && loaded.resource->records.size() == 175
            && loaded.resource->approximationPolicy.has_value()
            && loaded.resource->pragmaticProvenance.has_value()
            && loaded.diagnostic
                == "resource integrity and pragmatic schema validation passed",
        "pragmatic resource did not preserve its dialect, policy, and inventory");
    const auto constants = std::ranges::count_if(
        loaded.resource->records,
        [](const auto& record) {
            return record.modelKind
                == application::RuntimeCalibrationMeasuredModelKind::ConstantPerOperation;
        });
    const auto affine = std::ranges::count_if(
        loaded.resource->records,
        [](const auto& record) {
            return record.modelKind
                == application::RuntimeCalibrationMeasuredModelKind::AnchoredAffinePerOperation;
        });
    require(constants == 78 && affine == 97,
        "pragmatic resource model counts are not 78 constant / 97 anchored affine");
    require(loaded.resource->pragmaticProvenance->missingFields.size() == 7
            && !loaded.resource->pragmaticProvenance->referenceWorkerSha256
            && !loaded.resource->pragmaticProvenance->referenceRamBytes,
        "pragmatic missing historical provenance was not preserved as typed absence");
    const auto& policy = *loaded.resource->approximationPolicy;
    require(policy.warmupOperationsPerLogicalRun == 1
            && policy.fixedEntryOverhead.nanoseconds == 0
            && policy.batchOverhead.nanoseconds == 0
            && policy.fixedEntryOverhead.tag
                == application::RuntimeCalibrationAssumptionTag::AssumedUnmeasured
            && policy.batchOverhead.tag
                == application::RuntimeCalibrationAssumptionTag::AssumedUnmeasured
            && policy.samplingAssumptions.size() == 4
            && policy.samplingAssumptions.front().requestedIntervalMilliseconds == 1
            && policy.samplingAssumptions.back().requestedIntervalMilliseconds == 4
            && policy.samplingAssumptions.front().sourceMeasuredIntervalMilliseconds == 5
            && policy.samplingAssumptions.front().tag
                == application::RuntimeCalibrationAssumptionTag::AssumedFrom5ms,
        "pragmatic policy did not preserve the explicit approximation assumptions");

    const auto firstVariable = std::ranges::find_if(
        loaded.resource->records,
        [](const auto& record) { return record.calibrationCase.hasVariableInputSize; });
    require(firstVariable != loaded.resource->records.end()
            && firstVariable->pragmaticModel.has_value()
            && std::holds_alternative<
                application::RuntimeCalibrationAnchoredAffinePerOperationModel>(
                    *firstVariable->pragmaticModel),
        "pragmatic typed anchored-affine model was not retained");
    const auto firstFixed = std::ranges::find_if(
        loaded.resource->records,
        [](const auto& record) { return !record.calibrationCase.hasVariableInputSize; });
    require(firstFixed != loaded.resource->records.end()
            && firstFixed->pragmaticModel.has_value()
            && std::holds_alternative<
                application::RuntimeCalibrationConstantPerOperationModel>(
                    *firstFixed->pragmaticModel),
        "pragmatic typed constant model was not retained");
    require(firstFixed->evidenceStatus
                == application::RuntimeCalibrationRecordEvidenceStatus::PerOperationReferenceFitOnly
            && firstVariable->evidenceStatus
                == application::RuntimeCalibrationRecordEvidenceStatus::PerOperationReferenceFitSizeHoldoutOnly,
        "pragmatic evidence status did not distinguish fixed and size-holdout records");
    require(loaded.resource->pragmaticProvenance->sourceEvidenceSha256.splitManifest
                == loaded.resource->pragmaticProvenance->rawEvidenceManifestSha256,
        "pragmatic split-manifest hash was not retained consistently");
    require(firstVariable->samplingIntervalMilliseconds == 5
            && firstFixed->samplingIntervalMilliseconds == 5,
        "assumed 1-4 ms intervals were incorrectly represented as measured records");
    const auto zeroByteHash = std::ranges::find_if(
        loaded.resource->records,
        [](const auto& record) {
            return record.calibrationCase.inputKind
                == application::RuntimeCalibrationInputKind::HashXof;
        });
    require(zeroByteHash != loaded.resource->records.end()
            && zeroByteHash->minimumInputBytes == std::optional<std::uint64_t>{0}
            && zeroByteHash->pragmaticModel.has_value()
            && std::get<
                application::RuntimeCalibrationAnchoredAffinePerOperationModel>(
                    *zeroByteHash->pragmaticModel).anchorInputBytes == 0,
        "pragmatic Hash/XOF records did not preserve the legal zero-byte anchor");

    require(application::loadRuntimeCalibrationResource(
                path, kZeroHash, expectedEnvironment()).status
            == RuntimeCalibrationResourceStatus::Corrupt,
        "wrong compiled expected resource SHA was accepted for pragmatic dialect");
    auto otherEnvironment = expectedEnvironment();
    otherEnvironment.opensslVersion = "other-openssl";
    require(application::loadRuntimeCalibrationResource(
                path, digest(bytes).toStdString(), otherEnvironment).status
            == RuntimeCalibrationResourceStatus::Inapplicable,
        "pragmatic resource with mismatched runtime context was not inapplicable");
}

void verifyPragmaticProvenanceRejections(QTemporaryDir& directory)
{
    auto value = validPragmaticResource();
    auto missingReasons = value.value(
        QStringLiteral("provenanceMissingReasons")).toObject();
    missingReasons.remove(QStringLiteral("referenceCpu"));
    value.insert("provenanceMissingReasons", missingReasons);
    expectCorrupt(directory, "pragmatic-null-without-reason.json", serialize(value));

    value = validPragmaticResource();
    value.insert("referenceCpu", QStringLiteral("synthetic current CPU"));
    expectCorrupt(directory, "pragmatic-present-with-missing-reason.json", serialize(value));

    value = validPragmaticResource();
    missingReasons = value.value(
        QStringLiteral("provenanceMissingReasons")).toObject();
    missingReasons.insert(
        "referenceCpu", QStringLiteral("unknownReason"));
    value.insert("provenanceMissingReasons", missingReasons);
    expectCorrupt(directory, "pragmatic-unknown-null-reason.json", serialize(value));

    value = validPragmaticResource();
    missingReasons = value.value(
        QStringLiteral("provenanceMissingReasons")).toObject();
    missingReasons.insert(
        "sourceGitCommit", QStringLiteral("notRecordedInCampaignEvidence"));
    value.insert("provenanceMissingReasons", missingReasons);
    expectCorrupt(directory, "pragmatic-spurious-null-reason.json", serialize(value));

    value = validPragmaticResource();
    value.insert("sourceGitCommit", QJsonValue(QJsonValue::Null));
    missingReasons = value.value(
        QStringLiteral("provenanceMissingReasons")).toObject();
    missingReasons.insert(
        "sourceGitCommit", QStringLiteral("notRecordedInCampaignEvidence"));
    value.insert("provenanceMissingReasons", missingReasons);
    expectCorrupt(directory, "pragmatic-known-provenance-null.json", serialize(value));

    value = validPragmaticResource();
    value.insert("referenceRamBytes", QStringLiteral("0"));
    missingReasons = value.value(
        QStringLiteral("provenanceMissingReasons")).toObject();
    missingReasons.remove(QStringLiteral("referenceRamBytes"));
    value.insert("provenanceMissingReasons", missingReasons);
    expectCorrupt(directory, "pragmatic-zero-recorded-ram.json", serialize(value));

    value = validPragmaticResource();
    auto sourceHashes = value.value(
        QStringLiteral("sourceEvidenceSha256")).toObject();
    sourceHashes.insert("nightResultSha256", QStringLiteral("bad-hash"));
    value.insert("sourceEvidenceSha256", sourceHashes);
    expectCorrupt(directory, "pragmatic-source-hash-malformed.json", serialize(value));

    value = validPragmaticResource();
    value.insert("rawEvidenceManifestSha256", QString(64, QLatin1Char('a')));
    expectCorrupt(directory, "pragmatic-manifest-hash-conflict.json", serialize(value));
}

void verifyPragmaticModelAndIdentityRejections(QTemporaryDir& directory)
{
    auto value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            record.insert("validInputBytesMin", QStringLiteral("0"));
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorInputBytes", QStringLiteral("0"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-message-zero-minimum.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("aead"),
        [](QJsonObject& record) {
            record.insert("validInputBytesMin", QStringLiteral("0"));
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorInputBytes", QStringLiteral("0"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-aead-zero-minimum.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("hashXof"),
        [](QJsonObject& record) {
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorInputBytes", QStringLiteral("1"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-anchor-mismatch.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("aead"),
        [](QJsonObject& record) {
            record.insert("validInputBytesMax", QStringLiteral("268435457"));
        });
    expectCorrupt(directory, "pragmatic-size-out-of-range.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("slopePicosecondsPerBytePerOperation",
                QStringLiteral("18446744073709551615"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-size-prediction-overflow.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("hashXof"),
        [](QJsonObject& record) {
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorPicosecondsPerOperation",
                QStringLiteral("18446744073709551615"));
            model.insert("slopePicosecondsPerBytePerOperation", QStringLiteral("1"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-anchor-prediction-overflow.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorPicosecondsPerOperation", QStringLiteral("01"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-noncanonical-coefficient.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            auto model = record.value(QStringLiteral("measuredModel")).toObject();
            model.insert("anchorPicosecondsPerOperation",
                QStringLiteral("18446744073709551616"));
            record.insert("measuredModel", model);
        });
    expectCorrupt(directory, "pragmatic-coefficient-overflow.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("noSignature"),
        [](QJsonObject& record) {
            record.insert("profileId", QStringLiteral("unknown-profile"));
        });
    expectCorrupt(directory, "pragmatic-unknown-profile.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("noSignature"),
        [](QJsonObject& record) {
            record.insert("operation", QStringLiteral("unknown-operation"));
        });
    expectCorrupt(directory, "pragmatic-unknown-operation.json", serialize(value));

    value = validPragmaticResource();
    auto records = value.value(QStringLiteral("records")).toArray();
    records.replace(0, records[1]);
    value.insert("records", records);
    expectCorrupt(directory, "pragmatic-duplicate-record.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            record.insert("modelQualificationStatus", QStringLiteral("qualified"));
        });
    expectCorrupt(directory, "pragmatic-overqualified-record.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            record.insert("samplingIntervalMilliseconds", 4);
        });
    expectCorrupt(directory, "pragmatic-unmeasured-record-context.json", serialize(value));
}

void verifyPragmaticPolicyAndDialectRejections(QTemporaryDir& directory)
{
    auto value = validPragmaticResource();
    auto policy = value.value(QStringLiteral("approximationPolicy")).toObject();
    auto assumptions = policy.value(
        QStringLiteral("samplingIntervalAssumptions")).toArray();
    auto assumption = assumptions[0].toObject();
    assumption.insert("status", QStringLiteral("qualified"));
    assumptions[0] = assumption;
    policy.insert("samplingIntervalAssumptions", assumptions);
    value.insert("approximationPolicy", policy);
    expectCorrupt(directory, "pragmatic-sampling-assumption-tag.json", serialize(value));

    value = validPragmaticResource();
    policy = value.value(QStringLiteral("approximationPolicy")).toObject();
    assumptions = policy.value(
        QStringLiteral("samplingIntervalAssumptions")).toArray();
    assumptions.removeAt(3);
    policy.insert("samplingIntervalAssumptions", assumptions);
    value.insert("approximationPolicy", policy);
    expectCorrupt(directory, "pragmatic-sampling-assumption-missing.json", serialize(value));

    value = validPragmaticResource();
    policy = value.value(QStringLiteral("approximationPolicy")).toObject();
    auto overhead = policy.value(QStringLiteral("batchOverhead")).toObject();
    overhead.insert("status", QStringLiteral("measuredZero"));
    policy.insert("batchOverhead", overhead);
    value.insert("approximationPolicy", policy);
    expectCorrupt(directory, "pragmatic-batch-overhead-not-assumed.json", serialize(value));

    value = validPragmaticResource();
    policy = value.value(QStringLiteral("approximationPolicy")).toObject();
    overhead = policy.value(QStringLiteral("fixedEntryOverhead")).toObject();
    overhead.insert("nanoseconds", QStringLiteral("1"));
    policy.insert("fixedEntryOverhead", overhead);
    value.insert("approximationPolicy", policy);
    expectCorrupt(directory, "pragmatic-nonzero-fixed-overhead.json", serialize(value));

    value = validPragmaticResource();
    auto contexts = value.value(QStringLiteral("qualifiedRuntimeContexts")).toArray();
    auto context = contexts[0].toObject();
    context.insert("samplingIntervalMilliseconds", 4);
    contexts[0] = context;
    value.insert("qualifiedRuntimeContexts", contexts);
    expectCorrupt(directory, "pragmatic-assumption-as-measured-context.json", serialize(value));

    value = validPragmaticResource();
    contexts = value.value(QStringLiteral("qualifiedRuntimeContexts")).toArray();
    contexts.append(contexts[0]);
    value.insert("qualifiedRuntimeContexts", contexts);
    expectCorrupt(directory, "pragmatic-duplicate-measured-context.json", serialize(value));

    value = validPragmaticResource();
    value.insert("qualificationStatus", QStringLiteral("unqualified"));
    expectCorrupt(directory, "pragmatic-legacy-status-mix.json", serialize(value));

    value = validPragmaticResource();
    value.insert("batchOverheadModels", QJsonArray{QJsonObject{
        {"kind", QStringLiteral("constantNs")},
        {"nanoseconds", QStringLiteral("0")}}});
    expectCorrupt(directory, "pragmatic-batch-model-not-empty.json", serialize(value));

    value = validPragmaticResource();
    contexts = value.value(QStringLiteral("qualifiedRuntimeContexts")).toArray();
    context = contexts[0].toObject();
    context.insert("buildType", QStringLiteral("Debug"));
    contexts[0] = context;
    value.insert("qualifiedRuntimeContexts", contexts);
    expectCorrupt(directory, "pragmatic-context-environment-conflict.json", serialize(value));

    value = mutatePragmaticRecord(
        validPragmaticResource(),
        QStringLiteral("message"),
        [](QJsonObject& record) {
            record.insert("measuredModel", QJsonObject{
                {"kind", QStringLiteral("exactReference")},
                {"referenceInputBytes", QStringLiteral("1")},
                {"referenceMeasuredBlockNanoseconds", QStringLiteral("123")},
                {"referenceN", QStringLiteral("1")}});
        });
    expectCorrupt(directory, "pragmatic-legacy-model-mix.json", serialize(value));

    value = validPragmaticResource();
    value.insert("schemaVersion", 2);
    expectCorrupt(directory, "pragmatic-schema-version.json", serialize(value));

    value = validPragmaticResource();
    value.insert("modelSchemaVersion", QStringLiteral("m23-pragmatic-2"));
    expectCorrupt(directory, "pragmatic-model-schema-version.json", serialize(value));

    value = validPragmaticResource();
    value.insert("unexpectedPragmaticField", true);
    expectCorrupt(directory, "pragmatic-unknown-root-field.json", serialize(value));

    auto bytes = serialize(validPragmaticResource());
    const auto qualificationField = QByteArrayLiteral(
        "\"qualificationStatus\":\"reducedScopeApproximate\"");
    require(bytes.contains(qualificationField),
        "synthetic pragmatic JSON was missing its qualification marker");
    bytes.replace(
        qualificationField,
        QByteArrayLiteral(
            "\"qualificationStatus\":\"reducedScopeApproximate\","
            "\"qualificationStatus\":\"reducedScopeApproximate\""));
    expectCorrupt(directory, "pragmatic-duplicate-member.json", bytes);
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
    value.insert("modelSchemaVersion", QStringLiteral("m23-pragmatic-1"));
    expectCorrupt(directory, "legacy-root-with-pragmatic-dialect.json", serialize(value));

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
    records = value.value(QStringLiteral("records")).toArray();
    record = records[0].toObject();
    model = record.value(QStringLiteral("measuredModel")).toObject();
    model.insert("kind", QStringLiteral("constantPerOperation"));
    record.insert("measuredModel", model);
    records[0] = record;
    value.insert("records", records);
    expectCorrupt(directory, "legacy-record-with-pragmatic-model.json", serialize(value));

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
    const auto compiledSha256 = std::string(
        cryptobench::application::build_info::runtimeCalibrationResourceSha256);
    require(compiledSha256 == kApprovedPragmaticResourceSha256,
        "compiled calibration SHA-256 differs from the approved resource");
    QFile productionResource(buildResourcePath);
    require(productionResource.open(QIODevice::ReadOnly),
        "approved calibration resource was not staged beside the application");
    const auto productionBytes = productionResource.readAll();
    require(productionResource.error() == QFileDevice::NoError
            && digest(productionBytes).toStdString() == compiledSha256,
        "staged calibration bytes do not match the compiled expected SHA-256");

    const application::RuntimeCalibrationEnvironment referenceEnvironment{
        kProtocolId,
        "Windows 11 Version 25H2",
        "x86_64",
        "Release",
        "3.6.5"};
    require(productionBytes.size() == kApprovedPragmaticResourceBytes,
        "approved calibration resource size changed");
    const auto referenceLoad = application::loadRuntimeCalibrationResource(
        buildResourcePath, compiledSha256, referenceEnvironment);
    require(referenceLoad.status == RuntimeCalibrationResourceStatus::Loaded
            && referenceLoad.resource.has_value()
            && referenceLoad.resource->dialect
                    == application::RuntimeCalibrationResourceDialect::M23Pragmatic
            && referenceLoad.resource->records.size() == 175
            && referenceLoad.resource->qualificationStatus
                == "reducedScopeApproximate",
        "approved pragmatic resource did not load in its recorded reference context");

    const auto environmentInfo = application::collectEnvironmentInfo();
    const application::RuntimeCalibrationEnvironment actualEnvironment{
        kProtocolId,
        environmentInfo.operatingSystem,
        environmentInfo.architecture,
        environmentInfo.buildType,
        environmentInfo.opensslVersion};
    const bool actualContextMatchesReference =
        actualEnvironment.calibrationProtocolId
            == referenceEnvironment.calibrationProtocolId
        && actualEnvironment.operatingSystem == referenceEnvironment.operatingSystem
        && actualEnvironment.architecture == referenceEnvironment.architecture
        && actualEnvironment.buildType == referenceEnvironment.buildType
        && actualEnvironment.opensslVersion == referenceEnvironment.opensslVersion;
    const auto actualLoad = application::loadRuntimeCalibrationResource(
        buildResourcePath, compiledSha256, actualEnvironment);
    const auto expectedActualStatus = actualContextMatchesReference
        ? RuntimeCalibrationResourceStatus::Loaded
        : RuntimeCalibrationResourceStatus::Inapplicable;
    require(actualLoad.status == expectedActualStatus
            && actualLoad.resource.has_value() == actualContextMatchesReference,
        "actual-host compatibility did not match all recorded context fields");

    const auto requireInapplicableContext = [&](auto incompatibleEnvironment) {
        require(application::loadRuntimeCalibrationResource(
                    buildResourcePath,
                    compiledSha256,
                    incompatibleEnvironment).status
                == RuntimeCalibrationResourceStatus::Inapplicable,
            "deliberately mismatched runtime context was not inapplicable");
    };
    auto incompatibleEnvironment = referenceEnvironment;
    incompatibleEnvironment.operatingSystem += " (different)";
    requireInapplicableContext(incompatibleEnvironment);
    incompatibleEnvironment = referenceEnvironment;
    incompatibleEnvironment.architecture = "different-architecture";
    requireInapplicableContext(incompatibleEnvironment);
    incompatibleEnvironment = referenceEnvironment;
    incompatibleEnvironment.buildType = "Debug";
    requireInapplicableContext(incompatibleEnvironment);
    incompatibleEnvironment = referenceEnvironment;
    incompatibleEnvironment.opensslVersion = "different-openssl";
    requireInapplicableContext(incompatibleEnvironment);
    incompatibleEnvironment = referenceEnvironment;
    incompatibleEnvironment.calibrationProtocolId = "different-protocol";
    requireInapplicableContext(incompatibleEnvironment);

    const auto corruptStageDirectory =
        QDir(directory.path()).filePath(QStringLiteral("corrupt-stage"));
    require(QDir().mkpath(corruptStageDirectory),
        "corrupt staged-package test directory could not be created");
    const auto corruptExecutable =
        QDir(corruptStageDirectory).filePath(QStringLiteral("CryptoBenchmark.exe"));
    writeFile(corruptExecutable, QByteArrayLiteral("test-only executable placeholder"));
    const auto corruptResourcePath =
        application::runtimeCalibrationResourcePath(corruptExecutable);
    require(QDir().mkpath(QFileInfo(corruptResourcePath).absolutePath()),
        "corrupt staged-resource directory could not be created");
    auto corruptedBytes = productionBytes;
    require(!corruptedBytes.isEmpty(), "approved calibration resource is empty");
    corruptedBytes[0] = corruptedBytes[0] == '{' ? '[' : '{';
    writeFile(corruptResourcePath, corruptedBytes);
    require(application::loadRuntimeCalibrationResource(
                corruptResourcePath, compiledSha256, referenceEnvironment).status
            == RuntimeCalibrationResourceStatus::Corrupt,
        "corrupted temporary staged copy was not rejected by the compiled SHA");

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
    verifyPragmaticValidAndHashSemantics(directory);
    verifyPragmaticProvenanceRejections(directory);
    verifyPragmaticModelAndIdentityRejections(directory);
    verifyPragmaticPolicyAndDialectRejections(directory);
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
