#include <cryptobench/application/RuntimeCalibrationResource.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QString>

#include <cryptobench/application/BenchmarkConfigJson.h>
#include "BatchJsonInteger.h"
#include <cryptobench/application/StrictJsonPreflight.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/MeasurementSettings.h>

namespace cryptobench::application {
namespace {

constexpr auto kResourceFormat = "cryptobenchmark-runtime-calibration";
constexpr auto kProvisionalModelSchemaVersion = "m23.1-provisional-1";
constexpr std::size_t kMaximumRecords = 1000;
constexpr std::size_t kMaximumQualifiedContexts = 5;

class ResourceParseError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void reject(const std::string& message)
{
    throw ResourceParseError(message);
}

template <std::size_t N>
bool hasExactKeys(
    const QJsonObject& object,
    const std::array<std::string_view, N>& expected)
{
    if (static_cast<std::size_t>(object.size()) != N) {
        return false;
    }
    for (const auto key : expected) {
        if (!object.contains(QString::fromUtf8(
                key.data(), static_cast<qsizetype>(key.size())))) {
            return false;
        }
    }
    return true;
}

QString fieldKey(std::string_view name)
{
    return QString::fromUtf8(name.data(), static_cast<qsizetype>(name.size()));
}

QString requiredString(const QJsonObject& object, std::string_view name)
{
    const auto value = object.value(fieldKey(name));
    if (!value.isString() || value.toString().isEmpty()) {
        reject("required string field is missing or empty: " + std::string(name));
    }
    return value.toString();
}

QJsonObject requiredObject(const QJsonObject& object, std::string_view name)
{
    const auto value = object.value(fieldKey(name));
    if (!value.isObject()) {
        reject("required object field is missing: " + std::string(name));
    }
    return value.toObject();
}

QJsonArray requiredArray(const QJsonObject& object, std::string_view name)
{
    const auto value = object.value(fieldKey(name));
    if (!value.isArray()) {
        reject("required array field is missing: " + std::string(name));
    }
    return value.toArray();
}

std::uint64_t canonicalDecimalString(const QJsonObject& object, std::string_view name)
{
    const auto text = requiredString(object, name).toStdString();
    if (text.empty()
        || (text.size() > 1 && text.front() == '0')
        || !std::ranges::all_of(text, [](char value) {
            return value >= '0' && value <= '9';
        })) {
        reject("integer field is not a canonical unsigned decimal string: "
            + std::string(name));
    }
    const auto parsed = detail::parseExactUnsignedJsonInteger(text);
    if (!parsed) {
        reject("integer field is outside the supported range: " + std::string(name));
    }
    return *parsed;
}

int requiredSmallInteger(const QJsonObject& object, std::string_view name)
{
    const auto value = object.value(fieldKey(name));
    if (!value.isDouble()) {
        reject("required integer field is not a JSON integer: " + std::string(name));
    }
    const auto integer = value.toInt(-1);
    if (integer < 0 || static_cast<double>(integer) != value.toDouble()) {
        reject("required integer field is not an exact JSON integer: " + std::string(name));
    }
    return integer;
}

bool isLowerHex(std::string_view value, std::size_t exactLength)
{
    return value.size() == exactLength
        && std::ranges::all_of(value, [](char character) {
            return (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f');
        });
}

void requireHash(const QJsonObject& object, std::string_view name)
{
    const auto value = requiredString(object, name).toStdString();
    if (!isLowerHex(value, 64)) {
        reject("provenance field is not a lowercase SHA-256 digest: "
            + std::string(name));
    }
}

std::string asStdString(const QString& value)
{
    return value.toUtf8().toStdString();
}

std::optional<RuntimeCalibrationInputKind> parseInputKind(std::string_view value)
{
    constexpr std::array kinds{
        RuntimeCalibrationInputKind::NoSignature,
        RuntimeCalibrationInputKind::Prehashed,
        RuntimeCalibrationInputKind::Message,
        RuntimeCalibrationInputKind::KeyEstablishment,
        RuntimeCalibrationInputKind::Aead,
        RuntimeCalibrationInputKind::HashXof
    };
    for (const auto kind : kinds) {
        if (toStableString(kind) == value) {
            return kind;
        }
    }
    return std::nullopt;
}

bool hasCanonicalCase(
    const RuntimeCalibrationInventory& inventory,
    core::AlgorithmProfileId profileId,
    core::BenchmarkOperation operation,
    RuntimeCalibrationInputKind inputKind)
{
    return std::ranges::any_of(
        inventory.cases,
        [&](const RuntimeCalibrationCase& calibrationCase) {
            return calibrationCase.profileId == profileId
                && calibrationCase.operation == operation
                && calibrationCase.inputKind == inputKind;
        });
}

struct QualifiedContext {
    std::string operatingSystem;
    std::string architecture;
    std::string buildType;
    std::string opensslVersion;
    std::string protocolId;
    std::uint32_t samplingIntervalMilliseconds;
};

bool hasQualifiedContext(
    const std::vector<QualifiedContext>& contexts,
    const RuntimeCalibrationEnvironment& environment,
    std::uint32_t samplingIntervalMilliseconds)
{
    return std::ranges::any_of(
        contexts,
        [&](const QualifiedContext& context) {
            return context.operatingSystem == environment.operatingSystem
                && context.architecture == environment.architecture
                && context.buildType == environment.buildType
                && context.opensslVersion == environment.opensslVersion
                && context.protocolId == environment.calibrationProtocolId
                && context.samplingIntervalMilliseconds == samplingIntervalMilliseconds;
        });
}

std::uint64_t parseVariableSizeBound(
    const QJsonObject& record,
    std::string_view key,
    bool variableSize)
{
    const auto value = record.value(fieldKey(key));
    if (!variableSize) {
        if (!value.isUndefined()) {
            reject("fixed-input record must not contain input-size bounds");
        }
        return 0;
    }
    return canonicalDecimalString(record, key);
}

RuntimeCalibrationResourceRecord parseRecord(
    const QJsonObject& object,
    const RuntimeCalibrationInventory& inventory,
    const std::vector<QualifiedContext>& contexts,
    const RuntimeCalibrationEnvironment& environment,
    std::set<std::pair<std::string, std::uint32_t>>& identities)
{
    constexpr std::array<std::string_view, 8> fixedInputKeys{
        "profileId",
        "operation",
        "inputKind",
        "samplingIntervalMilliseconds",
        "measuredModel",
        "evidenceSubsetSha256",
        "holdoutSubsetSha256",
        "modelQualificationStatus"
    };
    constexpr std::array<std::string_view, 10> variableInputKeys{
        "profileId",
        "operation",
        "inputKind",
        "samplingIntervalMilliseconds",
        "measuredModel",
        "validInputBytesMin",
        "validInputBytesMax",
        "evidenceSubsetSha256",
        "holdoutSubsetSha256",
        "modelQualificationStatus"
    };
    const auto preliminaryInputKind =
        parseInputKind(asStdString(requiredString(object, "inputKind")));
    if (!preliminaryInputKind) {
        reject("record references an unknown canonical input kind");
    }
    const auto keysMatch = *preliminaryInputKind == RuntimeCalibrationInputKind::Message
            || *preliminaryInputKind == RuntimeCalibrationInputKind::Aead
            || *preliminaryInputKind == RuntimeCalibrationInputKind::HashXof
        ? hasExactKeys(object, variableInputKeys)
        : hasExactKeys(object, fixedInputKeys);
    if (!keysMatch) {
        reject("record has missing or unknown fields");
    }

    const auto profileText = asStdString(requiredString(object, "profileId"));
    const auto profileId = core::parseStableProfileId(profileText);
    if (!profileId || core::toStableProfileId(*profileId) != profileText) {
        reject("record references an unknown canonical profile ID");
    }
    const auto operationText = asStdString(requiredString(object, "operation"));
    const auto operation = parseStableOperationString(operationText);
    if (!operation || toStableOperationString(*operation) != operationText) {
        reject("record references an unknown canonical operation");
    }
    const auto inputKindText = asStdString(requiredString(object, "inputKind"));
    const auto inputKind = parseInputKind(inputKindText);
    if (!inputKind
        || !hasCanonicalCase(inventory, *profileId, *operation, *inputKind)) {
        reject("record references an illegal canonical typed input mode");
    }
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& value) {
            return value.profileId == *profileId
                && value.operation == *operation
                && value.inputKind == *inputKind;
        });
    if (calibrationCase == inventory.cases.end()) {
        reject("record references an absent canonical typed input mode");
    }

    const auto interval = requiredSmallInteger(
        object, "samplingIntervalMilliseconds");
    if (interval > std::numeric_limits<std::uint32_t>::max()
        || !core::isValidMeasurementSettings({
            static_cast<std::uint32_t>(interval)})) {
        reject("record sampling interval is outside the canonical settings range");
    }
    const auto samplingInterval = static_cast<std::uint32_t>(interval);
    if (!hasQualifiedContext(
            contexts, environment, samplingInterval)) {
        reject("record sampling interval has no matching qualified runtime context");
    }

    const auto identity = runtimeCalibrationCaseId(*calibrationCase);
    if (!identities.emplace(identity, samplingInterval).second) {
        reject("duplicate canonical record and measurement context");
    }

    const auto minimumInputBytes = parseVariableSizeBound(
        object, "validInputBytesMin", calibrationCase->hasVariableInputSize);
    const auto maximumInputBytes = parseVariableSizeBound(
        object, "validInputBytesMax", calibrationCase->hasVariableInputSize);
    if (calibrationCase->hasVariableInputSize) {
        const auto legalMinimum =
            *inputKind == RuntimeCalibrationInputKind::HashXof ? 0ULL : 1ULL;
        if (minimumInputBytes < legalMinimum
            || maximumInputBytes < minimumInputBytes
            || maximumInputBytes > core::kMaxWorkloadBytes) {
            reject("record input-size bounds are invalid for the canonical input kind");
        }
    }

    const auto model = requiredObject(object, "measuredModel");
    const auto modelKind = asStdString(requiredString(model, "kind"));
    RuntimeCalibrationMeasuredModelKind parsedModelKind;
    std::uint64_t referenceIterations = 0;
    std::uint64_t referenceMeasuredBlockNanoseconds = 0;
    std::uint64_t interceptPicosecondsPerIteration = 0;
    std::uint64_t slopePicosecondsPerBytePerIteration = 0;
    std::optional<std::uint64_t> referenceInputBytes;
    if (modelKind == "exactReference") {
        constexpr std::array<std::string_view, 3> fixedModelKeys{
            "kind", "referenceN", "referenceMeasuredBlockNanoseconds"};
        constexpr std::array<std::string_view, 4> variableModelKeys{
            "kind",
            "referenceN",
            "referenceMeasuredBlockNanoseconds",
            "referenceInputBytes"};
        const auto modelKeysMatch = calibrationCase->hasVariableInputSize
            ? hasExactKeys(model, variableModelKeys)
            : hasExactKeys(model, fixedModelKeys);
        if (!modelKeysMatch) {
            reject("exact-reference model has missing or unknown fields");
        }
        referenceIterations = canonicalDecimalString(model, "referenceN");
        referenceMeasuredBlockNanoseconds =
            canonicalDecimalString(model, "referenceMeasuredBlockNanoseconds");
        if (referenceIterations == 0) {
            reject("exact-reference model requires a positive reference N");
        }
        if (calibrationCase->hasVariableInputSize) {
            referenceInputBytes =
                canonicalDecimalString(model, "referenceInputBytes");
            if (*referenceInputBytes != minimumInputBytes
                || *referenceInputBytes != maximumInputBytes) {
                reject("exact-reference size must match its exact valid input range");
            }
        }
        parsedModelKind = RuntimeCalibrationMeasuredModelKind::ExactReference;
    } else if (modelKind == "affinePerIteration") {
        constexpr std::array<std::string_view, 3> modelKeys{
            "kind",
            "interceptPicosecondsPerIteration",
            "slopePicosecondsPerBytePerIteration"};
        if (!calibrationCase->hasVariableInputSize
            || !hasExactKeys(model, modelKeys)) {
            reject("affine model is invalid for this typed input or has unknown fields");
        }
        interceptPicosecondsPerIteration =
            canonicalDecimalString(model, "interceptPicosecondsPerIteration");
        slopePicosecondsPerBytePerIteration =
            canonicalDecimalString(model, "slopePicosecondsPerBytePerIteration");
        parsedModelKind = RuntimeCalibrationMeasuredModelKind::AffinePerIteration;
    } else {
        reject("unknown or pilot-gated measured-model kind");
    }

    requireHash(object, "evidenceSubsetSha256");
    requireHash(object, "holdoutSubsetSha256");
    const auto recordQualification =
        asStdString(requiredString(object, "modelQualificationStatus"));
    if (recordQualification != "unqualified") {
        reject("provisional resource schema cannot qualify individual records");
    }
    return {
        *calibrationCase,
        samplingInterval,
        parsedModelKind,
        referenceIterations,
        referenceMeasuredBlockNanoseconds,
        interceptPicosecondsPerIteration,
        slopePicosecondsPerBytePerIteration,
        referenceInputBytes,
        calibrationCase->hasVariableInputSize
            ? std::optional<std::uint64_t>{minimumInputBytes}
            : std::nullopt,
        calibrationCase->hasVariableInputSize
            ? std::optional<std::uint64_t>{maximumInputBytes}
            : std::nullopt
    };
}

RuntimeCalibrationResource parseResource(
    const QByteArray& bytes,
    const RuntimeCalibrationEnvironment& expectedEnvironment,
    bool& environmentMatches,
    bool& registryMatches)
{
    if (QString::fromUtf8(bytes.constData(), bytes.size()).toUtf8() != bytes) {
        reject("resource is not strict UTF-8");
    }
    if (const auto preflight = strictJsonPreflight(bytes)) {
        reject("strict JSON preflight rejected the resource: "
            + preflight->technicalMessage);
    }
    const auto numberTokens = inspectJsonNumberTokens(bytes);
    if (const auto* issue = std::get_if<BatchInputIssue>(&numberTokens)) {
        reject("strict JSON number preflight rejected the resource: "
            + issue->technicalMessage);
    }
    for (const auto& token : std::get<std::vector<JsonNumberToken>>(numberTokens)) {
        const auto lexeme = token.lexeme;
        if (lexeme.isEmpty()
            || (lexeme.size() > 1 && lexeme.front() == '0')
            || !std::ranges::all_of(lexeme, [](char value) {
                return value >= '0' && value <= '9';
            })) {
            reject("resource JSON numbers must be canonical nonnegative integer tokens");
        }
    }

    QJsonParseError jsonError{};
    const auto document = QJsonDocument::fromJson(bytes, &jsonError);
    if (jsonError.error != QJsonParseError::NoError || !document.isObject()) {
        reject("resource is not a valid JSON object");
    }
    const auto root = document.object();
    constexpr std::array<std::string_view, 28> rootKeys{
        "format",
        "schemaVersion",
        "datasetId",
        "datasetVersion",
        "generatedAtUtc",
        "calibrationProtocolId",
        "modelSchemaVersion",
        "generatorVersion",
        "sourceGitCommit",
        "referenceAppVersion",
        "referenceBuildType",
        "referenceWorkerSha256",
        "referenceAppSha256",
        "opensslVersion",
        "qtVersion",
        "compilerId",
        "os",
        "architecture",
        "referenceCpu",
        "referenceRamBytes",
        "powerPlan",
        "registryInventorySha256",
        "campaignPlanSha256",
        "rawEvidenceManifestSha256",
        "holdoutReportSha256",
        "qualificationStatus",
        "qualificationSummary",
        "qualifiedRuntimeContexts"
    };
    if (root.size() != static_cast<qsizetype>(rootKeys.size() + 2)
        || !std::ranges::all_of(rootKeys, [&](std::string_view key) {
            return root.contains(fieldKey(key));
        })
        || !root.contains(QStringLiteral("records"))
        || !root.contains(QStringLiteral("batchOverheadModels"))) {
        reject("resource has missing or unknown top-level fields");
    }
    if (requiredString(root, "format") != QString::fromLatin1(kResourceFormat)) {
        reject("resource format is unsupported");
    }
    if (requiredSmallInteger(root, "schemaVersion") != 1) {
        reject("resource schema version is unsupported");
    }
    if (requiredString(root, "modelSchemaVersion")
        != QString::fromLatin1(kProvisionalModelSchemaVersion)) {
        reject("resource model schema version is unsupported");
    }

    const auto generatedAt = requiredString(root, "generatedAtUtc");
    const auto generatedDateTime =
        QDateTime::fromString(generatedAt, Qt::ISODateWithMs);
    if (!generatedDateTime.isValid() || !generatedAt.endsWith(QLatin1Char('Z'))) {
        reject("generatedAtUtc is not an ISO-8601 UTC timestamp");
    }
    const auto buildType = asStdString(requiredString(root, "referenceBuildType"));
    if (buildType != "Debug" && buildType != "Release") {
        reject("reference build type is unknown");
    }
    const auto sourceCommit = asStdString(requiredString(root, "sourceGitCommit"));
    if (sourceCommit.size() < 40 || sourceCommit.size() > 64
        || !isLowerHex(sourceCommit, sourceCommit.size())) {
        reject("source Git commit is malformed");
    }
    requireHash(root, "referenceWorkerSha256");
    requireHash(root, "referenceAppSha256");
    requireHash(root, "registryInventorySha256");
    requireHash(root, "campaignPlanSha256");
    requireHash(root, "rawEvidenceManifestSha256");
    requireHash(root, "holdoutReportSha256");
    if (canonicalDecimalString(root, "referenceRamBytes") == 0) {
        reject("reference RAM must be positive");
    }
    const auto datasetId = asStdString(requiredString(root, "datasetId"));
    const auto datasetVersion = asStdString(requiredString(root, "datasetVersion"));
    const auto qualificationStatus =
        asStdString(requiredString(root, "qualificationStatus"));
    if (qualificationStatus != "unqualified") {
        reject("m23.1-provisional-1 cannot declare a qualified resource");
    }
    static_cast<void>(requiredString(root, "qualificationSummary"));
    static_cast<void>(requiredString(root, "generatorVersion"));
    static_cast<void>(requiredString(root, "referenceAppVersion"));
    static_cast<void>(requiredString(root, "opensslVersion"));
    static_cast<void>(requiredString(root, "qtVersion"));
    static_cast<void>(requiredString(root, "compilerId"));
    static_cast<void>(requiredString(root, "os"));
    static_cast<void>(requiredString(root, "architecture"));
    static_cast<void>(requiredString(root, "referenceCpu"));
    static_cast<void>(requiredString(root, "powerPlan"));

    const auto protocolId = asStdString(requiredString(root, "calibrationProtocolId"));
    const RuntimeCalibrationEnvironment sourceEnvironment{
        protocolId,
        asStdString(requiredString(root, "os")),
        asStdString(requiredString(root, "architecture")),
        buildType,
        asStdString(requiredString(root, "opensslVersion"))};

    const auto inventory = enumerateRuntimeCalibrationInventory();
    registryMatches =
        asStdString(requiredString(root, "registryInventorySha256"))
        == runtimeCalibrationInventorySha256(inventory).toStdString();

    const auto contextValues = requiredArray(root, "qualifiedRuntimeContexts");
    if (contextValues.isEmpty()
        || static_cast<std::size_t>(contextValues.size()) > kMaximumQualifiedContexts) {
        reject("qualified runtime context count is invalid");
    }
    std::vector<QualifiedContext> contexts;
    std::set<std::uint32_t> contextSamplingIntervals;
    for (const auto& value : contextValues) {
        if (!value.isObject()) {
            reject("qualified runtime context is not an object");
        }
        const auto contextObject = value.toObject();
        constexpr std::array<std::string_view, 6> contextKeys{
            "os",
            "architecture",
            "buildType",
            "opensslVersion",
            "calibrationProtocolId",
            "samplingIntervalMilliseconds"
        };
        if (!hasExactKeys(contextObject, contextKeys)) {
            reject("qualified runtime context has missing or unknown fields");
        }
        QualifiedContext context{
            asStdString(requiredString(contextObject, "os")),
            asStdString(requiredString(contextObject, "architecture")),
            asStdString(requiredString(contextObject, "buildType")),
            asStdString(requiredString(contextObject, "opensslVersion")),
            asStdString(requiredString(contextObject, "calibrationProtocolId")),
            0};
        const auto interval = requiredSmallInteger(
            contextObject, "samplingIntervalMilliseconds");
        if (interval > std::numeric_limits<std::uint32_t>::max()
            || !core::isValidMeasurementSettings({
                static_cast<std::uint32_t>(interval)})) {
            reject("qualified runtime context sampling interval is invalid");
        }
        context.samplingIntervalMilliseconds = static_cast<std::uint32_t>(interval);
        if (context.operatingSystem != sourceEnvironment.operatingSystem
            || context.architecture != sourceEnvironment.architecture
            || context.buildType != sourceEnvironment.buildType
            || context.opensslVersion != sourceEnvironment.opensslVersion
            || context.protocolId != sourceEnvironment.calibrationProtocolId
            || !contextSamplingIntervals.emplace(
                context.samplingIntervalMilliseconds).second) {
            reject("qualified runtime context conflicts with source provenance");
        }
        contexts.push_back(std::move(context));
    }

    const auto batchModels = requiredArray(root, "batchOverheadModels");
    if (!batchModels.isEmpty()) {
        reject("batch overhead model representation is pilot-gated");
    }

    const auto recordValues = requiredArray(root, "records");
    if (recordValues.isEmpty()
        || static_cast<std::size_t>(recordValues.size()) > kMaximumRecords) {
        reject("resource record count is invalid");
    }
    std::set<std::pair<std::string, std::uint32_t>> identities;
    RuntimeCalibrationResource resource{
        datasetId, datasetVersion, qualificationStatus, {}};
    resource.records.reserve(static_cast<std::size_t>(recordValues.size()));
    for (const auto& value : recordValues) {
        if (!value.isObject()) {
            reject("resource record is not an object");
        }
        resource.records.push_back(parseRecord(
            value.toObject(),
            inventory,
            contexts,
            sourceEnvironment,
            identities));
    }
    environmentMatches =
        sourceEnvironment.calibrationProtocolId == expectedEnvironment.calibrationProtocolId
        && sourceEnvironment.operatingSystem == expectedEnvironment.operatingSystem
        && sourceEnvironment.architecture == expectedEnvironment.architecture
        && sourceEnvironment.buildType == expectedEnvironment.buildType
        && sourceEnvironment.opensslVersion == expectedEnvironment.opensslVersion;
    if (!registryMatches) {
        environmentMatches = false;
    }
    return resource;
}

RuntimeCalibrationResourceLoadResult failed(
    RuntimeCalibrationResourceStatus status,
    std::string diagnostic)
{
    return {status, std::move(diagnostic), std::nullopt};
}

} // namespace

QString runtimeCalibrationResourcePath(const QString& executablePath)
{
    const QFileInfo executableInfo(executablePath);
    if (executablePath.isEmpty() || !executableInfo.isAbsolute()) {
        throw std::invalid_argument(
            "runtime calibration path requires an absolute executable path");
    }
    const auto executableDirectory = executableInfo.absolutePath();
    return QDir(executableDirectory).filePath(
        QString::fromUtf8(
            kRuntimeCalibrationResourceRelativePath.data(),
            static_cast<qsizetype>(kRuntimeCalibrationResourceRelativePath.size())));
}

RuntimeCalibrationResourceLoadResult loadRuntimeCalibrationResource(
    const QString& resourcePath,
    std::string_view expectedSha256,
    const RuntimeCalibrationEnvironment& expectedEnvironment)
{
    if (!QFileInfo::exists(resourcePath)) {
        return failed(RuntimeCalibrationResourceStatus::Missing, "resource file is missing");
    }
    if (!isLowerHex(expectedSha256, 64)) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, "expected SHA-256 is invalid");
    }

    QFile file(resourcePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, "resource file could not be opened");
    }
    if (file.size() < 0 || file.size() > kMaximumRuntimeCalibrationResourceBytes) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, "resource exceeds the size limit");
    }
    const auto bytes = file.read(kMaximumRuntimeCalibrationResourceBytes + 1);
    if (file.error() != QFileDevice::NoError
        || bytes.size() != file.size()
        || bytes.size() > kMaximumRuntimeCalibrationResourceBytes) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, "resource read was incomplete or oversized");
    }

    const auto actualSha256 =
        QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
    if (actualSha256 != QByteArray::fromStdString(std::string(expectedSha256))) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, "resource SHA-256 does not match");
    }

    bool environmentMatches = false;
    bool registryMatches = false;
    try {
        auto resource = parseResource(
            bytes, expectedEnvironment, environmentMatches, registryMatches);
        if (!environmentMatches || !registryMatches) {
            return failed(
                RuntimeCalibrationResourceStatus::Inapplicable,
                "resource runtime or canonical registry context is inapplicable");
        }
        return {
            RuntimeCalibrationResourceStatus::Loaded,
            "resource integrity and provisional schema validation passed",
            std::move(resource)};
    } catch (const ResourceParseError& error) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, error.what());
    }
}

} // namespace cryptobench::application
