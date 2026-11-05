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
constexpr auto kPragmaticModelSchemaVersion = "m23-pragmatic-1";
constexpr auto kPragmaticCalibrationProtocolId = "memory-v2-calibration-v1";
constexpr std::uint32_t kPragmaticMeasuredSamplingIntervalMilliseconds = 5;
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

std::uint64_t checkedPragmaticAdd(
    std::uint64_t left,
    std::uint64_t right,
    std::string_view field)
{
    if (left > std::numeric_limits<std::uint64_t>::max() - right) {
        reject("pragmatic model prediction overflows: " + std::string(field));
    }
    return left + right;
}

std::uint64_t checkedPragmaticMultiply(
    std::uint64_t left,
    std::uint64_t right,
    std::string_view field)
{
    if (left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left) {
        reject("pragmatic model prediction overflows: " + std::string(field));
    }
    return left * right;
}

std::optional<std::string> optionalHistoricalString(
    const QJsonObject& root,
    const QJsonObject& missingReasons,
    std::string_view name,
    RuntimeCalibrationMissingProvenanceField field,
    std::vector<RuntimeCalibrationMissingProvenance>& missingFields)
{
    const auto value = root.value(fieldKey(name));
    if (value.isNull()) {
        if (missingReasons.value(fieldKey(name)).toString()
            != "notRecordedInCampaignEvidence") {
            reject("null historical provenance requires its exact missing-evidence reason: "
                + std::string(name));
        }
        missingFields.push_back({
            field,
            RuntimeCalibrationMissingProvenanceReason::NotRecordedInCampaignEvidence});
        return std::nullopt;
    }
    if (!value.isString() || value.toString().isEmpty()
        || !missingReasons.value(fieldKey(name)).isUndefined()) {
        reject("historical provenance must be a non-empty string or a reasoned null: "
            + std::string(name));
    }
    return asStdString(value.toString());
}

std::optional<std::uint64_t> optionalHistoricalRamBytes(
    const QJsonObject& root,
    const QJsonObject& missingReasons,
    std::vector<RuntimeCalibrationMissingProvenance>& missingFields)
{
    constexpr std::string_view name = "referenceRamBytes";
    const auto value = root.value(fieldKey(name));
    if (value.isNull()) {
        if (missingReasons.value(fieldKey(name)).toString()
            != "notRecordedInCampaignEvidence") {
            reject("null historical provenance requires its exact missing-evidence reason: "
                + std::string(name));
        }
        missingFields.push_back({
            RuntimeCalibrationMissingProvenanceField::ReferenceRamBytes,
            RuntimeCalibrationMissingProvenanceReason::NotRecordedInCampaignEvidence});
        return std::nullopt;
    }
    const auto ramBytes = canonicalDecimalString(root, name);
    if (ramBytes == 0
        || !missingReasons.value(fieldKey(name)).isUndefined()) {
        reject("historical RAM provenance must be positive or a reasoned null");
    }
    return ramBytes;
}

void validateMissingProvenanceReasons(
    const QJsonObject& missingReasons,
    const std::vector<RuntimeCalibrationMissingProvenance>& missingFields)
{
    if (static_cast<std::size_t>(missingReasons.size()) != missingFields.size()) {
        reject("missing provenance reasons do not match the null historical fields");
    }
    for (auto iterator = missingReasons.begin();
         iterator != missingReasons.end();
         ++iterator) {
        const auto fieldMatches = std::ranges::any_of(
            missingFields,
            [&](const RuntimeCalibrationMissingProvenance& missing) {
                switch (missing.field) {
                case RuntimeCalibrationMissingProvenanceField::ReferenceWorkerSha256:
                    return iterator.key() == QStringLiteral("referenceWorkerSha256");
                case RuntimeCalibrationMissingProvenanceField::ReferenceAppSha256:
                    return iterator.key() == QStringLiteral("referenceAppSha256");
                case RuntimeCalibrationMissingProvenanceField::QtVersion:
                    return iterator.key() == QStringLiteral("qtVersion");
                case RuntimeCalibrationMissingProvenanceField::CompilerId:
                    return iterator.key() == QStringLiteral("compilerId");
                case RuntimeCalibrationMissingProvenanceField::ReferenceCpu:
                    return iterator.key() == QStringLiteral("referenceCpu");
                case RuntimeCalibrationMissingProvenanceField::ReferenceRamBytes:
                    return iterator.key() == QStringLiteral("referenceRamBytes");
                case RuntimeCalibrationMissingProvenanceField::PowerPlan:
                    return iterator.key() == QStringLiteral("powerPlan");
                }
                return false;
            });
        if (!fieldMatches
            || iterator.value().toString() != "notRecordedInCampaignEvidence") {
            reject("missing provenance reason is unknown, spurious, or unsupported");
        }
    }
}

RuntimeCalibrationPragmaticMeasuredModel parsePragmaticMeasuredModel(
    const QJsonObject& model,
    bool variableSize,
    std::uint64_t minimumInputBytes,
    std::uint64_t maximumInputBytes,
    RuntimeCalibrationMeasuredModelKind& modelKind)
{
    const auto kind = asStdString(requiredString(model, "kind"));
    if (kind == "constantPerOperation") {
        constexpr std::array<std::string_view, 2> keys{
            "kind", "picosecondsPerOperation"};
        if (variableSize || !hasExactKeys(model, keys)) {
            reject("constant-per-operation model is invalid for this typed input");
        }
        const auto picosecondsPerOperation =
            canonicalDecimalString(model, "picosecondsPerOperation");
        if (picosecondsPerOperation == 0) {
            reject("constant-per-operation model must have a positive duration");
        }
        modelKind = RuntimeCalibrationMeasuredModelKind::ConstantPerOperation;
        return RuntimeCalibrationConstantPerOperationModel{
            picosecondsPerOperation};
    }
    if (kind == "anchoredAffinePerOperation") {
        constexpr std::array<std::string_view, 4> keys{
            "kind",
            "anchorInputBytes",
            "anchorPicosecondsPerOperation",
            "slopePicosecondsPerBytePerOperation"};
        if (!variableSize || !hasExactKeys(model, keys)) {
            reject("anchored affine model is invalid for this typed input");
        }
        const auto anchorInputBytes =
            canonicalDecimalString(model, "anchorInputBytes");
        const auto anchorPicosecondsPerOperation =
            canonicalDecimalString(model, "anchorPicosecondsPerOperation");
        const auto slopePicosecondsPerBytePerOperation =
            canonicalDecimalString(model, "slopePicosecondsPerBytePerOperation");
        if (anchorInputBytes != minimumInputBytes) {
            reject("anchored affine model must use the exact minimum legal input size");
        }
        const auto sizeGrowth = checkedPragmaticMultiply(
            slopePicosecondsPerBytePerOperation,
            maximumInputBytes - minimumInputBytes,
            "anchored affine slope");
        static_cast<void>(checkedPragmaticAdd(
            anchorPicosecondsPerOperation, sizeGrowth,
            "anchored affine endpoint"));
        modelKind = RuntimeCalibrationMeasuredModelKind::AnchoredAffinePerOperation;
        return RuntimeCalibrationAnchoredAffinePerOperationModel{
            anchorInputBytes,
            anchorPicosecondsPerOperation,
            slopePicosecondsPerBytePerOperation};
    }
    reject("unknown pragmatic per-operation measured-model kind");
}

RuntimeCalibrationResourceRecord parsePragmaticRecord(
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
    const auto inputKind =
        parseInputKind(asStdString(requiredString(object, "inputKind")));
    if (!inputKind) {
        reject("pragmatic record references an unknown canonical input kind");
    }
    const bool variableSize =
        *inputKind == RuntimeCalibrationInputKind::Message
        || *inputKind == RuntimeCalibrationInputKind::Aead
        || *inputKind == RuntimeCalibrationInputKind::HashXof;
    if (!(variableSize ? hasExactKeys(object, variableInputKeys)
                       : hasExactKeys(object, fixedInputKeys))) {
        reject("pragmatic record has missing or unknown fields");
    }

    const auto profileText = asStdString(requiredString(object, "profileId"));
    const auto profileId = core::parseStableProfileId(profileText);
    const auto operationText = asStdString(requiredString(object, "operation"));
    const auto operation = parseStableOperationString(operationText);
    if (!profileId || core::toStableProfileId(*profileId) != profileText
        || !operation || toStableOperationString(*operation) != operationText
        || !hasCanonicalCase(inventory, *profileId, *operation, *inputKind)) {
        reject("pragmatic record references an unknown or illegal canonical typed identity");
    }
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& value) {
            return value.profileId == *profileId
                && value.operation == *operation
                && value.inputKind == *inputKind;
        });
    if (calibrationCase == inventory.cases.end()
        || calibrationCase->hasVariableInputSize != variableSize) {
        reject("pragmatic record input-size shape differs from canonical inventory");
    }

    const auto interval = requiredSmallInteger(
        object, "samplingIntervalMilliseconds");
    if (interval
            != static_cast<int>(kPragmaticMeasuredSamplingIntervalMilliseconds)
        || !hasQualifiedContext(
            contexts, environment,
            kPragmaticMeasuredSamplingIntervalMilliseconds)) {
        reject("pragmatic records must use the single measured 5 ms context");
    }
    const auto identity = runtimeCalibrationCaseId(*calibrationCase);
    if (!identities.emplace(
            identity, kPragmaticMeasuredSamplingIntervalMilliseconds).second) {
        reject("duplicate pragmatic canonical record and measurement context");
    }

    std::uint64_t minimumInputBytes = 0;
    std::uint64_t maximumInputBytes = 0;
    if (variableSize) {
        minimumInputBytes = canonicalDecimalString(object, "validInputBytesMin");
        maximumInputBytes = canonicalDecimalString(object, "validInputBytesMax");
        const auto legalMinimum =
            *inputKind == RuntimeCalibrationInputKind::HashXof ? 0ULL : 1ULL;
        if (minimumInputBytes != legalMinimum
            || maximumInputBytes != core::kMaxWorkloadBytes) {
            reject("pragmatic record must cover the exact canonical legal input range");
        }
    }

    RuntimeCalibrationMeasuredModelKind modelKind;
    auto model = parsePragmaticMeasuredModel(
        requiredObject(object, "measuredModel"),
        variableSize,
        minimumInputBytes,
        maximumInputBytes,
        modelKind);
    requireHash(object, "evidenceSubsetSha256");
    requireHash(object, "holdoutSubsetSha256");
    const auto recordStatus =
        asStdString(requiredString(object, "modelQualificationStatus"));
    const auto expectedRecordStatus = variableSize
        ? "perOperationReferenceFitSizeHoldoutOnly"
        : "perOperationReferenceFitOnly";
    if (recordStatus != expectedRecordStatus) {
        reject("pragmatic record evidence status does not match its model/holdout scope");
    }

    RuntimeCalibrationResourceRecord record{
        *calibrationCase,
        kPragmaticMeasuredSamplingIntervalMilliseconds,
        modelKind,
        0,
        0,
        0,
        0,
        std::nullopt,
        variableSize ? std::optional<std::uint64_t>{minimumInputBytes} : std::nullopt,
        variableSize ? std::optional<std::uint64_t>{maximumInputBytes} : std::nullopt};
    record.pragmaticModel = std::move(model);
    record.evidenceStatus = variableSize
        ? RuntimeCalibrationRecordEvidenceStatus::PerOperationReferenceFitSizeHoldoutOnly
        : RuntimeCalibrationRecordEvidenceStatus::PerOperationReferenceFitOnly;
    return record;
}

RuntimeCalibrationOverheadAssumption parsePragmaticOverheadAssumption(
    const QJsonObject& object)
{
    constexpr std::array<std::string_view, 2> keys{"nanoseconds", "status"};
    if (!hasExactKeys(object, keys)
        || canonicalDecimalString(object, "nanoseconds") != 0
        || requiredString(object, "status") != "assumedUnmeasured") {
        reject("pragmatic zero overhead must be explicitly tagged assumedUnmeasured");
    }
    return {0, RuntimeCalibrationAssumptionTag::AssumedUnmeasured};
}

RuntimeCalibrationApproximationPolicy parsePragmaticApproximationPolicy(
    const QJsonObject& root)
{
    const auto policy = requiredObject(root, "approximationPolicy");
    constexpr std::array<std::string_view, 4> keys{
        "warmupOperationsPerLogicalRun",
        "fixedEntryOverhead",
        "batchOverhead",
        "samplingIntervalAssumptions"};
    if (!hasExactKeys(policy, keys)
        || requiredSmallInteger(policy, "warmupOperationsPerLogicalRun") != 1) {
        reject("pragmatic policy must declare exactly one warm-up operation per run");
    }

    const auto fixedEntry = requiredObject(policy, "fixedEntryOverhead");
    const auto batch = requiredObject(policy, "batchOverhead");
    const auto assumptions = requiredArray(policy, "samplingIntervalAssumptions");
    if (assumptions.size() != 4) {
        reject("pragmatic policy must contain exactly four 1-4 ms sampling assumptions");
    }
    std::vector<RuntimeCalibrationSamplingAssumption> samplingAssumptions;
    samplingAssumptions.reserve(static_cast<std::size_t>(assumptions.size()));
    for (qsizetype index = 0; index < assumptions.size(); ++index) {
        if (!assumptions[index].isObject()) {
            reject("pragmatic sampling assumption is not an object");
        }
        const auto assumption = assumptions[index].toObject();
        constexpr std::array<std::string_view, 3> assumptionKeys{
            "requestedIntervalMilliseconds",
            "sourceMeasuredIntervalMilliseconds",
            "status"};
        if (!hasExactKeys(assumption, assumptionKeys)
            || requiredSmallInteger(assumption, "requestedIntervalMilliseconds")
                != static_cast<int>(index + 1)
            || requiredSmallInteger(assumption, "sourceMeasuredIntervalMilliseconds")
                != static_cast<int>(kPragmaticMeasuredSamplingIntervalMilliseconds)
            || requiredString(assumption, "status") != "assumedFrom5ms") {
            reject("pragmatic sampling assumptions must map 1-4 ms to measured 5 ms");
        }
        samplingAssumptions.push_back({
            static_cast<std::uint32_t>(index + 1),
            kPragmaticMeasuredSamplingIntervalMilliseconds,
            RuntimeCalibrationAssumptionTag::AssumedFrom5ms});
    }
    return {
        1,
        parsePragmaticOverheadAssumption(fixedEntry),
        parsePragmaticOverheadAssumption(batch),
        std::move(samplingAssumptions)};
}

RuntimeCalibrationResource parsePragmaticResource(
    const QJsonObject& root,
    const RuntimeCalibrationEnvironment& expectedEnvironment,
    bool& environmentMatches,
    bool& registryMatches)
{
    constexpr std::array<std::string_view, 31> rootKeys{
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
        "qualifiedRuntimeContexts",
        "sourceEvidenceSha256",
        "provenanceMissingReasons",
        "approximationPolicy"};
    if (root.size() != static_cast<qsizetype>(rootKeys.size() + 2)
        || !std::ranges::all_of(rootKeys, [&](std::string_view key) {
            return root.contains(fieldKey(key));
        })
        || !root.contains(QStringLiteral("records"))
        || !root.contains(QStringLiteral("batchOverheadModels"))) {
        reject("pragmatic resource has missing or unknown top-level fields");
    }
    if (requiredString(root, "format") != QString::fromLatin1(kResourceFormat)
        || requiredSmallInteger(root, "schemaVersion") != 1
        || requiredString(root, "modelSchemaVersion")
            != QString::fromLatin1(kPragmaticModelSchemaVersion)
        || requiredString(root, "qualificationStatus") != "reducedScopeApproximate") {
        reject("pragmatic resource format, version, or qualification status is unsupported");
    }

    const auto generatedAt = requiredString(root, "generatedAtUtc");
    const auto generatedDateTime =
        QDateTime::fromString(generatedAt, Qt::ISODateWithMs);
    if (!generatedDateTime.isValid() || !generatedAt.endsWith(QLatin1Char('Z'))) {
        reject("pragmatic generatedAtUtc is not an ISO-8601 UTC timestamp");
    }
    const auto buildType = asStdString(requiredString(root, "referenceBuildType"));
    if (buildType != "Release") {
        reject("pragmatic source measurements must be Release builds");
    }
    const auto sourceCommit = asStdString(requiredString(root, "sourceGitCommit"));
    if (sourceCommit.size() < 40 || sourceCommit.size() > 64
        || !isLowerHex(sourceCommit, sourceCommit.size())) {
        reject("pragmatic source Git commit is malformed");
    }
    const auto protocolId = asStdString(requiredString(root, "calibrationProtocolId"));
    if (protocolId != kPragmaticCalibrationProtocolId) {
        reject("pragmatic calibration protocol is unsupported");
    }

    RuntimeCalibrationPragmaticProvenance provenance;
    provenance.generatedAtUtc = asStdString(generatedAt);
    provenance.calibrationProtocolId = protocolId;
    provenance.generatorVersion = asStdString(requiredString(root, "generatorVersion"));
    provenance.qualificationSummary =
        asStdString(requiredString(root, "qualificationSummary"));
    provenance.sourceGitCommit = sourceCommit;
    provenance.referenceAppVersion =
        asStdString(requiredString(root, "referenceAppVersion"));
    provenance.referenceBuildType = buildType;
    provenance.opensslVersion = asStdString(requiredString(root, "opensslVersion"));
    provenance.operatingSystem = asStdString(requiredString(root, "os"));
    provenance.architecture = asStdString(requiredString(root, "architecture"));
    const auto missingReasons = requiredObject(root, "provenanceMissingReasons");
    provenance.referenceWorkerSha256 = optionalHistoricalString(
        root, missingReasons, "referenceWorkerSha256",
        RuntimeCalibrationMissingProvenanceField::ReferenceWorkerSha256,
        provenance.missingFields);
    provenance.referenceAppSha256 = optionalHistoricalString(
        root, missingReasons, "referenceAppSha256",
        RuntimeCalibrationMissingProvenanceField::ReferenceAppSha256,
        provenance.missingFields);
    provenance.qtVersion = optionalHistoricalString(
        root, missingReasons, "qtVersion",
        RuntimeCalibrationMissingProvenanceField::QtVersion,
        provenance.missingFields);
    provenance.compilerId = optionalHistoricalString(
        root, missingReasons, "compilerId",
        RuntimeCalibrationMissingProvenanceField::CompilerId,
        provenance.missingFields);
    provenance.referenceCpu = optionalHistoricalString(
        root, missingReasons, "referenceCpu",
        RuntimeCalibrationMissingProvenanceField::ReferenceCpu,
        provenance.missingFields);
    provenance.referenceRamBytes =
        optionalHistoricalRamBytes(root, missingReasons, provenance.missingFields);
    provenance.powerPlan = optionalHistoricalString(
        root, missingReasons, "powerPlan",
        RuntimeCalibrationMissingProvenanceField::PowerPlan,
        provenance.missingFields);
    validateMissingProvenanceReasons(missingReasons, provenance.missingFields);

    if (provenance.referenceWorkerSha256
        && !isLowerHex(*provenance.referenceWorkerSha256, 64)) {
        reject("pragmatic worker SHA-256 is malformed");
    }
    if (provenance.referenceAppSha256
        && !isLowerHex(*provenance.referenceAppSha256, 64)) {
        reject("pragmatic application SHA-256 is malformed");
    }

    provenance.registryInventorySha256 =
        asStdString(requiredString(root, "registryInventorySha256"));
    provenance.campaignPlanSha256 =
        asStdString(requiredString(root, "campaignPlanSha256"));
    provenance.rawEvidenceManifestSha256 =
        asStdString(requiredString(root, "rawEvidenceManifestSha256"));
    provenance.holdoutReportSha256 =
        asStdString(requiredString(root, "holdoutReportSha256"));
    requireHash(root, "registryInventorySha256");
    requireHash(root, "campaignPlanSha256");
    requireHash(root, "rawEvidenceManifestSha256");
    requireHash(root, "holdoutReportSha256");

    const auto sourceEvidence = requiredObject(root, "sourceEvidenceSha256");
    constexpr std::array<std::string_view, 3> sourceEvidenceKeys{
        "nightResultSha256", "supplementalResultSha256", "splitManifestSha256"};
    if (!hasExactKeys(sourceEvidence, sourceEvidenceKeys)) {
        reject("pragmatic source-evidence hashes have missing or unknown fields");
    }
    provenance.sourceEvidenceSha256 = {
        asStdString(requiredString(sourceEvidence, "nightResultSha256")),
        asStdString(requiredString(sourceEvidence, "supplementalResultSha256")),
        asStdString(requiredString(sourceEvidence, "splitManifestSha256"))};
    requireHash(sourceEvidence, "nightResultSha256");
    requireHash(sourceEvidence, "supplementalResultSha256");
    requireHash(sourceEvidence, "splitManifestSha256");
    if (provenance.rawEvidenceManifestSha256
        != provenance.sourceEvidenceSha256.splitManifest) {
        reject("raw evidence manifest SHA-256 differs from source-evidence manifest hash");
    }

    const auto inventory = enumerateRuntimeCalibrationInventory();
    if (inventory.cases.size() != 175
        || inventory.fixedInputCaseCount != 78
        || inventory.variableInputCaseCount != 97) {
        reject("pragmatic schema requires the reviewed 175-case canonical inventory");
    }
    registryMatches =
        provenance.registryInventorySha256
        == runtimeCalibrationInventorySha256(inventory).toStdString();
    const RuntimeCalibrationEnvironment sourceEnvironment{
        protocolId,
        provenance.operatingSystem,
        provenance.architecture,
        buildType,
        provenance.opensslVersion};

    const auto contextValues = requiredArray(root, "qualifiedRuntimeContexts");
    if (contextValues.size() != 1 || !contextValues[0].isObject()) {
        reject("pragmatic resource must contain exactly one measured runtime context");
    }
    const auto contextObject = contextValues[0].toObject();
    constexpr std::array<std::string_view, 6> contextKeys{
        "os",
        "architecture",
        "buildType",
        "opensslVersion",
        "calibrationProtocolId",
        "samplingIntervalMilliseconds"};
    if (!hasExactKeys(contextObject, contextKeys)) {
        reject("pragmatic measured runtime context has missing or unknown fields");
    }
    const auto contextInterval = requiredSmallInteger(
        contextObject, "samplingIntervalMilliseconds");
    QualifiedContext measuredContext{
        asStdString(requiredString(contextObject, "os")),
        asStdString(requiredString(contextObject, "architecture")),
        asStdString(requiredString(contextObject, "buildType")),
        asStdString(requiredString(contextObject, "opensslVersion")),
        asStdString(requiredString(contextObject, "calibrationProtocolId")),
        static_cast<std::uint32_t>(contextInterval)};
    if (contextInterval
            != static_cast<int>(kPragmaticMeasuredSamplingIntervalMilliseconds)
        || !hasQualifiedContext(
            std::vector<QualifiedContext>{measuredContext},
            sourceEnvironment,
            kPragmaticMeasuredSamplingIntervalMilliseconds)) {
        reject("pragmatic context must describe only the measured 5 ms source");
    }

    const auto batchModels = requiredArray(root, "batchOverheadModels");
    if (!batchModels.isEmpty()) {
        reject("pragmatic schema does not accept a measured Batch overhead model");
    }
    auto approximationPolicy = parsePragmaticApproximationPolicy(root);
    const auto recordValues = requiredArray(root, "records");
    if (recordValues.size() != static_cast<qsizetype>(inventory.cases.size())
        || static_cast<std::size_t>(recordValues.size()) > kMaximumRecords) {
        reject("pragmatic resource must contain one record for every canonical case");
    }
    std::set<std::pair<std::string, std::uint32_t>> identities;
    RuntimeCalibrationResource resource{
        asStdString(requiredString(root, "datasetId")),
        asStdString(requiredString(root, "datasetVersion")),
        "reducedScopeApproximate",
        {},
        RuntimeCalibrationResourceDialect::M23Pragmatic,
        std::move(approximationPolicy),
        std::move(provenance)};
    resource.records.reserve(static_cast<std::size_t>(recordValues.size()));
    const std::vector<QualifiedContext> contexts{measuredContext};
    for (const auto& value : recordValues) {
        if (!value.isObject()) {
            reject("pragmatic record is not an object");
        }
        resource.records.push_back(parsePragmaticRecord(
            value.toObject(), inventory, contexts, sourceEnvironment, identities));
    }
    if (identities.size() != inventory.cases.size()) {
        reject("pragmatic resource does not cover every canonical identity exactly once");
    }

    environmentMatches =
        sourceEnvironment.calibrationProtocolId == expectedEnvironment.calibrationProtocolId;
    return resource;
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
    const auto modelSchemaVersion = root.value(QStringLiteral("modelSchemaVersion"));
    if (modelSchemaVersion.isString()
        && modelSchemaVersion.toString()
            == QString::fromLatin1(kPragmaticModelSchemaVersion)) {
        return parsePragmaticResource(
            root, expectedEnvironment, environmentMatches, registryMatches);
    }

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
        const auto diagnostic =
            resource.dialect == RuntimeCalibrationResourceDialect::M23Pragmatic
            ? "resource integrity and pragmatic schema validation passed"
            : "resource integrity and provisional schema validation passed";
        return {
            RuntimeCalibrationResourceStatus::Loaded,
            diagnostic,
            std::move(resource)};
    } catch (const ResourceParseError& error) {
        return failed(RuntimeCalibrationResourceStatus::Corrupt, error.what());
    }
}

} // namespace cryptobench::application
