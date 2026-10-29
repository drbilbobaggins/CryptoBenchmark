#include "M23PilotPlan.h"

#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/MeasurementSettings.h>

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <algorithm>
#include <array>
#include <ranges>
#include <span>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace cryptobench::tests {
namespace {

namespace application = cryptobench::application;
namespace core = cryptobench::core;

using application::RuntimeCalibrationCase;
using application::RuntimeCalibrationInventory;
using application::RuntimeCalibrationInputKind;

struct CanonicalPilotCase {
    std::string_view caseId;
    std::string_view purpose;
};

constexpr std::array<CanonicalPilotCase, 12> kPilotCases{{
    {"rsa-3072-keygen/keyGen/noSignature", "costly fixed KeyGen"},
    {"rsa-pss-3072-sha256/sign/prehashed", "fixed signature input"},
    {"rsa-pss-3072-sha256/verify/message", "public-key verification plus message"},
    {"ed25519/sign/message", "EdDSA variable message"},
    {"ml-dsa-65/sign/message", "PQC variable message"},
    {"slh-dsa-sha2-128s/sign/message", "expensive PQC signature"},
    {"x25519/derive/keyEstablishment", "XDH fixed workload"},
    {"ml-kem-768/decapsulate/keyEstablishment", "KEM fixed workload"},
    {"aes-256-gcm/encrypt/aead", "AEAD encryption"},
    {"aes-256-gcm/decrypt/aead", "AEAD decryption"},
    {"sha256/hash/hashXof", "fast streaming hash and zero-byte edge"},
    {"shake256-64bytes/xof/hashXof", "fixed-output XOF"}
}};

constexpr std::array<std::uint64_t, 3> kMessageAeadReferenceBytes{
    1, 4'096, 1'048'576};
constexpr std::array<std::uint64_t, 2> kMessageAeadHoldoutBytes{
    64, 65'536};
constexpr std::array<std::uint64_t, 3> kHashReferenceBytes{
    0, 4'096, 1'048'576};
constexpr std::array<std::uint64_t, 2> kHashHoldoutBytes{
    1, 65'536};
constexpr std::uint32_t kPilotRepeatCount = 3;
constexpr std::uint64_t kPilotOrderSeed = 0x4d32332e325f504cULL;
constexpr auto kPlanFormat = "cryptobenchmark-m23-pilot-plan";
constexpr auto kApprovedPlanFormat = "cryptobenchmark-m23-approved-pilot-plan";
constexpr auto kPlanVersion = "m23.2-prep-v1";

QString qString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

const RuntimeCalibrationInventory& inventory()
{
    static const auto value = application::enumerateRuntimeCalibrationInventory();
    return value;
}

const RuntimeCalibrationCase& requireCase(std::string_view caseId)
{
    const auto found = std::ranges::find_if(
        inventory().cases,
        [&](const RuntimeCalibrationCase& value) {
            return application::runtimeCalibrationCaseId(value) == caseId;
        });
    if (found == inventory().cases.end()) {
        throw std::logic_error(
            "M23 pilot case is absent or illegal in the canonical registry: "
            + std::string(caseId));
    }
    return *found;
}

core::BenchmarkConfig makeConfig(
    const RuntimeCalibrationCase& calibrationCase,
    std::optional<std::uint64_t> inputBytes,
    std::uint64_t iterationsPerRun,
    std::uint32_t runs)
{
    core::PrimitiveConfig parameters;
    switch (calibrationCase.inputKind) {
    case RuntimeCalibrationInputKind::NoSignature:
        parameters = core::SignatureConfig{core::NoSignatureInput{}};
        break;
    case RuntimeCalibrationInputKind::Prehashed:
        parameters = core::SignatureConfig{core::PrehashedInput{}};
        break;
    case RuntimeCalibrationInputKind::Message:
        if (!inputBytes) {
            throw std::logic_error("M23 variable-message case lacks a byte size");
        }
        parameters = core::SignatureConfig{core::MessageInput{*inputBytes}};
        break;
    case RuntimeCalibrationInputKind::KeyEstablishment:
        parameters = core::KeyEstablishmentConfig{};
        break;
    case RuntimeCalibrationInputKind::Aead:
        if (!inputBytes) {
            throw std::logic_error("M23 AEAD case lacks a byte size");
        }
        parameters = core::AeadConfig{*inputBytes};
        break;
    case RuntimeCalibrationInputKind::HashXof:
        if (!inputBytes) {
            throw std::logic_error("M23 Hash/XOF case lacks a byte size");
        }
        parameters = core::HashConfig{*inputBytes};
        break;
    }

    return {
        calibrationCase.profileId,
        calibrationCase.operation,
        iterationsPerRun,
        runs,
        std::move(parameters)};
}

void require(bool condition, std::string_view message);

void requireLegalConfig(const M23PilotPlanRow& row)
{
    const auto config = makeConfig(
        row.calibrationCase,
        row.inputBytes,
        row.iterationsPerRun,
        row.runs);
    core::ValidationResult result;
    if (!core::ConfigValidator{}.validateAndCreate(config, result)) {
        throw std::logic_error("M23 pilot row violates the canonical ConfigValidator");
    }
    if (!core::isValidMeasurementSettings(
            {row.samplingIntervalMilliseconds})) {
        throw std::logic_error("M23 pilot row uses an unsupported sampling interval");
    }
}

std::string safeComponent(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const auto character : value) {
        result.push_back(
            character >= 'a' && character <= 'z'
                ? character
                : character >= 'A' && character <= 'Z'
                    ? static_cast<char>(character - 'A' + 'a')
                    : character >= '0' && character <= '9'
                        ? character
                        : '-');
    }
    return result;
}

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string rowId(
    std::string_view caseId,
    std::string_view probe,
    std::string_view role,
    std::optional<std::uint64_t> inputBytes,
    std::uint64_t iterationsPerRun,
    std::uint32_t runs,
    std::uint32_t samplingMilliseconds,
    std::uint32_t repetition)
{
    const auto identity = safeComponent(caseId) + "-" + std::string(probe)
        + "-" + std::string(role)
        + "-s" + (inputBytes ? std::to_string(*inputBytes) : "none")
        + "-n" + std::to_string(iterationsPerRun)
        + "-m" + std::to_string(runs)
        + "-t" + std::to_string(samplingMilliseconds)
        + "-r" + std::to_string(repetition);
    return "pilot-" + identity;
}

void appendRowsForSizes(
    std::vector<M23PilotPlanRow>& rows,
    std::string_view caseId,
    const RuntimeCalibrationCase& calibrationCase,
    M23PilotRole role,
    M23PilotProbeKind probe,
    std::span<const std::uint64_t> inputSizes,
    M23PilotRiskClass risk,
    std::string_view hypothesis)
{
    for (const auto inputBytes : inputSizes) {
        for (std::uint32_t repetition = 1;
             repetition <= kPilotRepeatCount;
             ++repetition) {
            rows.push_back({
                rowId(
                    caseId,
                    toStableString(probe),
                    toStableString(role),
                    inputBytes,
                    1,
                    1,
                    5,
                    repetition),
                calibrationCase,
                role,
                probe,
                M23PilotPlanStatus::Candidate,
                inputBytes,
                1,
                1,
                5,
                repetition,
                0,
                risk,
                std::string(hypothesis),
                {}});
        }
    }
}

void appendProbe(
    std::vector<M23PilotPlanRow>& rows,
    std::string_view caseId,
    M23PilotRole role,
    M23PilotProbeKind probe,
    std::optional<std::uint64_t> inputBytes,
    std::uint64_t iterationsPerRun,
    std::uint32_t runs,
    std::uint32_t samplingMilliseconds,
    M23PilotRiskClass risk,
    std::string_view hypothesis,
    std::uint32_t repetition = 1)
{
    const auto& calibrationCase = requireCase(caseId);
    rows.push_back({
        rowId(
            caseId,
            toStableString(probe),
            toStableString(role),
            inputBytes,
            iterationsPerRun,
            runs,
            samplingMilliseconds,
            repetition),
        calibrationCase,
        role,
        probe,
        M23PilotPlanStatus::Candidate,
        inputBytes,
        iterationsPerRun,
        runs,
        samplingMilliseconds,
        repetition,
        0,
        risk,
        std::string(hypothesis),
        {}});
}

std::vector<M23PilotPlanRow> buildPilotRows()
{
    std::vector<M23PilotPlanRow> rows;
    for (const auto& pilotCase : kPilotCases) {
        const auto& calibrationCase = requireCase(pilotCase.caseId);
        const auto variable = calibrationCase.hasVariableInputSize;
        if (variable) {
            const auto workloadRisk = pilotCase.caseId
                    == "slh-dsa-sha2-128s/sign/message"
                ? M23PilotRiskClass::High
                : calibrationCase.inputKind == RuntimeCalibrationInputKind::HashXof
                    ? M23PilotRiskClass::Low
                    : M23PilotRiskClass::Moderate;
            if (calibrationCase.inputKind == RuntimeCalibrationInputKind::HashXof) {
                appendRowsForSizes(
                    rows,
                    pilotCase.caseId,
                    calibrationCase,
                    M23PilotRole::Reference,
                    M23PilotProbeKind::WorkloadSize,
                    kHashReferenceBytes,
                    workloadRisk,
                    "Fit candidate measured-block response over the initial safe size grid");
                appendRowsForSizes(
                    rows,
                    pilotCase.caseId,
                    calibrationCase,
                    M23PilotRole::Holdout,
                    M23PilotProbeKind::WorkloadSize,
                    kHashHoldoutBytes,
                    workloadRisk,
                    "Independent size holdout; never include in fit");
            } else {
                appendRowsForSizes(
                    rows,
                    pilotCase.caseId,
                    calibrationCase,
                    M23PilotRole::Reference,
                    M23PilotProbeKind::WorkloadSize,
                    kMessageAeadReferenceBytes,
                    workloadRisk,
                    "Fit candidate measured-block response over the initial safe size grid");
                appendRowsForSizes(
                    rows,
                    pilotCase.caseId,
                    calibrationCase,
                    M23PilotRole::Holdout,
                    M23PilotProbeKind::WorkloadSize,
                    kMessageAeadHoldoutBytes,
                    workloadRisk,
                    "Independent size holdout; never include in fit");
            }
        } else {
            constexpr std::uint64_t holdoutN = 2;
            const auto deferNHoldout = pilotCase.caseId
                == "rsa-3072-keygen/keyGen/noSignature";
            const auto risk = pilotCase.caseId
                    == "rsa-3072-keygen/keyGen/noSignature"
                ? M23PilotRiskClass::High
                : M23PilotRiskClass::Moderate;
            for (std::uint32_t repetition = 1;
                 repetition <= kPilotRepeatCount;
                 ++repetition) {
                rows.push_back({
                    rowId(pilotCase.caseId, "fixed-n", "reference",
                        std::nullopt, 1, 1, 5, repetition),
                    calibrationCase,
                    M23PilotRole::Reference,
                    M23PilotProbeKind::IterationScaling,
                    M23PilotPlanStatus::Candidate,
                    std::nullopt,
                    1,
                    1,
                    5,
                    repetition,
                    0,
                    risk,
                    std::string(pilotCase.purpose) + "; baseline N=1",
                    {}});
                rows.push_back({
                    rowId(pilotCase.caseId, "fixed-n", "holdout",
                        std::nullopt, holdoutN, 1, 5, repetition),
                    calibrationCase,
                    M23PilotRole::Holdout,
                    M23PilotProbeKind::IterationScaling,
                    deferNHoldout
                        ? M23PilotPlanStatus::Deferred
                        : M23PilotPlanStatus::Candidate,
                    std::nullopt,
                    holdoutN,
                    1,
                    5,
                    repetition,
                    0,
                    risk,
                    "Independent fixed-mode N=2 scaling holdout",
                    deferNHoldout
                        ? "RSA-3072 KeyGen N=2 is deferred until pilot feasibility review"
                        : std::string{}});
            }
        }
    }

    appendProbe(rows, "rsa-pss-3072-sha256/sign/prehashed",
        M23PilotRole::Holdout, M23PilotProbeKind::IterationScaling,
        std::nullopt, 2, 1, 5, M23PilotRiskClass::Moderate,
        "Check fixed-mode N scaling against its N=1 reference");
    appendProbe(rows, "x25519/derive/keyEstablishment",
        M23PilotRole::Holdout, M23PilotProbeKind::IterationScaling,
        std::nullopt, 10, 1, 5, M23PilotRiskClass::Low,
        "Probe N scaling on a low-cost fixed operation");
    appendProbe(rows, "ml-kem-768/decapsulate/keyEstablishment",
        M23PilotRole::Holdout, M23PilotProbeKind::IterationScaling,
        std::nullopt, 2, 1, 5, M23PilotRiskClass::Moderate,
        "Check fixed-mode N scaling with one conservative multiplier");
    appendProbe(rows, "ed25519/sign/message",
        M23PilotRole::Holdout, M23PilotProbeKind::IterationScaling,
        4'096, 10, 1, 5, M23PilotRiskClass::Low,
        "Probe variable-size N scaling at the middle reference size");
    appendProbe(rows, "sha256/hash/hashXof",
        M23PilotRole::Holdout, M23PilotProbeKind::IterationScaling,
        4'096, 100, 1, 5, M23PilotRiskClass::Low,
        "Probe high-throughput N scaling without a long workload");

    appendProbe(rows, "x25519/derive/keyEstablishment",
        M23PilotRole::Sensitivity, M23PilotProbeKind::RunCountSensitivity,
        std::nullopt, 1, 3, 5, M23PilotRiskClass::Low,
        "Compare M=3 end-to-end run scaling; measured block remains per-run");
    appendProbe(rows, "sha256/hash/hashXof",
        M23PilotRole::Sensitivity, M23PilotProbeKind::RunCountSensitivity,
        4'096, 1, 3, 5, M23PilotRiskClass::Low,
        "Compare M=3 on a low-cost variable-size case");
    appendProbe(rows, "sha256/hash/hashXof",
        M23PilotRole::Sensitivity, M23PilotProbeKind::RunCountSensitivity,
        4'096, 1, 10, 5, M23PilotRiskClass::Moderate,
        "Probe M=10 only on a low-cost operation");
    appendProbe(rows, "aes-256-gcm/encrypt/aead",
        M23PilotRole::Sensitivity, M23PilotProbeKind::RunCountSensitivity,
        4'096, 1, 3, 5, M23PilotRiskClass::Moderate,
        "Compare M=3 for a low-size AEAD workload");

    for (const auto sampling : {1U, 2U, 3U, 4U}) {
        appendProbe(rows, "sha256/hash/hashXof",
            M23PilotRole::Sensitivity, M23PilotProbeKind::SamplingSensitivity,
            4'096, 1, 1, sampling, M23PilotRiskClass::Low,
            "Compare this sampling context with the default 5 ms reference");
        appendProbe(rows, "ml-dsa-65/sign/message",
            M23PilotRole::Sensitivity, M23PilotProbeKind::SamplingSensitivity,
            4'096, 1, 1, sampling, M23PilotRiskClass::Moderate,
            "Probe sampling sensitivity on a PQC signature case");
    }

    std::set<std::string> identities;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        auto& row = rows[index];
        requireLegalConfig(row);
        if (!identities.emplace(row.rowId).second) {
            throw std::logic_error("M23 pilot plan contains a duplicate row ID");
        }
    }
    auto randomState = kPilotOrderSeed;
    for (std::size_t remaining = rows.size(); remaining > 1; --remaining) {
        randomState ^= randomState << 13U;
        randomState ^= randomState >> 7U;
        randomState ^= randomState << 17U;
        const auto swapIndex = static_cast<std::size_t>(randomState % remaining);
        std::swap(rows[remaining - 1], rows[swapIndex]);
    }
    for (std::size_t index = 0; index < rows.size(); ++index) {
        rows[index].order = static_cast<std::uint32_t>(index + 1);
    }
    return rows;
}

std::vector<M23PilotBatchShape> buildBatchShapes()
{
    const auto& hash = requireCase("sha256/hash/hashXof");
    return {
        {"batch-e1-sha256", {hash}, 4'096, 1, 1, 5,
            M23PilotPlanStatus::Candidate, M23PilotRiskClass::Low,
            "One-entry baseline for separating entry from Batch overhead", {}},
        {"batch-e3-sha256", {hash, hash, hash}, 4'096, 1, 1, 5,
            M23PilotPlanStatus::Candidate, M23PilotRiskClass::Low,
            "Three-entry Batch checkpoint-position probe", {}},
        {"batch-e10-sha256", std::vector<RuntimeCalibrationCase>(10, hash),
            4'096, 1, 1, 5, M23PilotPlanStatus::Deferred,
            M23PilotRiskClass::High,
            "Deferred until E=3 evidence and checkpoint growth review",
            "Requires separate approval for ten-entry checkpoint work"},
        {"batch-e20-sha256", std::vector<RuntimeCalibrationCase>(20, hash),
            4'096, 1, 1, 5, M23PilotPlanStatus::Deferred,
            M23PilotRiskClass::High,
            "Deferred; no E=20 observation is in the initial executable plan",
            "Requires separate feasibility and disk-growth review"}
    };
}

QJsonObject rowObject(const M23PilotPlanRow& row)
{
    return {
        {"caseId", qString(application::runtimeCalibrationCaseId(row.calibrationCase))},
        {"deferredReason", qString(row.deferredReason)},
        {"hypothesis", qString(row.hypothesis)},
        {"inputBytes", row.inputBytes
            ? QJsonValue(QString::number(*row.inputBytes))
            : QJsonValue(QJsonValue::Null)},
        {"iterationsPerRun", QString::number(row.iterationsPerRun)},
        {"order", static_cast<qint64>(row.order)},
        {"probeKind", qString(toStableString(row.probeKind))},
        {"repetition", static_cast<qint64>(row.repetition)},
        {"riskClass", qString(toStableString(row.risk))},
        {"role", qString(toStableString(row.role))},
        {"rowId", qString(row.rowId)},
        {"runs", static_cast<qint64>(row.runs)},
        {"samplingIntervalMilliseconds",
            static_cast<qint64>(row.samplingIntervalMilliseconds)},
        {"status", qString(toStableString(row.status))}};
}

QJsonObject batchShapeObject(const M23PilotBatchShape& shape)
{
    QJsonArray entries;
    for (std::size_t index = 0; index < shape.entries.size(); ++index) {
        entries.append(QJsonObject{
            {"caseId", qString(application::runtimeCalibrationCaseId(shape.entries[index]))},
            {"entryIndex", static_cast<qint64>(index + 1)}});
    }
    return {
        {"batchId", qString(shape.batchId)},
        {"entries", entries},
        {"hypothesis", qString(shape.hypothesis)},
        {"inputBytes", QString::number(shape.inputBytes)},
        {"iterationsPerRun", QString::number(shape.iterationsPerRun)},
        {"runs", static_cast<qint64>(shape.runs)},
        {"samplingIntervalMilliseconds",
            static_cast<qint64>(shape.samplingIntervalMilliseconds)},
        {"status", qString(toStableString(shape.status))},
        {"riskClass", qString(toStableString(shape.risk))},
        {"deferredReason", qString(shape.deferredReason)}};
}

QJsonDocument pilotPlanDocument(
    const std::vector<M23PilotPlanRow>& rows,
    const std::vector<M23PilotBatchShape>& shapes,
    const std::vector<std::string>& deferred)
{
    QJsonArray rowArray;
    for (const auto& row : rows) {
        rowArray.append(rowObject(row));
    }
    QJsonArray shapeArray;
    for (const auto& shape : shapes) {
        shapeArray.append(batchShapeObject(shape));
    }
    QJsonArray deferredArray;
    for (const auto& item : deferred) {
        deferredArray.append(qString(item));
    }
    return QJsonDocument(QJsonObject{
        {"batchShapes", shapeArray},
        {"caseCount", static_cast<qint64>(kPilotCases.size())},
        {"deferredProbes", deferredArray},
        {"format", QString::fromLatin1(kPlanFormat)},
        {"inventorySha256", QString::fromLatin1(
            application::runtimeCalibrationInventorySha256(inventory()))},
        {"measurementAuthorized", false},
        {"orderSeed", QString::number(kPilotOrderSeed)},
        {"planVersion", QString::fromLatin1(kPlanVersion)},
        {"resourceCaps", QJsonObject{
            {"maximumBatchEntries", static_cast<qint64>(kM23PilotMaximumBatchEntries)},
            {"maximumInputBytes", QString::number(kM23PilotMaximumInitialInputBytes)},
            {"maximumObservationSeconds",
                static_cast<qint64>(kM23PilotMaximumObservationSeconds)},
            {"maximumN", QString::number(kM23PilotMaximumN)},
            {"maximumM", static_cast<qint64>(kM23PilotMaximumM)},
            {"minimumAvailableMemoryBytes",
                QString::number(kM23PilotMinimumAvailableMemoryBytes)},
            {"minimumFreeDiskBytes",
                QString::number(kM23PilotMinimumFreeDiskBytes)}}},
        {"rows", rowArray},
        {"schemaVersion", 1},
        {"status", QStringLiteral("CANDIDATE_ONLY_NOT_AUTHORIZED")}});
}

std::vector<std::string> buildDeferredProbes()
{
    std::vector<std::string> deferred;
    for (const auto& pilotCase : kPilotCases) {
        const auto& calibrationCase = requireCase(pilotCase.caseId);
        if (!calibrationCase.hasVariableInputSize) {
            continue;
        }
        deferred.push_back(std::string(pilotCase.caseId)
            + "|inputBytes=16777216|status=deferred|reason=separate feasibility approval");
        deferred.push_back(std::string(pilotCase.caseId)
            + "|inputBytes=268435456|status=deferred|reason=resource/wall-time feasibility gate");
    }
    deferred.push_back(
        "rsa-3072-keygen/keyGen/noSignature|N=2|status=deferred|reason=cost risk");
    deferred.push_back(
        "slh-dsa-sha2-128s/sign/message|N=10|status=deferred|reason=cost risk");
    deferred.push_back(
        "batch-e10-sha256|E=10|status=deferred|reason=checkpoint growth review");
    deferred.push_back(
        "batch-e20-sha256|E=20|status=deferred|reason=disk/resource feasibility review");
    return deferred;
}

} // namespace

std::vector<M23PilotPlanRow> m23PilotPlanRows()
{
    return buildPilotRows();
}

std::vector<M23PilotBatchShape> m23PilotBatchShapes()
{
    return buildBatchShapes();
}

std::vector<std::string> m23PilotDeferredProbeIds()
{
    return buildDeferredProbes();
}

QByteArray m23PilotPlanManifest()
{
    return pilotPlanDocument(
        m23PilotPlanRows(),
        m23PilotBatchShapes(),
        m23PilotDeferredProbeIds()).toJson(QJsonDocument::Compact);
}

QByteArray m23PilotPlanSha256()
{
    return QCryptographicHash::hash(
        m23PilotPlanManifest(), QCryptographicHash::Sha256).toHex();
}

QByteArray m23PilotDryRunReport()
{
    const auto rows = m23PilotPlanRows();
    const auto shapes = m23PilotBatchShapes();
    const auto deferred = m23PilotDeferredProbeIds();
    const auto candidateRows = std::ranges::count_if(
        rows, [](const auto& row) {
            return row.status == M23PilotPlanStatus::Candidate;
        });
    const auto deferredRows = rows.size() - static_cast<std::size_t>(candidateRows);
    const auto candidateShapes = std::ranges::count_if(
        shapes, [](const auto& shape) {
            return shape.status == M23PilotPlanStatus::Candidate;
        });
    const auto deferredShapes = shapes.size()
        - static_cast<std::size_t>(candidateShapes);
    const auto candidatePlan =
        QJsonDocument::fromJson(m23PilotPlanManifest()).object();
    return QJsonDocument(QJsonObject{
        {"batchShapeCandidateCount", static_cast<qint64>(candidateShapes)},
        {"batchShapeDeferredCount", static_cast<qint64>(deferredShapes)},
        {"candidateObservationRowCount", static_cast<qint64>(candidateRows)},
        {"candidatePlan", candidatePlan},
        {"caseCount", static_cast<qint64>(kPilotCases.size())},
        {"deferredObservationRowCount", static_cast<qint64>(deferredRows)},
        {"deferredProbeCount", static_cast<qint64>(deferred.size())},
        {"measurementAuthorized", false},
        {"pilotPlanSha256", QString::fromLatin1(m23PilotPlanSha256())},
        {"reportLabel", QStringLiteral("DRY RUN - NO OBSERVATIONS")},
        {"status", QStringLiteral("CANDIDATE_ONLY_NOT_AUTHORIZED")}})
        .toJson(QJsonDocument::Compact);
}

std::optional<M23PilotExecutionGroup> m23PilotExecutionGroup(
    std::string_view groupId)
{
    for (const auto& row : m23PilotPlanRows()) {
        if (row.rowId == groupId) {
            if (row.status != M23PilotPlanStatus::Candidate) {
                return std::nullopt;
            }
            return M23PilotExecutionGroup{
                row.rowId,
                false,
                row.risk,
                row.hypothesis,
                {{row.rowId,
                  row.calibrationCase,
                  row.role,
                  row.probeKind,
                  row.inputBytes,
                  row.iterationsPerRun,
                  row.runs,
                  row.samplingIntervalMilliseconds,
                  row.repetition,
                  row.order}}};
        }
    }

    for (const auto& shape : m23PilotBatchShapes()) {
        if (shape.batchId != groupId
            || shape.status != M23PilotPlanStatus::Candidate) {
            continue;
        }
        M23PilotExecutionGroup result{
            shape.batchId,
            true,
            shape.risk,
            shape.hypothesis,
            {}};
        result.entries.reserve(shape.entries.size());
        for (std::size_t index = 0; index < shape.entries.size(); ++index) {
            result.entries.push_back({
                shape.batchId + "-entry-" + std::to_string(index + 1),
                shape.entries[index],
                M23PilotRole::BatchShape,
                M23PilotProbeKind::BatchEntryCount,
                shape.inputBytes,
                shape.iterationsPerRun,
                shape.runs,
                shape.samplingIntervalMilliseconds,
                1,
                static_cast<std::uint32_t>(index + 1)});
        }
        return result;
    }
    return std::nullopt;
}

std::optional<M23PilotApprovedPlan> validateApprovedM23PilotPlan(
    const QJsonObject& document,
    bool allowSyntheticTestApproval)
{
    constexpr std::array<std::string_view, 7> expectedKeys{
        "format",
        "schemaVersion",
        "candidatePlanSha256",
        "approvalStatus",
        "approvalReference",
        "approvedAtUtc",
        "plan"};
    if (document.size() != static_cast<qsizetype>(expectedKeys.size())
        || !std::ranges::all_of(expectedKeys, [&](std::string_view key) {
            return document.contains(qString(key));
        })
        || document.value(QStringLiteral("format"))
            != QString::fromLatin1(kApprovedPlanFormat)
        || document.value(QStringLiteral("schemaVersion")).toInt(-1) != 1
        || document.value(QStringLiteral("approvalStatus"))
            != QStringLiteral("GO")
        || !document.value(QStringLiteral("plan")).isObject()) {
        return std::nullopt;
    }

    const auto candidateHash =
        document.value(QStringLiteral("candidatePlanSha256")).toString().toLatin1();
    if (candidateHash != m23PilotPlanSha256()) {
        return std::nullopt;
    }
    const auto expectedPlan = QJsonDocument::fromJson(m23PilotPlanManifest()).object();
    if (document.value(QStringLiteral("plan")).toObject() != expectedPlan) {
        return std::nullopt;
    }
    const auto reference =
        document.value(QStringLiteral("approvalReference")).toString().trimmed();
    if (reference.isEmpty()
        || (!allowSyntheticTestApproval
            && reference.startsWith(QStringLiteral("SYNTHETIC")))) {
        return std::nullopt;
    }
    const auto approvedAt =
        document.value(QStringLiteral("approvedAtUtc")).toString();
    const auto timestamp = QDateTime::fromString(approvedAt, Qt::ISODateWithMs);
    if (!timestamp.isValid() || !approvedAt.endsWith(QLatin1Char('Z'))) {
        return std::nullopt;
    }
    return M23PilotApprovedPlan{
        reference.toStdString(),
        approvedAt.toStdString(),
        QCryptographicHash::hash(
            QJsonDocument(document).toJson(QJsonDocument::Compact),
            QCryptographicHash::Sha256).toHex()};
}

QJsonObject syntheticApprovedM23PilotPlanForTests()
{
    const auto candidate = QJsonDocument::fromJson(m23PilotPlanManifest()).object();
    return {
        {"approvalReference", QStringLiteral("SYNTHETIC-TEST-ONLY")},
        {"approvalStatus", QStringLiteral("GO")},
        {"approvedAtUtc", QStringLiteral("2026-10-29T00:00:00.000Z")},
        {"candidatePlanSha256", QString::fromLatin1(m23PilotPlanSha256())},
        {"format", QString::fromLatin1(kApprovedPlanFormat)},
        {"plan", candidate},
        {"schemaVersion", 1}};
}

std::string toStableString(M23PilotRole role)
{
    switch (role) {
    case M23PilotRole::Reference: return "reference";
    case M23PilotRole::Holdout: return "holdout";
    case M23PilotRole::Sensitivity: return "sensitivity";
    case M23PilotRole::BatchShape: return "batchShape";
    }
    throw std::invalid_argument("unknown M23 pilot role");
}

std::string toStableString(M23PilotProbeKind probeKind)
{
    switch (probeKind) {
    case M23PilotProbeKind::WorkloadSize: return "workloadSize";
    case M23PilotProbeKind::IterationScaling: return "iterationScaling";
    case M23PilotProbeKind::RunCountSensitivity: return "runCountSensitivity";
    case M23PilotProbeKind::SamplingSensitivity: return "samplingSensitivity";
    case M23PilotProbeKind::BatchEntryCount: return "batchEntryCount";
    }
    throw std::invalid_argument("unknown M23 pilot probe kind");
}

std::string toStableString(M23PilotRiskClass risk)
{
    switch (risk) {
    case M23PilotRiskClass::Low: return "low";
    case M23PilotRiskClass::Moderate: return "moderate";
    case M23PilotRiskClass::High: return "high";
    }
    throw std::invalid_argument("unknown M23 pilot risk class");
}

std::string toStableString(M23PilotPlanStatus status)
{
    switch (status) {
    case M23PilotPlanStatus::Candidate: return "candidate";
    case M23PilotPlanStatus::Deferred: return "deferred";
    }
    throw std::invalid_argument("unknown M23 pilot plan status");
}

} // namespace cryptobench::tests
