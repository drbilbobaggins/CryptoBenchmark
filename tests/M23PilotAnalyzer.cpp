#include "M23PilotAnalyzer.h"

#include "M23PilotPlan.h"

#include <cryptobench/application/RuntimeCalibrationInventory.h>

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

namespace application = cryptobench::application;

constexpr std::uint64_t kMaxPilotObservationNanoseconds =
    static_cast<std::uint64_t>(kM23PilotMaximumObservationSeconds)
    * 1'000'000'000ULL;
constexpr double kPilotHoldoutScreenFactor = 5.0;

class EvidenceError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void reject(const std::string& message)
{
    throw EvidenceError(message);
}

void require(bool condition, std::string_view message)
{
    if (!condition) {
        reject(std::string(message));
    }
}

QString qString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

template <std::size_t N>
bool hasExactKeys(
    const QJsonObject& object,
    const std::array<std::string_view, N>& names)
{
    if (object.size() != static_cast<qsizetype>(N)) {
        return false;
    }
    return std::ranges::all_of(names, [&](std::string_view name) {
        return object.contains(qString(name));
    });
}

std::string requiredString(const QJsonObject& object, const char* field)
{
    const auto value = object.value(QLatin1String(field));
    if (!value.isString() || value.toString().isEmpty()) {
        reject(std::string("missing or empty evidence string: ") + field);
    }
    return value.toString().toStdString();
}

std::uint64_t parseUnsignedString(
    const QJsonObject& object,
    const char* field,
    bool allowZero)
{
    const auto text = requiredString(object, field);
    if (text.size() > 1 && text.front() == '0') {
        reject(std::string("noncanonical evidence integer: ") + field);
    }
    std::uint64_t result = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size()
        || (!allowZero && result == 0)) {
        reject(std::string("malformed or overflowing evidence integer: ") + field);
    }
    return result;
}

int parseSmallInteger(const QJsonObject& object, const char* field)
{
    const auto value = object.value(QLatin1String(field));
    if (!value.isDouble()) {
        reject(std::string("evidence field is not a JSON integer: ") + field);
    }
    const auto result = value.toInt(-1);
    if (result < 0 || static_cast<double>(result) != value.toDouble()) {
        reject(std::string("evidence field is not an exact small integer: ") + field);
    }
    return result;
}

bool validLowerSha256(std::string_view digest)
{
    return digest.size() == 64
        && std::ranges::all_of(digest, [](char value) {
            return (value >= '0' && value <= '9')
                || (value >= 'a' && value <= 'f');
        });
}

QByteArray sha256(const QByteArray& bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
}

QJsonObject intervalObject(
    std::string_view kind,
    std::uint64_t start,
    std::uint64_t end)
{
    return {
        {"endOffsetNanoseconds", QString::number(end)},
        {"kind", qString(kind)},
        {"startOffsetNanoseconds", QString::number(start)}};
}

QJsonArray stringsArray(const std::vector<std::string>& values)
{
    QJsonArray result;
    for (const auto& value : values) {
        result.append(qString(value));
    }
    return result;
}

bool validUtcTimestamp(const QString& text)
{
    return text.endsWith(QLatin1Char('Z'))
        && QDateTime::fromString(text, Qt::ISODateWithMs).isValid();
}

std::uint64_t checkedAdd(std::uint64_t left, std::uint64_t right)
{
    if (left > std::numeric_limits<std::uint64_t>::max() - right) {
        reject("pilot evidence duration sum overflowed");
    }
    return left + right;
}

double mean(const std::vector<double>& values)
{
    if (values.empty()) {
        return 0.0;
    }
    long double sum = 0;
    for (const auto value : values) {
        sum += value;
    }
    return static_cast<double>(sum / static_cast<long double>(values.size()));
}

struct Sample {
    std::string rowId;
    std::string caseId;
    std::string groupId;
    M23PilotRole role;
    M23PilotProbeKind probeKind;
    std::optional<std::uint64_t> inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingMilliseconds;
    std::uint64_t measuredBlockNanoseconds;
    std::uint64_t controllerElapsedNanoseconds;
};

struct BatchObservation {
    std::string groupId;
    std::uint32_t entryCount;
    std::uint64_t batchOnlyNanoseconds;
};

struct ParsedPilotFile {
    bool synthetic;
    std::string applicationSha256;
    std::string workerSha256;
    std::string environmentSha256;
    std::string approvedPlanSha256;
    std::string approvalReference;
    std::vector<Sample> samples;
    BatchObservation batch;
    std::uint64_t availableDiskBytes;
    std::uint64_t availableMemoryBytes;
    std::uint64_t maximumInputBytes;
    std::uint64_t maximumRunNanoseconds;
};

struct ParsedGroup {
    std::vector<Sample> samples;
    std::vector<BatchObservation> batches;
    std::uint64_t maximumInputBytes = 0;
    std::uint64_t maximumRunNanoseconds = 0;
    std::uint32_t maximumRuns = 0;
    std::uint32_t maximumEntries = 0;
    std::uint64_t minimumAvailableDiskBytes =
        std::numeric_limits<std::uint64_t>::max();
    std::uint64_t minimumAvailableMemoryBytes =
        std::numeric_limits<std::uint64_t>::max();
};

M23PilotRole parseRole(std::string_view value)
{
    for (const auto role : {
             M23PilotRole::Reference,
             M23PilotRole::Holdout,
             M23PilotRole::Sensitivity,
             M23PilotRole::BatchShape}) {
        if (toStableString(role) == value) {
            return role;
        }
    }
    reject("pilot evidence contains an unknown data role");
}

M23PilotProbeKind parseProbeKind(std::string_view value)
{
    for (const auto probe : {
             M23PilotProbeKind::WorkloadSize,
             M23PilotProbeKind::IterationScaling,
             M23PilotProbeKind::RunCountSensitivity,
             M23PilotProbeKind::SamplingSensitivity,
             M23PilotProbeKind::BatchEntryCount}) {
        if (toStableString(probe) == value) {
            return probe;
        }
    }
    reject("pilot evidence contains an unknown probe kind");
}

std::optional<std::uint64_t> optionalInputSize(const QJsonValue& value)
{
    if (value.isNull()) {
        return std::nullopt;
    }
    if (!value.isString()) {
        reject("pilot input bytes must be a decimal string or null");
    }
    const auto text = value.toString().toStdString();
    if (text.size() > 1 && text.front() == '0') {
        reject("pilot input bytes are not canonical decimal");
    }
    std::uint64_t result = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size()) {
        reject("pilot input bytes are malformed or overflowing");
    }
    return result;
}

bool sameOptionalSize(
    std::optional<std::uint64_t> left,
    std::optional<std::uint64_t> right)
{
    return left == right;
}

struct LinearFit {
    bool valid = false;
    double intercept = 0.0;
    double slope = 0.0;
    double rmsResidual = 0.0;
};

LinearFit fitLine(const std::vector<std::pair<double, double>>& points)
{
    if (points.size() < 2) {
        return {};
    }
    long double meanX = 0;
    long double meanY = 0;
    for (const auto& [x, y] : points) {
        meanX += x;
        meanY += y;
    }
    meanX /= static_cast<long double>(points.size());
    meanY /= static_cast<long double>(points.size());

    long double covariance = 0;
    long double variance = 0;
    for (const auto& [x, y] : points) {
        const auto dx = static_cast<long double>(x) - meanX;
        covariance += dx * (static_cast<long double>(y) - meanY);
        variance += dx * dx;
    }
    if (variance == 0) {
        return {};
    }
    const auto slope = covariance / variance;
    const auto intercept = meanY - slope * meanX;
    if (!std::isfinite(static_cast<double>(slope))
        || !std::isfinite(static_cast<double>(intercept))) {
        return {};
    }
    long double squaredError = 0;
    for (const auto& [x, y] : points) {
        const auto error =
            static_cast<long double>(y) - (intercept + slope * x);
        squaredError += error * error;
    }
    return {
        true,
        static_cast<double>(intercept),
        static_cast<double>(slope),
        std::sqrt(static_cast<double>(
            squaredError / static_cast<long double>(points.size())))};
}

LinearFit fitBatchLinear(
    const std::vector<std::pair<double, double>>& points)
{
    return fitLine(points);
}

struct PilotGroupData {
    std::vector<Sample> samples;
    std::vector<BatchObservation> batches;
    std::vector<std::string> inputDigests;
    std::string applicationSha256;
    std::string workerSha256;
    std::string environmentSha256;
    std::string approvedPlanSha256;
    std::string approvalReference;
    bool synthetic = false;
    std::uint64_t maximumInputBytes = 0;
    std::uint64_t maximumRunNanoseconds = 0;
};

ParsedPilotFile parseAndValidateFile(
    const QJsonObject& root,
    bool allowSyntheticTestFixtures,
    std::set<std::string>& workerIdentities)
{
    constexpr std::array<std::string_view, 17> rootKeys{
        "format",
        "schemaVersion",
        "evidenceKind",
        "status",
        "candidatePlanSha256",
        "approvedPlanSha256",
        "approvalReference",
        "applicationSha256",
        "workerSha256",
        "environmentSha256",
        "environment",
        "groupId",
        "entries",
        "batch",
        "startedAtUtc",
        "completedAtUtc",
        "resourcePreflight"
    };
    if (!hasExactKeys(root, rootKeys)
        || root.value(QStringLiteral("format"))
            != QStringLiteral("cryptobenchmark-m23-pilot-evidence")
        || parseSmallInteger(root, "schemaVersion") != 1
        || root.value(QStringLiteral("status")) != QStringLiteral("completed")) {
        reject("pilot evidence has an invalid schema or incomplete status");
    }

    const auto evidenceKind = requiredString(root, "evidenceKind");
    const auto synthetic = evidenceKind == "syntheticTestFixture";
    if ((!synthetic && evidenceKind != "realPilotObservation")
        || (synthetic && !allowSyntheticTestFixtures)) {
        reject("pilot evidence kind is not permitted for this analysis");
    }
    if (root.value(QStringLiteral("candidatePlanSha256")).toString().toLatin1()
        != m23PilotPlanSha256()) {
        reject("pilot evidence references a different candidate plan");
    }

    const auto applicationHash = requiredString(root, "applicationSha256");
    const auto workerHash = requiredString(root, "workerSha256");
    const auto environmentHash = requiredString(root, "environmentSha256");
    const auto approvedPlanHash = requiredString(root, "approvedPlanSha256");
    if (!validLowerSha256(applicationHash)
        || !validLowerSha256(workerHash)
        || !validLowerSha256(environmentHash)
        || !validLowerSha256(approvedPlanHash)) {
        reject("pilot evidence contains malformed provenance hashes");
    }
    const auto approvalReference = requiredString(root, "approvalReference");
    const auto hasSyntheticApprovalReference =
        approvalReference.starts_with("SYNTHETIC");
    if (approvalReference.empty()
        || (synthetic && !hasSyntheticApprovalReference)
        || (!synthetic && hasSyntheticApprovalReference)) {
        reject("pilot evidence approval provenance is invalid");
    }
    const auto environment = root.value(QStringLiteral("environment")).toObject();
    if (environment.isEmpty()
        || sha256(QJsonDocument(environment).toJson(QJsonDocument::Compact))
            != QByteArray::fromStdString(environmentHash)) {
        reject("pilot evidence environment checksum is invalid");
    }

    const auto startedAt = root.value(QStringLiteral("startedAtUtc")).toString();
    const auto completedAt = root.value(QStringLiteral("completedAtUtc")).toString();
    if (!validUtcTimestamp(startedAt) || !validUtcTimestamp(completedAt)
        || QDateTime::fromString(completedAt, Qt::ISODateWithMs)
            < QDateTime::fromString(startedAt, Qt::ISODateWithMs)) {
        reject("pilot evidence timestamps are invalid");
    }
    const auto preflight = root.value(QStringLiteral("resourcePreflight")).toObject();
    constexpr std::array<std::string_view, 5> preflightKeys{
        "availableDiskBytes",
        "availablePhysicalMemoryBytes",
        "maximumObservationSeconds",
        "minimumAvailableMemoryBytes",
        "minimumFreeDiskBytes"};
    if (!hasExactKeys(preflight, preflightKeys)) {
        reject("pilot resource feasibility preflight is malformed");
    }
    const auto availableDisk =
        parseUnsignedString(preflight, "availableDiskBytes", false);
    const auto availableMemory =
        parseUnsignedString(preflight, "availablePhysicalMemoryBytes", false);
    if (availableDisk < kM23PilotMinimumFreeDiskBytes
        || availableMemory < kM23PilotMinimumAvailableMemoryBytes
        || parseSmallInteger(preflight, "maximumObservationSeconds")
            != static_cast<int>(kM23PilotMaximumObservationSeconds)
        || parseUnsignedString(preflight, "minimumFreeDiskBytes", false)
            != kM23PilotMinimumFreeDiskBytes
        || parseUnsignedString(preflight, "minimumAvailableMemoryBytes", false)
            != kM23PilotMinimumAvailableMemoryBytes) {
        reject("pilot resource feasibility preflight did not meet its caps");
    }

    const auto groupId = requiredString(root, "groupId");
    const auto planGroup = m23PilotExecutionGroup(groupId);
    if (!planGroup) {
        reject("pilot evidence references an unplanned or deferred group");
    }
    const auto entryValues = root.value(QStringLiteral("entries"));
    if (!entryValues.isArray()) {
        reject("pilot evidence entries are missing");
    }
    const auto entryArray = entryValues.toArray();
    if (entryArray.size()
        != static_cast<qsizetype>(planGroup->entries.size())) {
        reject("pilot evidence entry count differs from the reviewed plan");
    }

    ParsedPilotFile parsed{
        synthetic,
        applicationHash,
        workerHash,
        environmentHash,
        approvedPlanHash,
        approvalReference,
        {},
        {},
        availableDisk,
        availableMemory,
        0,
        0};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> entryOffsets;
    std::uint64_t sumEntryElapsed = 0;
    for (qsizetype index = 0; index < entryArray.size(); ++index) {
        if (!entryArray[index].isObject()) {
            reject("pilot evidence entry is not an object");
        }
        const auto entry = entryArray[index].toObject();
        constexpr std::array<std::string_view, 15> entryKeys{
            "rowId",
            "caseId",
            "role",
            "probeKind",
            "inputBytes",
            "iterationsPerRun",
            "runs",
            "samplingIntervalMilliseconds",
            "repetition",
            "order",
            "entryStartOffsetNanoseconds",
            "entryEndOffsetNanoseconds",
            "entryElapsedNanoseconds",
            "entryOutsideRunNanoseconds",
            "runObservations"
        };
        if (!hasExactKeys(entry, entryKeys)) {
            reject("pilot evidence entry has missing or unknown fields");
        }
        const auto& expected = planGroup->entries[static_cast<std::size_t>(index)];
        const auto rowId = requiredString(entry, "rowId");
        const auto caseId = requiredString(entry, "caseId");
        if (rowId != expected.rowId
            || caseId != application::runtimeCalibrationCaseId(expected.calibrationCase)
            || parseRole(requiredString(entry, "role")) != expected.role
            || parseProbeKind(requiredString(entry, "probeKind"))
                != expected.probeKind
            || !sameOptionalSize(
                optionalInputSize(entry.value(QStringLiteral("inputBytes"))),
                expected.inputBytes)
            || parseUnsignedString(entry, "iterationsPerRun", false)
                != expected.iterationsPerRun
            || parseSmallInteger(entry, "runs") != expected.runs
            || parseSmallInteger(entry, "samplingIntervalMilliseconds")
                != expected.samplingIntervalMilliseconds
            || parseSmallInteger(entry, "repetition") != expected.repetition
            || parseSmallInteger(entry, "order") != expected.order) {
            reject("pilot evidence entry does not exactly match its canonical plan row");
        }

        const auto entryStart =
            parseUnsignedString(entry, "entryStartOffsetNanoseconds", true);
        const auto entryEnd =
            parseUnsignedString(entry, "entryEndOffsetNanoseconds", false);
        const auto entryElapsed =
            parseUnsignedString(entry, "entryElapsedNanoseconds", false);
        const auto entryOutside =
            parseUnsignedString(entry, "entryOutsideRunNanoseconds", true);
        if (entryEnd <= entryStart || entryElapsed != entryEnd - entryStart) {
            reject("pilot entry interval does not match its elapsed value");
        }
        const auto runValue = entry.value(QStringLiteral("runObservations"));
        if (!runValue.isArray() || runValue.toArray().size() != expected.runs) {
            reject("pilot entry does not contain exactly M run observations");
        }
        const auto runs = runValue.toArray();
        std::uint64_t sumRunElapsed = 0;
        for (qsizetype runIndex = 0; runIndex < runs.size(); ++runIndex) {
            if (!runs[runIndex].isObject()) {
                reject("pilot run observation is not an object");
            }
            const auto run = runs[runIndex].toObject();
            constexpr std::array<std::string_view, 5> runKeys{
                "runIndex",
                "measuredBlockNanoseconds",
                "controllerElapsedNanoseconds",
                "workerPid",
                "workerCreationTime100ns"
            };
            if (!hasExactKeys(run, runKeys)
                || parseSmallInteger(run, "runIndex") != runIndex) {
                reject("pilot run observation has an invalid shape or order");
            }
            const auto measured =
                parseUnsignedString(run, "measuredBlockNanoseconds", true);
            const auto controller =
                parseUnsignedString(run, "controllerElapsedNanoseconds", false);
            const auto pid = parseUnsignedString(run, "workerPid", false);
            const auto creation =
                parseUnsignedString(run, "workerCreationTime100ns", false);
            if (controller < measured
                || pid > std::numeric_limits<std::uint32_t>::max()) {
                reject("pilot run timing or worker identity is invalid");
            }
            if (!workerIdentities.emplace(
                    std::to_string(pid) + "/" + std::to_string(creation)).second) {
                reject("pilot evidence reuses a fresh-worker identity");
            }
            sumRunElapsed = checkedAdd(sumRunElapsed, controller);
            parsed.maximumRunNanoseconds =
                std::max(parsed.maximumRunNanoseconds, controller);
            parsed.samples.push_back({
                rowId,
                caseId,
                groupId,
                expected.role,
                expected.probeKind,
                expected.inputBytes,
                expected.iterationsPerRun,
                expected.runs,
                expected.samplingIntervalMilliseconds,
                measured,
                controller});
        }
        if (sumRunElapsed > entryElapsed
            || entryOutside != entryElapsed - sumRunElapsed) {
            reject("pilot entry/run timing does not conserve");
        }
        entryOffsets.emplace_back(entryStart, entryEnd);
        sumEntryElapsed = checkedAdd(sumEntryElapsed, entryElapsed);
        if (expected.inputBytes) {
            parsed.maximumInputBytes =
                std::max(parsed.maximumInputBytes, *expected.inputBytes);
        }
    }

    const auto batchValue = root.value(QStringLiteral("batch"));
    if (!batchValue.isObject()) {
        reject("pilot batch timing evidence is missing");
    }
    const auto batch = batchValue.toObject();
    constexpr std::array<std::string_view, 7> batchKeys{
        "groupId",
        "status",
        "entryCount",
        "batchElapsedNanoseconds",
        "batchOnlyNanoseconds",
        "batchOnlyIntervals",
        "checkpointIntervals"
    };
    if (!hasExactKeys(batch, batchKeys)
        || requiredString(batch, "groupId") != groupId
        || requiredString(batch, "status") != "completed"
        || parseSmallInteger(batch, "entryCount") != entryArray.size()) {
        reject("pilot Batch evidence has an invalid group or status");
    }
    const auto batchElapsed =
        parseUnsignedString(batch, "batchElapsedNanoseconds", false);
    const auto batchOnly =
        parseUnsignedString(batch, "batchOnlyNanoseconds", true);
    if (batchElapsed
        > static_cast<std::uint64_t>(kM23PilotMaximumObservationSeconds)
            * 1'000'000'000ULL) {
        reject("pilot Batch exceeds its maximum observation wall-time cap");
    }
    const auto batchOnlyIntervals =
        batch.value(QStringLiteral("batchOnlyIntervals")).toArray();
    const auto checkpoints =
        batch.value(QStringLiteral("checkpointIntervals")).toArray();
    const auto entryCount = static_cast<std::size_t>(entryOffsets.size());
    if (entryCount > kM23PilotMaximumBatchEntries) {
        reject("pilot Batch exceeds its maximum executable entry count");
    }
    if (batchOnlyIntervals.size()
            != static_cast<qsizetype>(entryCount + 1)
        || checkpoints.size() != static_cast<qsizetype>(entryCount + 1)) {
        reject("pilot Batch evidence lacks a complete disjoint interval sequence");
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> expectedGaps;
    std::uint64_t previousEntryEnd = 0;
    std::uint64_t sumEntryIntervals = 0;
    for (const auto& [entryStart, entryEnd] : entryOffsets) {
        if (entryStart < previousEntryEnd) {
            reject("pilot entry intervals overlap or are out of order");
        }
        expectedGaps.emplace_back(previousEntryEnd, entryStart);
        sumEntryIntervals = checkedAdd(
            sumEntryIntervals, entryEnd - entryStart);
        previousEntryEnd = entryEnd;
    }
    if (previousEntryEnd > batchElapsed) {
        reject("pilot entry interval extends beyond the Batch timer");
    }
    expectedGaps.emplace_back(previousEntryEnd, batchElapsed);

    std::uint64_t summedBatchOnly = 0;
    for (qsizetype index = 0; index < batchOnlyIntervals.size(); ++index) {
        if (!batchOnlyIntervals[index].isObject()) {
            reject("pilot Batch-only interval is not an object");
        }
        const auto interval = batchOnlyIntervals[index].toObject();
        constexpr std::array<std::string_view, 3> intervalKeys{
            "kind", "startOffsetNanoseconds", "endOffsetNanoseconds"};
        if (!hasExactKeys(interval, intervalKeys)) {
            reject("pilot Batch-only interval has missing or unknown fields");
        }
        const auto start =
            parseUnsignedString(interval, "startOffsetNanoseconds", true);
        const auto end =
            parseUnsignedString(interval, "endOffsetNanoseconds", true);
        const auto [expectedStart, expectedEnd] =
            expectedGaps[static_cast<std::size_t>(index)];
        if (start != expectedStart || end != expectedEnd || end < start) {
            reject("pilot Batch-only intervals are not the complement of entry intervals");
        }
        const auto expectedKind = index == 0
            ? std::string{"beforeEntries"}
            : index == entryCount
                ? std::string{"afterEntries"}
                : std::string{"betweenEntries-"} + std::to_string(index)
                    + "-" + std::to_string(index + 1);
        if (requiredString(interval, "kind") != expectedKind) {
            reject("pilot Batch-only interval kind is invalid");
        }
        summedBatchOnly = checkedAdd(summedBatchOnly, end - start);
    }
    if (summedBatchOnly != batchOnly
        || checkedAdd(sumEntryIntervals, batchOnly) != batchElapsed) {
        reject("pilot Batch conservation identity does not hold");
    }

    std::uint64_t checkpointSum = 0;
    std::uint64_t previousCheckpointEnd = 0;
    for (qsizetype index = 0; index < checkpoints.size(); ++index) {
        if (!checkpoints[index].isObject()) {
            reject("pilot checkpoint interval is not an object");
        }
        const auto checkpoint = checkpoints[index].toObject();
        constexpr std::array<std::string_view, 3> checkpointKeys{
            "kind", "startOffsetNanoseconds", "endOffsetNanoseconds"};
        if (!hasExactKeys(checkpoint, checkpointKeys)) {
            reject("pilot checkpoint interval has missing or unknown fields");
        }
        const auto start =
            parseUnsignedString(checkpoint, "startOffsetNanoseconds", true);
        const auto end =
            parseUnsignedString(checkpoint, "endOffsetNanoseconds", true);
        const auto [gapStart, gapEnd] =
            expectedGaps[static_cast<std::size_t>(index)];
        const auto expectedKind = index == 0
            ? std::string{"initial"}
            : index == entryCount
                ? std::string{"final"}
                : std::string{"entryCheckpoint-"} + std::to_string(index);
        if (requiredString(checkpoint, "kind") != expectedKind
            || start < gapStart || end > gapEnd || end < start
            || (index > 0 && start < previousCheckpointEnd)) {
            reject("pilot checkpoint is not inside its disjoint Batch-only interval");
        }
        previousCheckpointEnd = end;
        checkpointSum = checkedAdd(checkpointSum, end - start);
    }
    if (checkpointSum > batchOnly) {
        reject("pilot checkpoint diagnostics exceed Batch-only overhead");
    }

    return {
        synthetic,
        requiredString(root, "applicationSha256"),
        requiredString(root, "workerSha256"),
        requiredString(root, "environmentSha256"),
        requiredString(root, "approvedPlanSha256"),
        requiredString(root, "approvalReference"),
        std::move(parsed.samples),
        {groupId, static_cast<std::uint32_t>(entryCount), batchOnly},
        parsed.availableDiskBytes,
        parsed.availableMemoryBytes,
        parsed.maximumInputBytes,
        parsed.maximumRunNanoseconds};
}

std::optional<LinearFit> fitAffineForCase(
    const std::vector<Sample>& samples,
    std::string_view caseId)
{
    std::vector<std::pair<double, double>> points;
    std::set<std::uint64_t> sizes;
    for (const auto& sample : samples) {
        if (sample.caseId == caseId
            && sample.role == M23PilotRole::Reference
            && sample.probeKind == M23PilotProbeKind::WorkloadSize
            && sample.samplingMilliseconds == 5
            && sample.inputBytes.has_value()) {
            sizes.emplace(*sample.inputBytes);
            points.emplace_back(
                static_cast<double>(*sample.inputBytes),
                static_cast<double>(sample.measuredBlockNanoseconds)
                    / static_cast<double>(sample.iterationsPerRun));
        }
    }
    if (sizes.size() < 2) {
        return std::nullopt;
    }
    const auto fit = fitLine(points);
    return fit.valid && fit.intercept >= 0.0 && fit.slope >= 0.0
        ? std::optional<LinearFit>{fit}
        : std::nullopt;
}

std::vector<std::string> rowsFor(
    const std::vector<Sample>& samples,
    std::string_view caseId,
    M23PilotRole role,
    M23PilotProbeKind probe)
{
    std::set<std::string> ids;
    for (const auto& sample : samples) {
        if (sample.caseId == caseId && sample.role == role
            && sample.probeKind == probe) {
            ids.emplace(sample.rowId);
        }
    }
    return {ids.begin(), ids.end()};
}

std::optional<double> baselinePerIteration(
    const std::vector<Sample>& samples,
    const Sample& target)
{
    const auto expectedProbe = target.inputBytes
        ? M23PilotProbeKind::WorkloadSize
        : M23PilotProbeKind::IterationScaling;
    std::vector<double> rates;
    for (const auto& sample : samples) {
        if (sample.caseId == target.caseId
            && sample.role == M23PilotRole::Reference
            && sample.probeKind == expectedProbe
            && sample.inputBytes == target.inputBytes
            && sample.samplingMilliseconds == target.samplingMilliseconds) {
            rates.push_back(
                static_cast<double>(sample.measuredBlockNanoseconds)
                / static_cast<double>(sample.iterationsPerRun));
        }
    }
    if (rates.empty()) {
        return std::nullopt;
    }
    return mean(rates);
}

struct QuadraticFit {
    bool valid = false;
    double constant = 0.0;
    double perEntry = 0.0;
    double triangular = 0.0;
    double rmsResidual = 0.0;
};

QuadraticFit fitTriangularBatchModel(
    const std::vector<std::pair<double, double>>& points)
{
    std::set<double> distinctEntries;
    for (const auto& [entries, value] : points) {
        static_cast<void>(value);
        distinctEntries.emplace(entries);
    }
    if (distinctEntries.size() < 3) {
        return {};
    }

    long double matrix[3][4]{};
    for (const auto& [entries, value] : points) {
        const long double e = entries;
        const long double x[3]{1.0L, e, e * (e + 1.0L) / 2.0L};
        for (int row = 0; row < 3; ++row) {
            for (int column = 0; column < 3; ++column) {
                matrix[row][column] += x[row] * x[column];
            }
            matrix[row][3] += x[row] * static_cast<long double>(value);
        }
    }

    for (int pivot = 0; pivot < 3; ++pivot) {
        int best = pivot;
        for (int row = pivot + 1; row < 3; ++row) {
            if (std::abs(matrix[row][pivot]) > std::abs(matrix[best][pivot])) {
                best = row;
            }
        }
        if (std::abs(matrix[best][pivot]) < 1e-18L) {
            return {};
        }
        if (best != pivot) {
            for (int column = pivot; column < 4; ++column) {
                std::swap(matrix[pivot][column], matrix[best][column]);
            }
        }
        const auto divisor = matrix[pivot][pivot];
        for (int column = pivot; column < 4; ++column) {
            matrix[pivot][column] /= divisor;
        }
        for (int row = 0; row < 3; ++row) {
            if (row == pivot) continue;
            const auto factor = matrix[row][pivot];
            for (int column = pivot; column < 4; ++column) {
                matrix[row][column] -= factor * matrix[pivot][column];
            }
        }
    }

    long double squaredError = 0;
    for (const auto& [entries, value] : points) {
        const long double e = entries;
        const auto predicted = matrix[0][3] + matrix[1][3] * e
            + matrix[2][3] * e * (e + 1.0L) / 2.0L;
        const auto error = static_cast<long double>(value) - predicted;
        squaredError += error * error;
    }
    return {
        true,
        static_cast<double>(matrix[0][3]),
        static_cast<double>(matrix[1][3]),
        static_cast<double>(matrix[2][3]),
        std::sqrt(static_cast<double>(
            squaredError / static_cast<long double>(points.size())))};
}

QJsonObject buildSyntheticEvidenceFile(
    const M23PilotExecutionGroup& group,
    std::uint64_t& nextPid,
    std::uint64_t& nextCreation)
{
    constexpr auto fakeSha =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const QJsonObject environment{
        {"applicationVersion", QStringLiteral("synthetic-test-only")},
        {"architecture", QStringLiteral("synthetic-x64")},
        {"buildType", QStringLiteral("Release")},
        {"compiler", QStringLiteral("synthetic compiler")},
        {"gitCommit", QString(40, QLatin1Char('0'))},
        {"gitDirty", false},
        {"logicalProcessorCount", 8},
        {"opensslBuildVersion", QStringLiteral("synthetic OpenSSL")},
        {"opensslRuntimeVersion", QStringLiteral("synthetic OpenSSL")},
        {"operatingSystem", QStringLiteral("synthetic Windows")},
        {"physicalMemoryBytes", QStringLiteral("8589934592")},
        {"powerPlan", QStringLiteral("synthetic power plan")},
        {"processor", QStringLiteral("synthetic CPU")},
        {"qtVersion", QStringLiteral("synthetic Qt")}};
    const auto environmentHash =
        sha256(QJsonDocument(environment).toJson(QJsonDocument::Compact));
    const QJsonObject resourcePreflight{
        {"availableDiskBytes", QStringLiteral("2147483648")},
        {"availablePhysicalMemoryBytes", QStringLiteral("4294967296")},
        {"maximumObservationSeconds",
            static_cast<qint64>(kM23PilotMaximumObservationSeconds)},
        {"minimumAvailableMemoryBytes",
            QString::number(kM23PilotMinimumAvailableMemoryBytes)},
        {"minimumFreeDiskBytes",
            QString::number(kM23PilotMinimumFreeDiskBytes)}};

    std::uint64_t batchOnly = 100;
    if (group.batchShape) {
        const auto entries = group.entries.size();
        batchOnly = 100 + 20 * entries + 10 * entries * (entries + 1) / 2;
    }
    const auto entryCount = group.entries.size();
    const std::uint64_t beforeEntries = 20;
    const auto betweenEntries = entryCount > 1
        ? std::uint64_t{10} * (entryCount - 1)
        : 0;
    require(batchOnly > beforeEntries + betweenEntries + 10,
        "synthetic Batch-only interval is too small for checkpoint fixtures");
    const auto afterEntries = batchOnly - beforeEntries - betweenEntries;
    const auto betweenEach = entryCount > 1
        ? std::uint64_t{10}
        : 0;

    QJsonArray entryArray;
    QJsonArray batchOnlyIntervals;
    QJsonArray checkpointIntervals;
    std::uint64_t sumEntryElapsed = 0;
    std::uint64_t previousEntryEnd = 0;
    for (std::size_t index = 0; index < entryCount; ++index) {
        const auto& planned = group.entries[index];
        std::uint64_t perIteration = 500;
        const auto caseId =
            application::runtimeCalibrationCaseId(planned.calibrationCase);
        if (caseId == "sha256/hash/hashXof") {
            perIteration = 10 + 2 * planned.inputBytes.value_or(0);
            if (planned.probeKind == M23PilotProbeKind::SamplingSensitivity) {
                perIteration +=
                    (5 - planned.samplingIntervalMilliseconds) * 100;
            }
        } else if (caseId == "x25519/derive/keyEstablishment") {
            perIteration = 100;
        }
        const auto measuredBlock =
            perIteration * planned.iterationsPerRun;
        std::uint64_t sumRunElapsed = 0;
        QJsonArray runs;
        for (std::uint32_t runIndex = 0;
             runIndex < planned.runs;
             ++runIndex) {
            const auto controllerElapsed = measuredBlock + 50;
            sumRunElapsed += controllerElapsed;
            runs.append(QJsonObject{
                {"controllerElapsedNanoseconds",
                    QString::number(controllerElapsed)},
                {"measuredBlockNanoseconds", QString::number(measuredBlock)},
                {"runIndex", static_cast<qint64>(runIndex)},
                {"workerCreationTime100ns", QString::number(nextCreation++)},
                {"workerPid", QString::number(nextPid++)}});
        }
        const auto entryElapsed = sumRunElapsed + 25;
        const auto entryStart = index == 0
            ? beforeEntries
            : previousEntryEnd + betweenEach;
        const auto entryEnd = entryStart + entryElapsed;
        previousEntryEnd = entryEnd;
        sumEntryElapsed = checkedAdd(sumEntryElapsed, entryElapsed);
        entryArray.append(QJsonObject{
            {"caseId", qString(caseId)},
            {"entryElapsedNanoseconds", QString::number(entryElapsed)},
            {"entryEndOffsetNanoseconds", QString::number(entryEnd)},
            {"entryOutsideRunNanoseconds", QStringLiteral("25")},
            {"entryStartOffsetNanoseconds", QString::number(entryStart)},
            {"inputBytes", planned.inputBytes
                ? QJsonValue(QString::number(*planned.inputBytes))
                : QJsonValue(QJsonValue::Null)},
            {"iterationsPerRun", QString::number(planned.iterationsPerRun)},
            {"order", static_cast<qint64>(planned.order)},
            {"probeKind", qString(toStableString(planned.probeKind))},
            {"repetition", static_cast<qint64>(planned.repetition)},
            {"role", qString(toStableString(planned.role))},
            {"rowId", qString(planned.rowId)},
            {"runObservations", runs},
            {"runs", static_cast<qint64>(planned.runs)},
            {"samplingIntervalMilliseconds",
                static_cast<qint64>(planned.samplingIntervalMilliseconds)}});
    }
    const auto batchElapsed = checkedAdd(sumEntryElapsed, batchOnly);

    std::uint64_t gapStart = 0;
    for (std::size_t index = 0; index < entryCount; ++index) {
        const auto entryStart =
            entryArray[index].toObject()
                .value(QStringLiteral("entryStartOffsetNanoseconds"))
                .toString().toULongLong();
        const auto entryEnd =
            entryArray[index].toObject()
                .value(QStringLiteral("entryEndOffsetNanoseconds"))
                .toString().toULongLong();
        const auto gapKind = index == 0
            ? std::string{"beforeEntries"}
            : std::string{"betweenEntries-"} + std::to_string(index)
                + "-" + std::to_string(index + 1);
        batchOnlyIntervals.append(intervalObject(gapKind, gapStart, entryStart));
        if (index == 0) {
            checkpointIntervals.append(intervalObject("initial", 2, 8));
        } else {
            const auto start = gapStart + 2;
            checkpointIntervals.append(intervalObject(
                "entryCheckpoint-" + std::to_string(index), start, start + 3));
        }
        gapStart = entryEnd;
    }
    batchOnlyIntervals.append(
        intervalObject("afterEntries", gapStart, batchElapsed));
    const auto finalCheckpointStart = gapStart + 2;
    checkpointIntervals.append(intervalObject(
        "final", finalCheckpointStart, finalCheckpointStart + 4));

    const auto batch = QJsonObject{
        {"batchElapsedNanoseconds", QString::number(batchElapsed)},
        {"batchOnlyIntervals", batchOnlyIntervals},
        {"batchOnlyNanoseconds", QString::number(batchOnly)},
        {"checkpointIntervals", checkpointIntervals},
        {"entryCount", static_cast<qint64>(entryCount)},
        {"groupId", qString(group.groupId)},
        {"status", QStringLiteral("completed")}};
    return {
        {"applicationSha256", QLatin1String(fakeSha)},
        {"approvalReference", QStringLiteral("SYNTHETIC TEST ONLY")},
        {"approvedPlanSha256", QLatin1String(fakeSha)},
        {"batch", batch},
        {"candidatePlanSha256", QString::fromLatin1(m23PilotPlanSha256())},
        {"completedAtUtc", QStringLiteral("2026-10-29T00:01:00.000Z")},
        {"entries", entryArray},
        {"environment", environment},
        {"environmentSha256", QString::fromLatin1(environmentHash)},
        {"evidenceKind", QStringLiteral("syntheticTestFixture")},
        {"format", QStringLiteral("cryptobenchmark-m23-pilot-evidence")},
        {"groupId", qString(group.groupId)},
        {"resourcePreflight", resourcePreflight},
        {"schemaVersion", 1},
        {"startedAtUtc", QStringLiteral("2026-10-29T00:00:00.000Z")},
        {"status", QStringLiteral("completed")},
        {"workerSha256", QLatin1String(fakeSha)}};
}

} // namespace

std::vector<QJsonObject> syntheticM23PilotEvidenceForTests()
{
    std::vector<QJsonObject> evidence;
    std::uint64_t nextPid = 5000;
    std::uint64_t nextCreation = 100000;
    const auto rows = m23PilotPlanRows();
    const auto addRow = [&](std::string_view caseId,
                            M23PilotRole role,
                            M23PilotProbeKind probe,
                            std::optional<std::uint64_t> size,
                            std::uint32_t sampling = 5) {
        const auto found = std::ranges::find_if(
            rows,
            [&](const M23PilotPlanRow& row) {
                return row.status == M23PilotPlanStatus::Candidate
                    && application::runtimeCalibrationCaseId(row.calibrationCase) == caseId
                    && row.role == role
                    && row.probeKind == probe
                    && row.inputBytes == size
                    && row.samplingIntervalMilliseconds == sampling
                    && row.repetition == 1;
            });
        if (found == rows.end()) {
            reject("synthetic M23 pilot evidence row is absent from the candidate plan");
        }
        const auto group = m23PilotExecutionGroup(found->rowId);
        if (!group) {
            reject("synthetic M23 pilot evidence group is not executable");
        }
        evidence.push_back(buildSyntheticEvidenceFile(
            *group, nextPid, nextCreation));
    };

    for (const auto size : {0ULL, 4'096ULL, 1'048'576ULL}) {
        addRow("sha256/hash/hashXof", M23PilotRole::Reference,
            M23PilotProbeKind::WorkloadSize, size);
    }
    for (const auto size : {1ULL, 65'536ULL}) {
        addRow("sha256/hash/hashXof", M23PilotRole::Holdout,
            M23PilotProbeKind::WorkloadSize, size);
    }
    addRow("x25519/derive/keyEstablishment",
        M23PilotRole::Reference,
        M23PilotProbeKind::IterationScaling,
        std::nullopt);
    addRow("x25519/derive/keyEstablishment",
        M23PilotRole::Holdout,
        M23PilotProbeKind::IterationScaling,
        std::nullopt);
    addRow("ed25519/sign/message",
        M23PilotRole::Reference,
        M23PilotProbeKind::WorkloadSize,
        4'096);
    addRow("ed25519/sign/message",
        M23PilotRole::Holdout,
        M23PilotProbeKind::IterationScaling,
        4'096);
    addRow("sha256/hash/hashXof",
        M23PilotRole::Sensitivity,
        M23PilotProbeKind::SamplingSensitivity,
        4'096,
        1);
    addRow("sha256/hash/hashXof",
        M23PilotRole::Sensitivity,
        M23PilotProbeKind::RunCountSensitivity,
        4'096);

    for (const auto& shape : m23PilotBatchShapes()) {
        if (shape.status != M23PilotPlanStatus::Candidate) {
            continue;
        }
        const auto group = m23PilotExecutionGroup(shape.batchId);
        if (!group) {
            reject("synthetic M23 pilot Batch shape is not executable");
        }
        evidence.push_back(buildSyntheticEvidenceFile(
            *group, nextPid, nextCreation));
    }
    return evidence;
}

QJsonObject analyzeM23PilotEvidence(
    const std::vector<QJsonObject>& evidenceFiles,
    bool allowSyntheticTestFixtures)
{
    if (evidenceFiles.empty()) {
        reject("no pilot evidence files were supplied");
    }
    std::set<std::string> workerIdentities;
    std::set<std::string> groupIds;
    ParsedGroup parsed;
    std::optional<ParsedPilotFile> provenance;
    for (const auto& root : evidenceFiles) {
        auto file = parseAndValidateFile(
            root, allowSyntheticTestFixtures, workerIdentities);
        if (!groupIds.emplace(file.batch.groupId).second) {
            reject("pilot evidence repeats an observation group");
        }
        if (provenance
            && (file.applicationSha256 != provenance->applicationSha256
                || file.workerSha256 != provenance->workerSha256
                || file.environmentSha256 != provenance->environmentSha256
                || file.approvedPlanSha256 != provenance->approvedPlanSha256
                || file.approvalReference != provenance->approvalReference
                || file.synthetic != provenance->synthetic)) {
            reject("pilot evidence combines incompatible provenance contexts");
        }
        if (!provenance) {
            provenance = file;
        }
        parsed.samples.insert(
            parsed.samples.end(),
            file.samples.begin(),
            file.samples.end());
        parsed.batches.push_back(file.batch);
        parsed.maximumInputBytes =
            std::max(parsed.maximumInputBytes, file.maximumInputBytes);
        parsed.maximumRunNanoseconds =
            std::max(parsed.maximumRunNanoseconds, file.maximumRunNanoseconds);
        parsed.maximumRuns = std::max(
            parsed.maximumRuns,
            file.samples.empty() ? 0U : file.samples.front().runs);
        parsed.maximumEntries = std::max(
            parsed.maximumEntries, file.batch.entryCount);
        parsed.minimumAvailableDiskBytes = std::min(
            parsed.minimumAvailableDiskBytes, file.availableDiskBytes);
        parsed.minimumAvailableMemoryBytes = std::min(
            parsed.minimumAvailableMemoryBytes, file.availableMemoryBytes);
    }

    const auto expectedRows = m23PilotPlanRows();
    std::set<std::string> observedCandidateRows;
    for (const auto& sample : parsed.samples) {
        if (sample.role != M23PilotRole::BatchShape) {
            observedCandidateRows.emplace(sample.rowId);
        }
    }
    std::size_t candidateRowCount = 0;
    for (const auto& row : expectedRows) {
        if (row.status == M23PilotPlanStatus::Candidate) {
            ++candidateRowCount;
        }
    }
    std::set<std::string> trainingRowIds;
    std::set<std::string> holdoutRowIds;
    for (const auto& sample : parsed.samples) {
        if (sample.role == M23PilotRole::Reference) {
            trainingRowIds.emplace(sample.rowId);
        } else if (sample.role == M23PilotRole::Holdout) {
            holdoutRowIds.emplace(sample.rowId);
        }
    }
    const auto fitHoldoutLeakage = std::ranges::any_of(
        trainingRowIds,
        [&](const std::string& rowId) { return holdoutRowIds.contains(rowId); });
    if (fitHoldoutLeakage) {
        reject("pilot evidence reuses a training row as an independent holdout");
    }

    QJsonArray modelReports;
    QJsonArray holdoutReports;
    std::set<std::string> cases;
    for (const auto& sample : parsed.samples) {
        if (sample.role != M23PilotRole::BatchShape) {
            cases.emplace(sample.caseId);
        }
    }
    double maximumHoldoutFactor = 0.0;
    std::size_t holdoutCount = 0;
    std::size_t factorOutlierCount = 0;
    const auto canonicalInventory =
        application::enumerateRuntimeCalibrationInventory();
    for (const auto& caseId : cases) {
        const auto foundCase = std::ranges::find_if(
            canonicalInventory.cases,
            [&](const application::RuntimeCalibrationCase& calibrationCase) {
                return application::runtimeCalibrationCaseId(calibrationCase) == caseId;
            });
        if (foundCase == canonicalInventory.cases.end()) {
            reject("pilot analyzer encountered an unknown canonical case");
        }
        QJsonObject report{
            {"caseId", qString(caseId)},
            {"fitRowIds", QJsonArray{}},
            {"modelStatus", QStringLiteral("INSUFFICIENT_SYNTHETIC_OR_PILOT_DATA")}};

        if (foundCase->hasVariableInputSize) {
            const auto fit = fitAffineForCase(parsed.samples, caseId);
            if (fit) {
                const auto fitIds = rowsFor(
                    parsed.samples,
                    caseId,
                    M23PilotRole::Reference,
                    M23PilotProbeKind::WorkloadSize);
                report.insert("fitRowIds", stringsArray(fitIds));
                report.insert("modelStatus", QStringLiteral("AFFINE_CANDIDATE"));
                report.insert("interceptNanosecondsPerOperation", fit->intercept);
                report.insert("slopeNanosecondsPerBytePerOperation", fit->slope);
                report.insert("trainingRmsResidualNanoseconds", fit->rmsResidual);
                report.insert("holdoutRowIds", stringsArray(rowsFor(
                    parsed.samples,
                    caseId,
                    M23PilotRole::Holdout,
                    M23PilotProbeKind::WorkloadSize)));

                for (const auto& sample : parsed.samples) {
                    if (sample.caseId != caseId
                        || sample.role != M23PilotRole::Holdout
                        || sample.probeKind != M23PilotProbeKind::WorkloadSize
                        || sample.samplingMilliseconds != 5
                        || !sample.inputBytes) {
                        continue;
                    }
                    const auto predicted = sample.iterationsPerRun
                        * (fit->intercept
                            + fit->slope
                                * static_cast<double>(*sample.inputBytes));
                    const auto actual =
                        static_cast<double>(sample.measuredBlockNanoseconds);
                    if (predicted <= 0.0 || actual <= 0.0) {
                        holdoutReports.append(QJsonObject{
                            {"caseId", qString(caseId)},
                            {"factor", QJsonValue(QJsonValue::Null)},
                            {"rowId", qString(sample.rowId)},
                            {"status", QStringLiteral("INVALID_ZERO_DURATION")}});
                        ++holdoutCount;
                        ++factorOutlierCount;
                        continue;
                    }
                    const auto factor = std::max(predicted / actual, actual / predicted);
                    maximumHoldoutFactor = std::max(maximumHoldoutFactor, factor);
                    ++holdoutCount;
                    if (factor > kPilotHoldoutScreenFactor) {
                        ++factorOutlierCount;
                    }
                    holdoutReports.append(QJsonObject{
                        {"caseId", qString(caseId)},
                        {"factor", factor},
                        {"inputBytes", QString::number(*sample.inputBytes)},
                        {"rowId", qString(sample.rowId)},
                        {"status", QStringLiteral("DIAGNOSTIC_ONLY")}});
                }
            }
        } else {
            std::vector<double> referenceRates;
            for (const auto& sample : parsed.samples) {
                if (sample.caseId == caseId
                    && sample.role == M23PilotRole::Reference
                    && sample.probeKind == M23PilotProbeKind::IterationScaling
                    && sample.samplingMilliseconds == 5) {
                    referenceRates.push_back(
                        static_cast<double>(sample.measuredBlockNanoseconds)
                        / static_cast<double>(sample.iterationsPerRun));
                }
            }
            if (!referenceRates.empty()) {
                const auto rate = mean(referenceRates);
                report.insert("modelStatus", QStringLiteral("EXACT_MODE_N_SCALING_CANDIDATE"));
                report.insert("nanosecondsPerIteration", rate);
                const auto holdoutIds = rowsFor(
                    parsed.samples,
                    caseId,
                    M23PilotRole::Holdout,
                    M23PilotProbeKind::IterationScaling);
                report.insert("holdoutRowIds", stringsArray(holdoutIds));
                report.insert("fitRowIds", stringsArray(rowsFor(
                    parsed.samples,
                    caseId,
                    M23PilotRole::Reference,
                    M23PilotProbeKind::IterationScaling)));
                for (const auto& sample : parsed.samples) {
                    if (sample.caseId != caseId
                        || sample.role != M23PilotRole::Holdout
                        || sample.probeKind != M23PilotProbeKind::IterationScaling
                        || sample.samplingMilliseconds != 5) {
                        continue;
                    }
                    const auto predicted = rate * sample.iterationsPerRun;
                    const auto actual = static_cast<double>(
                        sample.measuredBlockNanoseconds);
                    if (predicted <= 0.0 || actual <= 0.0) {
                        ++factorOutlierCount;
                        ++holdoutCount;
                        continue;
                    }
                    const auto factor = std::max(predicted / actual, actual / predicted);
                    maximumHoldoutFactor = std::max(maximumHoldoutFactor, factor);
                    ++holdoutCount;
                    if (factor > kPilotHoldoutScreenFactor) {
                        ++factorOutlierCount;
                    }
                    holdoutReports.append(QJsonObject{
                        {"caseId", qString(caseId)},
                        {"factor", factor},
                        {"iterationsPerRun",
                            QString::number(sample.iterationsPerRun)},
                        {"rowId", qString(sample.rowId)},
                        {"status", QStringLiteral("DIAGNOSTIC_ONLY")}});
                }
            }
        }
        modelReports.append(report);
    }

    QJsonArray nSensitivity;
    QJsonArray mSensitivity;
    QJsonArray samplingSensitivity;
    for (const auto& sample : parsed.samples) {
        if (sample.role != M23PilotRole::Holdout
            && sample.role != M23PilotRole::Sensitivity) {
            continue;
        }
        auto baselineTarget = sample;
        if (sample.probeKind == M23PilotProbeKind::SamplingSensitivity) {
            baselineTarget.samplingMilliseconds = 5;
        }
        const auto baseline =
            baselinePerIteration(parsed.samples, baselineTarget);
        if (!baseline || *baseline <= 0.0) {
            continue;
        }
        const auto actual = static_cast<double>(sample.measuredBlockNanoseconds)
            / static_cast<double>(sample.iterationsPerRun);
        if (sample.probeKind == M23PilotProbeKind::IterationScaling) {
            const auto predicted = *baseline
                * static_cast<double>(sample.iterationsPerRun);
            const auto observed = static_cast<double>(sample.measuredBlockNanoseconds);
            const auto factor = predicted > 0.0 && observed > 0.0
                ? std::max(predicted / observed, observed / predicted)
                : std::numeric_limits<double>::infinity();
            // Fixed/no-size holdouts were already counted in exact-mode evaluation.
            if (sample.role == M23PilotRole::Holdout
                && sample.inputBytes.has_value()) {
                ++holdoutCount;
                if (!std::isfinite(factor)) {
                    ++factorOutlierCount;
                } else {
                    maximumHoldoutFactor =
                        std::max(maximumHoldoutFactor, factor);
                    if (factor > kPilotHoldoutScreenFactor) {
                        ++factorOutlierCount;
                    }
                }
            }
            nSensitivity.append(QJsonObject{
                {"caseId", qString(sample.caseId)},
                {"factor", std::isfinite(factor) ? QJsonValue(factor)
                                                  : QJsonValue(QJsonValue::Null)},
                {"rowId", qString(sample.rowId)},
                {"status", QStringLiteral("DIAGNOSTIC_ONLY")}});
        } else if (sample.probeKind == M23PilotProbeKind::RunCountSensitivity) {
            mSensitivity.append(QJsonObject{
                {"caseId", qString(sample.caseId)},
                {"measuredBlockPerIterationRatio", actual / *baseline},
                {"runs", static_cast<qint64>(sample.runs)},
                {"rowId", qString(sample.rowId)},
                {"status", QStringLiteral("DIAGNOSTIC_ONLY")}});
        } else if (sample.probeKind == M23PilotProbeKind::SamplingSensitivity) {
            samplingSensitivity.append(QJsonObject{
                {"caseId", qString(sample.caseId)},
                {"measuredBlockPerIterationRatio", actual / *baseline},
                {"rowId", qString(sample.rowId)},
                {"samplingIntervalMilliseconds",
                    static_cast<qint64>(sample.samplingMilliseconds)},
                {"status", QStringLiteral("DIAGNOSTIC_ONLY")}});
        }
    }

    std::map<std::uint32_t, std::vector<double>> batchValuesByEntryCount;
    for (const auto& batch : parsed.batches) {
        batchValuesByEntryCount[batch.entryCount].push_back(
            static_cast<double>(batch.batchOnlyNanoseconds));
    }
    std::vector<std::pair<double, double>> batchPoints;
    std::vector<double> allBatchValues;
    for (const auto& [entryCount, values] : batchValuesByEntryCount) {
        const auto batchMean = mean(values);
        batchPoints.emplace_back(entryCount, batchMean);
        allBatchValues.insert(allBatchValues.end(), values.begin(), values.end());
    }
    QJsonArray batchModels;
    batchModels.append(QJsonObject{
        {"model", QStringLiteral("constant")},
        {"observedBatchShapes", static_cast<qint64>(batchPoints.size())},
        {"status", allBatchValues.empty()
            ? QStringLiteral("INSUFFICIENT_EVIDENCE")
            : QStringLiteral("CANDIDATE_DIAGNOSTIC")},
        {"valueNanoseconds", allBatchValues.empty()
            ? QJsonValue(QJsonValue::Null)
            : QJsonValue(mean(allBatchValues))}});
    const auto perEntryFit = fitBatchLinear(batchPoints);
    batchModels.append(QJsonObject{
        {"interceptNanoseconds", perEntryFit.valid
            ? QJsonValue(perEntryFit.intercept)
            : QJsonValue(QJsonValue::Null)},
        {"model", QStringLiteral("constantPlusPerEntry")},
        {"perEntryNanoseconds", perEntryFit.valid
            ? QJsonValue(perEntryFit.slope)
            : QJsonValue(QJsonValue::Null)},
        {"rmsResidualNanoseconds", perEntryFit.valid
            ? QJsonValue(perEntryFit.rmsResidual)
            : QJsonValue(QJsonValue::Null)},
        {"status", perEntryFit.valid
            ? QStringLiteral("CANDIDATE_DIAGNOSTIC")
            : QStringLiteral("INSUFFICIENT_E_SHAPES")}});
    const auto triangularFit = fitTriangularBatchModel(batchPoints);
    batchModels.append(QJsonObject{
        {"constantNanoseconds", triangularFit.valid
            ? QJsonValue(triangularFit.constant)
            : QJsonValue(QJsonValue::Null)},
        {"model", QStringLiteral("constantPlusPerEntryPlusTriangular")},
        {"perEntryNanoseconds", triangularFit.valid
            ? QJsonValue(triangularFit.perEntry)
            : QJsonValue(QJsonValue::Null)},
        {"rmsResidualNanoseconds", triangularFit.valid
            ? QJsonValue(triangularFit.rmsResidual)
            : QJsonValue(QJsonValue::Null)},
        {"status", triangularFit.valid
            ? QStringLiteral("CANDIDATE_DIAGNOSTIC")
            : QStringLiteral("INSUFFICIENT_E_SHAPES")},
        {"triangularCoefficientNanoseconds", triangularFit.valid
            ? QJsonValue(triangularFit.triangular)
            : QJsonValue(QJsonValue::Null)}});

    QJsonArray missingRowIds;
    for (const auto& row : m23PilotPlanRows()) {
        if (row.status == M23PilotPlanStatus::Candidate
            && !observedCandidateRows.contains(row.rowId)) {
            missingRowIds.append(qString(row.rowId));
        }
    }
    const auto synthetic = provenance->synthetic;
    const auto evidenceLabel = synthetic
        ? QStringLiteral("SYNTHETIC / NOT QUALIFIED")
        : QStringLiteral("PILOT EVIDENCE ONLY / NOT PRODUCTION QUALIFICATION");
    const auto factorScreen = holdoutCount > 0
        && factorOutlierCount == 0
        && maximumHoldoutFactor <= kPilotHoldoutScreenFactor;

    return {
        {"affineAndExactModelCandidates", modelReports},
        {"batchOverheadModelCandidates", batchModels},
        {"candidatePlanSha256", QString::fromLatin1(m23PilotPlanSha256())},
        {"candidatePlanRowsTotal", static_cast<qint64>(candidateRowCount)},
        {"evidenceFileCount", static_cast<qint64>(evidenceFiles.size())},
        {"evidenceLabel", evidenceLabel},
        {"fitHoldoutLeakage", fitHoldoutLeakage},
        {"holdoutDiagnosticCount", static_cast<qint64>(holdoutCount)},
        {"holdoutFactorOutlierCount",
            static_cast<qint64>(factorOutlierCount)},
        {"holdoutDiagnosticFactorMax",
            holdoutCount ? QJsonValue(maximumHoldoutFactor)
                         : QJsonValue(QJsonValue::Null)},
        {"holdoutScreenFactorLimit", kPilotHoldoutScreenFactor},
        {"holdoutScreeningDiagnosticPass", factorScreen},
        {"mSensitivityDiagnostics", mSensitivity},
        {"maximumObservedInputBytes",
            QString::number(parsed.maximumInputBytes)},
        {"maximumObservedRunNanoseconds",
            QString::number(parsed.maximumRunNanoseconds)},
        {"maximumObservedRuns", static_cast<qint64>(parsed.maximumRuns)},
        {"observedCandidatePlanRows",
            static_cast<qint64>(observedCandidateRows.size())},
        {"maximumObservedSamplingIntervalMilliseconds",
            static_cast<qint64>([&] {
                std::uint32_t maximum = 0;
                for (const auto& sample : parsed.samples) {
                    maximum = std::max(maximum, sample.samplingMilliseconds);
                }
                return maximum;
            }())},
        {"maximumObservedBatchEntryCount",
            static_cast<qint64>(parsed.maximumEntries)},
        {"missingCandidatePlanRows", missingRowIds},
        {"modelSelection", QStringLiteral("DEFERRED TO SEPARATE HUMAN PILOT REVIEW")},
        {"minimumObservedAvailableDiskBytes",
            QString::number(parsed.minimumAvailableDiskBytes)},
        {"minimumObservedAvailableMemoryBytes",
            QString::number(parsed.minimumAvailableMemoryBytes)},
        {"nScalingDiagnostics", nSensitivity},
        {"pilotDecision", QStringLiteral("PENDING HUMAN REVIEW")},
        {"resourceAndWallCaps", QJsonObject{
            {"maximumInitialInputBytes",
                QString::number(kM23PilotMaximumInitialInputBytes)},
            {"maximumObservationSeconds",
                QString::number(kM23PilotMaximumObservationSeconds)},
            {"minimumAvailableMemoryBytes",
                QString::number(kM23PilotMinimumAvailableMemoryBytes)},
            {"minimumFreeDiskBytes",
                QString::number(kM23PilotMinimumFreeDiskBytes)}}},
        {"samplingSensitivityDiagnostics", samplingSensitivity},
        {"schemaVersion", 1}};
}

} // namespace cryptobench::tests
