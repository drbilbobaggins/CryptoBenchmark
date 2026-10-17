#include "MemoryV2Qualification.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <QChar>

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>

namespace cryptobench::tests {
namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::invalid_argument(message);
}

QualificationCampaignMode modeFromString(const QString& value)
{
    if (value == QStringLiteral("off")) return {QualificationSamplingMode::BoundaryOnlyControl, 5};
    bool ok = false;
    const auto interval = value.toUInt(&ok);
    if (!ok || (interval != 1 && interval != 2 && interval != 5)) {
        throw std::invalid_argument("campaign mode must be off, 5, 2 or 1");
    }
    return {QualificationSamplingMode::Periodic, interval};
}

QString modeToString(const QualificationCampaignMode& mode);

void validateCampaignIdentifier(const QString& value, const char* field)
{
    if (value.isEmpty() || value.size() > 80) throw std::invalid_argument(std::string(field) + " is invalid");
    for (const auto character : value) {
        if (character.unicode() < 0x20 || character.unicode() == 0x7F ||
            character == QChar('/') || character == QChar('\\') ||
            character == QChar('<') || character == QChar('>') || character == QChar(':') ||
            character == QChar('"') || character == QChar('|') || character == QChar('?') || character == QChar('*') ||
            (character == QChar('.') && value.endsWith(QChar('.'))) ||
            (character == QChar(' ') && value.endsWith(QChar(' '))) ||
            (character == QChar('.') && value.startsWith(QStringLiteral("..")))) {
            throw std::invalid_argument(std::string(field) + " contains an unsafe character");
        }
    }
    const auto upper = value.toUpper();
    const QSet<QString> reserved{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
    if (reserved.contains(upper)) throw std::invalid_argument(std::string(field) + " uses a reserved Windows name");
}

void validateCampaignManifest(const QualificationCampaignManifest& manifest)
{
    validateCampaignIdentifier(manifest.campaignId, "campaignId");
    if (manifest.phase != QStringLiteral("pilot") || manifest.repetitions == 0 ||
        manifest.repetitions > 100 || manifest.modes.empty() || manifest.cases.empty()) {
        throw std::invalid_argument("campaign manifest bounds or phase are invalid");
    }
    if (manifest.cases.size() > 100 ||
        manifest.cases.size() * manifest.modes.size() * manifest.repetitions > 10'000) {
        throw std::invalid_argument("campaign manifest cardinality is excessive");
    }
    QSet<QString> modeNames;
    for (const auto& mode : manifest.modes) {
        if (mode.mode != QualificationSamplingMode::Periodic &&
            mode.mode != QualificationSamplingMode::BoundaryOnlyControl) {
            throw std::invalid_argument("campaign mode enum is invalid");
        }
        const auto name = modeToString(mode);
        if (modeNames.contains(name)) throw std::invalid_argument("duplicate campaign mode");
        modeNames.insert(name);
        if (mode.mode == QualificationSamplingMode::Periodic &&
            (mode.intervalMilliseconds != 1 && mode.intervalMilliseconds != 2 && mode.intervalMilliseconds != 5)) {
            throw std::invalid_argument("campaign sampling interval is invalid");
        }
    }
    QSet<QString> caseIds;
    for (const auto& item : manifest.cases) {
        validateCampaignIdentifier(item.caseId, "caseId");
        if (caseIds.contains(item.caseId)) throw std::invalid_argument("duplicate campaign caseId");
        caseIds.insert(item.caseId);
        validateSyntheticScenario(item.scenario);
    }
}

QString modeToString(const QualificationCampaignMode& mode)
{
    return mode.mode == QualificationSamplingMode::BoundaryOnlyControl
        ? QStringLiteral("off")
        : QString::number(mode.intervalMilliseconds);
}

std::uint64_t requiredU64(const QJsonObject& object, const char* name)
{
    const auto value = object.value(QString::fromLatin1(name));
    if (!value.isString()) throw std::invalid_argument(std::string(name) + " must be a decimal string");
    bool ok = false;
    const auto result = value.toString().toULongLong(&ok);
    if (!ok) throw std::invalid_argument(std::string(name) + " is not an unsigned integer");
    return result;
}

std::uint32_t requiredU32(const QJsonObject& object, const char* name)
{
    const auto jsonValue = object.value(QString::fromLatin1(name));
    std::uint64_t value = 0;
    if (jsonValue.isString()) {
        bool ok = false;
        value = jsonValue.toString().toULongLong(&ok);
        if (!ok) throw std::invalid_argument(std::string(name) + " is not an unsigned integer");
    } else if (jsonValue.isDouble() && std::floor(jsonValue.toDouble()) == jsonValue.toDouble() &&
               jsonValue.toDouble() >= 0.0 &&
               jsonValue.toDouble() <= std::numeric_limits<std::uint32_t>::max()) {
        value = static_cast<std::uint64_t>(jsonValue.toDouble());
    } else {
        throw std::invalid_argument(std::string(name) + " is not an unsigned integer");
    }
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(std::string(name) + " overflows uint32");
    }
    return static_cast<std::uint32_t>(value);
}

QJsonObject scenarioObject(const SyntheticScenario& scenario)
{
    return encodeSyntheticScenario(scenario).object();
}

SyntheticScenario scenarioFromObject(const QJsonObject& object)
{
    return parseSyntheticScenario(QJsonDocument(object).toJson(QJsonDocument::Compact));
}

void writeNewFile(const QString& path, const QByteArray& bytes)
{
    if (QFileInfo::exists(path)) throw std::invalid_argument("campaign output collision");
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
        throw std::runtime_error("campaign atomic output failed");
    }
}

std::int64_t signedDifference(std::uint64_t value, std::uint64_t baseline)
{
    if (value >= baseline) return static_cast<std::int64_t>(value - baseline);
    return -static_cast<std::int64_t>(baseline - value);
}

QString parseManifestString(const QString& text, qsizetype& position)
{
    if (position >= text.size() || text[position++] != QChar('"')) {
        throw std::invalid_argument("manifest key is not a JSON string");
    }
    QString result;
    while (position < text.size()) {
        const auto character = text[position++];
        if (character == QChar('"')) return result;
        if (character != QChar('\\')) { result += character; continue; }
        if (position >= text.size()) throw std::invalid_argument("manifest escape is incomplete");
        const auto escape = text[position++];
        if (escape == QChar('u')) {
            if (position + 4 > text.size()) throw std::invalid_argument("manifest unicode escape is incomplete");
            bool ok = false;
            const auto codePoint = text.mid(position, 4).toUInt(&ok, 16);
            if (!ok) throw std::invalid_argument("manifest unicode escape is invalid");
            result += QChar(static_cast<ushort>(codePoint));
            position += 4;
        } else {
            const QHash<QChar, QChar> escapes{{QChar('"'), QChar('"')}, {QChar('\\'), QChar('\\')},
                {QChar('/'), QChar('/')}, {QChar('b'), QChar('\b')}, {QChar('f'), QChar('\f')},
                {QChar('n'), QChar('\n')}, {QChar('r'), QChar('\r')}, {QChar('t'), QChar('\t')}};
            if (!escapes.contains(escape)) throw std::invalid_argument("manifest escape is invalid");
            result += escapes.value(escape);
        }
    }
    throw std::invalid_argument("manifest key is unterminated");
}

void scanManifestValue(const QString& text, qsizetype& position)
{
    while (position < text.size()) {
        while (position < text.size() && text[position].isSpace()) ++position;
        if (position >= text.size()) return;
        if (text[position] == QChar('"')) { static_cast<void>(parseManifestString(text, position)); return; }
        if (text[position] == QChar('{')) {
            ++position;
            QSet<QString> names;
            while (true) {
                while (position < text.size() && text[position].isSpace()) ++position;
                if (position < text.size() && text[position] == QChar('}')) { ++position; return; }
                const auto name = parseManifestString(text, position);
                if (names.contains(name)) throw std::invalid_argument("duplicate manifest field");
                names.insert(name);
                while (position < text.size() && text[position].isSpace()) ++position;
                if (position >= text.size() || text[position++] != QChar(':')) throw std::invalid_argument("manifest member colon missing");
                scanManifestValue(text, position);
                while (position < text.size() && text[position].isSpace()) ++position;
                if (position < text.size() && text[position] == QChar(',')) { ++position; continue; }
                if (position < text.size() && text[position] == QChar('}')) { ++position; return; }
                throw std::invalid_argument("manifest member separator invalid");
            }
        }
        if (text[position] == QChar('[')) {
            ++position;
            while (true) {
                while (position < text.size() && text[position].isSpace()) ++position;
                if (position < text.size() && text[position] == QChar(']')) { ++position; return; }
                scanManifestValue(text, position);
                while (position < text.size() && text[position].isSpace()) ++position;
                if (position < text.size() && text[position] == QChar(',')) { ++position; continue; }
                if (position < text.size() && text[position] == QChar(']')) { ++position; return; }
                throw std::invalid_argument("manifest array separator invalid");
            }
        }
        while (position < text.size() && !text[position].isSpace() &&
               text[position] != QChar(',') && text[position] != QChar('}') && text[position] != QChar(']')) ++position;
        return;
    }
}

void rejectDuplicateManifestKeys(const QString& text)
{
    qsizetype position = 0;
    while (position < text.size() && text[position].isSpace()) ++position;
    scanManifestValue(text, position);
    while (position < text.size() && text[position].isSpace()) ++position;
    if (position != text.size()) throw std::invalid_argument("manifest has trailing data");
}

struct GroupStats {
    std::uint32_t planned = 0;
    std::uint32_t completed = 0;
    std::uint32_t failed = 0;
    std::uint32_t cancelled = 0;
    std::uint32_t indeterminate = 0;
    std::vector<std::uint64_t> preparationSampleCounts;
    std::vector<std::uint64_t> executionSampleCounts;
    std::uint32_t prepZeroSamples = 0;
    std::uint32_t executionZeroSamples = 0;
    std::uint32_t transientCaptured = 0;
    std::uint32_t transientEligible = 0;
    std::uint32_t phaseChecks = 0;
    std::uint32_t phaseConsistent = 0;
    std::vector<double> preparationPeakRatios;
    std::vector<double> executionPeakRatios;
    std::vector<std::int64_t> preparationBoundaryResiduals;
    std::vector<std::int64_t> executionBoundaryResiduals;
    std::uint32_t preparationSignalDetected = 0;
    std::uint32_t preparationSignalEligible = 0;
    std::uint32_t executionSignalDetected = 0;
    std::uint32_t executionSignalEligible = 0;
};

struct PlanItem {
    std::size_t caseIndex;
    std::size_t modeIndex;
    std::uint32_t repetition;
};

std::vector<PlanItem> campaignPlan(const QualificationCampaignManifest& manifest)
{
    std::vector<PlanItem> plan;
    for (std::size_t caseIndex = 0; caseIndex < manifest.cases.size(); ++caseIndex)
        for (std::size_t modeIndex = 0; modeIndex < manifest.modes.size(); ++modeIndex)
            for (std::uint32_t repetition = 0; repetition < manifest.repetitions; ++repetition)
                plan.push_back({caseIndex, modeIndex, repetition});
    std::mt19937_64 random(manifest.seed);
    std::shuffle(plan.begin(), plan.end(), random);
    return plan;
}

QJsonObject distribution(const std::vector<std::uint64_t>& values)
{
    if (values.empty()) return QJsonObject{{"total", 0}, {"min", QJsonValue(QJsonValue::Null)},
        {"median", QJsonValue(QJsonValue::Null)}, {"max", QJsonValue(QJsonValue::Null)},
        {"zeroRuns", 0}, {"runsWithSamples", 0}};
    auto sorted = values;
    std::sort(sorted.begin(), sorted.end());
    const auto zeroRuns = static_cast<std::uint64_t>(std::count(sorted.begin(), sorted.end(), 0));
    return QJsonObject{
        {"total", QString::number(std::accumulate(values.begin(), values.end(), std::uint64_t{0}))},
        {"min", QString::number(sorted.front())},
        {"median", QString::number(sorted[sorted.size() / 2])},
        {"max", QString::number(sorted.back())},
        {"zeroRuns", static_cast<qint64>(zeroRuns)},
        {"runsWithSamples", static_cast<qint64>(sorted.size() - zeroRuns)}};
}

QJsonObject signedDistribution(const std::vector<std::int64_t>& values)
{
    if (values.empty()) return QJsonObject{{"count", 0}, {"min", QJsonValue(QJsonValue::Null)},
        {"median", QJsonValue(QJsonValue::Null)}, {"max", QJsonValue(QJsonValue::Null)}};
    auto sorted = values;
    std::sort(sorted.begin(), sorted.end());
    return QJsonObject{{"count", static_cast<qint64>(sorted.size())},
        {"min", QString::number(sorted.front())},
        {"median", QString::number(sorted[sorted.size() / 2])},
        {"max", QString::number(sorted.back())}};
}

QJsonValue ratioDistribution(const std::vector<double>& values)
{
    if (values.empty()) return QJsonValue(QJsonValue::Null);
    auto sorted = values;
    std::sort(sorted.begin(), sorted.end());
    return QJsonValue(QJsonObject{{"min", sorted.front()},
        {"median", sorted[sorted.size() / 2]}, {"max", sorted.back()}});
}

QJsonObject groupToJson(const GroupStats& stats)
{
    const auto interval = [](double numerator, double denominator) {
        if (denominator == 0.0) return QJsonValue(QJsonValue::Null);
        const auto proportion = numerator / denominator;
        const auto z = 1.959963984540054;
        const auto denominatorAdjusted = 1.0 + z * z / denominator;
        const auto center = (proportion + z * z / (2.0 * denominator)) / denominatorAdjusted;
        const auto radius = z * std::sqrt(
            proportion * (1.0 - proportion) / denominator + z * z / (4.0 * denominator * denominator)) /
            denominatorAdjusted;
        return QJsonValue(QJsonObject{{"low", center - radius}, {"high", center + radius}});
    };
    QJsonObject result{
        {"planned", static_cast<qint64>(stats.planned)},
        {"completed", static_cast<qint64>(stats.completed)},
        {"failed", static_cast<qint64>(stats.failed)},
        {"cancelled", static_cast<qint64>(stats.cancelled)},
        {"indeterminate", static_cast<qint64>(stats.indeterminate)},
        {"preparationSampleCountDistribution", distribution(stats.preparationSampleCounts)},
        {"executionSampleCountDistribution", distribution(stats.executionSampleCounts)},
        {"preparationSignalDetected", static_cast<qint64>(stats.preparationSignalDetected)},
        {"preparationSignalDenominator", static_cast<qint64>(stats.preparationSignalEligible)},
        {"executionSignalDetected", static_cast<qint64>(stats.executionSignalDetected)},
        {"executionSignalDenominator", static_cast<qint64>(stats.executionSignalEligible)},
        {"transientCaptureNumerator", static_cast<qint64>(stats.transientCaptured)},
        {"transientCaptureDenominator", static_cast<qint64>(stats.transientEligible)},
        {"transientCaptureWilson95", interval(stats.transientCaptured, stats.transientEligible)},
        {"preparationPeakRatio", ratioDistribution(stats.preparationPeakRatios)},
        {"executionPeakRatio", ratioDistribution(stats.executionPeakRatios)},
        {"preparationBoundaryResidual", signedDistribution(stats.preparationBoundaryResiduals)},
        {"executionBoundaryResidual", signedDistribution(stats.executionBoundaryResiduals)},
        {"phaseConsistencyNumerator", static_cast<qint64>(stats.phaseConsistent)},
        {"phaseConsistencyDenominator", static_cast<qint64>(stats.phaseChecks)}};
    return result;
}

std::uint64_t rawU64(const QJsonObject& object, const char* name)
{
    const auto value = object.value(QString::fromLatin1(name));
    if (!value.isString()) throw std::invalid_argument("raw qualification integer is not a string");
    bool ok = false;
    const auto result = value.toString().toULongLong(&ok);
    if (!ok) throw std::invalid_argument("raw qualification integer is invalid");
    return result;
}

std::optional<std::uint64_t> rawOptionalU64(const QJsonObject& object, const char* name)
{
    const auto value = object.value(QString::fromLatin1(name));
    if (value.isNull()) return std::nullopt;
    return rawU64(object, name);
}

void accumulateGroupFromRaw(GroupStats& stats,
                            const QJsonObject& raw,
                            const SyntheticScenario& scenario,
                            QualificationSamplingMode mode)
{
    const auto status = raw.value("status").toString();
    if (status == QStringLiteral("failed")) {
        ++stats.failed;
        return;
    }
    if (status == QStringLiteral("cancelled")) {
        ++stats.cancelled;
        return;
    }
    if (status == QStringLiteral("indeterminate")) {
        ++stats.indeterminate;
        return;
    }
    if (status != QStringLiteral("completed")) throw std::invalid_argument("raw status is invalid");
    ++stats.completed;
    const auto observations = raw.value("observations").toObject();
    const auto baseline = rawU64(observations, "b0PrivateUsageBytes");
    const auto ready = rawU64(observations, "b1PrivateUsageBytes");
    const auto finalValue = rawU64(observations, "ePrivateUsageBytes");
    const auto preparationSamples = rawU64(observations, "preparationSampleCount");
    const auto executionSamples = rawU64(observations, "executionSampleCount");
    const auto preparationPeak = rawOptionalU64(observations, "preparationPeakSampledPrivateUsageBytes");
    const auto executionPeak = rawOptionalU64(observations, "executionPeakSampledPrivateUsageBytes");
    if ((preparationSamples == 0) != !preparationPeak.has_value() ||
        (executionSamples == 0) != !executionPeak.has_value()) {
        throw std::invalid_argument("raw sample count/peak invariant is invalid");
    }
    stats.preparationSampleCounts.push_back(preparationSamples);
    stats.executionSampleCounts.push_back(executionSamples);
    const auto preparationSignal = preparationPeak
        ? signedDifference(*preparationPeak, baseline) : 0;
    const auto executionSignal = executionPeak
        ? signedDifference(*executionPeak, ready) : 0;
    stats.preparationBoundaryResiduals.push_back(signedDifference(ready, baseline));
    stats.executionBoundaryResiduals.push_back(signedDifference(finalValue, ready));
    const auto preparationExpected = mode == QualificationSamplingMode::Periodic &&
        scenario.preparationBytes != 0 && scenario.releasePreparationBeforeBoundary;
    const auto executionExpected = mode == QualificationSamplingMode::Periodic &&
        scenario.executionBytes != 0 && scenario.releaseExecutionBeforeEnd;
    if (preparationExpected) {
        ++stats.preparationSignalEligible;
        if (preparationSignal > 0) ++stats.preparationSignalDetected;
    }
    if (executionExpected) {
        ++stats.executionSignalEligible;
        if (executionSignal > 0) ++stats.executionSignalDetected;
    }
    const auto transient = preparationExpected || executionExpected;
    if (transient) {
        ++stats.transientEligible;
        if ((preparationExpected && preparationSignal > 0) ||
            (executionExpected && executionSignal > 0)) ++stats.transientCaptured;
    }
    if (mode == QualificationSamplingMode::Periodic) {
        ++stats.phaseChecks;
        if ((!preparationExpected || preparationPeak.has_value()) &&
            (!executionExpected || executionPeak.has_value())) ++stats.phaseConsistent;
    }
    if (scenario.preparationBytes != 0 && preparationPeak.has_value()) {
        stats.preparationPeakRatios.push_back(
            static_cast<double>(preparationSignal) / static_cast<double>(scenario.preparationBytes));
    }
    if (scenario.executionBytes != 0 && executionPeak.has_value()) {
        stats.executionPeakRatios.push_back(
            static_cast<double>(executionSignal) / static_cast<double>(scenario.executionBytes));
    }
}

} // namespace

QualificationCampaignManifest defaultExploratoryPilotManifest()
{
    const auto sustained = [](std::uint64_t preparation, std::uint64_t execution,
                              bool releasePreparation, bool releaseExecution,
                              std::uint32_t hold) {
        return SyntheticScenario{preparation, execution, hold, hold,
                                 releasePreparation, releaseExecution, SyntheticOutcome::Completed};
    };
    QualificationCampaignManifest manifest;
    manifest.campaignId = QStringLiteral("m19.2-gate-a-exploratory-pilot");
    manifest.phase = QStringLiteral("pilot");
    manifest.seed = 0x4D31392E32ULL;
    manifest.repetitions = 3;
    manifest.modes = {{QualificationSamplingMode::BoundaryOnlyControl, 5},
                      {QualificationSamplingMode::Periodic, 5},
                      {QualificationSamplingMode::Periodic, 2},
                      {QualificationSamplingMode::Periodic, 1}};
    manifest.cases = {
        {QStringLiteral("quiet"), sustained(0, 0, true, true, 80)},
        {QStringLiteral("preparation-retained"), sustained(8ULL * 1024U * 1024U, 0, false, true, 80)},
        {QStringLiteral("execution-retained"), sustained(0, 8ULL * 1024U * 1024U, true, false, 80)},
        {QStringLiteral("preparation-transient"), sustained(8ULL * 1024U * 1024U, 0, true, true, 20)},
        {QStringLiteral("execution-transient"), sustained(0, 8ULL * 1024U * 1024U, true, true, 20)},
        {QStringLiteral("distinct-phases"), sustained(8ULL * 1024U * 1024U, 16ULL * 1024U * 1024U, false, false, 80)}};
    return manifest;
}

QualificationCampaignManifest parseQualificationCampaignManifest(const QJsonDocument& document)
{
    if (!document.isObject()) throw std::invalid_argument("campaign manifest must be an object");
    const auto object = document.object();
    const std::array<QString, 5> required{QStringLiteral("format"), QStringLiteral("schemaVersion"),
        QStringLiteral("campaignId"), QStringLiteral("phase"), QStringLiteral("seed")};
    for (const auto& name : required) if (!object.contains(name)) throw std::invalid_argument("manifest field missing");
    const QSet<QString> allowed{
        QStringLiteral("format"), QStringLiteral("schemaVersion"), QStringLiteral("campaignId"),
        QStringLiteral("phase"), QStringLiteral("seed"), QStringLiteral("repetitions"),
        QStringLiteral("modes"), QStringLiteral("cases")};
    for (const auto& name : object.keys()) {
        if (!allowed.contains(name)) throw std::invalid_argument("unknown manifest field");
    }
    if (object.value("format") != QStringLiteral("cryptobenchmark-memory-v2-campaign") ||
        !object.value("schemaVersion").isDouble() ||
        std::floor(object.value("schemaVersion").toDouble()) != object.value("schemaVersion").toDouble() ||
        object.value("schemaVersion").toInt() != 1) throw std::invalid_argument("manifest format/version mismatch");
    if (!object.value("modes").isArray() || !object.value("cases").isArray()) throw std::invalid_argument("manifest arrays missing");

    QualificationCampaignManifest result;
    result.campaignId = object.value("campaignId").toString();
    result.phase = object.value("phase").toString();
    result.seed = requiredU64(object, "seed");
    result.repetitions = requiredU32(object, "repetitions");
    if (result.campaignId.isEmpty() || result.phase != QStringLiteral("pilot") || result.repetitions == 0) {
        throw std::invalid_argument("manifest identity or repetitions are invalid");
    }
    for (const auto& value : object.value("modes").toArray()) {
        if (!value.isString()) throw std::invalid_argument("manifest mode is not a string");
        result.modes.push_back(modeFromString(value.toString()));
    }
    if (result.modes.empty()) throw std::invalid_argument("manifest has no modes");
    for (const auto& value : object.value("cases").toArray()) {
        const auto caseObject = value.toObject();
        const QSet<QString> allowedCaseMembers{QStringLiteral("caseId"), QStringLiteral("scenario")};
        for (const auto& name : caseObject.keys()) {
            if (!allowedCaseMembers.contains(name)) throw std::invalid_argument("unknown campaign case field");
        }
        const auto id = caseObject.value("caseId").toString();
        if (id.isEmpty() || !caseObject.value("scenario").isObject()) throw std::invalid_argument("manifest case is invalid");
        result.cases.push_back({id, scenarioFromObject(caseObject.value("scenario").toObject())});
    }
    if (result.cases.empty()) throw std::invalid_argument("manifest has no cases");
    validateCampaignManifest(result);
    return result;
}

QualificationCampaignManifest parseQualificationCampaignManifest(const QString& encoded)
{
    rejectDuplicateManifestKeys(encoded);
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(encoded.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) throw std::invalid_argument("campaign manifest JSON is invalid");
    return parseQualificationCampaignManifest(document);
}

QJsonDocument encodeQualificationCampaignManifest(const QualificationCampaignManifest& manifest)
{
    validateCampaignManifest(manifest);
    QJsonArray modes;
    for (const auto& mode : manifest.modes) modes.append(modeToString(mode));
    QJsonArray cases;
    for (const auto& item : manifest.cases) cases.append(QJsonObject{
        {"caseId", item.caseId}, {"scenario", scenarioObject(item.scenario)}});
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-campaign"}, {"schemaVersion", 1},
        {"campaignId", manifest.campaignId}, {"phase", manifest.phase},
        {"seed", QString::number(manifest.seed)}, {"repetitions", static_cast<qint64>(manifest.repetitions)},
        {"modes", modes}, {"cases", cases}});
}

QJsonDocument runQualificationCampaign(const QualificationCampaignManifest& manifest,
                                       const QString& outputDirectory)
{
    validateCampaignManifest(manifest);
    const auto manifestDocument = encodeQualificationCampaignManifest(manifest);
    QDir directory;
    if (!directory.mkpath(outputDirectory)) throw std::runtime_error("campaign output directory could not be created");
    const auto runsDirectory = QDir(outputDirectory).filePath(QStringLiteral("runs"));
    if (!directory.mkpath(runsDirectory)) throw std::runtime_error("campaign runs directory could not be created");
    const auto manifestBytes = manifestDocument.toJson(QJsonDocument::Indented);
    writeNewFile(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")), manifestBytes);

    const auto plan = campaignPlan(manifest);

    std::map<QString, GroupStats> groups;
    QJsonArray runIndex;
    std::uint32_t executionOrder = 0;
    for (const auto& item : plan) {
        const auto& caseItem = manifest.cases[item.caseIndex];
        const auto mode = manifest.modes[item.modeIndex];
        const auto groupKey = caseItem.caseId + QStringLiteral("/") + modeToString(mode);
        auto& stats = groups[groupKey];
        ++stats.planned;
        QualificationRun run;
        const QualificationIdentity identity{manifest.campaignId, caseItem.caseId,
            QString::number(item.repetition), executionOrder++};
        try {
            run = runQualification(mode.mode, caseItem.scenario,
                                   mode.intervalMilliseconds, identity);
        } catch (const std::exception& error) {
            run.status = QStringLiteral("failed");
            run.error = QString::fromUtf8(error.what());
        }
        if (run.status == QStringLiteral("completed") &&
            run.terminationStatus != ProcessTerminationStatus::Exited) {
            run.status = QStringLiteral("indeterminate");
            run.error = QStringLiteral("worker termination evidence was indeterminate");
        }
        const auto rawName = QStringLiteral("%1-%2-%3-%4.json")
            .arg(identity.executionOrder, 5, 10, QLatin1Char('0'))
            .arg(caseItem.caseId, modeToString(mode))
            .arg(item.repetition);
        const auto rawPath = QDir(runsDirectory).filePath(rawName);
        if (QFileInfo::exists(rawPath)) throw std::invalid_argument("campaign raw artifact collision");
        const auto rawDocument = makeQualificationArtifact(
            run, mode.mode, caseItem.scenario, mode.intervalMilliseconds, identity);
        writeQualificationArtifact(rawPath, rawDocument);
        QFile rawFile(rawPath);
        if (!rawFile.open(QIODevice::ReadOnly)) throw std::runtime_error("raw artifact hash read failed");
        const auto rawHash = QString::fromLatin1(
            QCryptographicHash::hash(rawFile.readAll(), QCryptographicHash::Sha256).toHex());
        runIndex.append(QJsonObject{{"path", QStringLiteral("runs/") + rawName},
            {"sha256", rawHash},
            {"caseId", caseItem.caseId}, {"mode", modeToString(mode)},
            {"repetitionId", identity.repetitionId},
            {"executionOrder", static_cast<qint64>(identity.executionOrder)},
            {"status", run.status}});
        accumulateGroupFromRaw(stats, rawDocument.object(), caseItem.scenario, mode.mode);
    }

    QJsonObject groupObject;
    for (const auto& entry : groups) groupObject.insert(entry.first, groupToJson(entry.second));
    const auto attemptedRuns = static_cast<std::uint32_t>(runIndex.size());
    std::uint32_t failedRuns = 0;
    std::uint32_t cancelledRuns = 0;
    std::uint32_t indeterminateRuns = 0;
    for (const auto& value : runIndex) {
        const auto status = value.toObject().value("status").toString();
        if (status == QStringLiteral("failed")) ++failedRuns;
        if (status == QStringLiteral("cancelled")) ++cancelledRuns;
        if (status == QStringLiteral("indeterminate")) ++indeterminateRuns;
    }
    const auto missingRuns = static_cast<std::uint32_t>(plan.size()) - attemptedRuns;
    const auto campaignStatus = failedRuns == 0 && cancelledRuns == 0 &&
        indeterminateRuns == 0 && missingRuns == 0
        ? QStringLiteral("completed") : QStringLiteral("failed");
    const auto summary = QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-campaign-summary"}, {"schemaVersion", 1},
        {"campaignId", manifest.campaignId}, {"phase", manifest.phase},
        {"manifestSha256", QString::fromLatin1(
            QCryptographicHash::hash(manifestBytes, QCryptographicHash::Sha256).toHex())},
        {"status", campaignStatus},
        {"plannedRuns", static_cast<qint64>(plan.size())},
        {"attemptedRuns", static_cast<qint64>(attemptedRuns)},
        {"completedRuns", static_cast<qint64>(attemptedRuns - failedRuns - cancelledRuns - indeterminateRuns)},
        {"failedRuns", static_cast<qint64>(failedRuns)},
        {"cancelledRuns", static_cast<qint64>(cancelledRuns)},
        {"missingRuns", static_cast<qint64>(missingRuns)},
        {"indeterminateRuns", static_cast<qint64>(indeterminateRuns)},
        {"runs", runIndex}, {"groups", groupObject}});
    writeNewFile(QDir(outputDirectory).filePath(QStringLiteral("summary.json")),
                 summary.toJson(QJsonDocument::Indented));
    return summary;
}

void verifyQualificationCampaign(const QString& outputDirectory)
{
    QFile manifestFile(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")));
    QFile summaryFile(QDir(outputDirectory).filePath(QStringLiteral("summary.json")));
    if (!manifestFile.open(QIODevice::ReadOnly) || !summaryFile.open(QIODevice::ReadOnly)) {
        throw std::invalid_argument("campaign manifest or summary is missing");
    }
    const auto manifestBytes = manifestFile.readAll();
    const auto manifest = parseQualificationCampaignManifest(QString::fromUtf8(manifestBytes));
    const auto summaryDocument = QJsonDocument::fromJson(summaryFile.readAll());
    if (!summaryDocument.isObject()) throw std::invalid_argument("campaign summary is invalid");
    const auto summary = summaryDocument.object();
    const auto expectedManifestHash = QString::fromLatin1(
        QCryptographicHash::hash(manifestBytes, QCryptographicHash::Sha256).toHex());
    if (summary.value("manifestSha256") != expectedManifestHash) {
        throw std::invalid_argument("campaign manifest hash mismatch");
    }
    const auto plan = campaignPlan(manifest);
    const auto runs = summary.value("runs").toArray();
    if (runs.size() != static_cast<int>(plan.size()) ||
        summary.value("plannedRuns").toInt() != static_cast<int>(plan.size())) {
        throw std::invalid_argument("campaign run count mismatch");
    }
    QSet<QString> identities;
    std::map<QString, GroupStats> replayedGroups;
    for (const auto& item : plan) {
        const auto& caseItem = manifest.cases[item.caseIndex];
        const auto mode = manifest.modes[item.modeIndex];
        ++replayedGroups[caseItem.caseId + QStringLiteral("/") + modeToString(mode)].planned;
    }
    QSet<QString> expectedRawPaths;
    QString expectedGitHead;
    QString expectedBuildType;
    QString expectedExecutableHash;
    std::uint32_t failed = 0;
    std::uint32_t cancelled = 0;
    std::uint32_t indeterminate = 0;
    for (int index = 0; index < runs.size(); ++index) {
        const auto entry = runs[index].toObject();
        const auto expected = plan[static_cast<std::size_t>(index)];
        const auto& caseItem = manifest.cases[expected.caseIndex];
        const auto mode = manifest.modes[expected.modeIndex];
        if (entry.value("caseId") != caseItem.caseId ||
            entry.value("mode") != modeToString(mode) ||
            entry.value("repetitionId").toString() != QString::number(expected.repetition) ||
            entry.value("executionOrder").toInt() != index) {
            throw std::invalid_argument("campaign execution identity/order mismatch");
        }
        const auto relativePath = entry.value("path").toString();
        if (expectedRawPaths.contains(relativePath)) throw std::invalid_argument("duplicate raw path");
        expectedRawPaths.insert(relativePath);
        const auto rawPath = QDir(outputDirectory).filePath(relativePath);
        QFile rawFile(rawPath);
        if (!rawFile.open(QIODevice::ReadOnly)) throw std::invalid_argument("campaign raw artifact missing");
        const auto rawBytes = rawFile.readAll();
        const auto actualHash = QString::fromLatin1(
            QCryptographicHash::hash(rawBytes, QCryptographicHash::Sha256).toHex());
        if (entry.value("sha256") != actualHash) throw std::invalid_argument("campaign raw hash mismatch");
        const auto rawDocument = QJsonDocument::fromJson(rawBytes);
        requireQualificationArtifact(rawDocument);
        const auto raw = rawDocument.object();
        const auto rawScenario = raw.value("scenario").toObject();
        if (rawScenario.value("requestedPreparationBytes") != QString::number(caseItem.scenario.preparationBytes) ||
            rawScenario.value("requestedExecutionBytes") != QString::number(caseItem.scenario.executionBytes) ||
            rawScenario.value("preparationHoldMilliseconds").toInteger() != caseItem.scenario.preparationHoldMilliseconds ||
            rawScenario.value("executionHoldMilliseconds").toInteger() != caseItem.scenario.executionHoldMilliseconds ||
            rawScenario.value("releasePreparationBeforeBoundary").toBool() != caseItem.scenario.releasePreparationBeforeBoundary ||
            rawScenario.value("releaseExecutionBeforeEnd").toBool() != caseItem.scenario.releaseExecutionBeforeEnd ||
            rawScenario.value("outcome") != syntheticOutcomeName(caseItem.scenario.outcome)) {
            throw std::invalid_argument("campaign raw scenario mismatch");
        }
        const auto provenance = raw.value("provenance").toObject();
        if (!provenance.value("provenanceVerified").toBool() ||
            !provenance.value("syntheticExecutable").toObject().value("hashObserved").toBool()) {
            throw std::invalid_argument("campaign raw provenance is incomplete");
        }
        const auto rawGitHead = provenance.value("gitHead").toString();
        const auto rawBuildType = provenance.value("buildType").toString();
        const auto rawExecutableHash = provenance.value("syntheticExecutable").toObject().value("sha256").toString();
        if (expectedGitHead.isEmpty()) {
            expectedGitHead = rawGitHead;
            expectedBuildType = rawBuildType;
            expectedExecutableHash = rawExecutableHash;
        } else if (rawGitHead != expectedGitHead || rawBuildType != expectedBuildType ||
                   rawExecutableHash != expectedExecutableHash) {
            throw std::invalid_argument("campaign provenance mismatch");
        }
        if (raw.value("status") != entry.value("status") ||
            raw.value("identity").toObject().value("caseId") != caseItem.caseId ||
            raw.value("identity").toObject().value("repetitionId").toString() != QString::number(expected.repetition) ||
            raw.value("identity").toObject().value("executionOrder").toInt() != index ||
            raw.value("sampling").toObject().value("mode") !=
                (mode.mode == QualificationSamplingMode::BoundaryOnlyControl
                    ? QStringLiteral("boundaryOnlyControl") : QStringLiteral("periodic")) ||
            raw.value("sampling").toObject().value("intervalMilliseconds").toInt() !=
                static_cast<int>(mode.intervalMilliseconds) ||
            raw.value("lifecycle").toObject().value("terminationStatus") == QStringLiteral("running")) {
            throw std::invalid_argument("campaign raw/summary status or identity mismatch");
        }
        const auto lifecycle = raw.value("lifecycle").toObject();
        if (!lifecycle.value("processCreationTimeObserved").toBool() ||
            !lifecycle.value("individualLifecycleProof").toBool() ||
            (raw.value("status") == QStringLiteral("completed") &&
             lifecycle.value("terminationStatus") != QStringLiteral("exited"))) {
            throw std::invalid_argument("campaign raw lifecycle proof is incomplete");
        }
        const auto timing = raw.value("timing").toObject();
        const auto scenarioLifetime = rawScenario;
        if (raw.value("status") == QStringLiteral("completed") &&
            (!scenarioLifetime.value("observedPreparationLifetimeNanoseconds").isString() ||
             !scenarioLifetime.value("observedExecutionLifetimeNanoseconds").isString() ||
             timing.value("observationStatus") != QStringLiteral("observed"))) {
            throw std::invalid_argument("campaign lifetime evidence is incomplete");
        }
        const auto identityKey = QString::number(lifecycle.value("workerPid").toInt()) + ":" +
            lifecycle.value("processCreationTime100ns").toString();
        if (identities.contains(identityKey)) throw std::invalid_argument("worker identity was reused");
        identities.insert(identityKey);
        accumulateGroupFromRaw(
            replayedGroups[caseItem.caseId + QStringLiteral("/") + modeToString(mode)],
            raw, caseItem.scenario, mode.mode);
        const auto terminalStatus = raw.value("status").toString();
        if (terminalStatus == QStringLiteral("failed")) ++failed;
        else if (terminalStatus == QStringLiteral("cancelled")) ++cancelled;
        else if (terminalStatus == QStringLiteral("indeterminate")) ++indeterminate;
    }
    const auto runsDirectory = QDir(outputDirectory).filePath(QStringLiteral("runs"));
    const auto files = QDir(runsDirectory).entryList(QStringList{QStringLiteral("*.json")}, QDir::Files);
    if (files.size() != static_cast<int>(expectedRawPaths.size())) throw std::invalid_argument("unexpected or missing raw files");
    for (const auto& file : files) {
        if (!expectedRawPaths.contains(QStringLiteral("runs/") + file)) throw std::invalid_argument("extra raw file");
    }
    const auto attempted = static_cast<std::uint32_t>(runs.size());
    const auto completed = static_cast<std::uint32_t>(std::count_if(
        runs.begin(), runs.end(), [](const QJsonValue& value) {
            return value.toObject().value("status") == QStringLiteral("completed");
        }));
    const auto missing = static_cast<std::uint32_t>(plan.size()) - attempted;
    const auto expectedStatus = failed == 0 && cancelled == 0 && missing == 0 && indeterminate == 0
        ? QStringLiteral("completed") : QStringLiteral("failed");
    QJsonObject expectedGroups;
    for (const auto& entry : replayedGroups) expectedGroups.insert(entry.first, groupToJson(entry.second));
    if (summary.value("groups").toObject() != expectedGroups) {
        throw std::invalid_argument("campaign group statistics mismatch");
    }
    if (summary.value("status") != expectedStatus ||
        summary.value("attemptedRuns").toInt() != static_cast<int>(attempted) ||
        summary.value("completedRuns").toInt() != static_cast<int>(completed) ||
        summary.value("failedRuns").toInt() != static_cast<int>(failed) ||
        summary.value("cancelledRuns").toInt() != static_cast<int>(cancelled) ||
        summary.value("indeterminateRuns").toInt() != static_cast<int>(indeterminate) ||
        summary.value("missingRuns").toInt() != static_cast<int>(missing)) {
        throw std::invalid_argument(
            std::string("campaign terminal counts/status mismatch expected attempted/completed/failed/cancelled/indeterminate/missing=") +
            std::to_string(attempted) + "/" + std::to_string(completed) + "/" + std::to_string(failed) + "/" +
            std::to_string(cancelled) + "/" + std::to_string(indeterminate) + "/" + std::to_string(missing) +
            " stored=" + std::to_string(summary.value("attemptedRuns").toInt()) + "/" +
            std::to_string(summary.value("completedRuns").toInt()) + "/" +
            std::to_string(summary.value("failedRuns").toInt()) + "/" +
            std::to_string(summary.value("cancelledRuns").toInt()) + "/" +
            std::to_string(summary.value("indeterminateRuns").toInt()) + "/" +
            std::to_string(summary.value("missingRuns").toInt()));
    }
}

} // namespace cryptobench::tests
