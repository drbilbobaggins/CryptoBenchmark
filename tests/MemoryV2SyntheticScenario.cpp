#include "MemoryV2SyntheticScenario.h"

#include <QJsonObject>
#include <QChar>

#include <limits>
#include <vector>

namespace cryptobench::tests {
namespace {

constexpr std::uint64_t kMaximumAllocationBytes = 512ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t kMaximumHoldMilliseconds = 5'000;

QString outcomeToString(SyntheticOutcome outcome)
{
    switch (outcome) {
    case SyntheticOutcome::Completed: return QStringLiteral("completed");
    case SyntheticOutcome::WorkerFailure: return QStringLiteral("workerFailure");
    case SyntheticOutcome::AbnormalExit: return QStringLiteral("abnormalExit");
    case SyntheticOutcome::WaitForCancellation: return QStringLiteral("waitForCancellation");
    }
    throw std::invalid_argument("unknown synthetic outcome");
}

SyntheticOutcome outcomeFromString(const QString& value)
{
    if (value == QStringLiteral("completed")) return SyntheticOutcome::Completed;
    if (value == QStringLiteral("workerFailure")) return SyntheticOutcome::WorkerFailure;
    if (value == QStringLiteral("abnormalExit")) return SyntheticOutcome::AbnormalExit;
    if (value == QStringLiteral("waitForCancellation")) return SyntheticOutcome::WaitForCancellation;
    throw std::invalid_argument("synthetic outcome is invalid");
}

std::uint64_t unsignedValue(const QJsonObject& object, const QString& name)
{
    const auto value = object.value(name);
    if (!value.isString() || value.toString().isEmpty()) {
        throw std::invalid_argument((name + " must be a decimal string").toStdString());
    }
    bool ok = false;
    const auto result = value.toString().toULongLong(&ok);
    if (!ok) throw std::invalid_argument((name + " is not an unsigned integer").toStdString());
    return result;
}

bool booleanValue(const QJsonObject& object, const QString& name)
{
    const auto value = object.value(name);
    if (!value.isBool()) throw std::invalid_argument((name + " must be boolean").toStdString());
    return value.toBool();
}

void skipWhitespace(const QString& text, qsizetype& position)
{
    while (position < text.size() && text[position].isSpace()) ++position;
}

QString parseJsonString(const QString& text, qsizetype& position)
{
    if (position >= text.size() || text[position] != QChar('"')) {
        throw std::invalid_argument("synthetic scenario key is not a JSON string");
    }
    ++position;
    QString result;
    while (position < text.size()) {
        const auto character = text[position++];
        if (character == QChar('"')) return result;
        if (character != QChar('\\')) {
            result += character;
            continue;
        }
        if (position >= text.size()) throw std::invalid_argument("unterminated JSON escape");
        const auto escape = text[position++];
        switch (escape.unicode()) {
        case '"': result += QChar('"'); break;
        case '\\': result += QChar('\\'); break;
        case '/': result += QChar('/'); break;
        case 'b': result += QChar('\b'); break;
        case 'f': result += QChar('\f'); break;
        case 'n': result += QChar('\n'); break;
        case 'r': result += QChar('\r'); break;
        case 't': result += QChar('\t'); break;
        case 'u': {
            if (position + 4 > text.size()) throw std::invalid_argument("short unicode escape");
            bool ok = false;
            const auto codePoint = text.mid(position, 4).toUInt(&ok, 16);
            if (!ok) throw std::invalid_argument("invalid unicode escape");
            result += QChar(static_cast<ushort>(codePoint));
            position += 4;
            break;
        }
        default: throw std::invalid_argument("unknown JSON escape");
        }
    }
    throw std::invalid_argument("unterminated JSON string");
}

void skipJsonValue(const QString& text, qsizetype& position)
{
    int depth = 0;
    while (position < text.size()) {
        skipWhitespace(text, position);
        if (position >= text.size()) break;
        const auto character = text[position];
        if (character == QChar('"')) {
            static_cast<void>(parseJsonString(text, position));
            continue;
        }
        if (character == QChar('{') || character == QChar('[')) {
            ++depth;
            ++position;
            continue;
        }
        if (character == QChar('}') || character == QChar(']')) {
            if (depth == 0) return;
            --depth;
            ++position;
            if (depth == 0) return;
            continue;
        }
        if (depth == 0 && character == QChar(',')) return;
        ++position;
    }
}

std::vector<QString> decodedObjectMemberNames(const QString& text)
{
    qsizetype position = 0;
    skipWhitespace(text, position);
    if (position >= text.size() || text[position++] != QChar('{')) {
        throw std::invalid_argument("synthetic scenario root is not an object");
    }
    std::vector<QString> names;
    while (true) {
        skipWhitespace(text, position);
        if (position < text.size() && text[position] == QChar('}')) break;
        names.push_back(parseJsonString(text, position));
        skipWhitespace(text, position);
        if (position >= text.size() || text[position++] != QChar(':')) {
            throw std::invalid_argument("synthetic scenario member has no colon");
        }
        skipJsonValue(text, position);
        skipWhitespace(text, position);
        if (position < text.size() && text[position] == QChar(',')) {
            ++position;
            continue;
        }
        if (position < text.size() && text[position] == QChar('}')) break;
        throw std::invalid_argument("synthetic scenario object separator is invalid");
    }
    return names;
}

} // namespace

QString syntheticOutcomeName(SyntheticOutcome outcome)
{
    return outcomeToString(outcome);
}

void validateSyntheticScenario(const SyntheticScenario& scenario)
{
    if (scenario.outcome != SyntheticOutcome::Completed &&
        scenario.outcome != SyntheticOutcome::WorkerFailure &&
        scenario.outcome != SyntheticOutcome::AbnormalExit &&
        scenario.outcome != SyntheticOutcome::WaitForCancellation) {
        throw std::invalid_argument("synthetic outcome enum is invalid");
    }
    if (scenario.preparationBytes > kMaximumAllocationBytes ||
        scenario.executionBytes > kMaximumAllocationBytes) {
        throw std::invalid_argument("synthetic allocation exceeds qualification limit");
    }
    if (scenario.preparationHoldMilliseconds == 0 ||
        scenario.executionHoldMilliseconds == 0 ||
        scenario.preparationHoldMilliseconds > kMaximumHoldMilliseconds ||
        scenario.executionHoldMilliseconds > kMaximumHoldMilliseconds) {
        throw std::invalid_argument("synthetic hold duration is outside qualification limits");
    }
}

SyntheticScenario parseSyntheticScenario(const QString& encoded)
{
    QJsonParseError parseError{};
    const auto document = QJsonDocument::fromJson(encoded.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        throw std::invalid_argument("synthetic scenario must be a JSON object");
    }

    const auto object = document.object();
    const QStringList required{
        QStringLiteral("preparationBytes"), QStringLiteral("executionBytes"),
        QStringLiteral("preparationHoldMilliseconds"), QStringLiteral("executionHoldMilliseconds"),
        QStringLiteral("releasePreparationBeforeBoundary"), QStringLiteral("releaseExecutionBeforeEnd"),
        QStringLiteral("outcome")};
    for (const auto& name : required) {
        if (!object.contains(name)) {
            throw std::invalid_argument(("missing synthetic scenario field: " + name).toStdString());
        }
    }
    if (object.size() != required.size()) throw std::invalid_argument("unknown synthetic scenario field");

    QHash<QString, int> counts;
    for (const auto& name : decodedObjectMemberNames(encoded)) ++counts[name];
    for (const auto& name : required) {
        if (counts.value(name) != 1) {
            throw std::invalid_argument(("duplicate synthetic scenario field: " + name).toStdString());
        }
    }

    SyntheticScenario result;
    result.preparationBytes = unsignedValue(object, QStringLiteral("preparationBytes"));
    result.executionBytes = unsignedValue(object, QStringLiteral("executionBytes"));
    const auto preparationHold = unsignedValue(object, QStringLiteral("preparationHoldMilliseconds"));
    const auto executionHold = unsignedValue(object, QStringLiteral("executionHoldMilliseconds"));
    if (preparationHold > std::numeric_limits<std::uint32_t>::max() ||
        executionHold > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("synthetic hold duration overflows uint32");
    }
    result.preparationHoldMilliseconds = static_cast<std::uint32_t>(preparationHold);
    result.executionHoldMilliseconds = static_cast<std::uint32_t>(executionHold);
    result.releasePreparationBeforeBoundary = booleanValue(
        object, QStringLiteral("releasePreparationBeforeBoundary"));
    result.releaseExecutionBeforeEnd = booleanValue(
        object, QStringLiteral("releaseExecutionBeforeEnd"));
    if (!object.value(QStringLiteral("outcome")).isString()) {
        throw std::invalid_argument("synthetic outcome must be a string");
    }
    result.outcome = outcomeFromString(object.value(QStringLiteral("outcome")).toString());
    validateSyntheticScenario(result);
    return result;
}

QJsonDocument encodeSyntheticScenario(const SyntheticScenario& scenario)
{
    validateSyntheticScenario(scenario);
    return QJsonDocument(QJsonObject{
        {"preparationBytes", QString::number(scenario.preparationBytes)},
        {"executionBytes", QString::number(scenario.executionBytes)},
        {"preparationHoldMilliseconds", QString::number(scenario.preparationHoldMilliseconds)},
        {"executionHoldMilliseconds", QString::number(scenario.executionHoldMilliseconds)},
        {"releasePreparationBeforeBoundary", scenario.releasePreparationBeforeBoundary},
        {"releaseExecutionBeforeEnd", scenario.releaseExecutionBeforeEnd},
        {"outcome", outcomeToString(scenario.outcome)}});
}

} // namespace cryptobench::tests
