#include <cryptobench/application/BatchInputSchema.h>

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonParseError>
#include <QJsonValue>

#include <array>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cryptobench/application/StrictJsonPreflight.h>

namespace cryptobench::application {
namespace {

constexpr qsizetype kMaximumEntryCount = 1000;

BatchInputIssue issue(BatchInputIssueCode code, std::string path, const char* message)
{
    return {code, std::move(path), message, std::nullopt};
}

std::vector<BatchInputIssue> oneIssue(BatchInputIssueCode code, std::string path, const char* message)
{
    return {issue(code, std::move(path), message)};
}

std::string pointer(std::string_view base, std::string_view segment)
{
    std::string escaped;
    escaped.reserve(segment.size());
    for (const char character : segment) {
        if (character == '~') {
            escaped += "~0";
        } else if (character == '/') {
            escaped += "~1";
        } else {
            escaped += character;
        }
    }
    return std::string(base) + '/' + escaped;
}

std::string pointer(std::string_view base, qsizetype index)
{
    return std::string(base) + '/' + std::to_string(index);
}

const QByteArray* numberTokenForPath(const std::vector<JsonNumberToken>& numberTokens, std::string_view path)
{
    for (const auto& numberToken : numberTokens) {
        if (numberToken.path == path) {
            return &numberToken.lexeme;
        }
    }
    return nullptr;
}

bool isMathematicallyIntegralToken(const QByteArray& lexeme)
{
    const auto exponentPosition = lexeme.indexOf('e') >= 0 ? lexeme.indexOf('e') : lexeme.indexOf('E');
    const auto mantissaEnd = exponentPosition >= 0 ? exponentPosition : lexeme.size();
    const auto decimalPosition = lexeme.indexOf('.');
    const auto fractionStart = decimalPosition >= 0 ? decimalPosition + 1 : mantissaEnd;
    const auto fractionEnd = decimalPosition >= 0 ? mantissaEnd : mantissaEnd;
    const auto fractionDigits = fractionEnd - fractionStart;

    bool negativeExponent = false;
    qsizetype exponentMagnitude = 0;
    if (exponentPosition >= 0) {
        auto exponentStart = exponentPosition + 1;
        if (exponentStart < lexeme.size() && (lexeme[exponentStart] == '+' || lexeme[exponentStart] == '-')) {
            negativeExponent = lexeme[exponentStart] == '-';
            ++exponentStart;
        }
        constexpr auto maximum = std::numeric_limits<qsizetype>::max();
        for (qsizetype index = exponentStart; index < lexeme.size(); ++index) {
            const auto digit = static_cast<qsizetype>(lexeme[index] - '0');
            if (exponentMagnitude > (maximum - digit) / 10) {
                exponentMagnitude = maximum;
                break;
            }
            exponentMagnitude = exponentMagnitude * 10 + digit;
        }
    }

    if (!negativeExponent && exponentMagnitude >= fractionDigits) {
        return true;
    }

    qsizetype decimalPlaces = fractionDigits;
    if (negativeExponent) {
        if (exponentMagnitude > std::numeric_limits<qsizetype>::max() - decimalPlaces) {
            decimalPlaces = std::numeric_limits<qsizetype>::max();
        } else {
            decimalPlaces += exponentMagnitude;
        }
    } else {
        decimalPlaces -= exponentMagnitude;
    }

    qsizetype remaining = decimalPlaces;
    for (qsizetype index = mantissaEnd - 1; index >= 0 && remaining > 0; --index) {
        const auto character = lexeme[index];
        if (character == '.') {
            continue;
        }
        if (character == '-') {
            break;
        }
        if (character != '0') {
            return false;
        }
        --remaining;
    }
    return remaining == 0 || remaining > 0;
}

bool isFiniteJsonToken(const QByteArray& lexeme)
{
    return std::isfinite(std::strtod(lexeme.constData(), nullptr));
}

bool isDomRepresentableJsonToken(const QByteArray& lexeme)
{
    errno = 0;
    const auto value = std::strtod(lexeme.constData(), nullptr);
    return std::isfinite(value) && errno != ERANGE;
}

QByteArray domSafeJson(const QByteArray& utf8Bytes, const std::vector<JsonNumberToken>& numberTokens)
{
    QByteArray safeBytes = utf8Bytes;
    for (const auto& token : numberTokens) {
        if (!isDomRepresentableJsonToken(token.lexeme)) {
            safeBytes[token.startOffset] = '0';
            for (qsizetype offset = token.startOffset + 1; offset < token.endOffset; ++offset) {
                safeBytes[offset] = ' ';
            }
        }
    }
    return safeBytes;
}

bool isIntegralJsonNumber(const QJsonValue& value, std::string_view path,
                          const std::vector<JsonNumberToken>& numberTokens)
{
    if (!value.isDouble() || !std::isfinite(value.toDouble())) {
        return false;
    }
    const auto* token = numberTokenForPath(numberTokens, path);
    return token != nullptr && isFiniteJsonToken(*token) && isMathematicallyIntegralToken(*token);
}

bool isDirectEntryNumericPath(std::string_view path)
{
    constexpr std::string_view prefix = "/entries/";
    if (!path.starts_with(prefix)) {
        return false;
    }
    const auto separator = path.find('/', prefix.size());
    if (separator == std::string_view::npos || separator == prefix.size()) {
        return false;
    }
    for (std::size_t index = prefix.size(); index < separator; ++index) {
        if (path[index] < '0' || path[index] > '9') {
            return false;
        }
    }
    return path.substr(separator) == "/runs" || path.substr(separator) == "/iterationsPerRun";
}

std::optional<BatchInputIssue> invalidIntegralTokenIssue(const std::vector<JsonNumberToken>& numberTokens)
{
    for (const auto& token : numberTokens) {
        const auto isSchemaVersion = token.path == "/schemaVersion";
        const auto isEntryNumber = isDirectEntryNumericPath(token.path);
        if (isSchemaVersion || isEntryNumber) {
            if (!isFiniteJsonToken(token.lexeme) || !isMathematicallyIntegralToken(token.lexeme)) {
                return issue(BatchInputIssueCode::InvalidType, token.path,
                             isSchemaVersion ? "schemaVersion must be an integral JSON number"
                                             : "batch entry field must be an integral JSON number");
            }
        }
    }
    return std::nullopt;
}

bool isValidId(const QString& id)
{
    if (id.isEmpty() || id.size() > 64) {
        return false;
    }
    const auto first = id.front().unicode();
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9'))) {
        return false;
    }
    for (const auto character : id) {
        const auto ascii = character.unicode();
        if (ascii > 0x7FU
            || !(ascii >= 'A' && ascii <= 'Z') && !(ascii >= 'a' && ascii <= 'z')
                && !(ascii >= '0' && ascii <= '9') && ascii != '.' && ascii != '_' && ascii != '-') {
            return false;
        }
    }
    return true;
}

bool isFieldWithinLimit(const QJsonValue& value, qsizetype maximum)
{
    return value.isString() && !value.toString().isEmpty() && value.toString().size() <= maximum;
}

std::string firstNonWhitespacePath(const QByteArray& bytes)
{
    for (const auto character : bytes) {
        if (character != ' ' && character != '\t' && character != '\r' && character != '\n') {
            return std::string(1, character);
        }
    }
    return {};
}

} // namespace

BatchInputSchemaResult decodeBatchInputSchema(const QByteArray& utf8Bytes)
{
    const auto numberTokenResult = inspectJsonNumberTokens(utf8Bytes);
    if (std::holds_alternative<BatchInputIssue>(numberTokenResult)) {
        return std::vector<BatchInputIssue>{std::get<BatchInputIssue>(numberTokenResult)};
    }
    const auto& numberTokens = std::get<std::vector<JsonNumberToken>>(numberTokenResult);

    const auto first = firstNonWhitespacePath(utf8Bytes);
    if (first != "{") {
        return oneIssue(BatchInputIssueCode::InvalidRootType, {}, "batch input root must be a JSON object");
    }

    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(domSafeJson(utf8Bytes, numberTokens), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (const auto numericIssue = invalidIntegralTokenIssue(numberTokens); numericIssue.has_value()) {
            return std::vector<BatchInputIssue>{*numericIssue};
        }
        return oneIssue(BatchInputIssueCode::InvalidJson, {}, "batch input JSON document could not be parsed");
    }

    const auto root = document.object();
    const std::array requiredRootFields{"format", "schemaVersion", "entries"};
    std::vector<BatchInputIssue> issues;
    for (const auto& key : root.keys()) {
        if (key != "format" && key != "schemaVersion" && key != "entries") {
            issues.push_back(issue(BatchInputIssueCode::UnknownField, pointer({}, key.toStdString()),
                                   "unknown batch input root field"));
        }
    }
    for (const auto* key : requiredRootFields) {
        if (!root.contains(key)) {
            issues.push_back(issue(BatchInputIssueCode::MissingField, pointer({}, key),
                                   "required batch input root field is missing"));
        }
    }
    if (!issues.empty()) {
        return issues;
    }

    const auto format = root.value("format");
    if (!format.isString()) {
        issues.push_back(issue(BatchInputIssueCode::InvalidType, "/format", "format must be a JSON string"));
    } else if (format.toString() != "cryptobenchmark-batch-input") {
        issues.push_back(issue(BatchInputIssueCode::UnsupportedFormat, "/format", "unsupported batch input format"));
    }

    const auto schemaVersion = root.value("schemaVersion");
    if (!isIntegralJsonNumber(schemaVersion, "/schemaVersion", numberTokens)) {
        issues.push_back(issue(BatchInputIssueCode::InvalidType, "/schemaVersion",
                               "schemaVersion must be an integral JSON number"));
    } else if (schemaVersion.toDouble() != 1.0) {
        issues.push_back(issue(BatchInputIssueCode::UnsupportedSchemaVersion, "/schemaVersion",
                               "unsupported batch input schema version"));
    }

    const auto entriesValue = root.value("entries");
    if (!entriesValue.isArray()) {
        issues.push_back(issue(BatchInputIssueCode::InvalidType, "/entries", "entries must be a JSON array"));
    } else if (entriesValue.toArray().size() < 1 || entriesValue.toArray().size() > kMaximumEntryCount) {
        issues.push_back(issue(BatchInputIssueCode::InvalidEntryCount, "/entries",
                               "batch input entries count must be between 1 and 1000"));
    }
    if (!issues.empty()) {
        return issues;
    }

    const auto entries = entriesValue.toArray();
    std::set<QString> ids;
    for (qsizetype index = 0; index < entries.size(); ++index) {
        const auto entryPath = pointer("/entries", index);
        if (!entries[index].isObject()) {
            issues.push_back(issue(BatchInputIssueCode::InvalidType, entryPath,
                                   "batch input entry must be a JSON object"));
            continue;
        }

        const auto entry = entries[index].toObject();
        const std::array requiredEntryFields{"profileId", "operation", "iterationsPerRun", "runs", "parameters"};
        for (const auto& key : entry.keys()) {
            if (key != "id" && key != "profileId" && key != "operation" && key != "iterationsPerRun"
                && key != "runs" && key != "parameters") {
                issues.push_back(issue(BatchInputIssueCode::UnknownField,
                                       pointer(entryPath, key.toStdString()), "unknown batch entry field"));
            }
        }
        for (const auto* key : requiredEntryFields) {
            if (!entry.contains(key)) {
                issues.push_back(issue(BatchInputIssueCode::MissingField,
                                       pointer(entryPath, key), "required batch entry field is missing"));
            }
        }

        if (entry.contains("id")) {
            const auto id = entry.value("id");
            if (!id.isString() || !isValidId(id.toString())) {
                issues.push_back(issue(BatchInputIssueCode::InvalidId, pointer(entryPath, "id"),
                                       "batch entry id must match the ASCII identifier pattern"));
            } else if (ids.contains(id.toString())) {
                issues.push_back(issue(BatchInputIssueCode::DuplicateId, pointer(entryPath, "id"),
                                       "batch entry id is duplicated"));
            } else {
                ids.insert(id.toString());
            }
        }

        const auto profileId = entry.value("profileId");
        if (!isFieldWithinLimit(profileId, 64)) {
            issues.push_back(issue(BatchInputIssueCode::InvalidType, pointer(entryPath, "profileId"),
                                   "profileId must be a nonempty string of at most 64 characters"));
        }
        const auto operation = entry.value("operation");
        if (!isFieldWithinLimit(operation, 32)) {
            issues.push_back(issue(BatchInputIssueCode::InvalidType, pointer(entryPath, "operation"),
                                   "operation must be a nonempty string of at most 32 characters"));
        }
        for (const auto* key : {"iterationsPerRun", "runs"}) {
            if (!isIntegralJsonNumber(entry.value(key), pointer(entryPath, key), numberTokens)) {
                issues.push_back(issue(BatchInputIssueCode::InvalidType,
                                       pointer(entryPath, key), "batch entry field must be an integral JSON number"));
            }
        }
        if (!entry.value("parameters").isObject()) {
            issues.push_back(issue(BatchInputIssueCode::InvalidType, pointer(entryPath, "parameters"),
                                   "parameters must be a JSON object"));
        }
    }

    if (!issues.empty()) {
        return issues;
    }

    BatchInputSchema schema;
    schema.entries.reserve(static_cast<std::size_t>(entries.size()));
    schema.numberTokens = numberTokens;
    for (const auto& entry : entries) {
        schema.entries.push_back(entry.toObject());
    }
    return schema;
}

} // namespace cryptobench::application
