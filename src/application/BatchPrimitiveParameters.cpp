#include <cryptobench/application/BatchPrimitiveParameters.h>

#include <QJsonValue>

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace cryptobench::application {
namespace {

BatchInputIssue makeIssue(BatchInputIssueCode code, std::string path, const char* message)
{
    return {code, std::move(path), message, std::nullopt};
}

BatchPrimitiveParametersResult oneIssue(BatchInputIssueCode code, std::string path, const char* message)
{
    return std::vector<BatchInputIssue>{makeIssue(code, std::move(path), message)};
}

std::string childPath(std::string_view base, std::string_view key)
{
    std::string escaped;
    escaped.reserve(base.size() + key.size() + 1);
    escaped.append(base);
    escaped.push_back('/');
    for (const char character : key) {
        if (character == '~') {
            escaped.append("~0");
        } else if (character == '/') {
            escaped.append("~1");
        } else {
            escaped.push_back(character);
        }
    }
    return escaped;
}

bool isKnownField(std::string_view key, std::initializer_list<std::string_view> allowed)
{
    for (const auto candidate : allowed) {
        if (key == candidate) {
            return true;
        }
    }
    return false;
}

std::optional<BatchInputIssue> rejectUnknownFields(
    const QJsonObject& parameters,
    std::string_view parametersPath,
    std::initializer_list<std::string_view> allowed)
{
    for (const auto& key : parameters.keys()) {
        if (!isKnownField(key.toStdString(), allowed)) {
            return makeIssue(BatchInputIssueCode::UnknownField,
                             childPath(parametersPath, key.toStdString()),
                             "unknown primitive parameter field");
        }
    }
    return std::nullopt;
}

const JsonNumberToken* findNumberToken(
    std::string_view path,
    const std::vector<JsonNumberToken>& numberTokens)
{
    for (const auto& token : numberTokens) {
        if (token.path == path) {
            return &token;
        }
    }
    return nullptr;
}

bool parseExponent(std::string_view lexeme, std::size_t start, bool& negative, std::int64_t& value)
{
    negative = false;
    value = 0;
    if (start >= lexeme.size()) {
        return false;
    }
    if (lexeme[start] == '+' || lexeme[start] == '-') {
        negative = lexeme[start] == '-';
        ++start;
    }
    if (start == lexeme.size()) {
        return false;
    }
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    for (; start < lexeme.size(); ++start) {
        if (lexeme[start] < '0' || lexeme[start] > '9') {
            return false;
        }
        const auto digit = static_cast<std::int64_t>(lexeme[start] - '0');
        if (value > (maximum - digit) / 10) {
            value = maximum;
        } else if (value != maximum) {
            value = value * 10 + digit;
        }
    }
    return true;
}

bool addSigned(std::int64_t left, bool rightNegative, std::int64_t right, std::int64_t& result)
{
    if (rightNegative) {
        if (right > 0 && left < std::numeric_limits<std::int64_t>::min() + right) {
            return false;
        }
        result = left - right;
        return true;
    }
    if (left > std::numeric_limits<std::int64_t>::max() - right) {
        return false;
    }
    result = left + right;
    return true;
}

std::optional<core::WorkloadBytes> exactWorkloadValue(std::string_view lexeme)
{
    if (lexeme.empty()) {
        return std::nullopt;
    }
    std::size_t position = 0;
    const bool negative = lexeme[position] == '-';
    if (negative) {
        ++position;
    }
    if (position == lexeme.size()) {
        return std::nullopt;
    }

    std::string digits;
    std::size_t fractionalDigits = 0;
    bool afterDecimal = false;
    while (position < lexeme.size() && lexeme[position] != 'e' && lexeme[position] != 'E') {
        const auto character = lexeme[position++];
        if (character == '.') {
            afterDecimal = true;
            continue;
        }
        if (character < '0' || character > '9') {
            return std::nullopt;
        }
        digits.push_back(character);
        if (afterDecimal) {
            ++fractionalDigits;
        }
    }
    if (digits.empty()) {
        return std::nullopt;
    }

    bool exponentNegative = false;
    std::int64_t exponent = 0;
    if (position < lexeme.size() && !parseExponent(lexeme, position + 1, exponentNegative, exponent)) {
        return std::nullopt;
    }
    std::size_t firstSignificantDigit = 0;
    while (firstSignificantDigit < digits.size() && digits[firstSignificantDigit] == '0') {
        ++firstSignificantDigit;
    }
    if (firstSignificantDigit == digits.size()) {
        return 0;
    }

    if (fractionalDigits > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
    }
    std::int64_t decimalShift = 0;
    if (!addSigned(exponentNegative ? 0 : exponent, exponentNegative, exponentNegative ? exponent : 0,
                   decimalShift)) {
        return std::nullopt;
    }
    std::size_t trailingZeros = 0;
    if (decimalShift < static_cast<std::int64_t>(fractionalDigits)) {
        const auto fractionCount = static_cast<std::int64_t>(fractionalDigits);
        if (decimalShift < 0 && -decimalShift > std::numeric_limits<std::int64_t>::max() - fractionCount) {
            return std::nullopt;
        }
        const auto fractionalCount = static_cast<std::size_t>(fractionCount - decimalShift);
        if (fractionalCount > digits.size()) {
            return std::nullopt;
        }
        const auto significantEnd = digits.size() - fractionalCount;
        for (std::size_t index = significantEnd; index < digits.size(); ++index) {
            if (digits[index] != '0') {
                return std::nullopt;
            }
        }
        digits.resize(significantEnd);
    } else {
        trailingZeros = static_cast<std::size_t>(decimalShift - static_cast<std::int64_t>(fractionalDigits));
        if (trailingZeros > 20) {
            return std::nullopt;
        }
    }

    std::uint64_t value = 0;
    const auto significantEnd = digits.size();
    for (std::size_t index = firstSignificantDigit; index < significantEnd; ++index) {
        const auto digit = digits[index];
        const auto next = static_cast<std::uint64_t>(digit - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - next) / 10) {
            return std::nullopt;
        }
        value = value * 10 + next;
    }
    for (std::size_t index = 0; index < trailingZeros; ++index) {
        if (value > std::numeric_limits<std::uint64_t>::max() / 10) {
            return std::nullopt;
        }
        value *= 10;
    }
    if (negative && value != 0) {
        return std::nullopt;
    }
    return value;
}

std::optional<core::WorkloadBytes> workloadValue(
    const QJsonObject& parameters,
    std::string_view key,
    std::string_view parametersPath,
    const std::vector<JsonNumberToken>& numberTokens,
    std::vector<BatchInputIssue>& issues)
{
    const auto path = childPath(parametersPath, key);
    const auto value = parameters.value(QString::fromStdString(std::string(key)));
    if (!value.isDouble()) {
        issues.push_back(makeIssue(BatchInputIssueCode::InvalidType, path,
                                   "primitive workload parameter must be a JSON number"));
        return std::nullopt;
    }
    const auto* token = findNumberToken(path, numberTokens);
    if (token == nullptr) {
        issues.push_back(makeIssue(BatchInputIssueCode::InvalidValue, path,
                                   "original numeric token metadata is missing"));
        return std::nullopt;
    }
    const auto converted = exactWorkloadValue(token->lexeme.toStdString());
    if (!converted.has_value()) {
        issues.push_back(makeIssue(BatchInputIssueCode::InvalidValue, path,
                                   "primitive workload parameter is not an exact unsigned integer"));
        return std::nullopt;
    }
    return converted;
}

BatchPrimitiveParametersResult decodeSignature(
    const QJsonObject& parameters,
    std::string_view parametersPath,
    const std::vector<JsonNumberToken>& numberTokens)
{
    if (parameters.isEmpty()) {
        return core::SignatureConfig{core::NoSignatureInput{}};
    }
    if (const auto unknown = rejectUnknownFields(parameters, parametersPath, {"inputMode", "messageSizeBytes"});
        unknown.has_value()) {
        return std::vector<BatchInputIssue>{*unknown};
    }
    if (!parameters.contains("inputMode")) {
        return oneIssue(BatchInputIssueCode::MissingField, childPath(parametersPath, "inputMode"),
                        "inputMode is required for non-empty signature parameters");
    }
    const auto mode = parameters.value("inputMode");
    if (!mode.isString()) {
        return oneIssue(BatchInputIssueCode::InvalidType, childPath(parametersPath, "inputMode"),
                        "inputMode must be a short JSON string");
    }
    if (mode.toString().size() > 16) {
        return oneIssue(BatchInputIssueCode::InvalidValue, childPath(parametersPath, "inputMode"),
                        "inputMode exceeds the maximum length");
    }
    if (mode.toString() == "prehashed") {
        if (parameters.contains("messageSizeBytes")) {
            return oneIssue(BatchInputIssueCode::UnknownField, childPath(parametersPath, "messageSizeBytes"),
                            "messageSizeBytes is not allowed for prehashed input");
        }
        return core::SignatureConfig{core::PrehashedInput{}};
    }
    if (mode.toString() != "message") {
        return oneIssue(BatchInputIssueCode::InvalidValue, childPath(parametersPath, "inputMode"),
                        "unsupported signature inputMode");
    }
    if (!parameters.contains("messageSizeBytes")) {
        return oneIssue(BatchInputIssueCode::MissingField, childPath(parametersPath, "messageSizeBytes"),
                        "messageSizeBytes is required for message input");
    }
    std::vector<BatchInputIssue> issues;
    const auto size = workloadValue(parameters, "messageSizeBytes", parametersPath, numberTokens, issues);
    if (!issues.empty()) {
        return issues;
    }
    return core::SignatureConfig{core::MessageInput{*size}};
}

} // namespace

BatchPrimitiveParametersResult decodeBatchPrimitiveParameters(
    core::PrimitiveCategory category,
    const QJsonObject& parameters,
    std::string_view parametersPath,
    const std::vector<JsonNumberToken>& numberTokens)
{
    if (category == core::PrimitiveCategory::Signature) {
        return decodeSignature(parameters, parametersPath, numberTokens);
    }
    if (category == core::PrimitiveCategory::KeyEstablishment) {
        if (!parameters.isEmpty()) {
            return oneIssue(BatchInputIssueCode::UnknownField, childPath(parametersPath, parameters.keys().front().toStdString()),
                            "key-establishment parameters must be empty");
        }
        return core::KeyEstablishmentConfig{};
    }
    if (category != core::PrimitiveCategory::Aead && category != core::PrimitiveCategory::HashXof) {
        return oneIssue(BatchInputIssueCode::InvalidValue, std::string(parametersPath),
                        "unsupported primitive category");
    }

    const auto field = category == core::PrimitiveCategory::Aead ? "plaintextSizeBytes" : "inputSizeBytes";
    if (const auto unknown = rejectUnknownFields(parameters, parametersPath, {field});
        unknown.has_value()) {
        return std::vector<BatchInputIssue>{*unknown};
    }
    if (!parameters.contains(field)) {
        return oneIssue(BatchInputIssueCode::MissingField, childPath(parametersPath, field),
                        "required primitive workload parameter is missing");
    }
    std::vector<BatchInputIssue> issues;
    const auto size = workloadValue(parameters, field, parametersPath, numberTokens, issues);
    if (!issues.empty()) {
        return issues;
    }
    if (category == core::PrimitiveCategory::Aead) {
        return core::AeadConfig{*size};
    }
    return core::HashConfig{*size};
}

} // namespace cryptobench::application