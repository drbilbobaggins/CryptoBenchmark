#include <cryptobench/application/BatchPrimitiveParameters.h>

#include "BatchJsonInteger.h"

#include <QJsonValue>

#include <cstdint>
#include <initializer_list>
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
    const auto converted = detail::parseExactUnsignedJsonInteger(token->lexeme.toStdString());
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