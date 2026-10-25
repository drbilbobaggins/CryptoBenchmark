#include <cryptobench/application/BatchInputParser.h>

#include <cryptobench/application/BatchInputFile.h>
#include <cryptobench/application/BatchInputSchema.h>
#include <cryptobench/application/BatchPrimitiveParameters.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include "BatchJsonInteger.h"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace cryptobench::application {
namespace {

std::string entryPath(std::size_t index, std::string_view field = {})
{
    std::string path = "/entries/" + std::to_string(index);
    if (!field.empty()) {
        path += '/';
        path += field;
    }
    return path;
}

BatchInputIssue semanticIssue(BatchInputIssueCode code, std::string path, const char* message)
{
    return {code, std::move(path), message, std::nullopt};
}

const JsonNumberToken* numberTokenAt(const BatchInputSchema& schema, std::string_view path)
{
    for (const auto& token : schema.numberTokens) {
        if (token.path == path) {
            return &token;
        }
    }
    return nullptr;
}

std::optional<std::uint64_t> unsignedIntegerAt(
    const BatchInputSchema& schema,
    std::string_view path)
{
    const auto* token = numberTokenAt(schema, path);
    if (token == nullptr) {
        return std::nullopt;
    }
    return detail::parseExactUnsignedJsonInteger(token->lexeme.toStdString());
}

std::string validationPath(std::size_t index, core::ValidationField field)
{
    switch (field) {
    case core::ValidationField::Operation:
        return entryPath(index, "operation");
    case core::ValidationField::PrimitiveConfig:
        return entryPath(index, "parameters");
    case core::ValidationField::SignatureInput:
        return entryPath(index, "parameters/inputMode");
    case core::ValidationField::MessageSize:
        return entryPath(index, "parameters/messageSizeBytes");
    case core::ValidationField::PlaintextSize:
        return entryPath(index, "parameters/plaintextSizeBytes");
    case core::ValidationField::HashInputSize:
        return entryPath(index, "parameters/inputSizeBytes");
    case core::ValidationField::IterationsPerRun:
        return entryPath(index, "iterationsPerRun");
    case core::ValidationField::Runs:
        return entryPath(index, "runs");
    case core::ValidationField::SeriesIterationBudget:
        return entryPath(index);
    }
    return entryPath(index);
}

} // namespace

BatchParseResult BatchInputParser::parsePreparedData(const QByteArray& bytes) const
{
    const auto schemaResult = decodeBatchInputSchema(bytes);
    if (std::holds_alternative<std::vector<BatchInputIssue>>(schemaResult)) {
        return {std::nullopt, std::get<std::vector<BatchInputIssue>>(schemaResult)};
    }

    const auto& schema = std::get<BatchInputSchema>(schemaResult);
    std::vector<BatchEntryDefinition> entries;
    std::vector<BatchInputIssue> issues;
    entries.reserve(schema.entries.size());

    for (std::size_t index = 0; index < schema.entries.size(); ++index) {
        const auto& input = schema.entries[index];
        const auto profileText = input.value("profileId").toString().toStdString();
        const auto profileId = core::parseStableProfileId(profileText);
        const auto operationText = input.value("operation").toString().toStdString();
        const auto operation = parseStableOperationString(operationText);

        const auto iterations = unsignedIntegerAt(schema, entryPath(index, "iterationsPerRun"));
        const auto runsValue = unsignedIntegerAt(schema, entryPath(index, "runs"));
        const bool runsRepresentable = runsValue.has_value()
            && *runsValue <= std::numeric_limits<std::uint32_t>::max();

        const core::AlgorithmProfile* profile = nullptr;
        if (!profileId.has_value()) {
            issues.push_back(semanticIssue(BatchInputIssueCode::UnknownProfileId,
                                           entryPath(index, "profileId"), "unknown algorithm profile id"));
        } else {
            profile = core::AlgorithmRegistry::find(*profileId);
            if (profile == nullptr) {
                throw std::logic_error("AlgorithmProfileId is missing from AlgorithmRegistry");
            }
        }
        if (!operation.has_value()) {
            issues.push_back(semanticIssue(BatchInputIssueCode::UnknownOperation,
                                           entryPath(index, "operation"), "unknown benchmark operation"));
        }
        if (!iterations.has_value()) {
            issues.push_back(semanticIssue(BatchInputIssueCode::InvalidValue,
                                           entryPath(index, "iterationsPerRun"),
                                           "iterations per run is not an exact unsigned integer"));
        }
        if (!runsValue.has_value() || !runsRepresentable) {
            issues.push_back(semanticIssue(BatchInputIssueCode::InvalidValue,
                                           entryPath(index, "runs"),
                                           "runs is not an exact uint32 integer"));
        }
        if (profile == nullptr || !operation.has_value() || !iterations.has_value() || !runsRepresentable) {
            continue;
        }

        const auto parameters = decodeBatchPrimitiveParameters(
            profile->category, input.value("parameters").toObject(),
            entryPath(index, "parameters"), schema.numberTokens);
        if (std::holds_alternative<std::vector<BatchInputIssue>>(parameters)) {
            const auto& parameterIssues = std::get<std::vector<BatchInputIssue>>(parameters);
            issues.insert(issues.end(), parameterIssues.begin(), parameterIssues.end());
            continue;
        }

        core::BenchmarkConfig config{
            *profileId,
            *operation,
            *iterations,
            static_cast<std::uint32_t>(*runsValue),
            std::get<core::PrimitiveConfig>(parameters)
        };
        const auto validation = core::ConfigValidator{}.validate(config);
        if (!validation.isValid()) {
            for (const auto& error : validation.errors) {
                issues.push_back({BatchInputIssueCode::ConfigurationInvalid,
                                  validationPath(index, error.field),
                                  error.technicalMessage,
                                  error.code});
            }
            continue;
        }

        std::optional<std::string> id;
        if (input.contains("id")) {
            id = input.value("id").toString().toStdString();
        }
        entries.push_back({static_cast<std::uint32_t>(index + 1), std::move(id),
                           std::move(config), profile->characteristics});
    }

    if (!issues.empty()) {
        return {std::nullopt, std::move(issues)};
    }
    return {BatchDefinition{std::move(entries)}, {}};
}

BatchParseResult BatchInputParser::parseFile(const QString& filePath) const
{
    const auto fileResult = readBatchInputFile(filePath);
    if (std::holds_alternative<BatchInputIssue>(fileResult)) {
        return {std::nullopt, {std::get<BatchInputIssue>(fileResult)}};
    }
    return parsePreparedData(std::get<QByteArray>(fileResult));
}

BatchParseResult BatchInputParser::parseData(const QByteArray& bytes) const
{
    const auto prepared = prepareBatchInputData(bytes);
    if (std::holds_alternative<BatchInputIssue>(prepared)) {
        return {std::nullopt, {std::get<BatchInputIssue>(prepared)}};
    }
    return parsePreparedData(std::get<QByteArray>(prepared));
}

} // namespace cryptobench::application
