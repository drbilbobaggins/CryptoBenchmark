#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/core/StructuralCharacteristics.h>

namespace cryptobench::application {

enum class BatchInputIssueCode {
    FileOpenFailed,
    InputTooLarge,
    InvalidUtf8,
    InvalidJson,
    DuplicateKey,
    InvalidRootType,
    UnknownField,
    MissingField,
    InvalidType,
    InvalidValue,
    UnsupportedFormat,
    UnsupportedSchemaVersion,
    InvalidEntryCount,
    InvalidId,
    DuplicateId,
    UnknownProfileId,
    UnknownOperation,
    InvalidParameters,
    ConfigurationInvalid
};

std::string_view toStableString(BatchInputIssueCode code);
std::string_view toStableString(core::ValidationErrorCode code);

struct BatchInputIssue {
    BatchInputIssueCode code;
    std::string path;
    std::string technicalMessage;
    std::optional<core::ValidationErrorCode> domainCode;
};

struct BatchEntryDefinition {
    std::uint32_t entryIndex;
    std::optional<std::string> id;
    core::BenchmarkConfig config;
    core::StructuralCharacteristics characteristics;
};

class BatchInputParser;

class BatchDefinition {
public:
    const std::vector<BatchEntryDefinition>& entries() const noexcept
    {
        return entries_;
    }

private:
    explicit BatchDefinition(std::vector<BatchEntryDefinition> entries)
        : entries_(std::move(entries))
    {
    }

    std::vector<BatchEntryDefinition> entries_;

    friend class BatchInputParser;
};

} // namespace cryptobench::application
