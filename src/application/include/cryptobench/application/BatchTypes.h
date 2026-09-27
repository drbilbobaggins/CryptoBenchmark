#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <QString>

#include <cryptobench/application/ResultDocument.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/core/ProgressInfo.h>
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

enum class BatchEntryStatus {
    NotStarted,
    Completed,
    Failed,
    Cancelled
};

enum class BatchStatus {
    InProgress,
    Completed,
    CompletedWithFailures,
    Cancelled,
    Failed
};

std::string_view toStableString(BatchEntryStatus status);
std::string_view toStableString(BatchStatus status);

struct BatchEntryState {
    BatchEntryDefinition definition;
    BatchEntryStatus status = BatchEntryStatus::NotStarted;
    std::optional<core::BenchmarkResult> result;
};

struct BatchExecutionState {
    std::vector<BatchEntryState> entries;
    BatchStatus status = BatchStatus::InProgress;
    std::optional<std::uint32_t> currentEntryIndex;
    bool cancelRequested = false;
    std::optional<BatchError> batchError;
    QString outputTarget;
};

struct BatchProgress {
    std::uint32_t totalEntries = 0;
    std::optional<std::uint32_t> currentEntryIndex;
    std::uint32_t completedCount = 0;
    std::uint32_t failedCount = 0;
    std::uint32_t cancelledCount = 0;
    std::uint32_t notStartedCount = 0;
    std::optional<core::AlgorithmProfileId> currentProfile;
    std::optional<core::BenchmarkOperation> currentOperation;
    std::optional<core::ProgressInfo> currentProgress;
    bool persistenceInProgress = false;
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

BatchExecutionState createBatchExecutionState(
    const BatchDefinition& definition,
    QString outputTarget);
void validateBatchEntryState(const BatchEntryState& entry);
BatchProgress deriveBatchProgress(
    const BatchExecutionState& state,
    std::optional<core::ProgressInfo> currentProgress = std::nullopt);

} // namespace cryptobench::application
