#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkStatistics.h>
#include <cryptobench/core/EnvironmentInfo.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/StructuralCharacteristics.h>

namespace cryptobench::application {

enum class ResultMode {
    Single,
    Batch
};

enum class ResultDocumentStatus {
    InProgress,
    Completed,
    CompletedWithFailures,
    Cancelled,
    Failed
};

enum class ExportEntryStatus {
    NotStarted,
    Completed,
    Failed,
    Cancelled
};

enum class BatchErrorCode {
    OutputInitializationFailed,
    OutputWriteFailed,
    InternalError
};

enum class BatchErrorStage {
    OutputInitialization,
    SnapshotPersistence,
    Orchestration
};

std::string_view toStableString(ResultMode mode);
std::string_view toStableString(ResultDocumentStatus status);
std::string_view toStableString(ExportEntryStatus status);
std::string_view toStableString(BatchErrorCode code);
std::string_view toStableString(BatchErrorStage stage);

struct BatchError {
    BatchErrorCode code;
    BatchErrorStage stage;
    std::optional<std::uint32_t> entryIndex;
    std::string technicalMessage;
};

struct ExportEntry {
    std::uint32_t entryIndex;
    std::optional<std::string> id;
    ExportEntryStatus status;
    core::BenchmarkConfig config;
    core::StructuralCharacteristics characteristics;
    std::optional<core::EnvironmentInfo> environment;
    std::optional<core::BenchmarkStatistics> statistics;
    std::optional<core::ErrorInfo> error;
};

struct ResultDocument {
    ResultMode mode;
    ResultDocumentStatus status;
    std::vector<ExportEntry> entries;
    std::optional<BatchError> batchError = std::nullopt;
};

} // namespace cryptobench::application