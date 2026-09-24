#include <cryptobench/application/ResultDocument.h>

#include <stdexcept>

namespace cryptobench::application {

std::string_view toStableString(ResultMode mode)
{
    switch (mode) {
    case ResultMode::Single:
        return "single";
    case ResultMode::Batch:
        return "batch";
    }
    throw std::invalid_argument("unsupported result mode");
}

std::string_view toStableString(ResultDocumentStatus status)
{
    switch (status) {
    case ResultDocumentStatus::InProgress:
        return "inProgress";
    case ResultDocumentStatus::Completed:
        return "completed";
    case ResultDocumentStatus::CompletedWithFailures:
        return "completedWithFailures";
    case ResultDocumentStatus::Cancelled:
        return "cancelled";
    case ResultDocumentStatus::Failed:
        return "failed";
    }
    throw std::invalid_argument("unsupported result document status");
}

std::string_view toStableString(ExportEntryStatus status)
{
    switch (status) {
    case ExportEntryStatus::NotStarted:
        return "notStarted";
    case ExportEntryStatus::Completed:
        return "completed";
    case ExportEntryStatus::Failed:
        return "failed";
    case ExportEntryStatus::Cancelled:
        return "cancelled";
    }
    throw std::invalid_argument("unsupported export entry status");
}

std::string_view toStableString(BatchErrorCode code)
{
    switch (code) {
    case BatchErrorCode::OutputInitializationFailed:
        return "outputInitializationFailed";
    case BatchErrorCode::OutputWriteFailed:
        return "outputWriteFailed";
    case BatchErrorCode::InternalError:
        return "internalError";
    }
    throw std::invalid_argument("unsupported batch error code");
}

std::string_view toStableString(BatchErrorStage stage)
{
    switch (stage) {
    case BatchErrorStage::OutputInitialization:
        return "outputInitialization";
    case BatchErrorStage::SnapshotPersistence:
        return "snapshotPersistence";
    case BatchErrorStage::Orchestration:
        return "orchestration";
    }
    throw std::invalid_argument("unsupported batch error stage");
}

} // namespace cryptobench::application