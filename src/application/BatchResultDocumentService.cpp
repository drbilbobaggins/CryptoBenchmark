#include <cryptobench/application/BatchResultDocumentService.h>

#include <stdexcept>
#include <utility>

namespace cryptobench::application {

namespace {

ResultDocumentStatus documentStatus(BatchStatus status)
{
    switch (status) {
    case BatchStatus::InProgress:
        return ResultDocumentStatus::InProgress;
    case BatchStatus::Completed:
        return ResultDocumentStatus::Completed;
    case BatchStatus::CompletedWithFailures:
        return ResultDocumentStatus::CompletedWithFailures;
    case BatchStatus::Cancelled:
        return ResultDocumentStatus::Cancelled;
    case BatchStatus::Failed:
        return ResultDocumentStatus::Failed;
    }
    throw std::invalid_argument("unsupported batch status");
}

ExportEntryStatus exportStatus(BatchEntryStatus status)
{
    switch (status) {
    case BatchEntryStatus::NotStarted:
        return ExportEntryStatus::NotStarted;
    case BatchEntryStatus::Completed:
        return ExportEntryStatus::Completed;
    case BatchEntryStatus::Failed:
        return ExportEntryStatus::Failed;
    case BatchEntryStatus::Cancelled:
        return ExportEntryStatus::Cancelled;
    }
    throw std::invalid_argument("unsupported batch entry status");
}

} // namespace

ResultDocument BatchResultDocumentService::create(const BatchExecutionState& state) const
{
    if (state.batchError.has_value() && state.status != BatchStatus::Failed) {
        throw std::invalid_argument("batch error requires a failed batch state");
    }

    ResultDocument document{
        ResultMode::Batch,
        documentStatus(state.status),
        {},
        state.status == BatchStatus::Failed ? state.batchError : std::nullopt
    };
    document.entries.reserve(state.entries.size());

    for (const auto& entry : state.entries) {
        validateBatchEntryState(entry);
        ExportEntry exported{
            entry.definition.entryIndex,
            entry.definition.id,
            exportStatus(entry.status),
            entry.definition.config,
            entry.definition.characteristics,
            std::nullopt,
            std::nullopt,
            std::nullopt
        };

        if (entry.result.has_value()) {
            exported.environment = entry.result->environment;
            if (entry.status == BatchEntryStatus::Completed) {
                exported.statistics = entry.result->statistics;
            } else if (entry.status == BatchEntryStatus::Failed) {
                exported.error = entry.result->error;
            }
        }
        document.entries.push_back(std::move(exported));
    }

    return document;
}

} // namespace cryptobench::application