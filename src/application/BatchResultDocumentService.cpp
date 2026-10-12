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
    if (!state.measurementSettings.has_value() ||
        !core::isValidMeasurementSettings(*state.measurementSettings)) {
        throw std::invalid_argument("batch result is missing valid measurement settings");
    }
    if (state.batchError.has_value() && state.status != BatchStatus::Failed) {
        throw std::invalid_argument("batch error requires a failed batch state");
    }

    ResultDocument document{
        ResultMode::Batch,
        documentStatus(state.status),
        {},
        state.status == BatchStatus::Failed ? state.batchError : std::nullopt
    };
    document.measurement = ResultMeasurementMetadata{*state.measurementSettings};
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
            if (!entry.result->measurementSettings.has_value() ||
                !core::isValidMeasurementSettings(*entry.result->measurementSettings) ||
                entry.result->measurementSettings->memorySamplingIntervalMilliseconds !=
                    state.measurementSettings->memorySamplingIntervalMilliseconds) {
                throw std::invalid_argument("batch entry measurement settings do not match the batch snapshot");
            }
            exported.environment = entry.result->environment;
            if (entry.status == BatchEntryStatus::Completed) {
                if (!entry.result->statistics.has_value() ||
                    !std::holds_alternative<core::MemoryV2Statistics>(entry.result->statistics->memory)) {
                    throw std::invalid_argument("completed batch entry is not Memory v2");
                }
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