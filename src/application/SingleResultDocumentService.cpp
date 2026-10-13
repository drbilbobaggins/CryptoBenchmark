#include <cryptobench/application/SingleResultDocumentService.h>

#include <stdexcept>
#include <variant>
#include <utility>

namespace cryptobench::application {

ResultDocument SingleResultDocumentService::create(const core::BenchmarkResult& result) const
{
    if (result.status != core::BenchmarkStatus::Completed) {
        throw std::invalid_argument("single result document requires a completed benchmark result");
    }
    if (!result.statistics.has_value()) {
        throw std::invalid_argument("completed benchmark result is missing statistics");
    }
    if (result.error.has_value()) {
        throw std::invalid_argument("completed benchmark result contains an error");
    }
    if (!result.measurementSettings.has_value() ||
        !core::isValidMeasurementSettings(*result.measurementSettings)) {
        throw std::invalid_argument("completed benchmark result has invalid measurement settings");
    }
    if (!std::holds_alternative<core::MemoryV2Statistics>(result.statistics->memory)) {
        throw std::invalid_argument("completed benchmark result is not Memory v2");
    }

    ResultDocument document{
        ResultMode::Single,
        ResultDocumentStatus::Completed,
        {ExportEntry{
            1,
            std::nullopt,
            ExportEntryStatus::Completed,
            result.config,
            result.characteristics,
            result.environment,
            result.statistics,
            std::nullopt
        }},
        std::nullopt,
        ResultMeasurementMetadata{*result.measurementSettings}
    };
    return document;
}

} // namespace cryptobench::application
