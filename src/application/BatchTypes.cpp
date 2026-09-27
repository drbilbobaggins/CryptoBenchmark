#include <cryptobench/application/BatchTypes.h>

#include <stdexcept>
#include <type_traits>

namespace cryptobench::application {

namespace {

bool benchmarkConfigMatches(
    const core::BenchmarkConfig& actual,
    const core::BenchmarkConfig& expected)
{
    if (actual.profile != expected.profile || actual.operation != expected.operation ||
        actual.iterationsPerRun != expected.iterationsPerRun || actual.runs != expected.runs ||
        actual.parameters.index() != expected.parameters.index()) {
        return false;
    }

    return std::visit([](const auto& actualValue, const auto& expectedValue) {
        using Actual = std::decay_t<decltype(actualValue)>;
        using Expected = std::decay_t<decltype(expectedValue)>;
        if constexpr (!std::is_same_v<Actual, Expected>) {
            return false;
        } else if constexpr (std::is_same_v<Actual, core::SignatureConfig>) {
            if (actualValue.input.index() != expectedValue.input.index()) return false;
            return std::visit([](const auto& actualInput, const auto& expectedInput) {
                using ActualInput = std::decay_t<decltype(actualInput)>;
                using ExpectedInput = std::decay_t<decltype(expectedInput)>;
                if constexpr (!std::is_same_v<ActualInput, ExpectedInput>) {
                    return false;
                } else if constexpr (std::is_same_v<ActualInput, core::MessageInput>) {
                    return actualInput.messageSize == expectedInput.messageSize;
                } else {
                    return true;
                }
            }, actualValue.input, expectedValue.input);
        } else if constexpr (std::is_same_v<Actual, core::AeadConfig>) {
            return actualValue.plaintextSize == expectedValue.plaintextSize;
        } else if constexpr (std::is_same_v<Actual, core::HashConfig>) {
            return actualValue.inputSize == expectedValue.inputSize;
        } else {
            return true;
        }
    }, actual.parameters, expected.parameters);
}

bool characteristicsMatch(
    const core::StructuralCharacteristics& actual,
    const core::StructuralCharacteristics& expected)
{
    if (actual.index() != expected.index()) return false;

    const auto signatureSizeMatches = [](const auto& left, const auto& right) {
        if (left.has_value() != right.has_value()) return false;
        if (!left.has_value()) return true;
        return left->bytes == right->bytes && left->kind == right->kind;
    };

    return std::visit([&signatureSizeMatches](const auto& actualValue, const auto& expectedValue) {
        using Actual = std::decay_t<decltype(actualValue)>;
        using Expected = std::decay_t<decltype(expectedValue)>;
        if constexpr (!std::is_same_v<Actual, Expected>) {
            return false;
        } else if constexpr (std::is_same_v<Actual, core::SignatureCharacteristics>) {
            return actualValue.publicKeyBytes == expectedValue.publicKeyBytes &&
                   actualValue.privateKeyBytes == expectedValue.privateKeyBytes &&
                   signatureSizeMatches(actualValue.signatureSize, expectedValue.signatureSize);
        } else if constexpr (std::is_same_v<Actual, core::KeyEstablishmentCharacteristics>) {
            return actualValue.sharedSecretBytes == expectedValue.sharedSecretBytes &&
                   actualValue.publicKeyBytes == expectedValue.publicKeyBytes &&
                   actualValue.privateKeyBytes == expectedValue.privateKeyBytes &&
                   actualValue.ciphertextBytes == expectedValue.ciphertextBytes;
        } else if constexpr (std::is_same_v<Actual, core::AeadCharacteristics>) {
            return actualValue.keyBytes == expectedValue.keyBytes &&
                   actualValue.nonceBytes == expectedValue.nonceBytes &&
                   actualValue.aadBytes == expectedValue.aadBytes &&
                   actualValue.tagBytes == expectedValue.tagBytes;
        } else {
            return actualValue.outputBytes == expectedValue.outputBytes;
        }
    }, actual, expected);
}

} // namespace

std::string_view toStableString(BatchInputIssueCode code)
{
    switch (code) {
    case BatchInputIssueCode::FileOpenFailed:
        return "fileOpenFailed";
    case BatchInputIssueCode::InputTooLarge:
        return "inputTooLarge";
    case BatchInputIssueCode::InvalidUtf8:
        return "invalidUtf8";
    case BatchInputIssueCode::InvalidJson:
        return "invalidJson";
    case BatchInputIssueCode::DuplicateKey:
        return "duplicateKey";
    case BatchInputIssueCode::InvalidRootType:
        return "invalidRootType";
    case BatchInputIssueCode::UnknownField:
        return "unknownField";
    case BatchInputIssueCode::MissingField:
        return "missingField";
    case BatchInputIssueCode::InvalidType:
        return "invalidType";
    case BatchInputIssueCode::InvalidValue:
        return "invalidValue";
    case BatchInputIssueCode::UnsupportedFormat:
        return "unsupportedFormat";
    case BatchInputIssueCode::UnsupportedSchemaVersion:
        return "unsupportedSchemaVersion";
    case BatchInputIssueCode::InvalidEntryCount:
        return "invalidEntryCount";
    case BatchInputIssueCode::InvalidId:
        return "invalidId";
    case BatchInputIssueCode::DuplicateId:
        return "duplicateId";
    case BatchInputIssueCode::UnknownProfileId:
        return "unknownProfileId";
    case BatchInputIssueCode::UnknownOperation:
        return "unknownOperation";
    case BatchInputIssueCode::InvalidParameters:
        return "invalidParameters";
    case BatchInputIssueCode::ConfigurationInvalid:
        return "configurationInvalid";
    }
    throw std::invalid_argument("unsupported batch input issue code");
}

std::string_view toStableString(core::ValidationErrorCode code)
{
    switch (code) {
    case core::ValidationErrorCode::UnsupportedOperation:
        return "unsupportedOperation";
    case core::ValidationErrorCode::PrimitiveConfigMismatch:
        return "primitiveConfigMismatch";
    case core::ValidationErrorCode::SignatureInputMismatch:
        return "signatureInputMismatch";
    case core::ValidationErrorCode::IterationsOutOfRange:
        return "iterationsOutOfRange";
    case core::ValidationErrorCode::RunsOutOfRange:
        return "runsOutOfRange";
    case core::ValidationErrorCode::SeriesIterationBudgetExceeded:
        return "seriesIterationBudgetExceeded";
    case core::ValidationErrorCode::WorkloadOutOfRange:
        return "workloadOutOfRange";
    }
    throw std::invalid_argument("unsupported validation error code");
}

std::string_view toStableString(BatchEntryStatus status)
{
    switch (status) {
    case BatchEntryStatus::NotStarted:
        return "notStarted";
    case BatchEntryStatus::Completed:
        return "completed";
    case BatchEntryStatus::Failed:
        return "failed";
    case BatchEntryStatus::Cancelled:
        return "cancelled";
    }
    throw std::invalid_argument("unsupported batch entry status");
}

std::string_view toStableString(BatchStatus status)
{
    switch (status) {
    case BatchStatus::InProgress:
        return "inProgress";
    case BatchStatus::Completed:
        return "completed";
    case BatchStatus::CompletedWithFailures:
        return "completedWithFailures";
    case BatchStatus::Cancelled:
        return "cancelled";
    case BatchStatus::Failed:
        return "failed";
    }
    throw std::invalid_argument("unsupported batch status");
}

void validateBatchEntryState(const BatchEntryState& entry)
{
    const auto reject = [](const char* message) { throw std::invalid_argument(message); };
    switch (entry.status) {
    case BatchEntryStatus::NotStarted:
        if (entry.result.has_value()) reject("not-started batch entry cannot contain a result");
        return;
    case BatchEntryStatus::Completed:
        if (!entry.result || entry.result->status != core::BenchmarkStatus::Completed ||
            !entry.result->statistics || entry.result->error ||
            !benchmarkConfigMatches(entry.result->config, entry.definition.config) ||
            !characteristicsMatch(entry.result->characteristics, entry.definition.characteristics)) {
            reject("completed batch entry has an invalid benchmark result");
        }
        return;
    case BatchEntryStatus::Failed:
        if (!entry.result || entry.result->status != core::BenchmarkStatus::Failed ||
            !entry.result->error || entry.result->statistics ||
            !benchmarkConfigMatches(entry.result->config, entry.definition.config) ||
            !characteristicsMatch(entry.result->characteristics, entry.definition.characteristics)) {
            reject("failed batch entry has an invalid benchmark result");
        }
        return;
    case BatchEntryStatus::Cancelled:
        if (!entry.result || entry.result->status != core::BenchmarkStatus::Cancelled ||
            entry.result->statistics || entry.result->error ||
            !benchmarkConfigMatches(entry.result->config, entry.definition.config) ||
            !characteristicsMatch(entry.result->characteristics, entry.definition.characteristics)) {
            reject("cancelled batch entry has an invalid benchmark result");
        }
        return;
    }
    reject("unsupported batch entry status");
}

BatchExecutionState createBatchExecutionState(const BatchDefinition& definition, QString outputTarget)
{
    BatchExecutionState state;
    state.outputTarget = std::move(outputTarget);
    state.entries.reserve(definition.entries().size());
    for (const auto& definitionEntry : definition.entries()) {
        state.entries.push_back({definitionEntry, BatchEntryStatus::NotStarted, std::nullopt});
    }
    return state;
}

BatchProgress deriveBatchProgress(
    const BatchExecutionState& state,
    std::optional<core::ProgressInfo> currentProgress)
{
    BatchProgress progress;
    progress.totalEntries = static_cast<std::uint32_t>(state.entries.size());
    progress.currentEntryIndex = state.currentEntryIndex;
    progress.currentProgress = std::move(currentProgress);
    for (const auto& entry : state.entries) {
        validateBatchEntryState(entry);
        switch (entry.status) {
        case BatchEntryStatus::NotStarted:
            ++progress.notStartedCount;
            break;
        case BatchEntryStatus::Completed:
            ++progress.completedCount;
            break;
        case BatchEntryStatus::Failed:
            ++progress.failedCount;
            break;
        case BatchEntryStatus::Cancelled:
            ++progress.cancelledCount;
            break;
        }
    }
    if (state.currentEntryIndex.has_value()) {
        for (const auto& entry : state.entries) {
            if (entry.definition.entryIndex == *state.currentEntryIndex) {
                progress.currentProfile = entry.definition.config.profile;
                progress.currentOperation = entry.definition.config.operation;
                break;
            }
        }
    }
    return progress;
}

} // namespace cryptobench::application
