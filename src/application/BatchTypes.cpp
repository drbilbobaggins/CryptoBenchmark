#include <cryptobench/application/BatchTypes.h>

#include <stdexcept>

namespace cryptobench::application {

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

} // namespace cryptobench::application
