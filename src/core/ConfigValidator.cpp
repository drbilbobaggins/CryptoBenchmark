#include <cryptobench/core/ConfigValidator.h>

#include <stdexcept>
#include <variant>

#include <cryptobench/core/AlgorithmRegistry.h>

namespace cryptobench::core {
namespace {

void addError(
    ValidationResult& result,
    ValidationErrorCode code,
    ValidationField field,
    const char* message)
{
    result.errors.push_back({code, field, message});
}

bool primitiveMatchesCategory(const PrimitiveConfig& parameters, PrimitiveCategory category)
{
    switch (category) {
        case PrimitiveCategory::Signature:
            return std::holds_alternative<SignatureConfig>(parameters);
        case PrimitiveCategory::KeyEstablishment:
            return std::holds_alternative<KeyEstablishmentConfig>(parameters);
        case PrimitiveCategory::Aead:
            return std::holds_alternative<AeadConfig>(parameters);
        case PrimitiveCategory::HashXof:
            return std::holds_alternative<HashConfig>(parameters);
    }

    return false;
}

bool isMessageOperation(BenchmarkOperation operation)
{
    return operation == BenchmarkOperation::Sign || operation == BenchmarkOperation::Verify;
}

bool validateSignatureInput(
    const AlgorithmProfile& profile,
    BenchmarkOperation operation,
    const SignatureConfig& signature,
    ValidationResult& result)
{
    bool inputValid = false;

    if (operation == BenchmarkOperation::KeyGen) {
        inputValid = std::holds_alternative<NoSignatureInput>(signature.input);
    } else if (isMessageOperation(operation)) {
        const auto& capability = std::get<SignatureInputCapability>(profile.inputCapability);
        if (capability.support == SignatureInputSupport::PrehashedAndMessage) {
            inputValid = std::holds_alternative<PrehashedInput>(signature.input) ||
                         std::holds_alternative<MessageInput>(signature.input);
        } else {
            inputValid = std::holds_alternative<MessageInput>(signature.input);
        }
    }

    if (!inputValid) {
        addError(result, ValidationErrorCode::SignatureInputMismatch,
                 ValidationField::SignatureInput, "signature input mode is incompatible with the profile operation");
    }

    return inputValid;
}

void validateWorkload(
    const AlgorithmProfile& profile,
    const SignatureConfig& signature,
    const PrimitiveConfig& parameters,
    ValidationResult& result)
{
    if (profile.category == PrimitiveCategory::Signature) {
        if (const auto* message = std::get_if<MessageInput>(&signature.input)) {
            if (message->messageSize == 0 || message->messageSize > kMaxWorkloadBytes) {
                addError(result, ValidationErrorCode::WorkloadOutOfRange,
                         ValidationField::MessageSize, "message size is outside the supported range");
            }
        }
    } else if (profile.category == PrimitiveCategory::Aead) {
        const auto plaintextSize = std::get<AeadConfig>(parameters).plaintextSize;
        if (plaintextSize == 0 || plaintextSize > kMaxWorkloadBytes) {
            addError(result, ValidationErrorCode::WorkloadOutOfRange,
                     ValidationField::PlaintextSize, "plaintext size is outside the supported range");
        }
    } else if (profile.category == PrimitiveCategory::HashXof) {
        const auto inputSize = std::get<HashConfig>(parameters).inputSize;
        if (inputSize > kMaxWorkloadBytes) {
            addError(result, ValidationErrorCode::WorkloadOutOfRange,
                     ValidationField::HashInputSize, "hash input size is outside the supported range");
        }
    }
}

ValidationResult validateConfig(const BenchmarkConfig& config)
{
    ValidationResult result;

    if (config.iterationsPerRun < kMinIterationsPerRun ||
        config.iterationsPerRun > kMaxIterationsPerRun) {
        addError(result, ValidationErrorCode::IterationsOutOfRange,
                 ValidationField::IterationsPerRun, "iterations per run is outside the supported range");
    }

    if (config.runs < kMinRuns || config.runs > kMaxRuns) {
        addError(result, ValidationErrorCode::RunsOutOfRange,
                 ValidationField::Runs, "runs is outside the supported range");
    }

    if (config.runs != 0 &&
        config.iterationsPerRun > kMaxSeriesIterations / config.runs) {
        addError(result, ValidationErrorCode::SeriesIterationBudgetExceeded,
                 ValidationField::SeriesIterationBudget, "total series iteration budget is exceeded");
    }

    const auto* profile = AlgorithmRegistry::find(config.profile);
    if (profile == nullptr) {
        throw std::logic_error("AlgorithmProfileId is missing from AlgorithmRegistry");
    }

    const bool operationSupported = profile->operations.contains(config.operation);
    if (!operationSupported) {
        addError(result, ValidationErrorCode::UnsupportedOperation,
                 ValidationField::Operation, "operation is not supported by the selected profile");
    }

    const bool primitiveMatches = primitiveMatchesCategory(config.parameters, profile->category);
    if (!primitiveMatches) {
        addError(result, ValidationErrorCode::PrimitiveConfigMismatch,
                 ValidationField::PrimitiveConfig, "primitive configuration does not match the profile category");
    }

    bool signatureInputUsable = false;
    if (operationSupported && primitiveMatches && profile->category == PrimitiveCategory::Signature) {
        const auto& signature = std::get<SignatureConfig>(config.parameters);
        signatureInputUsable = validateSignatureInput(*profile, config.operation, signature, result);
    }

    if (primitiveMatches &&
        (profile->category != PrimitiveCategory::Signature || operationSupported) &&
        (profile->category != PrimitiveCategory::Signature || signatureInputUsable)) {
        if (profile->category == PrimitiveCategory::Signature) {
            validateWorkload(*profile, std::get<SignatureConfig>(config.parameters), config.parameters, result);
        } else {
            const SignatureConfig emptySignature{};
            validateWorkload(*profile, emptySignature, config.parameters, result);
        }
    }

    return result;
}

} // namespace

ValidationResult ConfigValidator::validate(const BenchmarkConfig& config) const
{
    return validateConfig(config);
}

std::optional<ValidatedBenchmarkConfig> ConfigValidator::validateAndCreate(
    const BenchmarkConfig& config,
    ValidationResult& validation) const
{
    validation = validateConfig(config);
    if (!validation.isValid()) {
        return std::nullopt;
    }

    return ValidatedBenchmarkConfig(config);
}

} // namespace cryptobench::core
