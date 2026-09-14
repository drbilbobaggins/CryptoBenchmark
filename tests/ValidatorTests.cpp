#include <cryptobench/core/ConfigValidator.h>

#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace cryptobench::tests {
namespace {

using namespace core;
using SignatureInput = std::variant<NoSignatureInput, PrehashedInput, MessageInput>;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

BenchmarkConfig signatureConfig(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    SignatureInput input,
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return {profile, operation, iterations, runs, SignatureConfig{std::move(input)}};
}

BenchmarkConfig keyEstablishmentConfig(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return {profile, operation, iterations, runs, KeyEstablishmentConfig{}};
}

BenchmarkConfig aeadConfig(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    WorkloadBytes plaintextSize,
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return {profile, operation, iterations, runs, AeadConfig{plaintextSize}};
}

BenchmarkConfig hashConfig(
    AlgorithmProfileId profile,
    BenchmarkOperation operation,
    WorkloadBytes inputSize,
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return {profile, operation, iterations, runs, HashConfig{inputSize}};
}

bool hasError(const ValidationResult& result, ValidationErrorCode code, ValidationField field)
{
    for (const auto& error : result.errors) {
        if (error.code == code && error.field == field) return true;
    }
    return false;
}

void requireError(const ValidationResult& result, ValidationErrorCode code, ValidationField field)
{
    require(hasError(result, code, field), "expected validation error is missing");
}

void requireOnlyError(const ValidationResult& result, ValidationErrorCode code, ValidationField field)
{
    require(result.errors.size() == 1, "unexpected additional validation errors");
    require(result.errors.front().code == code && result.errors.front().field == field,
            "validation error code or field mismatch");
}

void requireValid(const ConfigValidator& validator, const BenchmarkConfig& config)
{
    const auto result = validator.validate(config);
    require(result.isValid(), "configuration should be valid");
}

void requireInvalid(const ConfigValidator& validator, const BenchmarkConfig& config,
                    ValidationErrorCode code, ValidationField field)
{
    const auto result = validator.validate(config);
    requireError(result, code, field);
}

void testSignatureInputTable()
{
    const ConfigValidator validator;
    struct Row {
        AlgorithmProfileId profile;
        BenchmarkOperation operation;
        SignatureInput input;
        bool valid;
    };

    const std::array rows{
        Row{AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, NoSignatureInput{}, true},
        Row{AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, PrehashedInput{}, false},
        Row{AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, MessageInput{1}, false},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, PrehashedInput{}, true},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, MessageInput{1}, true},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Verify, PrehashedInput{}, true},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Verify, MessageInput{1}, true},
        Row{AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Verify, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign, PrehashedInput{}, true},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign, MessageInput{1}, true},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Sign, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Verify, PrehashedInput{}, true},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Verify, MessageInput{1}, true},
        Row{AlgorithmProfileId::EcdsaP256Sha256, BenchmarkOperation::Verify, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::KeyGen, NoSignatureInput{}, true},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::KeyGen, PrehashedInput{}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::KeyGen, MessageInput{1}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, MessageInput{1}, true},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, PrehashedInput{}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Verify, MessageInput{1}, true},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Verify, NoSignatureInput{}, false},
        Row{AlgorithmProfileId::Ed25519, BenchmarkOperation::Verify, PrehashedInput{}, false},
        Row{AlgorithmProfileId::MlDsa65, BenchmarkOperation::Sign, MessageInput{1}, true},
        Row{AlgorithmProfileId::MlDsa65, BenchmarkOperation::Verify, PrehashedInput{}, false},
        Row{AlgorithmProfileId::SlhDsaSha2128S, BenchmarkOperation::Sign, MessageInput{1}, true},
        Row{AlgorithmProfileId::SlhDsaSha2128S, BenchmarkOperation::Verify, NoSignatureInput{}, false}
    };

    for (const auto& row : rows) {
        const auto result = validator.validate(signatureConfig(row.profile, row.operation, row.input));
        require(result.isValid() == row.valid, "signature input table row mismatch");
        if (!row.valid) requireOnlyError(result, ValidationErrorCode::SignatureInputMismatch, ValidationField::SignatureInput);
    }
}

void testIterationAndBudgetBoundaries()
{
    const ConfigValidator validator;
    const auto base = [](std::uint64_t iterations, std::uint32_t runs) {
        return keyEstablishmentConfig(AlgorithmProfileId::X25519, BenchmarkOperation::Derive, iterations, runs);
    };

    requireInvalid(validator, base(0, 1), ValidationErrorCode::IterationsOutOfRange, ValidationField::IterationsPerRun);
    requireValid(validator, base(1, 1));
    requireValid(validator, base(kMaxIterationsPerRun, 1));
    requireInvalid(validator, base(kMaxIterationsPerRun + 1, 1), ValidationErrorCode::IterationsOutOfRange, ValidationField::IterationsPerRun);
    requireInvalid(validator, base(1, 0), ValidationErrorCode::RunsOutOfRange, ValidationField::Runs);
    requireValid(validator, base(1, 1));
    requireValid(validator, base(1, kMaxRuns));
    requireInvalid(validator, base(1, kMaxRuns + 1), ValidationErrorCode::RunsOutOfRange, ValidationField::Runs);
    requireValid(validator, base(kMaxSeriesIterations, 1));
    requireInvalid(validator, base(kMaxSeriesIterations, 2), ValidationErrorCode::SeriesIterationBudgetExceeded, ValidationField::SeriesIterationBudget);
    requireInvalid(validator, base(kMaxIterationsPerRun, kMaxRuns), ValidationErrorCode::SeriesIterationBudgetExceeded, ValidationField::SeriesIterationBudget);
        const auto overflowCase = base(std::numeric_limits<std::uint64_t>::max(), 2);
        const auto overflowResult = validator.validate(overflowCase);
        require(overflowResult.errors.size() == 2, "overflow case produced unexpected errors");
        require(overflowResult.errors[0].code == ValidationErrorCode::IterationsOutOfRange &&
            overflowResult.errors[0].field == ValidationField::IterationsPerRun &&
            overflowResult.errors[1].code == ValidationErrorCode::SeriesIterationBudgetExceeded &&
            overflowResult.errors[1].field == ValidationField::SeriesIterationBudget,
            "overflow case error ordering mismatch");
}

void testWorkloadBoundaries()
{
    const ConfigValidator validator;
    const auto message = [](WorkloadBytes size) {
        return signatureConfig(AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, MessageInput{size});
    };
    const auto plaintext = [](WorkloadBytes size) {
        return aeadConfig(AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Encrypt, size);
    };
    const auto hash = [](WorkloadBytes size) {
        return hashConfig(AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, size);
    };

    requireInvalid(validator, message(0), ValidationErrorCode::WorkloadOutOfRange, ValidationField::MessageSize);
    requireValid(validator, message(1));
    requireValid(validator, message(kMaxWorkloadBytes));
    requireInvalid(validator, message(kMaxWorkloadBytes + 1), ValidationErrorCode::WorkloadOutOfRange, ValidationField::MessageSize);
    requireInvalid(validator, plaintext(0), ValidationErrorCode::WorkloadOutOfRange, ValidationField::PlaintextSize);
    requireValid(validator, plaintext(1));
    requireValid(validator, plaintext(kMaxWorkloadBytes));
    requireInvalid(validator, plaintext(kMaxWorkloadBytes + 1), ValidationErrorCode::WorkloadOutOfRange, ValidationField::PlaintextSize);
    requireValid(validator, hash(0));
    requireValid(validator, hash(1));
    requireValid(validator, hash(kMaxWorkloadBytes));
    requireInvalid(validator, hash(kMaxWorkloadBytes + 1), ValidationErrorCode::WorkloadOutOfRange, ValidationField::HashInputSize);
}

void testPrimitiveMismatches()
{
    const ConfigValidator validator;
    const std::array cases{
        BenchmarkConfig{AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 1, 1, HashConfig{1}},
        BenchmarkConfig{AlgorithmProfileId::X25519, BenchmarkOperation::Derive, 1, 1, AeadConfig{1}},
        BenchmarkConfig{AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Encrypt, 1, 1, SignatureConfig{NoSignatureInput{}}},
        BenchmarkConfig{AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 1, 1, KeyEstablishmentConfig{}}
    };

    for (const auto& config : cases) {
        const auto result = validator.validate(config);
        requireOnlyError(result, ValidationErrorCode::PrimitiveConfigMismatch, ValidationField::PrimitiveConfig);
    }
}

void testUnsupportedOperations()
{
    const ConfigValidator validator;
    const std::array cases{
        signatureConfig(AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::Sign, NoSignatureInput{}),
        keyEstablishmentConfig(AlgorithmProfileId::X25519, BenchmarkOperation::Encrypt),
        aeadConfig(AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Hash, 1),
        hashConfig(AlgorithmProfileId::Sha256, BenchmarkOperation::Verify, 1)
    };

    for (const auto& config : cases) {
        requireOnlyError(validator.validate(config), ValidationErrorCode::UnsupportedOperation, ValidationField::Operation);
    }
}

void testIndependentNonSignatureWorkloadErrors()
{
    const ConfigValidator validator;
    const auto result = validator.validate(
        aeadConfig(AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Hash, 0));
    require(result.errors.size() == 2, "AEAD independent errors were not collected");
    require(result.errors[0].code == ValidationErrorCode::UnsupportedOperation &&
            result.errors[0].field == ValidationField::Operation &&
            result.errors[1].code == ValidationErrorCode::WorkloadOutOfRange &&
            result.errors[1].field == ValidationField::PlaintextSize,
            "AEAD independent error ordering mismatch");
}

void testValidationResultAndGuarantee()
{
    const ConfigValidator validator;
    const auto validConfig = hashConfig(AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 0, 7, 3);
    ValidationResult validation{{{ValidationErrorCode::RunsOutOfRange, ValidationField::Runs, "stale"}}};
    const auto validated = validator.validateAndCreate(validConfig, validation);
    require(validated.has_value() && validation.isValid(), "valid config should create a guarantee type");
    require(validated->value().profile == validConfig.profile &&
            validated->value().operation == validConfig.operation &&
            validated->value().iterationsPerRun == validConfig.iterationsPerRun &&
            validated->value().runs == validConfig.runs &&
            std::holds_alternative<HashConfig>(validated->value().parameters) &&
            std::get<HashConfig>(validated->value().parameters).inputSize == 0,
            "validated config does not preserve the raw config");
    require(validConfig.iterationsPerRun == 7 && validConfig.runs == 3, "source config was mutated");

    const auto invalidConfig = hashConfig(AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, kMaxWorkloadBytes + 1);
    const auto invalid = validator.validateAndCreate(invalidConfig, validation);
    require(!invalid.has_value() && !validation.isValid(), "invalid config should not create a guarantee type");
}

void testInvalidProfileAndOrdering()
{
    const ConfigValidator validator;
    bool threw = false;
    try {
        static_cast<void>(validator.validate(hashConfig(static_cast<AlgorithmProfileId>(9999), BenchmarkOperation::Hash, 0)));
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "invalid typed profile did not take the invariant failure path");

    const BenchmarkConfig multiple{
        AlgorithmProfileId::X25519,
        BenchmarkOperation::Derive,
        0,
        0,
        KeyEstablishmentConfig{}
    };
    const auto result = validator.validate(multiple);
    require(result.errors.size() == 2, "unexpected dependent errors in multi-error result");
    require(result.errors[0].code == ValidationErrorCode::IterationsOutOfRange &&
            result.errors[0].field == ValidationField::IterationsPerRun,
            "first deterministic error mismatch");
    require(result.errors[1].code == ValidationErrorCode::RunsOutOfRange &&
            result.errors[1].field == ValidationField::Runs,
            "second deterministic error mismatch");

    const BenchmarkConfig mismatch{
        AlgorithmProfileId::Ed25519,
        BenchmarkOperation::Sign,
        0,
        0,
        HashConfig{1}
    };
    const auto mismatchResult = validator.validate(mismatch);
    require(mismatchResult.errors.size() == 3, "primitive mismatch should not reinterpret payload");
    require(mismatchResult.errors[0].code == ValidationErrorCode::IterationsOutOfRange &&
            mismatchResult.errors[0].field == ValidationField::IterationsPerRun &&
            mismatchResult.errors[1].code == ValidationErrorCode::RunsOutOfRange &&
            mismatchResult.errors[1].field == ValidationField::Runs &&
            mismatchResult.errors[2].code == ValidationErrorCode::PrimitiveConfigMismatch &&
            mismatchResult.errors[2].field == ValidationField::PrimitiveConfig,
            "primitive mismatch error ordering mismatch");
}

} // namespace

int runValidatorTests()
{
    const std::array tests{
        std::pair{"signature input table", &testSignatureInputTable},
        std::pair{"iteration and budget boundaries", &testIterationAndBudgetBoundaries},
        std::pair{"workload boundaries", &testWorkloadBoundaries},
        std::pair{"primitive mismatches", &testPrimitiveMismatches},
        std::pair{"unsupported operations", &testUnsupportedOperations},
        std::pair{"independent workload errors", &testIndependentNonSignatureWorkloadErrors},
        std::pair{"validation result and guarantee", &testValidationResultAndGuarantee},
        std::pair{"invalid profile and error ordering", &testInvalidProfileAndOrdering}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS validator total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
