#include <cryptobench/application/BatchInputParser.h>

#include <QFile>
#include <QTemporaryDir>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/StructuralCharacteristics.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace cryptobench::tests {
namespace {

using application::BatchInputIssueCode;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QByteArray documentForEntry(const QByteArray& entry)
{
    return R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)" + entry + "]}";
}

const application::BatchInputIssue& requireIssue(
    const application::BatchParseResult& result,
    BatchInputIssueCode code,
    std::string_view path)
{
    require(!result.definition.has_value(), "invalid batch returned a definition");
    for (const auto& issue : result.issues) {
        if (issue.code == code && issue.path == path) {
            return issue;
        }
    }
    throw std::runtime_error("expected parser issue was not found");
}

void requireCharacteristicsEqual(
    const core::StructuralCharacteristics& actual,
    const core::StructuralCharacteristics& expected)
{
    require(actual.index() == expected.index(), "structural characteristic variant mismatch");
    std::visit([](const auto& left, const auto& right) {
        using Left = std::decay_t<decltype(left)>;
        using Right = std::decay_t<decltype(right)>;
        if constexpr (std::is_same_v<Left, Right>) {
            if constexpr (std::is_same_v<Left, core::SignatureCharacteristics>) {
                require(left.publicKeyBytes == right.publicKeyBytes, "signature public key characteristic mismatch");
                require(left.privateKeyBytes == right.privateKeyBytes, "signature private key characteristic mismatch");
                require(left.signatureSize.has_value() == right.signatureSize.has_value(), "signature size presence mismatch");
                if (left.signatureSize.has_value()) {
                    require(left.signatureSize->bytes == right.signatureSize->bytes, "signature size mismatch");
                    require(left.signatureSize->kind == right.signatureSize->kind, "signature size kind mismatch");
                }
            } else if constexpr (std::is_same_v<Left, core::KeyEstablishmentCharacteristics>) {
                require(left.sharedSecretBytes == right.sharedSecretBytes, "shared secret characteristic mismatch");
                require(left.publicKeyBytes == right.publicKeyBytes, "key establishment public key mismatch");
                require(left.privateKeyBytes == right.privateKeyBytes, "key establishment private key mismatch");
                require(left.ciphertextBytes == right.ciphertextBytes, "ciphertext characteristic mismatch");
            } else if constexpr (std::is_same_v<Left, core::AeadCharacteristics>) {
                require(left.keyBytes == right.keyBytes, "AEAD key characteristic mismatch");
                require(left.nonceBytes == right.nonceBytes, "AEAD nonce characteristic mismatch");
                require(left.aadBytes == right.aadBytes, "AEAD AAD characteristic mismatch");
                require(left.tagBytes == right.tagBytes, "AEAD tag characteristic mismatch");
            } else {
                require(left.outputBytes == right.outputBytes, "hash output characteristic mismatch");
            }
        }
    }, actual, expected);
}

QString writeInput(const QByteArray& input)
{
    static QTemporaryDir directory;
    require(directory.isValid(), "temporary directory is invalid");
    const auto path = directory.filePath("batch.json");
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "batch fixture could not be opened");
    require(file.write(input) == input.size(), "batch fixture could not be written");
    return path;
}

void testRepresentativeEntries()
{
    const auto path = writeInput(
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"id":"sig","profileId":"ed25519","operation":"sign","iterationsPerRun":1e2,"runs":2,"parameters":{"inputMode":"message","messageSizeBytes":1.00e2}},)"
        R"({"id":"prehashed","profileId":"rsa-pss-2048-sha256","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"prehashed"}},)"
        R"({"profileId":"x25519","operation":"derive","iterationsPerRun":1,"runs":1,"parameters":{}},)"
        R"({"id":"aead","profileId":"aes-256-gcm","operation":"encrypt","iterationsPerRun":1,"runs":1,"parameters":{"plaintextSizeBytes":1024}},)"
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1.0e1,"parameters":{"inputSizeBytes":64}}]})");

    const auto result = application::BatchInputParser{}.parseFile(path);
    require(result.issues.empty() && result.definition.has_value(), "representative batch was rejected");
    const auto& entries = result.definition->entries();
        require(entries.size() == 5, "entry count mismatch");
        require(entries[0].entryIndex == 1 && entries[1].entryIndex == 2 && entries[2].entryIndex == 3
            && entries[3].entryIndex == 4 && entries[4].entryIndex == 5,
            "entry indexes were not one-based and ordered");
        require(entries[0].id == "sig" && entries[1].id == "prehashed" && entries[3].id == "aead"
            && !entries[2].id.has_value() && !entries[4].id.has_value(),
            "entry IDs were not preserved");
        require(entries[0].config.profile == core::AlgorithmProfileId::Ed25519
            && entries[0].config.operation == core::BenchmarkOperation::Sign,
            "message signature profile or operation mismatch");
        require(entries[1].config.profile == core::AlgorithmProfileId::RsaPss2048Sha256
            && entries[1].config.operation == core::BenchmarkOperation::Sign,
            "prehashed signature profile or operation mismatch");
        require(entries[2].config.profile == core::AlgorithmProfileId::X25519
            && entries[2].config.operation == core::BenchmarkOperation::Derive,
            "key establishment profile or operation mismatch");
        require(entries[3].config.profile == core::AlgorithmProfileId::Aes256Gcm
            && entries[3].config.operation == core::BenchmarkOperation::Encrypt,
            "AEAD profile or operation mismatch");
        require(entries[4].config.profile == core::AlgorithmProfileId::Sha256
            && entries[4].config.operation == core::BenchmarkOperation::Hash,
            "hash profile or operation mismatch");
        require(entries[0].config.iterationsPerRun == 100 && entries[0].config.runs == 2
            && entries[4].config.iterationsPerRun == 1 && entries[4].config.runs == 10,
            "exact entry numbers were not preserved");
        require(std::holds_alternative<core::MessageInput>(std::get<core::SignatureConfig>(entries[0].config.parameters).input)
            && std::get<core::MessageInput>(std::get<core::SignatureConfig>(entries[0].config.parameters).input).messageSize == 100,
            "exact parameter number was not preserved");
        require(std::holds_alternative<core::PrehashedInput>(std::get<core::SignatureConfig>(entries[1].config.parameters).input),
            "prehashed signature input was not typed");
        require(std::holds_alternative<core::KeyEstablishmentConfig>(entries[2].config.parameters),
            "key-establishment parameters were not typed");
        require(std::holds_alternative<core::AeadConfig>(entries[3].config.parameters)
            && std::get<core::AeadConfig>(entries[3].config.parameters).plaintextSize == 1024,
            "AEAD parameters were not typed");
        require(std::holds_alternative<core::HashConfig>(entries[4].config.parameters)
            && std::get<core::HashConfig>(entries[4].config.parameters).inputSize == 64,
            "hash parameters were not typed");
        for (const auto& entry : entries) {
        const auto* profile = core::AlgorithmRegistry::find(entry.config.profile);
        require(profile != nullptr, "representative profile was not found in registry");
        requireCharacteristicsEqual(entry.characteristics, profile->characteristics);
        }
}

void testStableNameRejections()
{
    for (const auto profileId : {QByteArray("unknown-profile"), QByteArray("SHA256"),
                                 QByteArray("SHA-256"), QByteArray("sha256-extra")}) {
        const auto path = writeInput(documentForEntry(
            "{\"profileId\":\"" + profileId
            + "\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}"));
        const auto result = application::BatchInputParser{}.parseFile(path);
        const auto& issue = requireIssue(result, BatchInputIssueCode::UnknownProfileId, "/entries/0/profileId");
        require(!issue.domainCode.has_value(), "unknown profile issue has a domain code");
    }

    for (const auto operation : {QByteArray("unknown-operation"), QByteArray("HASH")}) {
        const auto path = writeInput(documentForEntry(
            "{\"profileId\":\"sha256\",\"operation\":\"" + operation
            + "\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}"));
        const auto result = application::BatchInputParser{}.parseFile(path);
        const auto& issue = requireIssue(result, BatchInputIssueCode::UnknownOperation, "/entries/0/operation");
        require(!issue.domainCode.has_value(), "unknown operation issue has a domain code");
    }
}

void testExactEntryNumberRejections()
{
    const auto tooManyIterations = writeInput(documentForEntry(
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":18446744073709551616,"runs":1,"parameters":{"inputSizeBytes":1}})"));
    const auto iterationResult = application::BatchInputParser{}.parseFile(tooManyIterations);
    const auto& iterationIssue = requireIssue(iterationResult, BatchInputIssueCode::InvalidValue,
                                              "/entries/0/iterationsPerRun");
    require(!iterationIssue.domainCode.has_value(), "iteration representation issue has a domain code");

    const auto tooManyRuns = writeInput(documentForEntry(
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":4294967296,"parameters":{"inputSizeBytes":1}})"));
    const auto runsResult = application::BatchInputParser{}.parseFile(tooManyRuns);
    const auto& runsIssue = requireIssue(runsResult, BatchInputIssueCode::InvalidValue, "/entries/0/runs");
    require(!runsIssue.domainCode.has_value(), "runs representation issue has a domain code");
}

void testValidatorMappings()
{
    const auto signaturePath = writeInput(documentForEntry(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"prehashed"}})"));
    const auto signatureResult = application::BatchInputParser{}.parseFile(signaturePath);
    const auto& signatureIssue = requireIssue(signatureResult, BatchInputIssueCode::ConfigurationInvalid,
                                              "/entries/0/parameters/inputMode");
    require(signatureIssue.domainCode == core::ValidationErrorCode::SignatureInputMismatch
                && !signatureIssue.technicalMessage.empty(),
            "signature input validator mapping mismatch");

    const auto budgetPath = writeInput(documentForEntry(
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1000000000,"runs":2,"parameters":{"inputSizeBytes":1}})"));
    const auto budgetResult = application::BatchInputParser{}.parseFile(budgetPath);
    const auto& budgetIssue = requireIssue(budgetResult, BatchInputIssueCode::ConfigurationInvalid, "/entries/0");
    require(budgetIssue.domainCode == core::ValidationErrorCode::SeriesIterationBudgetExceeded
                && !budgetIssue.technicalMessage.empty(),
            "series budget validator mapping mismatch");

    const auto workloadPath = writeInput(documentForEntry(
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":268435457}})"));
    const auto workloadResult = application::BatchInputParser{}.parseFile(workloadPath);
    const auto& workloadIssue = requireIssue(workloadResult, BatchInputIssueCode::ConfigurationInvalid,
                                             "/entries/0/parameters/inputSizeBytes");
    require(workloadIssue.domainCode == core::ValidationErrorCode::WorkloadOutOfRange
                && !workloadIssue.technicalMessage.empty(),
            "workload validator mapping mismatch");
}

void testValidatorMappingAndAccumulation()
{
    const auto path = writeInput(
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
        R"({"profileId":"sha256","operation":"encrypt","iterationsPerRun":0,"runs":1001,"parameters":{"inputSizeBytes":1}},)"
        R"({"profileId":"missing","operation":"missing","iterationsPerRun":1,"runs":1,"parameters":{}}]})");

    const auto result = application::BatchInputParser{}.parseFile(path);
    require(!result.definition.has_value(), "invalid batch returned a definition");
    require(result.issues.size() >= 5, "semantic issues were not accumulated");
    bool operationMapped = false;
    bool iterationsMapped = false;
    bool runsMapped = false;
    bool domainCodePreserved = false;
    bool laterOperationRetained = false;
    for (const auto& issue : result.issues) {
        operationMapped = operationMapped || (issue.code == BatchInputIssueCode::ConfigurationInvalid
                                               && issue.path == "/entries/0/operation"
                                               && issue.domainCode == core::ValidationErrorCode::UnsupportedOperation
                                               && !issue.technicalMessage.empty());
        iterationsMapped = iterationsMapped || (issue.code == BatchInputIssueCode::ConfigurationInvalid
                                                 && issue.path == "/entries/0/iterationsPerRun"
                                                 && issue.domainCode == core::ValidationErrorCode::IterationsOutOfRange
                                                 && !issue.technicalMessage.empty());
        runsMapped = runsMapped || (issue.code == BatchInputIssueCode::ConfigurationInvalid
                                    && issue.path == "/entries/0/runs"
                                    && issue.domainCode == core::ValidationErrorCode::RunsOutOfRange
                                    && !issue.technicalMessage.empty());
        domainCodePreserved = domainCodePreserved
            || (issue.path == "/entries/0/operation"
                && issue.domainCode == core::ValidationErrorCode::UnsupportedOperation);
        laterOperationRetained = laterOperationRetained
            || (issue.code == BatchInputIssueCode::UnknownOperation
                && issue.path == "/entries/1/operation");
    }
    require(operationMapped, "operation validation issue was not mapped");
    require(iterationsMapped, "iterations validation issue was not mapped");
    require(runsMapped, "runs validation issue was not mapped");
    require(domainCodePreserved, "validator domain code was not preserved");
    require(laterOperationRetained, "later semantic issues were not retained");
}

void testFileAndSchemaPropagation()
{
    const auto missing = application::BatchInputParser{}.parseFile("does-not-exist.json");
    require(!missing.definition.has_value() && missing.issues.size() == 1
                && missing.issues.front().code == BatchInputIssueCode::FileOpenFailed,
            "file failure was not propagated");

    const auto path = writeInput("[]");
    const auto schema = application::BatchInputParser{}.parseFile(path);
    require(!schema.definition.has_value() && schema.issues.size() == 1
                && schema.issues.front().code == BatchInputIssueCode::InvalidRootType,
            "schema failure was not propagated");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testRepresentativeEntries();
        cryptobench::tests::testStableNameRejections();
        cryptobench::tests::testExactEntryNumberRejections();
        cryptobench::tests::testValidatorMappings();
        cryptobench::tests::testValidatorMappingAndAccumulation();
        cryptobench::tests::testFileAndSchemaPropagation();
        std::cout << "PASS batch input parser\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
