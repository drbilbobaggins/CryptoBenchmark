#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/core/ConfigValidation.h>

#include <QFile>
#include <QTemporaryDir>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QString writeInput(const QByteArray& input)
{
    static QTemporaryDir directory;
    static std::uint32_t fileIndex = 0;
    require(directory.isValid(), "temporary directory is invalid");

    const auto path = directory.filePath(QStringLiteral("error-%1.json").arg(++fileIndex));
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "error fixture could not be opened");
    require(file.write(input) == input.size(), "error fixture could not be written");
    return path;
}

BatchParseResult parseBytes(const QByteArray& input)
{
    return BatchInputParser{}.parseFile(writeInput(input));
}

const BatchInputIssue& requireIssue(const BatchParseResult& result,
                                    BatchInputIssueCode expectedCode,
                                    std::string_view expectedPath)
{
    require(!result.definition.has_value(), "invalid batch returned a definition");
    for (const auto& issue : result.issues) {
        if (issue.code == expectedCode && issue.path == expectedPath) {
            require(!issue.technicalMessage.empty(), "parser issue has no technical message");
            return issue;
        }
    }
    throw std::runtime_error("expected parser issue was not found");
}

void requireNonDomainIssue(const BatchParseResult& result,
                           BatchInputIssueCode expectedCode,
                           std::string_view expectedPath)
{
    const auto& issue = requireIssue(result, expectedCode, expectedPath);
    require(!issue.domainCode.has_value(), "non-domain parser issue has a domain code");
}

QByteArray validDocument(std::string_view entry =
                             R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})")
{
    QByteArray document = R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)";
    document += QByteArray::fromStdString(std::string(entry));
    document += "]}";
    return document;
}

void testBatchIssueStableStrings()
{
    const std::array expected{
        std::pair{BatchInputIssueCode::FileOpenFailed, "fileOpenFailed"},
        std::pair{BatchInputIssueCode::InputTooLarge, "inputTooLarge"},
        std::pair{BatchInputIssueCode::InvalidUtf8, "invalidUtf8"},
        std::pair{BatchInputIssueCode::InvalidJson, "invalidJson"},
        std::pair{BatchInputIssueCode::DuplicateKey, "duplicateKey"},
        std::pair{BatchInputIssueCode::InvalidRootType, "invalidRootType"},
        std::pair{BatchInputIssueCode::UnknownField, "unknownField"},
        std::pair{BatchInputIssueCode::MissingField, "missingField"},
        std::pair{BatchInputIssueCode::InvalidType, "invalidType"},
        std::pair{BatchInputIssueCode::InvalidValue, "invalidValue"},
        std::pair{BatchInputIssueCode::UnsupportedFormat, "unsupportedFormat"},
        std::pair{BatchInputIssueCode::UnsupportedSchemaVersion, "unsupportedSchemaVersion"},
        std::pair{BatchInputIssueCode::InvalidEntryCount, "invalidEntryCount"},
        std::pair{BatchInputIssueCode::InvalidId, "invalidId"},
        std::pair{BatchInputIssueCode::DuplicateId, "duplicateId"},
        std::pair{BatchInputIssueCode::UnknownProfileId, "unknownProfileId"},
        std::pair{BatchInputIssueCode::UnknownOperation, "unknownOperation"},
        std::pair{BatchInputIssueCode::InvalidParameters, "invalidParameters"},
        std::pair{BatchInputIssueCode::ConfigurationInvalid, "configurationInvalid"}
    };
    for (const auto& [code, value] : expected) {
        require(toStableString(code) == value, "batch issue stable string mismatch");
    }
}

void testValidationIssueStableStrings()
{
    const std::array expected{
        std::pair{ValidationErrorCode::UnsupportedOperation, "unsupportedOperation"},
        std::pair{ValidationErrorCode::PrimitiveConfigMismatch, "primitiveConfigMismatch"},
        std::pair{ValidationErrorCode::SignatureInputMismatch, "signatureInputMismatch"},
        std::pair{ValidationErrorCode::IterationsOutOfRange, "iterationsOutOfRange"},
        std::pair{ValidationErrorCode::RunsOutOfRange, "runsOutOfRange"},
        std::pair{ValidationErrorCode::SeriesIterationBudgetExceeded, "seriesIterationBudgetExceeded"},
        std::pair{ValidationErrorCode::WorkloadOutOfRange, "workloadOutOfRange"}
    };
    for (const auto& [code, value] : expected) {
        require(toStableString(code) == value, "validation issue stable string mismatch");
    }
}

void testReachablePublicParserIssueCategories()
{
    const auto missingPath = QStringLiteral("missing-batch-input-file.json");
    const auto missing = BatchInputParser{}.parseFile(missingPath);
    requireNonDomainIssue(missing, BatchInputIssueCode::FileOpenFailed, "");

    requireNonDomainIssue(parseBytes(QByteArray(4 * 1024 * 1024 + 1, 'x')),
                          BatchInputIssueCode::InputTooLarge, "");
    requireNonDomainIssue(parseBytes(QByteArray("{\xC3\x28", 3)),
                          BatchInputIssueCode::InvalidUtf8, "");
    requireNonDomainIssue(parseBytes("{\"format\":\"cryptobenchmark-batch-input\",\"entries\":[}"),
                          BatchInputIssueCode::InvalidJson, "");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1,\"inputSizeBytes\":2}}]}"),
                          BatchInputIssueCode::DuplicateKey, "/entries/0/parameters/inputSizeBytes");
    requireNonDomainIssue(parseBytes("[]"), BatchInputIssueCode::InvalidRootType, "");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[],\"extra\":true}"),
                          BatchInputIssueCode::UnknownField, "/extra");
    requireNonDomainIssue(parseBytes("{\"schemaVersion\":1,\"entries\":[]}"),
                          BatchInputIssueCode::MissingField, "/format");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1.5,\"entries\":[]}"),
                          BatchInputIssueCode::InvalidType, "/schemaVersion");
    requireNonDomainIssue(parseBytes(validDocument(
                              R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"bad"}})")),
                          BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputMode");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"other-format\",\"schemaVersion\":1,\"entries\":[]}"),
                          BatchInputIssueCode::UnsupportedFormat, "/format");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":2,\"entries\":[]}"),
                          BatchInputIssueCode::UnsupportedSchemaVersion, "/schemaVersion");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[]}"),
                          BatchInputIssueCode::InvalidEntryCount, "/entries");
    requireNonDomainIssue(parseBytes(validDocument(
                              R"({"id":"-bad","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})")),
                          BatchInputIssueCode::InvalidId, "/entries/0/id");
    requireNonDomainIssue(parseBytes(
                              "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"id\":\"same\",\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}},{\"id\":\"same\",\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}]}"),
                          BatchInputIssueCode::DuplicateId, "/entries/1/id");
    requireNonDomainIssue(parseBytes(validDocument(
                              R"({"profileId":"missing","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})")),
                          BatchInputIssueCode::UnknownProfileId, "/entries/0/profileId");
    requireNonDomainIssue(parseBytes(validDocument(
                              R"({"profileId":"sha256","operation":"missing","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})")),
                          BatchInputIssueCode::UnknownOperation, "/entries/0/operation");

    // InvalidParameters is a stable reserved/coarse value; strict Batch JSON v1
    // decoding emits the finer UnknownField/MissingField/InvalidType/InvalidValue codes.
    require(toStableString(BatchInputIssueCode::InvalidParameters) == "invalidParameters",
            "reserved invalid-parameters stable string changed");
}

void requireConfigurationIssue(const QByteArray& document,
                               ValidationErrorCode expectedCode,
                               std::string_view expectedPath)
{
    const auto result = parseBytes(document);
    const auto& issue = requireIssue(result, BatchInputIssueCode::ConfigurationInvalid, expectedPath);
    require(issue.domainCode == expectedCode, "configuration domain code mismatch");
}

void testReachableValidatorMappings()
{
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"sha256","operation":"encrypt","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})"),
                              ValidationErrorCode::UnsupportedOperation, "/entries/0/operation");
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"prehashed"}})"),
                              ValidationErrorCode::SignatureInputMismatch, "/entries/0/parameters/inputMode");
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"sha256","operation":"hash","iterationsPerRun":0,"runs":1,"parameters":{"inputSizeBytes":1}})"),
                              ValidationErrorCode::IterationsOutOfRange, "/entries/0/iterationsPerRun");
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1001,"parameters":{"inputSizeBytes":1}})"),
                              ValidationErrorCode::RunsOutOfRange, "/entries/0/runs");
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1000000000,"runs":2,"parameters":{"inputSizeBytes":1}})"),
                              ValidationErrorCode::SeriesIterationBudgetExceeded, "/entries/0");
    requireConfigurationIssue(validDocument(
                                  R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":268435457}})"),
                              ValidationErrorCode::WorkloadOutOfRange, "/entries/0/parameters/inputSizeBytes");
}

void testDeterministicMultiEntryAccumulation()
{
    const auto result = parseBytes(
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":["
        "{\"profileId\":\"sha256\",\"operation\":\"encrypt\",\"iterationsPerRun\":0,\"runs\":1001,\"parameters\":{\"inputSizeBytes\":1}},"
        "{\"profileId\":\"missing\",\"operation\":\"missing\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]}");
    require(!result.definition.has_value(), "multi-entry invalid batch returned a definition");
    require(result.issues.size() == 5, "multi-entry issue count changed");

    const std::array expected{
        std::pair{BatchInputIssueCode::ConfigurationInvalid, "/entries/0/iterationsPerRun"},
        std::pair{BatchInputIssueCode::ConfigurationInvalid, "/entries/0/runs"},
        std::pair{BatchInputIssueCode::ConfigurationInvalid, "/entries/0/operation"},
        std::pair{BatchInputIssueCode::UnknownProfileId, "/entries/1/profileId"},
        std::pair{BatchInputIssueCode::UnknownOperation, "/entries/1/operation"}
    };
    for (std::size_t index = 0; index < expected.size(); ++index) {
        require(result.issues[index].code == expected[index].first
                    && result.issues[index].path == expected[index].second,
                "multi-entry issue order or path mismatch");
        require(!result.issues[index].technicalMessage.empty(), "multi-entry issue has no message");
    }
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testBatchIssueStableStrings();
        cryptobench::tests::testValidationIssueStableStrings();
        cryptobench::tests::testReachablePublicParserIssueCategories();
        cryptobench::tests::testReachableValidatorMappings();
        cryptobench::tests::testDeterministicMultiEntryAccumulation();
        std::cout << "PASS BatchInputErrorConformance: 19 batch strings, 7 validation strings, 18 reachable categories, 6 domain mappings\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchInputErrorConformance: " << error.what() << '\n';
        return 1;
    }
}
