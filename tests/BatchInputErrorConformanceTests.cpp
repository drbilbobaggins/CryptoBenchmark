#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/core/StructuralCharacteristics.h>

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
#include <type_traits>
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
    return BatchInputParser{}.parseData(input);
}

void requireCharacteristicsEqual(
    const StructuralCharacteristics& left,
    const StructuralCharacteristics& right)
{
    require(left.index() == right.index(), "file and byte parser characteristic types differ");
    std::visit([](const auto& leftValue, const auto& rightValue) {
        using Left = std::decay_t<decltype(leftValue)>;
        using Right = std::decay_t<decltype(rightValue)>;
        if constexpr (std::is_same_v<Left, Right>) {
            if constexpr (std::is_same_v<Left, SignatureCharacteristics>) {
                const bool sameSignatureSize =
                    leftValue.signatureSize.has_value() == rightValue.signatureSize.has_value()
                    && (!leftValue.signatureSize.has_value()
                        || (leftValue.signatureSize->bytes == rightValue.signatureSize->bytes
                            && leftValue.signatureSize->kind == rightValue.signatureSize->kind));
                require(leftValue.publicKeyBytes == rightValue.publicKeyBytes
                            && leftValue.privateKeyBytes == rightValue.privateKeyBytes
                            && sameSignatureSize,
                        "file and byte parser signature characteristics differ");
            } else if constexpr (std::is_same_v<Left, KeyEstablishmentCharacteristics>) {
                require(leftValue.sharedSecretBytes == rightValue.sharedSecretBytes
                            && leftValue.publicKeyBytes == rightValue.publicKeyBytes
                            && leftValue.privateKeyBytes == rightValue.privateKeyBytes
                            && leftValue.ciphertextBytes == rightValue.ciphertextBytes,
                        "file and byte parser key-establishment characteristics differ");
            } else if constexpr (std::is_same_v<Left, AeadCharacteristics>) {
                require(leftValue.keyBytes == rightValue.keyBytes
                            && leftValue.nonceBytes == rightValue.nonceBytes
                            && leftValue.aadBytes == rightValue.aadBytes
                            && leftValue.tagBytes == rightValue.tagBytes,
                        "file and byte parser AEAD characteristics differ");
            } else {
                require(leftValue.outputBytes == rightValue.outputBytes,
                        "file and byte parser hash characteristics differ");
            }
        }
    }, left, right);
}

void requireFileDataParity(const QByteArray& input)
{
    const auto fileResult = BatchInputParser{}.parseFile(writeInput(input));
    const auto dataResult = BatchInputParser{}.parseData(input);
    require(fileResult.definition.has_value() == dataResult.definition.has_value(),
            "file and byte parser definition presence differs");
    require(fileResult.issues.size() == dataResult.issues.size(),
            "file and byte parser issue count differs");
    for (std::size_t index = 0; index < fileResult.issues.size(); ++index) {
        const auto& fileIssue = fileResult.issues[index];
        const auto& dataIssue = dataResult.issues[index];
        require(fileIssue.code == dataIssue.code && fileIssue.path == dataIssue.path
                    && fileIssue.technicalMessage == dataIssue.technicalMessage
                    && fileIssue.domainCode == dataIssue.domainCode,
                "file and byte parser issue details differ");
    }
    if (fileResult.definition.has_value()) {
        const auto& fileEntries = fileResult.definition->entries();
        const auto& dataEntries = dataResult.definition->entries();
        require(fileEntries.size() == dataEntries.size(), "file and byte parser entry counts differ");
        for (std::size_t index = 0; index < fileEntries.size(); ++index) {
            require(fileEntries[index].entryIndex == dataEntries[index].entryIndex
                        && fileEntries[index].id == dataEntries[index].id
                        && benchmarkConfigToJson(fileEntries[index].config)
                            == benchmarkConfigToJson(dataEntries[index].config),
                    "file and byte parser entry semantics differ");
            requireCharacteristicsEqual(fileEntries[index].characteristics,
                                        dataEntries[index].characteristics);
        }
    }
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

    requireNonDomainIssue(parseBytes({}), BatchInputIssueCode::InvalidJson, "");
    requireNonDomainIssue(parseBytes(QByteArray::fromHex("efbbbf")),
                          BatchInputIssueCode::InvalidJson, "");
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

    const std::vector<QByteArray> parityInputs{
        validDocument(
            R"({"id":"kept-id","profileId":"sha256","operation":"hash","iterationsPerRun":1e2,"runs":2,"parameters":{"inputSizeBytes":1.00e2}})"),
        QByteArray::fromHex("efbbbf")
            + validDocument(),
        "{\"format\":\"cryptobenchmark-batch-input\",\"entries\":[}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1,\"\\u0069nputSizeBytes\":2}}]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"missing\",\"operation\":\"missing\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]}",
        "{\"schemaVersion\":1,\"entries\":[]}",
        "[]",
        "{\"format\":\"other-format\",\"schemaVersion\":1,\"entries\":[]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":2,\"entries\":[]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[],\"extra\":true}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[]}",
        validDocument(
            R"({"id":"-invalid","profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":1}})"),
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"id\":\"same\",\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}},{\"id\":\"same\",\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}]}",
        validDocument(
            R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"unexpected":1}})"),
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1.5,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":18446744073709551616,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":4294967296,\"parameters\":{\"inputSizeBytes\":1}}]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"encrypt\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1}}]}",
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":268435457}}]}",
        QByteArray("{\xC3\x28", 3),
        QByteArray(4 * 1024 * 1024 + 1, 'x'),
        QByteArray::fromHex("efbbbf")
            + QByteArray(4 * 1024 * 1024 - 3, ' '),
        QByteArray::fromHex("efbbbf")
            + QByteArray(4 * 1024 * 1024 - 2, ' ')
    };
    for (const auto& input : parityInputs) {
        requireFileDataParity(input);
    }

    const std::array malformedUtf8{
        QByteArray::fromHex("80"),
        QByteArray::fromHex("e282"),
        QByteArray::fromHex("c0af"),
        QByteArray::fromHex("eda080"),
        QByteArray::fromHex("f4908080")
    };
    for (const auto& input : malformedUtf8) {
        requireNonDomainIssue(parseBytes(input), BatchInputIssueCode::InvalidUtf8, "");
        requireFileDataParity(input);
    }
    requireFileDataParity({});
    requireFileDataParity(QByteArray::fromHex("efbbbf"));
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
