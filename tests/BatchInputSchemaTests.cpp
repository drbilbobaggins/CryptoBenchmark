#include <cryptobench/application/BatchInputSchema.h>

#include <QJsonDocument>

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

namespace cryptobench::tests {
namespace {

using namespace application;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QByteArray validDocument(const QByteArray& entries = "[{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]")
{
    return "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":" + entries + '}';
}

QByteArray validEntry()
{
    return "{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}";
}

BatchInputIssue requireSingleIssue(const QByteArray& input, BatchInputIssueCode code)
{
    const auto result = decodeBatchInputSchema(input);
    require(std::holds_alternative<std::vector<BatchInputIssue>>(result), "invalid schema was accepted");
    const auto& issues = std::get<std::vector<BatchInputIssue>>(result);
    require(!issues.empty(), "schema failure returned no issues");
    require(issues.front().code == code, "schema issue code mismatch");
    require(!issues.front().technicalMessage.empty(), "schema issue message is empty");
    require(!issues.front().path.empty() || code == BatchInputIssueCode::InvalidJson
                || code == BatchInputIssueCode::InvalidRootType,
            "schema issue path is unexpectedly empty");
    require(!issues.front().domainCode.has_value(), "schema issue has a domain code");
    return issues.front();
}

BatchInputIssue requireIssueAt(const QByteArray& input, BatchInputIssueCode code, std::string_view path)
{
    const auto result = requireSingleIssue(input, code);
    require(result.path == path, "schema issue path mismatch");
    return result;
}

void requireValid(const QByteArray& input)
{
    const auto result = decodeBatchInputSchema(input);
    require(std::holds_alternative<BatchInputSchema>(result), "valid schema was rejected");
}

void testValidSchemaAndOrder()
{
    requireValid(validDocument());
    const auto result = decodeBatchInputSchema(validDocument(
        "[{\"id\":\"first\",\"profileId\":\"unknown-profile\",\"operation\":\"unknown-op\",\"iterationsPerRun\":1e2,\"runs\":1e2,\"parameters\":{}},"
        "{\"profileId\":\"unknown-profile\",\"operation\":\"unknown-op\",\"iterationsPerRun\":999999999999,\"runs\":1,\"parameters\":{}}]"));
    require(std::holds_alternative<BatchInputSchema>(result), "schema-valid entries were rejected");
    const auto& schema = std::get<BatchInputSchema>(result);
    require(schema.entries.size() == 2, "entry order/size was not preserved");
    require(schema.entries[0].value("id").toString() == "first", "first entry was not preserved");
    require(schema.entries[1].value("profileId").toString() == "unknown-profile",
            "second entry was not preserved");

    const auto tokenResult = decodeBatchInputSchema(
        validDocument("[{\"id\":\"0\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1.00e2,\"runs\":1,\"parameters\":{\"runs\":1.0000000000000001}}]"));
    require(std::holds_alternative<BatchInputSchema>(tokenResult), "token-preservation schema was rejected");
    const auto& tokenSchema = std::get<BatchInputSchema>(tokenResult);
    require(tokenSchema.numberTokens.size() == 4, "schema did not preserve all number tokens");
    require(tokenSchema.numberTokens[1].path == "/entries/0/iterationsPerRun"
                && tokenSchema.numberTokens[1].lexeme == "1.00e2",
            "integral exponent token was not preserved");
    require(tokenSchema.numberTokens[3].path == "/entries/0/parameters/runs"
                && tokenSchema.numberTokens[3].lexeme == "1.0000000000000001",
            "nested precision-sensitive token was not preserved");
}

void testRootAndEntryStructure()
{
    requireSingleIssue("[]", BatchInputIssueCode::InvalidRootType);
    requireSingleIssue("42", BatchInputIssueCode::InvalidRootType);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[]}",
                       BatchInputIssueCode::InvalidEntryCount);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{}]}",
                       BatchInputIssueCode::MissingField);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[1]}",
                       BatchInputIssueCode::InvalidType);
    requireSingleIssue("{\"format\":\"wrong\",\"schemaVersion\":1,\"entries\":[]}",
                       BatchInputIssueCode::UnsupportedFormat);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":2,\"entries\":[]}",
                       BatchInputIssueCode::UnsupportedSchemaVersion);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":true,\"entries\":[]}",
                       BatchInputIssueCode::InvalidType);
    const auto unknown = requireSingleIssue(
        "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"extra\":1,\"entries\":[]}",
        BatchInputIssueCode::UnknownField);
    require(unknown.path == "/extra", "root unknown-field path mismatch");
}

void testEntryFieldsAndIds()
{
    const auto unknown = requireSingleIssue(
        validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{},\"extra\":1}]"),
        BatchInputIssueCode::UnknownField);
    require(unknown.path == "/entries/0/extra", "entry unknown-field path mismatch");

    const auto invalidId = requireSingleIssue(validDocument(
        "[{\"id\":\"bad id\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
        BatchInputIssueCode::InvalidId);
    require(invalidId.path == "/entries/0/id", "invalid ID path mismatch");
    requireSingleIssue(validDocument(
        "[{\"id\":\"same\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}},{\"id\":\"same\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
        BatchInputIssueCode::DuplicateId);
    requireValid(validDocument(
        "[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}},{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireSingleIssue(validDocument(
        "[{\"profileId\":\"\",\"operation\":\"\",\"iterationsPerRun\":1.5,\"runs\":\"1\",\"parameters\":null}]"),
        BatchInputIssueCode::InvalidType);
}

void testPreflightAndCounts()
{
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"x\":1,\"x\":2}]}",
                       BatchInputIssueCode::DuplicateKey);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[1,]}",
                       BatchInputIssueCode::InvalidJson);
    requireSingleIssue("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1.5,\"entries\":[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]}",
                       BatchInputIssueCode::InvalidType);

    QByteArray manyEntries = "[";
    for (int index = 0; index < 1000; ++index) {
        if (index != 0) {
            manyEntries += ',';
        }
        manyEntries += "{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}";
    }
    manyEntries += ']';
    requireValid(validDocument(manyEntries));
}

void testCorrectiveConformanceMatrix()
{
    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[]}",
                   BatchInputIssueCode::InvalidEntryCount, "/entries");

    QByteArray oneThousandEntries = "[";
    for (int index = 0; index < 1000; ++index) {
        if (index != 0) {
            oneThousandEntries += ',';
        }
        oneThousandEntries += validEntry();
    }
    oneThousandEntries += ']';
    requireValid(validDocument(oneThousandEntries));
    auto oneThousandAndOneEntries = oneThousandEntries;
    oneThousandAndOneEntries.chop(1);
    oneThousandAndOneEntries += ',' + validEntry() + ']';
    requireIssueAt(validDocument(oneThousandAndOneEntries), BatchInputIssueCode::InvalidEntryCount, "/entries");

    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[null]}",
                   BatchInputIssueCode::InvalidType, "/entries/0");
    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[true]}",
                   BatchInputIssueCode::InvalidType, "/entries/0");

    const std::array missingFields{"profileId", "operation", "iterationsPerRun", "runs", "parameters"};
    const std::array fieldFragments{
        QByteArray("\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}"),
        QByteArray("\"profileId\":\"p\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}"),
        QByteArray("\"profileId\":\"p\",\"operation\":\"o\",\"runs\":1,\"parameters\":{}"),
        QByteArray("\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"parameters\":{}"),
        QByteArray("\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1")};
    for (std::size_t index = 0; index < missingFields.size(); ++index) {
        requireIssueAt(validDocument("[{" + fieldFragments[index] + "}]"), BatchInputIssueCode::MissingField,
                       std::string("/entries/0/") + missingFields[index]);
    }

    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1.5,\"entries\":[]}",
                   BatchInputIssueCode::InvalidType, "/schemaVersion");
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1.5,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/iterationsPerRun");
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1.0000000000000001,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/runs");
    requireValid(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1e2,\"runs\":1.00e2,\"parameters\":{}}]"));
    for (const auto& value : {QByteArray("true"), QByteArray("\"1\""), QByteArray("null")}) {
        requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":" + value
                                      + ",\"runs\":1,\"parameters\":{}}]"),
                       BatchInputIssueCode::InvalidType, "/entries/0/iterationsPerRun");
    }
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1e-9999,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/iterationsPerRun");
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1e309,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/iterationsPerRun");
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1e309,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/runs");

    const auto largeParameter = decodeBatchInputSchema(validDocument(
        "[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"inputSizeBytes\":1e309,\"opaque\":1e-9999}}]"));
    require(std::holds_alternative<BatchInputSchema>(largeParameter),
            "unrepresentable parameter number caused schema failure");
    const auto& largeParameterSchema = std::get<BatchInputSchema>(largeParameter);
    require(largeParameterSchema.numberTokens.size() == 5, "opaque parameter numbers were not retained");
    require(largeParameterSchema.numberTokens[3].path == "/entries/0/parameters/inputSizeBytes"
                && largeParameterSchema.numberTokens[3].lexeme == "1e309",
            "large parameter number was not retained");
    require(largeParameterSchema.numberTokens[4].path == "/entries/0/parameters/opaque"
                && largeParameterSchema.numberTokens[4].lexeme == "1e-9999",
            "opaque exponent number was not retained");
    requireIssueAt(validDocument(
                       "[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{},\"unknown\":1e309}]"),
                   BatchInputIssueCode::UnknownField, "/entries/0/unknown");

    requireIssueAt(validDocument("[{\"id\":\"\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidId, "/entries/0/id");
    requireValid(validDocument("[{\"id\":\"0\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireValid(validDocument("[{\"id\":\"1bad\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireValid(validDocument("[{\"id\":\"leading\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireIssueAt(validDocument("[{\"id\":\"-bad\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidId, "/entries/0/id");
    requireIssueAt(validDocument("[{\"id\":\"é\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidId, "/entries/0/id");
    requireIssueAt(validDocument("[{\"id\":\"" + QByteArray(65, 'a')
                                  + "\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidId, "/entries/0/id");
    requireValid(validDocument("[{\"id\":\"" + QByteArray(64, 'a')
                               + "\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireValid(validDocument("[{\"id\":\"A\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}},{\"id\":\"a\",\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));

    requireValid(validDocument("[{\"profileId\":\"é\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireValid(validDocument("[{\"profileId\":\"p\",\"operation\":\"é\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"));
    requireIssueAt(validDocument("[{\"profileId\":\"" + QByteArray(65, 'p')
                                  + "\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/profileId");
    requireIssueAt(validDocument("[{\"profileId\":\"p\",\"operation\":\"" + QByteArray(33, 'o')
                                  + "\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}]"),
                   BatchInputIssueCode::InvalidType, "/entries/0/operation");

    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"x\":1,\"\\u0078\":2}}]}",
                   BatchInputIssueCode::DuplicateKey, "/entries/0/parameters/x");
    requireIssueAt("{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{}}],\"\\u0065ntries\":[]}",
                   BatchInputIssueCode::DuplicateKey, "/entries");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testValidSchemaAndOrder();
        std::cout << "PASS valid schema and order\n";
        cryptobench::tests::testRootAndEntryStructure();
        std::cout << "PASS root and entry structure\n";
        cryptobench::tests::testEntryFieldsAndIds();
        std::cout << "PASS entry fields and IDs\n";
        cryptobench::tests::testPreflightAndCounts();
        std::cout << "PASS preflight and counts\n";
        cryptobench::tests::testCorrectiveConformanceMatrix();
        std::cout << "PASS corrective conformance matrix\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchInputSchema: " << error.what() << '\n';
        return 1;
    }
}
