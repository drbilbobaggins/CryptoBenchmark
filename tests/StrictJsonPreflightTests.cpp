#include <cryptobench/application/StrictJsonPreflight.h>

#include <QByteArray>
#include <QChar>
#include <QString>

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

void requireValid(const QByteArray& input)
{
    require(!strictJsonPreflight(input).has_value(), "valid JSON preflight input was rejected");
}

BatchInputIssue requireIssue(const QByteArray& input, BatchInputIssueCode code)
{
    const auto issue = strictJsonPreflight(input);
    require(issue.has_value(), "invalid JSON preflight input was accepted");
    require(issue->code == code, "JSON preflight issue code mismatch");
    require(!issue->technicalMessage.empty(), "JSON preflight issue message was empty");
    require(!issue->domainCode.has_value(), "JSON preflight issue unexpectedly had a domain code");
    return *issue;
}

void testValidValues()
{
    requireValid(" { \"name\": \"value\", \"items\": [true, false, null, -12.5e+2] } ");
        requireValid("[{\"x\": 1}, {\"x\": 2}]");
    requireValid("\"a escaped \\\" quote and \\\\ slash\\n\"");
    requireValid("[]");
    requireValid("\"root string\"");
    requireValid("42");
    requireValid("null");
}

void testDuplicateNamesAndPaths()
{
    const auto root = requireIssue("{\"key\":1,\"key\":2}", BatchInputIssueCode::DuplicateKey);
    require(root.path == "/key", "root duplicate path mismatch");

    const auto escaped = requireIssue("{\"x\":1,\"\\u0078\":2}", BatchInputIssueCode::DuplicateKey);
    require(escaped.path == "/x", "escaped duplicate path mismatch");

    const auto unicode = requireIssue(QByteArray::fromHex("7b22c3a9223a312c225c7530304539223a327d"),
                                      BatchInputIssueCode::DuplicateKey);
    require(unicode.path == QString::fromUtf8("/é").toStdString(), "Unicode duplicate path mismatch");

    const auto surrogate = requireIssue("{\"\\uD834\\uDD1E\":1,\"\\uD834\\uDD1E\":2}",
                                        BatchInputIssueCode::DuplicateKey);
    require(surrogate.path == QString::fromUtf8("/").append(QChar::highSurrogate(0x1D11E))
                                   .append(QChar::lowSurrogate(0x1D11E)).toStdString(),
            "surrogate duplicate path mismatch");

    const auto nested = requireIssue("{\"entries\":[{\"parameters\":{\"inputMode\":1,\"inputMode\":2}}]}",
                                     BatchInputIssueCode::DuplicateKey);
    require(nested.path == "/entries/0/parameters/inputMode", "nested duplicate path mismatch");

    const auto escapedPath = requireIssue("{\"a/b~c\":1,\"a\\u002Fb\\u007Ec\":2}",
                                          BatchInputIssueCode::DuplicateKey);
    require(escapedPath.path == "/a~1b~0c", "escaped JSON Pointer path mismatch");

    requireValid("{\"key\":{\"key\":1},\"other\":{\"key\":2}}");
    requireValid("{\"key\":\"key\"}");
}

void testInvalidSyntax()
{
    const std::array invalidInputs{
        QByteArray{}, QByteArray("   \n\t"), QByteArray("// comment\n{}"), QByteArray("{\"x\":1,}"),
        QByteArray("[1,]"), QByteArray("{\"x\" 1}"), QByteArray("{\"x\":1 \"y\":2}"),
        QByteArray("{\"x\":"), QByteArray("\"bad\nstring\""), QByteArray("{\"x\":\"\\q\"}"),
        QByteArray("{\"x\":\"\\uD800\"}"), QByteArray("{\"x\":\"\\uDC00\"}"),
        QByteArray("01"), QByteArray("1."), QByteArray("1e"), QByteArray("1 2"),
        QByteArray("NaN"), QByteArray("Infinity")
    };
    for (const auto& input : invalidInputs) {
        const auto issue = requireIssue(input, BatchInputIssueCode::InvalidJson);
        require(issue.path.empty(), "syntax issue path was not empty");
    }
}

void testDeepInputGuard()
{
    QByteArray deeplyNested;
    for (int index = 0; index < 600; ++index) {
        deeplyNested.append('[');
    }
    deeplyNested.append('0');
    for (int index = 0; index < 600; ++index) {
        deeplyNested.append(']');
    }
    requireIssue(deeplyNested, BatchInputIssueCode::InvalidJson);
}

void testNumberTokenInspection()
{
    const auto result = inspectJsonNumberTokens(
        "{\"schemaVersion\":1.0000000000000001,\"entries\":[{\"runs\":1e2,\"parameters\":{\"value\":1.5,\"large\":1e309}}]}");
    require(std::holds_alternative<std::vector<JsonNumberToken>>(result), "number inspection rejected valid JSON");
    const auto& tokens = std::get<std::vector<JsonNumberToken>>(result);
    require(tokens.size() == 4, "number inspection returned an unexpected token count");
    require(tokens[0].path == "/schemaVersion" && tokens[0].lexeme == "1.0000000000000001",
            "schemaVersion number lexeme was not preserved");
    require(tokens[1].path == "/entries/0/runs" && tokens[1].lexeme == "1e2",
            "nested number path or lexeme was not preserved");
        require(tokens[2].path == "/entries/0/parameters/value" && tokens[2].lexeme == "1.5",
            "parameter number path or lexeme was not preserved");
        require(tokens[3].path == "/entries/0/parameters/large" && tokens[3].lexeme == "1e309",
            "large exponent number path or lexeme was not preserved");
        require(tokens[3].startOffset < tokens[3].endOffset
            && tokens[3].endOffset - tokens[3].startOffset == tokens[3].lexeme.size(),
            "number token byte offsets were not preserved");
    require(!strictJsonPreflight("1.5").has_value(), "fractional JSON number became invalid syntax");
        require(!strictJsonPreflight("1e309").has_value(), "large exponent became invalid JSON syntax");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testValidValues();
        std::cout << "PASS valid JSON values\n";
        cryptobench::tests::testDuplicateNamesAndPaths();
        std::cout << "PASS duplicate names and paths\n";
        cryptobench::tests::testInvalidSyntax();
        std::cout << "PASS invalid syntax\n";
        cryptobench::tests::testDeepInputGuard();
        std::cout << "PASS nesting guard\n";
        cryptobench::tests::testNumberTokenInspection();
        std::cout << "PASS number token inspection\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL StrictJsonPreflight: " << error.what() << '\n';
        return 1;
    }
}
