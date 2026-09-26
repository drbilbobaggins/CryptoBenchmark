#include <cryptobench/application/BatchInputFile.h>

#include <QFile>
#include <QTemporaryDir>

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

QString filePath(const QTemporaryDir& directory, const char* name)
{
    return directory.filePath(QString::fromUtf8(name));
}

void writeFile(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "temporary input file could not be opened");
    require(file.write(bytes) == bytes.size(), "temporary input file could not be written");
    file.close();
}

QByteArray readSuccess(const QString& path)
{
    const auto result = readBatchInputFile(path);
    require(std::holds_alternative<QByteArray>(result), "batch input unexpectedly failed");
    return std::get<QByteArray>(result);
}

BatchInputIssue readFailure(const QString& path, BatchInputIssueCode expectedCode)
{
    const auto result = readBatchInputFile(path);
    require(std::holds_alternative<BatchInputIssue>(result), "batch input unexpectedly succeeded");
    const auto issue = std::get<BatchInputIssue>(result);
    require(issue.code == expectedCode, "batch input issue code mismatch");
    require(issue.path.empty(), "file boundary issue path was not empty");
    require(!issue.technicalMessage.empty(), "file boundary issue message was empty");
    require(!issue.domainCode.has_value(), "file boundary issue unexpectedly had a domain code");
    return issue;
}

void testValidBytesAndBom(const QTemporaryDir& directory)
{
    const auto ascii = QByteArray("{\"format\":\"batch\"}");
    writeFile(filePath(directory, "ascii.json"), ascii);
    require(readSuccess(filePath(directory, "ascii.json")) == ascii, "ASCII bytes were not preserved");

    const QByteArray multibyte("\xC2\xA2\xE2\x82\xAC\xF0\x90\x8D\x88", 9);
    writeFile(filePath(directory, "multibyte.json"), multibyte);
    require(readSuccess(filePath(directory, "multibyte.json")) == multibyte,
            "multibyte UTF-8 bytes were not preserved");

    const QByteArray bommed = QByteArray::fromHex("efbbbf") + ascii;
    writeFile(filePath(directory, "bom.json"), bommed);
    require(readSuccess(filePath(directory, "bom.json")) == ascii, "leading BOM was not removed");

    writeFile(filePath(directory, "empty.json"), {});
    require(readSuccess(filePath(directory, "empty.json")).isEmpty(), "empty input was not accepted");
    writeFile(filePath(directory, "bom-only.json"), QByteArray::fromHex("efbbbf"));
    require(readSuccess(filePath(directory, "bom-only.json")).isEmpty(), "BOM-only input was not accepted");

    const QByteArray notJson("plain UTF-8 text");
    writeFile(filePath(directory, "not-json.json"), notJson);
    require(readSuccess(filePath(directory, "not-json.json")) == notJson, "non-JSON UTF-8 was rejected");
}

void testSizeBoundaries(const QTemporaryDir& directory)
{
    const QByteArray exact(static_cast<qsizetype>(kMaxBatchInputFileBytes), 'a');
    writeFile(filePath(directory, "exact.bin"), exact);
    require(readSuccess(filePath(directory, "exact.bin")).size() == kMaxBatchInputFileBytes,
            "exact raw size was not accepted");

    const QByteArray oversized(static_cast<qsizetype>(kMaxBatchInputFileBytes + 1), 'a');
    writeFile(filePath(directory, "oversized.bin"), oversized);
    readFailure(filePath(directory, "oversized.bin"), BatchInputIssueCode::InputTooLarge);

    const QByteArray bommedExact = QByteArray::fromHex("efbbbf")
        + QByteArray(static_cast<qsizetype>(kMaxBatchInputFileBytes - 3), 'a');
    writeFile(filePath(directory, "bom-exact.bin"), bommedExact);
    require(readSuccess(filePath(directory, "bom-exact.bin")).size() == kMaxBatchInputFileBytes - 3,
            "BOM-counted exact raw size was not accepted");

    const QByteArray bommedOversized = QByteArray::fromHex("efbbbf")
        + QByteArray(static_cast<qsizetype>(kMaxBatchInputFileBytes - 2), 'a');
    writeFile(filePath(directory, "bom-oversized.bin"), bommedOversized);
    readFailure(filePath(directory, "bom-oversized.bin"), BatchInputIssueCode::InputTooLarge);
}

void testFailures(const QTemporaryDir& directory)
{
    readFailure(filePath(directory, "missing.json"), BatchInputIssueCode::FileOpenFailed);

    const std::array malformed{
        QByteArray::fromHex("80"),
        QByteArray::fromHex("e282"),
        QByteArray::fromHex("c0af"),
        QByteArray::fromHex("eda080"),
        QByteArray::fromHex("f4908080")
    };
    for (const auto& bytes : malformed) {
        const auto path = filePath(directory, "malformed.bin");
        writeFile(path, bytes);
        readFailure(path, BatchInputIssueCode::InvalidUtf8);
    }

    const auto bommedMalformedPath = filePath(directory, "bom-malformed.bin");
    writeFile(bommedMalformedPath, QByteArray::fromHex("efbbbfc2"));
    readFailure(bommedMalformedPath, BatchInputIssueCode::InvalidUtf8);
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        QTemporaryDir directory;
        if (!directory.isValid()) {
            throw std::runtime_error("temporary directory could not be created");
        }
        cryptobench::tests::testValidBytesAndBom(directory);
        std::cout << "PASS valid bytes and BOM\n";
        cryptobench::tests::testSizeBoundaries(directory);
        std::cout << "PASS size boundaries\n";
        cryptobench::tests::testFailures(directory);
        std::cout << "PASS file and UTF-8 failures\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchInputFile: " << error.what() << '\n';
        return 1;
    }
}
