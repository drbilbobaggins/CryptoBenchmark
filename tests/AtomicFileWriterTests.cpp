#include <cryptobench/application/AtomicFileWriter.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

namespace cryptobench::tests {
namespace {

using namespace application;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QByteArray readBytes(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not open written file for reading");
    return file.readAll();
}

void requireSuccess(const WriteResult& result)
{
    require(result.success, "atomic write unexpectedly failed");
    require(result.technicalMessage.isEmpty(), "successful write has a diagnostic message");
}

void testNewTargetPreservesUtf8Bytes()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("result.json");
    const auto payload = QByteArray::fromHex("7b226d657373616765223a22c3a9e29883227d");

    const auto result = AtomicFileWriter{}.writeAtomically(target, payload);

    requireSuccess(result);
    require(QFileInfo::exists(target), "new target was not created");
    require(readBytes(target) == payload, "new target bytes differ from payload");
}

void testExistingTargetIsReplaced()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("result.json");
    const QByteArray oldPayload = "old payload";
    const QByteArray newPayload = QByteArray::fromHex("e2 9c 93 20 6e 65 77");

    QFile initial(target);
    require(initial.open(QIODevice::WriteOnly), "could not create existing target");
    require(initial.write(oldPayload) == oldPayload.size(), "could not write existing target");
    initial.close();

    const auto result = AtomicFileWriter{}.writeAtomically(target, newPayload);

    requireSuccess(result);
    require(readBytes(target) == newPayload, "existing target was not replaced exactly");
    require(readBytes(target) != oldPayload, "old target bytes remain");
}

void testEmptyPayloadCreatesZeroByteFile()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("empty.json");

    QFile initial(target);
    require(initial.open(QIODevice::WriteOnly), "could not create existing target for empty replacement");
    require(initial.write("previous bytes") == 14, "could not write existing target for empty replacement");
    initial.close();

    const auto result = AtomicFileWriter{}.writeAtomically(target, {});

    requireSuccess(result);
    require(QFileInfo::exists(target), "empty target was not created");
    require(QFileInfo(target).size() == 0, "empty target is not zero bytes");
}

void testInvalidChildTargetReturnsFailure()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");

    const auto parentFilePath = directory.filePath("ordinary-file");
    QFile parentFile(parentFilePath);
    require(parentFile.open(QIODevice::WriteOnly), "could not create ordinary parent file");
    parentFile.close();

    const auto target = parentFilePath + "/child.json";
    const auto result = AtomicFileWriter{}.writeAtomically(target, QByteArray("payload"));

    require(!result.success, "invalid child target unexpectedly succeeded");
    require(!result.technicalMessage.isEmpty(), "failed write has no diagnostic message");
    require(!QFileInfo::exists(target), "invalid child target was created");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testNewTargetPreservesUtf8Bytes();
        std::cout << "PASS new target UTF-8 bytes\n";
        cryptobench::tests::testExistingTargetIsReplaced();
        std::cout << "PASS existing target replacement\n";
        cryptobench::tests::testEmptyPayloadCreatesZeroByteFile();
        std::cout << "PASS empty payload\n";
        cryptobench::tests::testInvalidChildTargetReturnsFailure();
        std::cout << "PASS invalid child target\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL AtomicFileWriter: " << error.what() << '\n';
        return 1;
    }
}
