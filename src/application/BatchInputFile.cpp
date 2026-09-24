#include <cryptobench/application/BatchInputFile.h>

#include <QFile>

namespace cryptobench::application {
namespace {

BatchInputIssue fileIssue(BatchInputIssueCode code, const char* message)
{
    return {code, {}, message, std::nullopt};
}

bool isContinuation(unsigned char byte)
{
    return (byte & 0xC0U) == 0x80U;
}

bool isStrictUtf8(const QByteArray& bytes)
{
    const auto* data = reinterpret_cast<const unsigned char*>(bytes.constData());
    const auto size = bytes.size();

    for (qsizetype index = 0; index < size;) {
        const auto first = data[index];
        if (first <= 0x7FU) {
            ++index;
            continue;
        }

        if (first >= 0xC2U && first <= 0xDFU) {
            if (index + 1 >= size || !isContinuation(data[index + 1])) {
                return false;
            }
            index += 2;
            continue;
        }

        if (first == 0xE0U) {
            if (index + 2 >= size || data[index + 1] < 0xA0U || data[index + 1] > 0xBFU
                || !isContinuation(data[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }

        if ((first >= 0xE1U && first <= 0xECU) || (first >= 0xEEU && first <= 0xEFU)) {
            if (index + 2 >= size || !isContinuation(data[index + 1]) || !isContinuation(data[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }

        if (first == 0xEDU) {
            if (index + 2 >= size || data[index + 1] < 0x80U || data[index + 1] > 0x9FU
                || !isContinuation(data[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }

        if (first == 0xF0U) {
            if (index + 3 >= size || data[index + 1] < 0x90U || data[index + 1] > 0xBFU
                || !isContinuation(data[index + 2]) || !isContinuation(data[index + 3])) {
                return false;
            }
            index += 4;
            continue;
        }

        if (first >= 0xF1U && first <= 0xF3U) {
            if (index + 3 >= size || !isContinuation(data[index + 1]) || !isContinuation(data[index + 2])
                || !isContinuation(data[index + 3])) {
                return false;
            }
            index += 4;
            continue;
        }

        if (first == 0xF4U) {
            if (index + 3 >= size || data[index + 1] < 0x80U || data[index + 1] > 0x8FU
                || !isContinuation(data[index + 2]) || !isContinuation(data[index + 3])) {
                return false;
            }
            index += 4;
            continue;
        }

        return false;
    }

    return true;
}

} // namespace

std::variant<QByteArray, BatchInputIssue> readBatchInputFile(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return fileIssue(BatchInputIssueCode::FileOpenFailed, "unable to open batch input file");
    }

    if (file.size() > kMaxBatchInputFileBytes) {
        return fileIssue(BatchInputIssueCode::InputTooLarge, "batch input file exceeds the 4 MiB limit");
    }

    QByteArray bytes;
    bytes.reserve(static_cast<qsizetype>(kMaxBatchInputFileBytes + 1));
    while (bytes.size() <= kMaxBatchInputFileBytes) {
        const auto remaining = kMaxBatchInputFileBytes + 1 - bytes.size();
        const auto chunk = file.read(remaining);
        if (chunk.isEmpty()) {
            if (file.error() != QFileDevice::NoError) {
                return fileIssue(BatchInputIssueCode::FileOpenFailed, "unable to read batch input file");
            }
            break;
        }
        bytes.append(chunk);
        if (bytes.size() > kMaxBatchInputFileBytes) {
            return fileIssue(BatchInputIssueCode::InputTooLarge, "batch input file exceeds the 4 MiB limit");
        }
    }

    if (bytes.startsWith(QByteArray::fromHex("efbbbf"))) {
        bytes.remove(0, 3);
    }

    if (!isStrictUtf8(bytes)) {
        return fileIssue(BatchInputIssueCode::InvalidUtf8, "batch input file is not valid UTF-8");
    }

    return bytes;
}

} // namespace cryptobench::application
