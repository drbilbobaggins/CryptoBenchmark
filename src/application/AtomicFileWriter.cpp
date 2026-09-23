#include <cryptobench/application/AtomicFileWriter.h>

#include <QIODevice>
#include <QSaveFile>

namespace cryptobench::application {

WriteResult AtomicFileWriter::writeAtomically(const QString& target, const QByteArray& utf8Json) const
{
    QSaveFile file(target);
    file.setDirectWriteFallback(false);

    if (!file.open(QIODevice::WriteOnly)) {
        return {false, QStringLiteral("Could not open target for atomic writing: %1").arg(file.errorString())};
    }

    const auto written = file.write(utf8Json);
    if (written != utf8Json.size()) {
        file.cancelWriting();
        return {false, QStringLiteral("Could not write the complete atomic payload: %1").arg(file.errorString())};
    }

    if (!file.commit()) {
        return {false, QStringLiteral("Could not commit atomic file replacement: %1").arg(file.errorString())};
    }

    return {true, {}};
}

} // namespace cryptobench::application
