#pragma once

#include <QByteArray>
#include <QString>

namespace cryptobench::application {

struct WriteResult {
    bool success;
    QString technicalMessage;
};

class AtomicFileWriter {
public:
    WriteResult writeAtomically(const QString& target, const QByteArray& utf8Json) const;
};

} // namespace cryptobench::application
