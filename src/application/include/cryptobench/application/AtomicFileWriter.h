#pragma once

#include <functional>
#include <memory>

#include <QByteArray>
#include <QString>

namespace cryptobench::application {

struct WriteResult {
    bool success;
    QString technicalMessage;
};

namespace detail {

class AtomicFileSaveSession {
public:
    virtual ~AtomicFileSaveSession() = default;

    virtual bool open() = 0;
    virtual qint64 write(const QByteArray& payload) = 0;
    virtual void cancelWriting() = 0;
    virtual bool commit() = 0;
    virtual QString errorString() const = 0;
};

using AtomicFileSaveSessionFactory =
    std::function<std::unique_ptr<AtomicFileSaveSession>(const QString& target)>;

} // namespace detail

class AtomicFileWriter {
public:
    explicit AtomicFileWriter(detail::AtomicFileSaveSessionFactory factory = {});

    WriteResult writeAtomically(const QString& target, const QByteArray& utf8Json) const;

private:
    detail::AtomicFileSaveSessionFactory factory_;
};

} // namespace cryptobench::application
