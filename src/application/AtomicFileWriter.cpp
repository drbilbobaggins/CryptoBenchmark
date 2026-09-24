#include <cryptobench/application/AtomicFileWriter.h>

#include <QIODevice>
#include <QSaveFile>

#include <utility>

namespace cryptobench::application {
namespace {

class QSaveFileSession final : public detail::AtomicFileSaveSession {
public:
    explicit QSaveFileSession(const QString& target)
        : file_(target)
    {
        file_.setDirectWriteFallback(false);
    }

    bool open() override
    {
        return file_.open(QIODevice::WriteOnly);
    }

    qint64 write(const QByteArray& payload) override
    {
        return file_.write(payload);
    }

    void cancelWriting() override
    {
        file_.cancelWriting();
    }

    bool commit() override
    {
        return file_.commit();
    }

    QString errorString() const override
    {
        return file_.errorString();
    }

private:
    QSaveFile file_;
};

QString failureMessage(const QString& prefix, const detail::AtomicFileSaveSession& session)
{
    const auto error = session.errorString();
    return error.isEmpty() ? prefix : prefix + QStringLiteral(": ") + error;
}

} // namespace

AtomicFileWriter::AtomicFileWriter(detail::AtomicFileSaveSessionFactory factory)
    : factory_(std::move(factory))
{
    if (!factory_) {
        factory_ = [](const QString& target) {
            return std::make_unique<QSaveFileSession>(target);
        };
    }
}

WriteResult AtomicFileWriter::writeAtomically(const QString& target, const QByteArray& utf8Json) const
{
    auto session = factory_(target);

    if (!session->open()) {
        return {false, failureMessage(QStringLiteral("Could not open target for atomic writing"), *session)};
    }

    const auto written = session->write(utf8Json);
    if (written != utf8Json.size()) {
        session->cancelWriting();
        return {false, failureMessage(QStringLiteral("Could not write the complete atomic payload"), *session)};
    }

    if (!session->commit()) {
        return {false, failureMessage(QStringLiteral("Could not commit atomic file replacement"), *session)};
    }

    return {true, {}};
}

} // namespace cryptobench::application
