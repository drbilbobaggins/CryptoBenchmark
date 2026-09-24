#include <cryptobench/application/AtomicFileWriter.h>

#include <initializer_list>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QTemporaryDir>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace application::detail;

struct SessionPlan {
    bool openResult = true;
    qint64 writeResult = 0;
    bool commitResult = true;
    QString error = QStringLiteral("scripted failure");
};

struct SessionState {
    std::vector<std::string> calls;
    QByteArray payload;
};

class ScriptedSaveSession final : public AtomicFileSaveSession {
public:
    ScriptedSaveSession(SessionPlan plan, std::shared_ptr<SessionState> state)
        : plan_(std::move(plan)), state_(std::move(state))
    {
    }

    bool open() override
    {
        state_->calls.emplace_back("open");
        return plan_.openResult;
    }

    qint64 write(const QByteArray& payload) override
    {
        state_->calls.emplace_back("write");
        state_->payload = payload;
        return plan_.writeResult;
    }

    void cancelWriting() override
    {
        state_->calls.emplace_back("cancelWriting");
    }

    bool commit() override
    {
        state_->calls.emplace_back("commit");
        return plan_.commitResult;
    }

    QString errorString() const override
    {
        return plan_.error;
    }

private:
    SessionPlan plan_;
    std::shared_ptr<SessionState> state_;
};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QByteArray readBytes(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not read target");
    return file.readAll();
}

void seedTarget(const QString& path)
{
    const QByteArray original = R"({"format":"previous-complete","schemaVersion":1})";
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "could not seed target");
    require(file.write(original) == original.size(), "could not write seeded target");
    file.close();
    require(QJsonDocument::fromJson(original).isObject(), "seed is not valid JSON");
}

AtomicFileWriter writerFor(SessionPlan plan, const std::shared_ptr<SessionState>& state)
{
    return AtomicFileWriter{[plan = std::move(plan), state](const QString&) mutable {
        return std::make_unique<ScriptedSaveSession>(std::move(plan), state);
    }};
}

void requireCalls(const SessionState& state, std::initializer_list<std::string_view> expected)
{
    require(state.calls.size() == expected.size(), "unexpected scripted call count");
    std::size_t index = 0;
    for (const auto call : expected) {
        require(state.calls[index] == call, "unexpected scripted call order");
        ++index;
    }
}

void requireFailure(const WriteResult& result)
{
    require(!result.success, "failure scenario unexpectedly succeeded");
    require(!result.technicalMessage.isEmpty(), "failure has no diagnostic");
}

void testOpenFailurePreservesExistingTarget()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("existing.json");
    seedTarget(target);
    const auto original = readBytes(target);
    auto state = std::make_shared<SessionState>();
    auto writer = writerFor(SessionPlan{false, 0, true, QStringLiteral("open failed")}, state);

    const auto result = writer.writeAtomically(target, QByteArray("new json"));

    requireFailure(result);
    requireCalls(*state, {"open"});
    require(readBytes(target) == original, "open failure changed existing target");
}

void testShortWriteCancelsAndPreservesExistingTarget()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("existing.json");
    seedTarget(target);
    const auto original = readBytes(target);
    const QByteArray payload("new json");
    auto state = std::make_shared<SessionState>();
    auto writer = writerFor(SessionPlan{true, payload.size() - 1, true, QStringLiteral("short write")}, state);

    const auto result = writer.writeAtomically(target, payload);

    requireFailure(result);
    requireCalls(*state, {"open", "write", "cancelWriting"});
    require(state->payload == payload, "writer did not pass the complete payload");
    require(readBytes(target) == original, "short write changed existing target");
}

void testNegativeWriteCancelsAndPreservesExistingTarget()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("existing.json");
    seedTarget(target);
    const auto original = readBytes(target);
    const QByteArray payload("new json");
    auto state = std::make_shared<SessionState>();
    auto writer = writerFor(SessionPlan{true, -1, true, QStringLiteral("negative write")}, state);

    const auto result = writer.writeAtomically(target, payload);

    requireFailure(result);
    requireCalls(*state, {"open", "write", "cancelWriting"});
    require(state->payload == payload, "writer did not pass the complete payload");
    require(readBytes(target) == original, "negative write changed existing target");
}

void testCommitFailurePreservesExistingTarget()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("existing.json");
    seedTarget(target);
    const auto original = readBytes(target);
    const QByteArray payload("new json");
    auto state = std::make_shared<SessionState>();
    auto writer = writerFor(SessionPlan{true, payload.size(), false, QStringLiteral("commit failed")}, state);

    const auto result = writer.writeAtomically(target, payload);

    requireFailure(result);
    requireCalls(*state, {"open", "write", "commit"});
    require(readBytes(target) == original, "commit failure changed existing target");
}

void testFailedWritesDoNotCreateAbsentTarget()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto writeTarget = directory.filePath("failed-write.json");
    const QByteArray payload("new json");
    auto writeState = std::make_shared<SessionState>();
    auto writeWriter = writerFor(SessionPlan{true, payload.size() - 1, true, QStringLiteral("short write")}, writeState);

    const auto writeResult = writeWriter.writeAtomically(writeTarget, payload);

    requireFailure(writeResult);
    require(!QFileInfo::exists(writeTarget), "failed write created an absent target");
    requireCalls(*writeState, {"open", "write", "cancelWriting"});

    const auto commitTarget = directory.filePath("failed-commit.json");
    auto commitState = std::make_shared<SessionState>();
    auto commitWriter = writerFor(SessionPlan{true, payload.size(), false, QStringLiteral("commit failed")}, commitState);

    const auto commitResult = commitWriter.writeAtomically(commitTarget, payload);

    requireFailure(commitResult);
    require(!QFileInfo::exists(commitTarget), "failed commit created an absent target");
    requireCalls(*commitState, {"open", "write", "commit"});
}

void testSuccessfulInjectedSessionCommitsOnce()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory was not created");
    const auto target = directory.filePath("success.json");
    const QByteArray payload("new json");
    auto state = std::make_shared<SessionState>();
    auto writer = writerFor(SessionPlan{true, payload.size(), true, QStringLiteral("unused")}, state);

    const auto result = writer.writeAtomically(target, payload);

    require(result.success, "injected successful session failed");
    require(result.technicalMessage.isEmpty(), "injected success has a diagnostic");
    requireCalls(*state, {"open", "write", "commit"});
    require(state->payload == payload, "successful session received the wrong payload");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testOpenFailurePreservesExistingTarget();
        std::cout << "PASS open failure preservation\n";
        cryptobench::tests::testShortWriteCancelsAndPreservesExistingTarget();
        std::cout << "PASS positive short write\n";
        cryptobench::tests::testNegativeWriteCancelsAndPreservesExistingTarget();
        std::cout << "PASS negative write\n";
        cryptobench::tests::testCommitFailurePreservesExistingTarget();
        std::cout << "PASS commit failure preservation\n";
        cryptobench::tests::testFailedWritesDoNotCreateAbsentTarget();
        std::cout << "PASS absent-target failure paths\n";
        cryptobench::tests::testSuccessfulInjectedSessionCommitsOnce();
        std::cout << "PASS injected successful session\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL AtomicFileWriterFailure: " << error.what() << '\n';
        return 1;
    }
}
