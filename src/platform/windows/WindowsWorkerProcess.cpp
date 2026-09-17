#include <cryptobench/platform/windows/WindowsWorkerProcess.h>

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

#include <stdexcept>

namespace cryptobench::platform::windows {

WindowsWorkerProcess::WindowsWorkerProcess(QObject* parent)
    : QObject(parent)
{
    connect(&process_, &QProcess::started, this, &WindowsWorkerProcess::started);
    connect(&process_, &QProcess::finished, this, &WindowsWorkerProcess::finished);
    connect(&process_, &QProcess::stateChanged, this, &WindowsWorkerProcess::stateChanged);
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        emit errorOccurred(error, process_.errorString());
    });
}

WindowsWorkerProcess::~WindowsWorkerProcess()
{
    kill();
}

void WindowsWorkerProcess::start(const QString& ipcEndpoint)
{
    if (ipcEndpoint.isEmpty()) {
        throw std::invalid_argument("WindowsWorkerProcess IPC endpoint must not be empty");
    }
    if (process_.state() != QProcess::NotRunning) {
        throw std::logic_error("WindowsWorkerProcess is already active");
    }

    const auto workerPath = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("CryptoBenchmarkWorker.exe"));
    const QFileInfo workerInfo(workerPath);
    if (!workerInfo.exists() || !workerInfo.isFile()) {
        const auto message = QStringLiteral("CryptoBenchmarkWorker.exe was not found at ") + workerPath;
        emit errorOccurred(QProcess::FailedToStart, message);
        throw std::runtime_error(message.toStdString());
    }

    process_.setProgram(workerInfo.absoluteFilePath());
    process_.setArguments({QStringLiteral("--ipc-endpoint"), ipcEndpoint});
    process_.start();
}

QProcess::ProcessState WindowsWorkerProcess::state() const
{
    return process_.state();
}

qint64 WindowsWorkerProcess::processId() const
{
    return process_.processId();
}

bool WindowsWorkerProcess::isRunning() const
{
    return state() != QProcess::NotRunning;
}

void WindowsWorkerProcess::kill()
{
    if (isRunning()) {
        process_.kill();
    }
}

} // namespace cryptobench::platform::windows
