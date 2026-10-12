#pragma once

#include <QProcess>

namespace cryptobench::platform::windows {

class WindowsWorkerProcess final : public QObject {
    Q_OBJECT

public:
    explicit WindowsWorkerProcess(QObject* parent = nullptr);
    ~WindowsWorkerProcess() override;

    void start(const QString& ipcEndpoint);
    void startV2(const QString& ipcEndpoint, const QString& workerExecutablePath = {});

    QProcess::ProcessState state() const;
    qint64 processId() const;
    bool isRunning() const;

    void kill();

signals:
    void started();
    void finished(int exitCode, QProcess::ExitStatus exitStatus);
    void errorOccurred(QProcess::ProcessError error, const QString& message);
    void stateChanged(QProcess::ProcessState state);

private:
    QProcess process_;
};

} // namespace cryptobench::platform::windows
