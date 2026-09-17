#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QUuid>

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace cryptobench;

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M05_2_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

void waitUntil(const std::function<bool()>& condition, const char* message)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < 5'000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(condition(), message);
}

class WorkerCleanup final {
public:
    explicit WorkerCleanup(platform::windows::WindowsWorkerProcess& worker)
        : worker_(worker)
    {
    }

    ~WorkerCleanup()
    {
        worker_.kill();
        if (worker_.isRunning()) {
            QElapsedTimer timer;
            timer.start();
            while (worker_.isRunning() && timer.elapsed() < 2'000) {
                QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
            }
        }
    }

private:
    platform::windows::WindowsWorkerProcess& worker_;
};

void testInputAndInitialState()
{
    platform::windows::WindowsWorkerProcess worker;
    require(worker.state() == QProcess::NotRunning, "worker was active before start");
    require(worker.processId() == 0, "worker exposed a PID before start");

    bool rejected = false;
    try {
        worker.start(QString{});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "empty endpoint was accepted");
}

void testRealWorkerLifecycle()
{
    ipc::ParentIpcChannel channel;
    const auto name = endpoint();
    channel.startListening(name);

    platform::windows::WindowsWorkerProcess worker;
    WorkerCleanup cleanup(worker);
    bool started = false;
    bool finished = false;
    bool workerReady = false;
    int exitCode = 0;
    QProcess::ExitStatus exitStatus = QProcess::NormalExit;
    worker.connect(&worker, &platform::windows::WindowsWorkerProcess::started, [&] { started = true; });
    worker.connect(&worker, &platform::windows::WindowsWorkerProcess::finished,
                   [&](int code, QProcess::ExitStatus status) {
                       finished = true;
                       exitCode = code;
                       exitStatus = status;
                   });
    channel.connect(&channel, &ipc::ParentIpcChannel::workerReadyReceived,
                    [&](const ipc::WorkerReady& value) { workerReady = value.protocolVersion == ipc::kProtocolVersion; });

    worker.start(name);
        require(worker.state() == QProcess::Starting || worker.state() == QProcess::Running,
            "worker did not enter an active state");
    waitUntil([&] { return started; }, "worker started signal was not observed");
    require(worker.isRunning(), "worker was not running after started signal");
    require(worker.processId() != 0, "worker PID was zero after startup");
    waitUntil([&] { return workerReady; }, "worker did not connect and send WorkerReady");

    bool rejectedSecondStart = false;
    try {
        worker.start(name);
    } catch (const std::logic_error&) {
        rejectedSecondStart = true;
    }
    require(rejectedSecondStart, "second active worker start was accepted");

    worker.kill();
    waitUntil([&] { return finished; }, "worker finished signal was not observed after kill");
    require(!worker.isRunning() && worker.state() == QProcess::NotRunning,
            "worker remained active after finished signal");
    require(worker.processId() == 0, "worker retained a PID after exit");
    static_cast<void>(exitCode);
    static_cast<void>(exitStatus);

    worker.kill();
    channel.close();
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInputAndInitialState();
        testRealWorkerLifecycle();
        std::cout << "Windows worker process tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Windows worker process tests failed: " << error.what() << '\n';
        return 1;
    }
}
