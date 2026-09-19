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
    platform::windows::WindowsWorkerProcess worker;
    WorkerCleanup cleanup(worker);
    int finishedCount = 0;
    worker.connect(&worker, &platform::windows::WindowsWorkerProcess::finished,
                   [&](int code, QProcess::ExitStatus status) {
                       static_cast<void>(code);
                       static_cast<void>(status);
                       ++finishedCount;
                   });

    require(qputenv("CRYPTOBENCH_TEST_WORKER_SCENARIO", "wait"),
            "failed to configure scripted worker scenario");
    worker.start(endpoint());
    require(worker.state() == QProcess::Starting || worker.state() == QProcess::Running,
            "first worker did not enter an active state");
    waitUntil([&] { return worker.state() == QProcess::Running; },
              "first worker did not reach Running");

    bool rejectedSecondStart = false;
    try {
        worker.start(endpoint());
    } catch (const std::logic_error&) {
        rejectedSecondStart = true;
    }
    require(rejectedSecondStart, "second active worker start was accepted");

    worker.kill();
    waitUntil([&] { return finishedCount == 1 && worker.state() == QProcess::NotRunning; },
              "first worker did not reach NotRunning after kill");

    worker.start(endpoint());
    waitUntil([&] { return worker.state() == QProcess::Running; },
              "second worker did not reach Running after sequential reuse");
    worker.kill();
    waitUntil([&] { return finishedCount == 2 && worker.state() == QProcess::NotRunning; },
              "second worker did not reach NotRunning after sequential reuse");
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
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
