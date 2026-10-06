#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>

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
    if (!condition) {
        throw std::runtime_error(message);
    }
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M05_3_%1")
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

void testInvalidProcessId()
{
    platform::windows::WorkerMemorySampler sampler;
    bool rejected = false;
    try {
        sampler.start(0, 1);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "zero process ID was accepted");
    require(!sampler.isActive(), "sampler became active after invalid input");
}

void testRealWorkerLifecycle()
{
    ipc::ParentIpcChannel channel;
    const auto name = endpoint();
    channel.startListening(name);

    platform::windows::WindowsWorkerProcess worker;
    WorkerCleanup cleanup(worker);
    bool started = false;
    bool workerReady = false;
    worker.connect(&worker, &platform::windows::WindowsWorkerProcess::started, [&] { started = true; });
    channel.connect(&channel, &ipc::ParentIpcChannel::workerReadyReceived,
                    [&](const ipc::WorkerReady& value) {
                        workerReady = value.protocolVersion == ipc::kProtocolVersion;
                    });

    worker.start(name);
    waitUntil([&] { return started; }, "worker did not start");
    waitUntil([&] { return workerReady; }, "worker did not become ready");

    platform::windows::WorkerMemorySampler sampler;
    sampler.start(static_cast<std::uint32_t>(worker.processId()), 7);
    require(sampler.isActive(), "sampler was not active after start");

    bool rejectedSecondStart = false;
    try {
        sampler.start(static_cast<std::uint32_t>(worker.processId()), 8);
    } catch (const std::logic_error&) {
        rejectedSecondStart = true;
    }
    require(rejectedSecondStart, "second sampler start was accepted");

    QElapsedTimer samplingWindow;
    samplingWindow.start();
    while (samplingWindow.elapsed() < 40) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    }

    const auto result = sampler.stopAndCollect();
    require(result.runIndex == 7, "sampler returned the wrong run index");
    require(result.memory.baselineBytes > 0, "worker PrivateUsage baseline was zero");
    require(result.memory.peakSampledBytes >= result.memory.baselineBytes,
            "sampled peak was below the baseline");
    require(result.memory.peakDeltaBytes
                == result.memory.peakSampledBytes - result.memory.baselineBytes,
            "sampled peak delta did not match the canonical formula");
    require(!sampler.isActive(), "sampler remained active after collection");

    sampler.start(static_cast<std::uint32_t>(worker.processId()), 8);
    const auto shortResult = sampler.stopAndCollect();
    require(shortResult.runIndex == 8, "short window returned the wrong run index");
    require(shortResult.memory.peakSampledBytes >= shortResult.memory.baselineBytes,
            "short-window peak was below the baseline");
    require(shortResult.memory.peakDeltaBytes
                == shortResult.memory.peakSampledBytes - shortResult.memory.baselineBytes,
            "short-window delta did not match the canonical formula");

    sampler.start(static_cast<std::uint32_t>(worker.processId()), 9);
    sampler.stopAndDiscard();
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "discard did not deactivate the sampler");

    sampler.start(static_cast<std::uint32_t>(worker.processId()), 10);
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "sampler could not be reused after discard");

    sampler.startV2(static_cast<std::uint32_t>(worker.processId()), {2});
    require(sampler.isActive(), "v2 sampler was not active after start");

    QElapsedTimer preparationWindow;
    preparationWindow.start();
    while (preparationWindow.elapsed() < 40) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    }

    sampler.markExecutionBoundaryV2();

    QElapsedTimer executionWindow;
    executionWindow.start();
    while (executionWindow.elapsed() < 40) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    }

    const auto v2Result = sampler.stopAndCollectV2();
    require(v2Result.baselinePrivateUsageBytes > 0, "v2 B0 was not collected");
    require(v2Result.readyPrivateUsageBytes > 0, "v2 B1 was not collected");
    require(v2Result.finalPrivateUsageBytes > 0, "v2 E was not collected");
    require(
        (v2Result.preparationSampleCount > 0
            && v2Result.preparationPeakSampledPrivateUsageBytes.has_value())
            || (v2Result.executionSampleCount > 0
                && v2Result.executionPeakSampledPrivateUsageBytes.has_value()),
        "v2 sampler did not collect a periodic phase sample");
    require(
        v2Result.preparationPeakSampledPrivateUsageBytes.has_value()
            == (v2Result.preparationSampleCount > 0),
        "v2 preparation peak/count semantics mismatch");
    require(
        v2Result.executionPeakSampledPrivateUsageBytes.has_value()
            == (v2Result.executionSampleCount > 0),
        "v2 execution peak/count semantics mismatch");
    require(!sampler.isActive(), "v2 sampler remained active after collection");

    channel.close();
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInvalidProcessId();
        testRealWorkerLifecycle();
        std::cout << "Worker memory sampler tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Worker memory sampler tests failed: " << error.what() << '\n';
        return 1;
    }
}
