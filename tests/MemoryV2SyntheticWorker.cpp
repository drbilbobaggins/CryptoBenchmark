#include "MemoryV2SyntheticScenario.h"

#include <cryptobench/ipc/WorkerIpcChannel.h>
#include <cryptobench/platform/windows/WindowsProcessCpuTimeSource.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>

#include <windows.h>

#include <cstdint>
#include <stdexcept>

namespace {

class Allocation final {
public:
    explicit Allocation(std::size_t bytes)
    {
        if (bytes == 0) return;
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        pageSize_ = info.dwPageSize == 0 ? 4096U : info.dwPageSize;
        memory_ = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (memory_ == nullptr) throw std::runtime_error("VirtualAlloc failed");
        size_ = bytes;
        auto* bytesPointer = static_cast<volatile unsigned char*>(memory_);
        for (std::size_t offset = 0; offset < size_; offset += pageSize_) bytesPointer[offset] = 0xA5;
        bytesPointer[size_ - 1] = 0x5A;
    }

    ~Allocation() { release(); }
    Allocation(const Allocation&) = delete;
    Allocation& operator=(const Allocation&) = delete;

    void release() noexcept
    {
        if (memory_ != nullptr) {
            VirtualFree(memory_, 0, MEM_RELEASE);
            memory_ = nullptr;
            size_ = 0;
        }
    }

private:
    void* memory_ = nullptr;
    std::size_t size_ = 0;
    std::uint32_t pageSize_ = 4096;
};

void hold(std::uint32_t milliseconds)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < static_cast<qint64>(milliseconds)) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
    }
}

void consumeCpuFor(std::uint32_t milliseconds)
{
    QElapsedTimer timer;
    timer.start();
    volatile std::uint64_t accumulator = 0;
    while (timer.elapsed() < static_cast<qint64>(milliseconds)) {
        for (std::uint64_t value = 1; value < 100'000; ++value) {
            accumulator = accumulator * 1664525U + value;
        }
    }
    static_cast<void>(accumulator);
}

int run(const QString& endpoint)
{
    const auto scenario = cryptobench::tests::parseSyntheticScenario(
        qEnvironmentVariable("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO"));
    cryptobench::ipc::WorkerIpcChannel channel(
        10'000, cryptobench::ipc::WorkerIpcMode::SingleRunV2);
    channel.connectToServer(endpoint);
    channel.sendWorkerReady();
    const auto request = channel.receiveBenchmarkRunRequest();
    channel.beginAlgorithmPreparation(request.logicalRunIndex);
    Allocation preparation(scenario.preparationBytes);
    hold(scenario.preparationHoldMilliseconds);
    if (scenario.releasePreparationBeforeBoundary) preparation.release();
    channel.finishAlgorithmPreparation(request.logicalRunIndex);

    channel.beforeMeasurement(request.logicalRunIndex);
    cryptobench::platform::windows::WindowsProcessCpuTimeSource cpuTimeSource;
    QElapsedTimer wallTimer;
    wallTimer.start();
    const auto cpuBefore = cpuTimeSource.currentProcessCpuTimeNanoseconds();
    Allocation execution(scenario.executionBytes);
    consumeCpuFor(5);
    hold(scenario.executionHoldMilliseconds);
    if (scenario.releaseExecutionBeforeEnd) execution.release();
    const auto elapsedNanoseconds = static_cast<std::uint64_t>(wallTimer.nsecsElapsed());
    const auto cpuAfter = cpuTimeSource.currentProcessCpuTimeNanoseconds();
    if (scenario.outcome == cryptobench::tests::SyntheticOutcome::WaitForCancellation) {
        hold(10'000);
    }
    if (scenario.outcome == cryptobench::tests::SyntheticOutcome::WorkerFailure) {
        channel.sendWorkerOutcome({cryptobench::ipc::WorkerOutcomeStatus::Failed, std::nullopt});
        return 9;
    }
    if (scenario.outcome == cryptobench::tests::SyntheticOutcome::AbnormalExit) return 10;
    channel.afterMeasurement({request.logicalRunIndex, elapsedNanoseconds, cpuAfter - cpuBefore});
    channel.sendWorkerOutcome({cryptobench::ipc::WorkerOutcomeStatus::Completed, std::nullopt});
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        if (argc != 4 || QString::fromLocal8Bit(argv[1]) != "--ipc-endpoint" ||
            QString::fromLocal8Bit(argv[3]) != "--ipc-v2") return 2;
        return run(QString::fromLocal8Bit(argv[2]));
    } catch (...) {
        return 1;
    }
}
