#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>
#include "WorkerMemorySamplerAccounting.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QUuid>

#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
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

void processEventsFor(std::int64_t milliseconds)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < milliseconds) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    }
}

void requireLogicError(const std::function<void()>& operation, const char* message)
{
    bool rejected = false;
    try {
        operation();
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, message);
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

    rejected = false;
    try {
        sampler.startV2(0, {1});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "v2 zero process ID was accepted");
    require(!sampler.isActive(), "sampler became active after invalid v2 process ID");

    rejected = false;
    try {
        sampler.startV2(std::numeric_limits<std::uint32_t>::max(), {0});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "zero interval was not rejected at the sampler boundary");
    require(!sampler.isActive(), "sampler became active after zero interval");

    rejected = false;
    try {
        sampler.startV2(std::numeric_limits<std::uint32_t>::max(), {6});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "six millisecond interval was not rejected at the sampler boundary");
    require(!sampler.isActive(), "sampler became active after six millisecond interval");
    sampler.stopAndDiscard();
}

void testInactiveLifecycle()
{
    platform::windows::WorkerMemorySampler sampler;
    requireLogicError(
        [&] { sampler.markExecutionBoundaryV2(); },
        "inactive sampler accepted the v2 execution boundary");
    requireLogicError(
        [&] { sampler.stopAndCollectV2(); },
        "inactive sampler accepted v2 collection");
    requireLogicError(
        [&] { sampler.stopAndCollect(); },
        "inactive sampler accepted legacy collection");
    sampler.stopAndDiscard();
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "inactive discard changed sampler state");
}

void testDeterministicAccounting()
{
    using platform::windows::MemoryV2SamplePhase;
    using platform::windows::recordMemoryV2Sample;

    core::MemoryV2RawObservations preparation;
    require(preparation.preparationSampleCount == 0, "preparation started with samples");
    require(!preparation.preparationPeakSampledPrivateUsageBytes.has_value(),
            "preparation zero-sample peak was present");
    recordMemoryV2Sample(preparation, MemoryV2SamplePhase::Preparation, 42);
    require(preparation.preparationSampleCount == 1,
            "first preparation sample was not counted once");
    require(preparation.preparationPeakSampledPrivateUsageBytes == 42,
            "first preparation sample was not stored as the peak");
    require(preparation.executionSampleCount == 0
                && !preparation.executionPeakSampledPrivateUsageBytes.has_value(),
            "preparation sample changed execution accounting");
    recordMemoryV2Sample(preparation, MemoryV2SamplePhase::Preparation, 7);
    recordMemoryV2Sample(preparation, MemoryV2SamplePhase::Preparation, 100);
    require(preparation.preparationSampleCount == 3,
            "preparation samples were not counted once each");
    require(preparation.preparationPeakSampledPrivateUsageBytes == 100,
            "preparation peak was not the maximum sample");

    core::MemoryV2RawObservations zeroPreparation;
    recordMemoryV2Sample(zeroPreparation, MemoryV2SamplePhase::Preparation, 0);
    require(zeroPreparation.preparationSampleCount == 1,
            "zero-valued preparation sample was not counted");
    require(zeroPreparation.preparationPeakSampledPrivateUsageBytes.has_value()
                && *zeroPreparation.preparationPeakSampledPrivateUsageBytes == 0,
            "zero-valued preparation sample was confused with absence");

    core::MemoryV2RawObservations execution;
    require(execution.executionSampleCount == 0, "execution started with samples");
    require(!execution.executionPeakSampledPrivateUsageBytes.has_value(),
            "execution zero-sample peak was present");
    recordMemoryV2Sample(execution, MemoryV2SamplePhase::Execution, 19);
    recordMemoryV2Sample(execution, MemoryV2SamplePhase::Execution, 3);
    recordMemoryV2Sample(execution, MemoryV2SamplePhase::Execution, 27);
    require(execution.executionSampleCount == 3,
            "execution samples were not counted once each");
    require(execution.executionPeakSampledPrivateUsageBytes == 27,
            "execution peak was not the maximum sample");
    require(execution.preparationSampleCount == 0
                && !execution.preparationPeakSampledPrivateUsageBytes.has_value(),
            "execution samples changed preparation accounting");

        core::MemoryV2RawObservations boundaries;
        boundaries.baselinePrivateUsageBytes = 111;
        boundaries.readyPrivateUsageBytes = 222;
        boundaries.finalPrivateUsageBytes = 333;
        recordMemoryV2Sample(boundaries, MemoryV2SamplePhase::Preparation, 444);
        recordMemoryV2Sample(boundaries, MemoryV2SamplePhase::Execution, 555);
        require(boundaries.baselinePrivateUsageBytes == 111,
            "preparation accounting changed B0");
        require(boundaries.readyPrivateUsageBytes == 222,
            "periodic accounting changed B1");
        require(boundaries.finalPrivateUsageBytes == 333,
            "execution accounting changed E");

    core::MemoryV2RawObservations zeroExecution;
    recordMemoryV2Sample(zeroExecution, MemoryV2SamplePhase::Execution, 0);
    require(zeroExecution.executionSampleCount == 1,
            "zero-valued execution sample was not counted");
    require(zeroExecution.executionPeakSampledPrivateUsageBytes.has_value()
                && *zeroExecution.executionPeakSampledPrivateUsageBytes == 0,
            "zero-valued execution sample was confused with absence");
}

void testLegacyModeMixing(std::uint32_t processId)
{
    platform::windows::WorkerMemorySampler sampler;
    sampler.start(processId, 20);
    requireLogicError(
        [&] { sampler.start(processId, 21); },
        "legacy sampler accepted a second legacy start");
    requireLogicError(
        [&] { sampler.startV2(processId, {2}); },
        "legacy sampler accepted a v2 start");
    requireLogicError(
        [&] { sampler.markExecutionBoundaryV2(); },
        "legacy sampler accepted a v2 boundary");
    requireLogicError(
        [&] { sampler.stopAndCollectV2(); },
        "legacy sampler accepted v2 collection");
    const auto result = sampler.stopAndCollect();
    require(result.runIndex == 20, "legacy lifecycle was corrupted by rejected v2 calls");
}

void testV2PreparationModeMixing(std::uint32_t processId)
{
    platform::windows::WorkerMemorySampler sampler;
    sampler.startV2(processId, {2});
    requireLogicError(
        [&] { sampler.startV2(processId, {1}); },
        "v2 preparation accepted a second v2 start");
    requireLogicError(
        [&] { sampler.start(processId, 22); },
        "v2 preparation accepted a legacy start");
    requireLogicError(
        [&] { sampler.stopAndCollect(); },
        "v2 preparation accepted legacy collection");
    requireLogicError(
        [&] { sampler.stopAndCollectV2(); },
        "v2 preparation accepted collection before B1");
    sampler.markExecutionBoundaryV2();
    const auto result = sampler.stopAndCollectV2();
    require(result.baselinePrivateUsageBytes > 0,
            "v2 preparation lifecycle was corrupted by rejected calls");
}

void testV2ExecutionModeMixing(std::uint32_t processId)
{
    platform::windows::WorkerMemorySampler sampler;
    sampler.startV2(processId, {2});
    sampler.markExecutionBoundaryV2();
    requireLogicError(
        [&] { sampler.markExecutionBoundaryV2(); },
        "v2 execution accepted a second B1 boundary");
    requireLogicError(
        [&] { sampler.stopAndCollect(); },
        "v2 execution accepted legacy collection");
    requireLogicError(
        [&] { sampler.start(processId, 23); },
        "v2 execution accepted a legacy start");
    requireLogicError(
        [&] { sampler.startV2(processId, {1}); },
        "v2 execution accepted another v2 start");
    const auto result = sampler.stopAndCollectV2();
    require(result.finalPrivateUsageBytes > 0,
            "v2 execution lifecycle was corrupted by rejected calls");
}

void testValidSamplingIntervals(std::uint32_t processId)
{
    platform::windows::WorkerMemorySampler reusableSampler;
    bool rejected = false;
    try {
        reusableSampler.startV2(processId, {0});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "reusable sampler accepted zero interval");
    require(!reusableSampler.isActive(), "zero interval activated reusable sampler");

    rejected = false;
    try {
        reusableSampler.startV2(processId, {6});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "reusable sampler accepted six millisecond interval");
    require(!reusableSampler.isActive(), "six millisecond interval activated reusable sampler");
    reusableSampler.startV2(processId, {1});
    reusableSampler.markExecutionBoundaryV2();
    reusableSampler.stopAndCollectV2();
    require(!reusableSampler.isActive(), "sampler was not reusable after invalid intervals");

    for (std::uint32_t interval = 1; interval <= 5; ++interval) {
        platform::windows::WorkerMemorySampler sampler;
        sampler.startV2(processId, {interval});
        processEventsFor(20);
        sampler.markExecutionBoundaryV2();
        processEventsFor(20);
        const auto result = sampler.stopAndCollectV2();
        require(result.baselinePrivateUsageBytes > 0,
                "valid interval did not collect B0");
        require(result.readyPrivateUsageBytes > 0,
                "valid interval did not collect B1");
        require(result.finalPrivateUsageBytes > 0,
                "valid interval did not collect E");
        require(!sampler.isActive(), "valid interval left sampler active");
    }
}

void testV2DiscardAndReuse(std::uint32_t processId)
{
    platform::windows::WorkerMemorySampler sampler;
    sampler.startV2(processId, {2});
    sampler.stopAndDiscard();
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "v2 preparation discard did not deactivate sampler");

    sampler.startV2(processId, {2});
    sampler.markExecutionBoundaryV2();
    sampler.stopAndDiscard();
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "v2 execution discard did not deactivate sampler");

    sampler.startV2(processId, {1});
    sampler.markExecutionBoundaryV2();
    const auto result = sampler.stopAndCollectV2();
    require(result.finalPrivateUsageBytes > 0,
            "sampler was not reusable after v2 discard");
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
    const auto processId = static_cast<std::uint32_t>(worker.processId());

    testLegacyModeMixing(processId);
    testV2PreparationModeMixing(processId);
    testV2ExecutionModeMixing(processId);
    testValidSamplingIntervals(processId);
    testV2DiscardAndReuse(processId);

    platform::windows::WorkerMemorySampler sampler;
    sampler.start(processId, 7);
    require(sampler.isActive(), "sampler was not active after start");

    bool rejectedSecondStart = false;
    try {
        sampler.start(processId, 8);
    } catch (const std::logic_error&) {
        rejectedSecondStart = true;
    }
    require(rejectedSecondStart, "second sampler start was accepted");

    processEventsFor(40);

    const auto result = sampler.stopAndCollect();
    require(result.runIndex == 7, "sampler returned the wrong run index");
    require(result.memory.baselineBytes > 0, "worker PrivateUsage baseline was zero");
    require(result.memory.peakSampledBytes >= result.memory.baselineBytes,
            "sampled peak was below the baseline");
    require(result.memory.peakDeltaBytes
                == result.memory.peakSampledBytes - result.memory.baselineBytes,
            "sampled peak delta did not match the canonical formula");
    require(!sampler.isActive(), "sampler remained active after collection");

    sampler.start(processId, 8);
    const auto shortResult = sampler.stopAndCollect();
    require(shortResult.runIndex == 8, "short window returned the wrong run index");
    require(shortResult.memory.peakSampledBytes >= shortResult.memory.baselineBytes,
            "short-window peak was below the baseline");
    require(shortResult.memory.peakDeltaBytes
                == shortResult.memory.peakSampledBytes - shortResult.memory.baselineBytes,
            "short-window delta did not match the canonical formula");

    sampler.start(processId, 9);
    sampler.stopAndDiscard();
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "discard did not deactivate the sampler");

    sampler.start(processId, 10);
    sampler.stopAndDiscard();
    require(!sampler.isActive(), "sampler could not be reused after discard");

    sampler.startV2(processId, {2});
    require(sampler.isActive(), "v2 sampler was not active after start");

    processEventsFor(60);

    sampler.markExecutionBoundaryV2();

    processEventsFor(60);

    const auto v2Result = sampler.stopAndCollectV2();
    require(v2Result.baselinePrivateUsageBytes > 0, "v2 B0 was not collected");
    require(v2Result.readyPrivateUsageBytes > 0, "v2 B1 was not collected");
    require(v2Result.finalPrivateUsageBytes > 0, "v2 E was not collected");
    require(
        v2Result.preparationSampleCount > 0
            && v2Result.preparationPeakSampledPrivateUsageBytes.has_value(),
        "v2 sampler did not collect a preparation periodic sample");
    require(
        v2Result.executionSampleCount > 0
            && v2Result.executionPeakSampledPrivateUsageBytes.has_value(),
        "v2 sampler did not collect an execution periodic sample");
    require(
        v2Result.preparationPeakSampledPrivateUsageBytes.has_value()
            == (v2Result.preparationSampleCount > 0),
        "v2 preparation peak/count semantics mismatch");
    require(
        v2Result.executionPeakSampledPrivateUsageBytes.has_value()
            == (v2Result.executionSampleCount > 0),
        "v2 execution peak/count semantics mismatch");
    require(!sampler.isActive(), "v2 sampler remained active after collection");

    sampler.startV2(processId, {2});
    sampler.markExecutionBoundaryV2();
    const auto reusedV2Result = sampler.stopAndCollectV2();
    require(reusedV2Result.baselinePrivateUsageBytes > 0,
            "sampler could not start v2 again after successful collection");
    require(!sampler.isActive(),
            "sampler remained active after successful v2 reuse collection");

    channel.close();
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInvalidProcessId();
        testInactiveLifecycle();
        testDeterministicAccounting();
        testRealWorkerLifecycle();
        std::cout << "Worker memory sampler tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Worker memory sampler tests failed: " << error.what() << '\n';
        return 1;
    }
}
