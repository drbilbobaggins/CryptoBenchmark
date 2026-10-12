#include <cryptobench/application/BenchmarkController.h>

#include <cryptobench/core/ConfigValidation.h>
#include "BackendIntegrationTestSupport.h"

#include <QCoreApplication>
#include <QDir>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QPointer>
#include <QTimer>

#include <windows.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

bool processIsRunning(DWORD processId)
{
    const auto handle = OpenProcess(SYNCHRONIZE, FALSE, processId);
    if (handle == nullptr) return false;
    const auto result = WaitForSingleObject(handle, 0);
    CloseHandle(handle);
    return result == WAIT_TIMEOUT;
}

core::BenchmarkConfig validConfig()
{
    return {
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        2,
        core::HashConfig{8}
    };
}

core::BenchmarkConfig seriesConfig(std::uint32_t runs)
{
    auto config = validConfig();
    config.runs = runs;
    return config;
}

void testInvalidPreflight()
{
    application::BenchmarkController controller;
    auto invalid = validConfig();
    invalid.parameters = core::HashConfig{core::kMaxWorkloadBytes + 1};

    bool rejected = false;
    try {
        controller.start(invalid);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }

    require(rejected, "invalid preflight configuration was accepted");
    require(!controller.isBusy(), "controller remained busy after invalid preflight");
}

void testSuccessfulSession()
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    application::BenchmarkController controller;
    const auto config = validConfig();
    std::optional<core::BenchmarkResult> result;
    std::size_t finishCount = 0;
    bool progressObserved = false;
    bool terminal = false;
    std::size_t progressAfterTerminal = 0;
    std::vector<core::ProgressInfo> progress;

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
                     [&](const core::ProgressInfo& value) {
                         progressObserved = true;
                         if (terminal) ++progressAfterTerminal;
                         progress.push_back(value);
                     });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++finishCount;
                         result = value;
                         terminal = true;
                         loop.quit();
                     });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    const auto startedAt = std::chrono::system_clock::now();
    controller.start(config);
    bool concurrentStartRejected = false;
    try {
        controller.start(config);
    } catch (const std::logic_error&) {
        concurrentStartRejected = true;
    }
    require(concurrentStartRejected, "concurrent controller start was accepted");

    timeout.start(20'000);
    loop.exec();
    require(result.has_value(), "controller test timed out without a result");
    require(finishCount == 1, "controller emitted more than one final result");
    require(!controller.isBusy(), "controller remained busy after completion");
    test_support::assertCompletedResult(*result, config, startedAt,
                                        std::chrono::system_clock::now());
    require(progressObserved, "no progress was forwarded");
    QCoreApplication::processEvents();
    require(progressAfterTerminal == 0, "Measuring progress arrived after terminal result");

    std::vector<std::uint32_t> measuredRuns;
    std::optional<std::size_t> finalizingIndex;
    std::optional<std::size_t> lastMeasuringIndex;
    for (std::size_t index = 0; index < progress.size(); ++index) {
        const auto& value = progress[index];
        require(value.totalRuns == config.runs, "progress total does not match configured runs");
        if (value.phase == core::BenchmarkPhase::Measuring) {
            require(value.runIndex.has_value(), "Measuring progress has no run index");
            measuredRuns.push_back(*value.runIndex);
            require(index > 0 && progress[index - 1].phase == core::BenchmarkPhase::Warmup,
                    "Measuring progress was not preceded by warm-up");
            require(progress[index - 1].runIndex == value.runIndex,
                    "Measuring progress did not follow the matching warm-up run");
            lastMeasuringIndex = index;
        } else if (value.phase == core::BenchmarkPhase::Finalizing) {
            finalizingIndex = index;
        }
    }
    require(measuredRuns == std::vector<std::uint32_t>{0, 1},
            "unexpected Measuring progress sequence");
        require(finalizingIndex.has_value() && lastMeasuringIndex.has_value() &&
            *finalizingIndex > *lastMeasuringIndex,
            "Finalizing progress was not emitted after measured runs");

    const auto hashCharacteristics = std::get_if<core::HashCharacteristics>(&result->characteristics);
    require(hashCharacteristics != nullptr && hashCharacteristics->outputBytes == 32,
            "SHA-256 result characteristics are incorrect");
}

void testFreshWorkerSeriesAndReuse()
{
    std::vector<qint64> workerPids;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPids.push_back(pid); };
    application::BenchmarkController controller(nullptr, {}, std::move(hooks));
    const auto config = seriesConfig(3);
    std::optional<core::BenchmarkResult> result;
    std::vector<core::ProgressInfo> progress;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
             [&](const core::ProgressInfo& value) { progress.push_back(value); });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
             [&](const core::BenchmarkResult& value) {
             result = value;
             loop.quit();
             });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    controller.start(config);
    timeout.start(30'000);
    loop.exec();
    require(result.has_value(), "M=3 controller series timed out");
    require(result->status == core::BenchmarkStatus::Completed,
        "M=3 controller series did not complete");
    require(result->runs.size() == 3, "M=3 controller series returned the wrong run count");
    require(workerPids.size() == 3, "M=3 controller series did not start exactly three workers");
    require(workerPids[0] != workerPids[1] && workerPids[1] != workerPids[2] &&
        workerPids[0] != workerPids[2],
        "M=3 controller series reused a worker process");
    require(result->statistics.has_value(), "M=3 controller result has no statistics");
    require(std::holds_alternative<core::MemoryV2Statistics>(result->statistics->memory),
        "M=3 controller result has legacy memory statistics");

    std::vector<std::uint32_t> measuringRuns;
    for (const auto& value : progress) {
    require(value.totalRuns == 3 && value.runIndex.has_value(),
        "M=3 progress has invalid logical context");
    if (value.phase == core::BenchmarkPhase::Measuring) {
        measuringRuns.push_back(*value.runIndex);
    }
    }
    require(measuringRuns == std::vector<std::uint32_t>{0, 1, 2},
        "M=3 progress did not preserve run ordering");
    require(!controller.isBusy(), "controller remained busy after M=3 completion");

    result.reset();
    workerPids.clear();
    const auto reuseConfig = seriesConfig(1);
    controller.start(reuseConfig);
    timeout.start(30'000);
    loop.exec();
    require(result.has_value() && result->status == core::BenchmarkStatus::Completed,
        "controller could not be reused after terminal cleanup");
    require(result->runs.size() == 1 && workerPids.size() == 1,
        "controller reuse did not start exactly one fresh worker");
}

void testCancellationDuringTerminalContinuationRetainsPrefix()
{
    std::vector<qint64> workerPids;
    bool cancellationWindowObserved = false;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPids.push_back(pid); };
    application::BenchmarkController* controllerPointer = nullptr;
    hooks.terminalContinuationQueued = [&] {
        cancellationWindowObserved = true;
        controllerPointer->requestCancel();
    };
    auto controller = std::make_unique<application::BenchmarkController>(
        nullptr, QString{}, std::move(hooks));
    controllerPointer = controller.get();
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    std::size_t finishCount = 0;

    QObject::connect(controller.get(), &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++finishCount;
                         result = value;
                         loop.quit();
                     });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    controller->start(seriesConfig(2));
    timeout.start(30'000);
    loop.exec();
    require(result.has_value(), "terminal-window cancellation timed out");
    require(cancellationWindowObserved, "terminal continuation cancellation hook was not reached");
    require(finishCount == 1 && result->status == core::BenchmarkStatus::Cancelled,
        "terminal-window cancellation did not publish exactly one Cancelled result");
    require(result->runs.size() == 1 && result->runs.front().runIndex == 0,
        "terminal-window cancellation did not retain the completed prefix");
    require(workerPids.size() == 1, "terminal-window cancellation launched an extra worker");
    require(!controller->isBusy(), "terminal-window cancellation left the controller busy");
}

void testDestructorSupervisesActiveSessionAsynchronously()
{
    qint64 workerPid = 0;
    QPointer<application::WorkerRunSession> sessionPointer;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPid = pid; };
    hooks.sessionCreated = [&](application::WorkerRunSession* session) {
        sessionPointer = session;
    };
    auto controller = std::make_unique<application::BenchmarkController>(
        nullptr, QString{}, std::move(hooks));
    controller->start(validConfig());
    QElapsedTimer startTimeout;
    startTimeout.start();
    while (startTimeout.elapsed() < 5'000 && workerPid == 0) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(workerPid != 0, "destructor test worker PID marker was missing");

    controller.reset();
    QElapsedTimer cleanupTimeout;
    cleanupTimeout.start();
    while (cleanupTimeout.elapsed() < 5'000 &&
           (processIsRunning(static_cast<DWORD>(workerPid)) || sessionPointer)) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(!processIsRunning(static_cast<DWORD>(workerPid)),
        "controller destruction orphaned the active worker");
    require(!sessionPointer, "controller destruction leaked the detached active session");
}

void testDestructorDefersTerminalSessionDeletion()
{
    QPointer<application::WorkerRunSession> sessionPointer;
    std::unique_ptr<application::BenchmarkController> controller;
    application::WorkerRunSessionTestHooks hooks;
    hooks.sessionCreated = [&](application::WorkerRunSession* session) {
        sessionPointer = session;
        QObject::connect(session, &application::WorkerRunSession::completed, [&] {
            controller.reset();
        });
    };
    controller = std::make_unique<application::BenchmarkController>(
        nullptr, QString{}, std::move(hooks));
    controller->start(validConfig());

    QElapsedTimer terminalTimeout;
    terminalTimeout.start();
    while (terminalTimeout.elapsed() < 10'000 && sessionPointer) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(!controller, "controller was not destroyed during terminal signal emission");
    require(!sessionPointer, "terminal WorkerRunSession was destroyed synchronously or leaked");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInvalidPreflight();
        testSuccessfulSession();
        testFreshWorkerSeriesAndReuse();
        testCancellationDuringTerminalContinuationRetainsPrefix();
        testDestructorSupervisesActiveSessionAsynchronously();
        testDestructorDefersTerminalSessionDeletion();
        std::cout << "PASS BenchmarkController\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BenchmarkController: " << error.what() << '\n';
        return 1;
    }
}
