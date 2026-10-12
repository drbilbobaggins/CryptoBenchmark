#include <cryptobench/application/WorkerRunSession.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QDir>
#include <QFileInfo>

#include <windows.h>

#include <cstdlib>
#include <array>
#include <iostream>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

void waitUntil(const std::function<bool()>& condition, const char* message)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < 15'000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(condition(), message);
}

core::BenchmarkConfig testConfig()
{
    return {
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{8}
    };
}

void setScenario(const char* scenario)
{
    const auto markerPath = QDir(QDir::tempPath()).filePath(
        QStringLiteral("CryptoBenchmark_WorkerRunSession_%1.signal")
            .arg(QCoreApplication::applicationPid()));
    QFile::remove(markerPath);
    qputenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE", markerPath.toLocal8Bit());
    qputenv("CRYPTOBENCH_TEST_WORKER_SCENARIO", scenario);
}

QString markerPath()
{
    return QDir(QDir::tempPath()).filePath(
        QStringLiteral("CryptoBenchmark_WorkerRunSession_%1.signal")
            .arg(QCoreApplication::applicationPid()));
}

std::optional<DWORD> workerPidFromMarker()
{
    QFile signalFile(markerPath());
    if (!signalFile.open(QIODevice::ReadOnly)) return std::nullopt;
    const auto lines = signalFile.readAll().split('\n');
    for (const auto& line : lines) {
        if (!line.startsWith("pid ")) continue;
        bool ok = false;
        const auto pid = line.mid(4).trimmed().toULongLong(&ok);
        if (ok && pid <= MAXDWORD) return static_cast<DWORD>(pid);
    }
    return std::nullopt;
}

bool processIsRunning(DWORD pid)
{
    const auto handle = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (handle == nullptr) return false;
    const auto result = WaitForSingleObject(handle, 0);
    CloseHandle(handle);
    return result == WAIT_TIMEOUT;
}

void clearScenario()
{
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE");
}

void waitForMarker(const char* marker)
{
    waitUntil([&] {
        const auto markerPath = qEnvironmentVariable("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE");
        QFile signalFile(markerPath);
        if (!signalFile.open(QIODevice::ReadOnly)) return false;
        return signalFile.readAll().contains(QByteArray(marker));
    }, (std::string("scripted worker did not reach marker: ") + marker).c_str());
}

void testSingleV2Run()
{
    setScenario("completed-before-exit");
    application::WorkerRunSession session;
    bool completed = false;
    bool failed = false;
    application::WorkerRunSessionResult result{};
    core::ErrorInfo failure{};
    std::vector<core::BenchmarkPhase> phases;

    QObject::connect(&session, &application::WorkerRunSession::progressChanged,
                     [&](const core::ProgressInfo& progress) { phases.push_back(progress.phase); });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult& value) {
                         result = value;
                         completed = true;
                     });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         failure = value;
                         failed = true;
                     });

    const auto config = testConfig();
    session.start(config, 0, {1});
    waitUntil([&] { return completed || failed; }, "v2 WorkerRunSession did not terminate");
    clearScenario();

    require(!failed, "v2 WorkerRunSession failed: " + failure.technicalMessage);
    require(completed, "v2 WorkerRunSession did not complete");
    require(result.logicalRunIndex == 0, "logical run index was not preserved");
    require(result.workerMeasurement.runIndex == 0, "worker measurement index was not preserved");
    require(result.workerMeasurement.elapsedNanoseconds == 1'000,
            "worker measurement timing was not preserved");
    require(result.memory.baselinePrivateUsageBytes > 0, "B0 was not collected");
    require(result.memory.readyPrivateUsageBytes > 0, "B1 was not collected");
    require(result.memory.finalPrivateUsageBytes > 0, "E was not collected");
    require(!session.isActive(), "session remained active after completion");
    require(phases.size() >= 4 && phases[0] == core::BenchmarkPhase::Preparing &&
                phases[1] == core::BenchmarkPhase::Warmup &&
                phases[phases.size() - 2] == core::BenchmarkPhase::Measuring &&
                phases.back() == core::BenchmarkPhase::Finalizing,
            "v2 session phases were not forwarded in lifecycle order");
}

void testExitBeforeFinalQueuedFramesDoesNotFalseFail()
{
    setScenario("exit-before-final-queued");
    application::WorkerRunSession session;
    bool completed = false;
    bool failed = false;
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return completed || failed; },
              "exit-before-final-queued scenario did not terminate");
    clearScenario();
    require(completed && !failed,
            "queued final IPC frames were treated as an early worker failure");
}

void testDisconnectedLiveWorkerRetainsExitWatchdog()
{
    setScenario("completed-disconnect-stays-alive");
    application::WorkerRunSession session;
    int terminalSignals = 0;
    bool failed = false;
    bool completed = false;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; ++terminalSignals; });
    session.start(testConfig(), 0, {1});
    waitForMarker("disconnected-alive");
    const auto pid = workerPidFromMarker();
    waitUntil([&] { return !session.isActive(); },
              "live disconnected worker did not reach a terminal cleanup result");
    clearScenario();
    require(failed && !completed && terminalSignals == 1,
            "live disconnected worker did not produce exactly one failure");
    require(pid && !processIsRunning(*pid), "live disconnected worker was orphaned");
}

void testProgressBeforePreparationIsRejected()
{
    setScenario("invalid-progress-before-preparation");
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); },
              "invalid pre-preparation progress did not terminate the session");
    clearScenario();
    require(failed && !completed, "invalid pre-preparation progress was accepted");
}

void testProgressDuringMeasurementIsRejected()
{
    setScenario("invalid-progress-during-measurement");
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); },
              "invalid measurement progress did not terminate the session");
    clearScenario();
    require(failed && !completed, "invalid measurement progress was accepted");
}

void testCancellationWaitingForBaselineReadyCleansUp()
{
    setScenario("silent-baseline");
    bool cancelled = false;
    bool failed = false;
    bool completed = false;
    qint64 workerPid = 0;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPid = pid; };
    application::WorkerRunSession hookedSession(nullptr, {}, std::move(hooks));
    QObject::connect(&hookedSession, &application::WorkerRunSession::cancelled,
             [&] { cancelled = true; });
    QObject::connect(&hookedSession, &application::WorkerRunSession::failed,
             [&](const core::ErrorInfo&) { failed = true; });
    QObject::connect(&hookedSession, &application::WorkerRunSession::completed,
             [&](const application::WorkerRunSessionResult&) { completed = true; });
    hookedSession.start(testConfig(), 0, {1});
    waitForMarker("baseline-silent");
    hookedSession.cancel();
    waitUntil([&] { return !hookedSession.isActive(); },
          "BaselineReady cancellation did not clean up");
    const auto pid = workerPid;
    clearScenario();
    require(cancelled && !failed && !completed,
        "BaselineReady cancellation did not produce one cancellation");
    require(pid > 0 && !processIsRunning(static_cast<DWORD>(pid)),
        "BaselineReady cancellation left the worker alive");
}

void testInjectedBoundaryFailure(
    const char* scenario,
    const char* boundary,
    bool failStart,
    bool failMark,
    bool failStop,
    core::ErrorCode expectedCode,
    core::FailureStage expectedStage,
    const char* forbiddenMarker)
{
    setScenario(scenario);
    bool samplerActive = false;
    bool samplerDiscarded = false;
    bool failed = false;
    bool completed = false;
    core::ErrorInfo error{};
    int terminalSignals = 0;
    qint64 workerPid = 0;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPid = pid; };
    hooks.startSampler = [&](std::uint32_t, const core::MeasurementSettings&) {
        if (failStart) throw std::runtime_error("injected B0 failure");
        samplerActive = true;
    };
    hooks.markExecutionBoundary = [&] {
        if (failMark) throw std::runtime_error("injected B1 failure");
    };
    hooks.stopAndCollectSampler = [&] {
        if (failStop) throw std::runtime_error("injected E failure");
        samplerActive = false;
        return core::MemoryV2RawObservations{1, 2, std::nullopt, std::nullopt, 3, 0, 0};
    };
    hooks.stopAndDiscardSampler = [&] {
        samplerActive = false;
        samplerDiscarded = true;
    };
    hooks.samplerIsActive = [&] { return samplerActive; };

    application::WorkerRunSession session(nullptr, {}, std::move(hooks));
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         error = value;
                         failed = true;
                         ++terminalSignals;
                     });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::cancelled,
                     [&] { ++terminalSignals; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); }, "injected boundary failure did not terminate");
    clearScenario();

    require(failed && !completed && terminalSignals == 1,
            std::string(boundary) + " failure did not produce one Failed outcome");
        require(error.code == expectedCode && error.stage == expectedStage,
            std::string(boundary) + " failure had the wrong error classification");
    require(samplerDiscarded && !samplerActive,
            std::string(boundary) + " failure did not discard the sampler");
    require(workerPid > 0 && !processIsRunning(static_cast<DWORD>(workerPid)),
            std::string(boundary) + " failure left the worker alive");
        QFile marker(markerPath());
        require(marker.open(QIODevice::ReadOnly),
            std::string(boundary) + " observation marker was unavailable");
        require(!marker.readAll().contains(forbiddenMarker),
            std::string(boundary) + " permission was sent after boundary failure");
}

void testBoundaryFailuresAreTerminalAndClean()
{
        testInjectedBoundaryFailure(
        "observe-b0-command", "B0", true, false, false,
        core::ErrorCode::MemoryMeasurementFailed, core::FailureStage::MemoryMeasurement,
        "start-preparation-sent");
        testInjectedBoundaryFailure(
        "observe-b1-command", "B1", false, true, false,
        core::ErrorCode::MemoryMeasurementFailed, core::FailureStage::MemoryMeasurement,
        "start-measurement-sent");
        testInjectedBoundaryFailure(
        "observe-e-command", "E", false, false, true,
        core::ErrorCode::MemoryMeasurementFailed, core::FailureStage::MemoryMeasurement,
        "memory-window-closed-sent");
}

void testNegativeV2FramesAreRejected()
{
    const std::array<const char*, 5> scenarios{
        "wrong-baseline-index",
        "duplicate-baseline",
        "v2-measurement-ready",
        "wrong-direction",
        "malformed-boundary"
    };
    for (const auto* scenario : scenarios) {
        setScenario(scenario);
        application::WorkerRunSession session;
        bool failed = false;
        bool completed = false;
        int terminalSignals = 0;
        QObject::connect(&session, &application::WorkerRunSession::failed,
                         [&](const core::ErrorInfo&) { failed = true; ++terminalSignals; });
        QObject::connect(&session, &application::WorkerRunSession::completed,
                         [&](const application::WorkerRunSessionResult&) { completed = true; ++terminalSignals; });
        session.start(testConfig(), 0, {1});
        waitUntil([&] { return !session.isActive(); }, "negative v2 frame did not terminate");
        clearScenario();
        require(failed && !completed && terminalSignals == 1,
                std::string(scenario) + " was not rejected exactly once");
    }
}

void testUnsupportedWorkerProtocolIsRejectedBeforeBenchmarkRequest()
{
    setScenario("unsupported-protocol");
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    int terminalSignals = 0;
    core::ErrorInfo error{};
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         failed = true;
                         error = value;
                         ++terminalSignals;
                     });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) {
                         completed = true;
                         ++terminalSignals;
                     });
    session.start(testConfig(), 0, {1});
    waitForMarker("unsupported-protocol-ready");
    waitUntil([&] { return !session.isActive(); },
              "unsupported worker protocol did not terminate the session");
    QFile marker(markerPath());
    require(marker.open(QIODevice::ReadOnly), "protocol marker was unavailable");
    const auto markerContent = marker.readAll();
    const auto pid = workerPidFromMarker();
    clearScenario();
    require(failed && !completed && terminalSignals == 1,
            "unsupported worker protocol did not produce one Failed outcome");
    require(error.code == core::ErrorCode::WorkerCommunicationFailed &&
                error.stage == core::FailureStage::WorkerCommunication,
            "unsupported worker protocol had the wrong classification");
    require(!markerContent.contains("unexpected-benchmark-request"),
            "benchmark request was sent after protocol rejection");
    require(pid && !processIsRunning(*pid),
            "unsupported worker protocol left the worker alive");
}

void testCancellationAfterMemoryWindowClosedDiscardsPartialResult()
{
    setScenario("wait-after-memory-window-closed");
    bool samplerActive = false;
    bool samplerDiscarded = false;
    qint64 workerPid = 0;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64 pid) { workerPid = pid; };
    hooks.startSampler = [&](std::uint32_t, const core::MeasurementSettings&) {
        samplerActive = true;
    };
    hooks.markExecutionBoundary = [&] {};
    hooks.stopAndCollectSampler = [&] {
        samplerActive = false;
        return core::MemoryV2RawObservations{1, 2, std::nullopt, std::nullopt, 3, 0, 0};
    };
    hooks.stopAndDiscardSampler = [&] {
        samplerActive = false;
        samplerDiscarded = true;
    };
    hooks.samplerIsActive = [&] { return samplerActive; };
    application::WorkerRunSession session(nullptr, {}, std::move(hooks));
    bool cancelled = false;
    bool failed = false;
    bool completed = false;
    int terminalSignals = 0;
    QObject::connect(&session, &application::WorkerRunSession::cancelled,
                     [&] { cancelled = true; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) {
                         completed = true;
                         ++terminalSignals;
                     });
    session.start(testConfig(), 0, {1});
    waitForMarker("memory-window-closed-received");
    session.cancel();
    waitUntil([&] { return !session.isActive(); },
              "post-memory-window cancellation did not terminate");
    clearScenario();
    require(cancelled && !failed && !completed && terminalSignals == 1,
            "post-memory-window cancellation produced the wrong terminal result");
    require(samplerDiscarded && !samplerActive,
            "post-memory-window cancellation did not discard the sampler");
    require(workerPid > 0 && !processIsRunning(static_cast<DWORD>(workerPid)),
            "post-memory-window cancellation left the worker alive");
}

void testSequentialSessionsUseDistinctWorkers()
{
    setScenario("completed-before-exit");
    const auto config = core::BenchmarkConfig{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        1,
        3,
        core::HashConfig{8}
    };
    std::vector<qint64> workerPids;
    for (std::uint32_t runIndex = 0; runIndex < 3; ++runIndex) {
        qint64 workerPid = 0;
        application::WorkerRunSessionTestHooks hooks;
        hooks.workerStarted = [&](qint64 pid) { workerPid = pid; };
        application::WorkerRunSession session(nullptr, {}, std::move(hooks));
        bool completed = false;
        QObject::connect(&session, &application::WorkerRunSession::completed,
                         [&](const application::WorkerRunSessionResult& result) {
                             completed = result.logicalRunIndex == runIndex;
                         });
        session.start(config, runIndex, {1});
        waitUntil([&] { return !session.isActive(); }, "sequential session did not terminate");
        require(completed && workerPid > 0, "sequential session lost completion or PID");
        require(!processIsRunning(static_cast<DWORD>(workerPid)),
                "next sequential session would overlap a live worker");
        workerPids.push_back(workerPid);
    }
    clearScenario();
    require(workerPids[0] != workerPids[1] && workerPids[1] != workerPids[2] &&
                workerPids[0] != workerPids[2],
            "sequential sessions reused a worker PID");
}

void testGenuineProductionWorkerV2Run(std::uint32_t logicalRunIndex)
{
    clearScenario();
    const auto workerPath = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(workerPath), "genuine production worker was not found");
    application::WorkerRunSession session(nullptr, workerPath);
    auto config = testConfig();
    config.runs = 3;
    config.iterationsPerRun = 100'000;
    bool completed = false;
    bool failed = false;
    application::WorkerRunSessionResult result{};
    core::ErrorInfo error{};
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult& value) {
                         completed = true;
                         result = value;
                     });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) { failed = true; error = value; });
    session.start(config, logicalRunIndex, {1});
    waitUntil([&] { return completed || failed; }, "genuine production worker did not terminate");
    require(completed && !failed,
            "genuine production worker v2 run failed: " + error.technicalMessage);
    require(result.logicalRunIndex == logicalRunIndex &&
                result.workerMeasurement.runIndex == logicalRunIndex &&
                result.workerMeasurement.elapsedNanoseconds > 0 &&
                result.workerMeasurement.processCpuNanoseconds > 0,
            "genuine production worker did not report timing and CPU data");
    require(result.memory.baselinePrivateUsageBytes > 0 &&
                result.memory.readyPrivateUsageBytes > 0 &&
                result.memory.finalPrivateUsageBytes > 0,
            "genuine production worker did not report B0/B1/E observations");
}

void testEarlyNormalExitMissingFinalFramesFails()
{
    setScenario("early-exit-missing-final");
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    int terminalSignals = 0;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; ++terminalSignals; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); }, "early normal exit did not terminate");
    clearScenario();
    require(failed && !completed && terminalSignals == 1,
            "early normal exit with missing final frames did not fail exactly once");
}

void testV2FailureScenario(const char* scenario, const char* expectedMessage)
{
    setScenario(scenario);
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    int terminalSignals = 0;
    core::ErrorInfo error{};
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         failed = true;
                         error = value;
                         ++terminalSignals;
                     });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) {
                         completed = true;
                         ++terminalSignals;
                     });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); }, "v2 failure scenario did not terminate");
    clearScenario();
    require(failed && !completed && terminalSignals == 1,
            "v2 failure scenario produced an invalid terminal signal set");
    require(error.technicalMessage == expectedMessage,
            "v2 failure scenario did not preserve its authoritative ErrorInfo");
}

void testV2CompletedOutcomeWithAbnormalExitFails()
{
    setScenario("completed-abnormal-exit-v2");
    application::WorkerRunSession session;
    bool failed = false;
    bool completed = false;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); }, "completed abnormal-exit scenario did not terminate");
    clearScenario();
    require(failed && !completed,
            "completed outcome followed by abnormal exit produced Completed");
}

void testWorkerFailureGracefulExit()
{
    setScenario("failed-graceful");
    application::WorkerRunSession session;
    core::ErrorInfo error{};
    int terminalSignals = 0;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) { error = value; ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { ++terminalSignals; });
    QObject::connect(&session, &application::WorkerRunSession::cancelled,
                     [&] { ++terminalSignals; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); }, "graceful worker failure did not terminate");
    clearScenario();
    require(terminalSignals == 1 && error.code == core::ErrorCode::CryptoOperationFailed,
            "graceful worker failure did not preserve one original Failed outcome");
    require(error.technicalMessage == "scripted v2 worker failure" &&
                error.libraryDetails && *error.libraryDetails == "scripted-library-details",
            "graceful worker failure lost complete ErrorInfo");
}

void testWorkerFailureGraceExpiryKillsWorker()
{
    setScenario("failed-stays-alive");
    application::WorkerRunSession session;
    core::ErrorInfo error{};
    int terminalSignals = 0;
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) { error = value; ++terminalSignals; });
    session.start(testConfig(), 0, {1});
    waitForMarker("failure-sent");
    const auto pid = workerPidFromMarker();
    waitUntil([&] { return !session.isActive(); }, "failure grace expiry did not terminate");
    clearScenario();
    require(terminalSignals == 1 && error.code == core::ErrorCode::CryptoOperationFailed,
            "failure grace expiry did not preserve one Failed outcome");
    require(pid && !processIsRunning(*pid), "failure grace expiry left the worker alive");
}

void testZeroSamplesAndMeasurementSettings()
{
    for (std::uint32_t interval = 1; interval <= 5; ++interval) {
        setScenario("completed");
        bool samplerActive = false;
        std::uint32_t observedInterval = 0;
        application::WorkerRunSessionTestHooks hooks;
        hooks.startSampler = [&](std::uint32_t, const core::MeasurementSettings& settings) {
            observedInterval = settings.memorySamplingIntervalMilliseconds;
            samplerActive = true;
        };
        hooks.samplerIsActive = [&] { return samplerActive; };
        hooks.markExecutionBoundary = [&] {};
        hooks.stopAndCollectSampler = [&] {
            samplerActive = false;
            return core::MemoryV2RawObservations{10, 20, std::nullopt, std::nullopt, 30, 0, 0};
        };
        hooks.stopAndDiscardSampler = [&] { samplerActive = false; };
        application::WorkerRunSession session(nullptr, {}, std::move(hooks));
        bool completed = false;
        QObject::connect(&session, &application::WorkerRunSession::completed,
                         [&](const application::WorkerRunSessionResult& result) {
                             completed = result.memory.preparationSampleCount == 0 &&
                                 result.memory.executionSampleCount == 0;
                         });
        session.start(testConfig(), 0, {interval});
        waitUntil([&] { return !session.isActive(); }, "zero-sample settings run did not terminate");
        clearScenario();
        require(completed && observedInterval == interval,
                "valid MeasurementSettings or zero-sample observations were not preserved");
    }
}

void testOutOfRangeLogicalRunIndexIsRejectedBeforeLaunch()
{
    application::WorkerRunSessionTestHooks hooks;
    bool workerStarted = false;
    hooks.workerStarted = [&](qint64) { workerStarted = true; };
    application::WorkerRunSession session(nullptr, {}, std::move(hooks));
    bool rejected = false;
    try {
        session.start(testConfig(), 1, {1});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected && !workerStarted && !session.isActive(),
            "out-of-range logical run index launched a worker");
}

void testInvalidSettingsAreRejected()
{
    application::WorkerRunSession session;
    const auto config = testConfig();
    bool rejected = false;
    try {
        session.start(config, 0, {6});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "invalid v2 sampling settings were accepted");
    require(!session.isActive(), "session became active after invalid settings");
}

void testInvalidCanonicalConfigurationIsRejectedBeforeLaunch()
{
    auto config = testConfig();
    config.iterationsPerRun = 0;
    bool workerStarted = false;
    application::WorkerRunSessionTestHooks hooks;
    hooks.workerStarted = [&](qint64) { workerStarted = true; };
    application::WorkerRunSession session(nullptr, {}, std::move(hooks));
    bool rejected = false;
    try {
        session.start(config, 0, {1});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected && !workerStarted && !session.isActive(),
            "invalid canonical configuration launched a worker");
}

void testFailedStartUsesVerifiedNoChildExit()
{
    const auto missingWorkerPath = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("missing-CryptoBenchmarkWorker.exe"));
    QFile::remove(missingWorkerPath);
    application::WorkerRunSession session(nullptr, missingWorkerPath);
    bool failed = false;
    bool completed = false;
    core::ErrorInfo error{};
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) { failed = true; error = value; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) { completed = true; });
    session.start(testConfig(), 0, {1});
    waitUntil([&] { return !session.isActive(); },
              "failed worker start did not produce a terminal result");
    require(failed && !completed && error.code == core::ErrorCode::WorkerStartupFailed,
            "failed worker start was not classified as a startup failure");
}

void testListenerStartupFailureDoesNotAwaitWorkerExit()
{
    application::WorkerRunSessionTestHooks hooks;
    bool workerStarted = false;
    hooks.workerStarted = [&](qint64) { workerStarted = true; };
    hooks.endpointFactory = [] { return QString(512, QLatin1Char('x')); };
    application::WorkerRunSession session(nullptr, {}, std::move(hooks));
    bool failed = false;
    bool completed = false;
    int terminalSignals = 0;
    core::ErrorInfo error{};
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         failed = true;
                         error = value;
                         ++terminalSignals;
                     });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult&) {
                         completed = true;
                         ++terminalSignals;
                     });

    session.start(testConfig(), 0, {1});
    require(!session.isActive(), "listener startup failure remained active");
    require(failed && !completed && terminalSignals == 1,
            "listener startup failure did not emit exactly one Failed signal");
    require(error.code == core::ErrorCode::WorkerStartupFailed &&
                error.stage == core::FailureStage::WorkerStartup,
            "listener startup failure had the wrong classification");
    require(!workerStarted, "listener startup failure attempted to launch a worker");
}

    void testEarlyWorkerFailurePreservesErrorInfo()
    {
        setScenario("failed-before-measurement");
        application::WorkerRunSession session;
        bool failed = false;
        bool completed = false;
        core::ErrorInfo error{};
        QObject::connect(&session, &application::WorkerRunSession::failed,
                 [&](const core::ErrorInfo& value) { error = value; failed = true; });
        QObject::connect(&session, &application::WorkerRunSession::completed,
                 [&] { completed = true; });
        session.start(testConfig(), 0, {1});
        waitUntil([&] { return failed || completed; }, "early worker failure did not terminate");
        clearScenario();
        require(failed && !completed, "early worker failure produced an invalid terminal result");
        require(error.code == core::ErrorCode::CryptoOperationFailed,
            "worker ErrorInfo code was not preserved");
        require(error.stage == core::FailureStage::Measurement,
            "worker ErrorInfo stage was not preserved");
        require(error.runIndex && *error.runIndex == 0,
            "worker ErrorInfo run index was not preserved");
        require(error.technicalMessage == "scripted v2 worker failure",
            "worker ErrorInfo technical message was not preserved");
        require(error.libraryDetails && *error.libraryDetails == "scripted-library-details",
            "worker ErrorInfo library details were not preserved");
    }

    void testCancellationDuringPreparationIsAsynchronous()
    {
        setScenario("wait-preparing");
        application::WorkerRunSession session;
        int cancelled = 0;
        bool failed = false;
        bool completed = false;
        QObject::connect(&session, &application::WorkerRunSession::cancelled,
                 [&] { ++cancelled; });
        QObject::connect(&session, &application::WorkerRunSession::failed,
                 [&](const core::ErrorInfo&) { failed = true; });
        QObject::connect(&session, &application::WorkerRunSession::completed,
                 [&] { completed = true; });
        session.start(testConfig(), 0, {1});
        waitForMarker("preparing");
        session.cancel();
        waitUntil([&] { return !session.isActive(); }, "preparation cancellation did not clean up");
        clearScenario();
        require(cancelled == 1 && !failed && !completed,
            "preparation cancellation did not emit exactly one cancellation");
    }

    void testPreparationLongerThanTwoSecondsCompletes()
    {
        setScenario("long-preparation");
        application::WorkerRunSession session;
        bool completed = false;
        bool failed = false;
        core::ErrorInfo error{};
        QObject::connect(&session, &application::WorkerRunSession::completed,
                         [&](const application::WorkerRunSessionResult&) { completed = true; });
        QObject::connect(&session, &application::WorkerRunSession::failed,
                         [&](const core::ErrorInfo& value) { failed = true; error = value; });
        session.start(testConfig(), 0, {1});
            waitForMarker("long-preparation-delay-started");
            QElapsedTimer preparationDelay;
            preparationDelay.start();
            waitForMarker("long-preparation-baseline-ready");
            require(preparationDelay.elapsed() >= 2'000,
                "BaselineReady was sent before the common preparation delay elapsed");
        waitUntil([&] { return !session.isActive(); },
                  "long valid preparation did not complete");
        clearScenario();
        require(completed && !failed,
                "valid preparation longer than two seconds failed: " + error.technicalMessage);
    }

void testCancellationDuringMeasurementIsAsynchronous()
{
    setScenario("wait-measuring");
    application::WorkerRunSession session;
    int cancelled = 0;
    bool failed = false;
    bool completed = false;
    QObject::connect(&session, &application::WorkerRunSession::cancelled,
                     [&] { ++cancelled; });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo&) { failed = true; });
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&] { completed = true; });
    session.start(testConfig(), 0, {1});
    waitForMarker("measuring");
    session.cancel();
    waitUntil([&] { return !session.isActive(); }, "measurement cancellation did not clean up");
    clearScenario();
    require(cancelled == 1 && !failed && !completed,
            "measurement cancellation did not emit exactly one cancellation");
}

    void testAbnormalExitCannotComplete()
    {
        setScenario("crash-before-outcome");
        application::WorkerRunSession session;
        bool failed = false;
        bool completed = false;
        QObject::connect(&session, &application::WorkerRunSession::failed,
                 [&](const core::ErrorInfo&) { failed = true; });
        QObject::connect(&session, &application::WorkerRunSession::completed,
                 [&] { completed = true; });
        session.start(testConfig(), 0, {1});
        waitUntil([&] { return failed || completed; }, "abnormal worker exit did not terminate");
        clearScenario();
        require(failed && !completed, "abnormal worker exit produced Completed");
    }

    void testDuplicateOutcomeCannotComplete()
    {
        setScenario("duplicate-outcome");
        application::WorkerRunSession session;
        int terminalSignals = 0;
        bool failed = false;
        QObject::connect(&session, &application::WorkerRunSession::failed,
                 [&](const core::ErrorInfo&) { failed = true; ++terminalSignals; });
        QObject::connect(&session, &application::WorkerRunSession::completed,
                 [&] { ++terminalSignals; });
        QObject::connect(&session, &application::WorkerRunSession::cancelled,
                 [&] { ++terminalSignals; });
        session.start(testConfig(), 0, {1});
        waitUntil([&] { return !session.isActive(); }, "duplicate outcome session did not terminate");
        clearScenario();
        require(failed && terminalSignals == 1,
            "duplicate outcome did not produce one failed terminal signal");
    }

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testInvalidSettingsAreRejected();
        testInvalidCanonicalConfigurationIsRejectedBeforeLaunch();
        testFailedStartUsesVerifiedNoChildExit();
        testListenerStartupFailureDoesNotAwaitWorkerExit();
        testSingleV2Run();
        testExitBeforeFinalQueuedFramesDoesNotFalseFail();
        testDisconnectedLiveWorkerRetainsExitWatchdog();
        testProgressBeforePreparationIsRejected();
        testProgressDuringMeasurementIsRejected();
        testCancellationWaitingForBaselineReadyCleansUp();
        testBoundaryFailuresAreTerminalAndClean();
        testNegativeV2FramesAreRejected();
        testUnsupportedWorkerProtocolIsRejectedBeforeBenchmarkRequest();
        testCancellationAfterMemoryWindowClosedDiscardsPartialResult();
        testSequentialSessionsUseDistinctWorkers();
        testGenuineProductionWorkerV2Run(0);
        testGenuineProductionWorkerV2Run(1);
        testEarlyNormalExitMissingFinalFramesFails();
        testV2FailureScenario("failed-during-measurement-v2",
                      "scripted v2 measurement failure");
        testV2FailureScenario("failed-after-memory-window-closed-v2",
                      "scripted v2 post-window failure");
        testV2FailureScenario("failed-disconnect-immediately-v2",
                      "scripted v2 worker failure");
        testV2FailureScenario("missing-final-outcome-v2",
                      "worker session technical timeout");
        testV2CompletedOutcomeWithAbnormalExitFails();
        testWorkerFailureGracefulExit();
        testWorkerFailureGraceExpiryKillsWorker();
        testZeroSamplesAndMeasurementSettings();
        testOutOfRangeLogicalRunIndexIsRejectedBeforeLaunch();
        testEarlyWorkerFailurePreservesErrorInfo();
        testCancellationDuringPreparationIsAsynchronous();
        testPreparationLongerThanTwoSecondsCompletes();
        testCancellationDuringMeasurementIsAsynchronous();
        testAbnormalExitCannotComplete();
        testDuplicateOutcomeCannotComplete();
        std::cout << "WorkerRunSession tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WorkerRunSession tests failed: " << error.what() << '\n';
        return 1;
    }
}
