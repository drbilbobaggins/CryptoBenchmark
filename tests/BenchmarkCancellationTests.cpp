#include <cryptobench/application/BenchmarkController.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QDir>
#include <QUuid>
#include <QTimer>

#include <cstdlib>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

core::BenchmarkConfig configFor(std::uint32_t runs)
{
    return {
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2,
        runs,
        core::HashConfig{8}
    };
}

core::BenchmarkConfig matrixConfig(std::size_t index)
{
    return {
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        2 + static_cast<std::uint64_t>(index % 2),
        1 + static_cast<std::uint32_t>(index % 2),
        core::HashConfig{8 + static_cast<std::uint64_t>(index)}
    };
}

void waitForResult(QEventLoop& loop, QTimer& timeout, std::optional<core::BenchmarkResult>& result)
{
    if (result.has_value()) return;
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(25'000);
    loop.exec();
    require(result.has_value(), "cancellation test timed out without a result");
}

void beginScenario(const char* scenario)
{
    require(qputenv("CRYPTOBENCH_TEST_WORKER_SCENARIO", scenario),
            "failed to configure scripted worker scenario");
}

void endScenario()
{
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE");
}

QString signalFilePath()
{
    return QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("cancellation_%1.signal")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
}

void waitForMarker(
    const QString& path,
    const QByteArray& expectedMarker,
    const std::optional<core::BenchmarkResult>* result = nullptr)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 5'000) {
        QFile signalFile(path);
        if (signalFile.open(QIODevice::ReadOnly)) {
            const auto lines = signalFile.readAll().split('\n');
            for (const auto& line : lines) {
                if (line == expectedMarker) return;
            }
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    std::string message = "scripted worker did not signal: " + expectedMarker.toStdString();
    QFile signalFile(path);
    if (signalFile.open(QIODevice::ReadOnly)) {
        message += "; signal file: " + signalFile.readAll().toStdString();
    } else {
        message += "; signal file: <unavailable>";
    }
    if (result != nullptr && result->has_value()) {
        message += "; terminal status=" +
            std::to_string(static_cast<int>((*result)->status));
        if ((*result)->error) message += "; error=" + (*result)->error->technicalMessage;
    }
    throw std::runtime_error(message);
}

struct ReuseSessionPlan {
    const char* scenario;
    core::BenchmarkStatus expectedStatus;
    core::BenchmarkConfig config;
    bool cancelOnProgress = false;
};

struct ReuseSessionObservation {
    core::BenchmarkResult result;
    bool controllerWasIdle = false;
    std::uint32_t workerPid = 0;
};

std::uint32_t readWorkerPid(const QString& path)
{
    QFile signalFile(path);
    require(signalFile.open(QIODevice::ReadOnly), "worker PID marker file was not created");
    for (const auto& line : signalFile.readAll().split('\n')) {
        if (line.startsWith("pid ")) {
            bool ok = false;
            const auto pid = line.mid(4).toUInt(&ok);
            require(ok && pid != 0, "worker PID marker was invalid");
            return pid;
        }
    }
    throw std::runtime_error("worker PID marker was missing");
}

void requireSameConfig(const core::BenchmarkConfig& actual, const core::BenchmarkConfig& expected)
{
    const auto* actualHash = std::get_if<core::HashConfig>(&actual.parameters);
    const auto* expectedHash = std::get_if<core::HashConfig>(&expected.parameters);
    require(actual.profile == expected.profile && actual.operation == expected.operation &&
                actual.iterationsPerRun == expected.iterationsPerRun && actual.runs == expected.runs &&
                actualHash != nullptr && expectedHash != nullptr &&
                actualHash->inputSize == expectedHash->inputSize,
            "reuse result did not preserve the current session configuration");
}

void requireReuseResult(
    const ReuseSessionObservation& observation,
    const ReuseSessionPlan& plan)
{
    require(observation.controllerWasIdle, "controller was busy while terminal result was emitted");
    require(observation.result.status == plan.expectedStatus,
            "reuse result status did not match the current session scenario");
    requireSameConfig(observation.result.config, plan.config);

    if (plan.expectedStatus == core::BenchmarkStatus::Completed) {
        require(observation.result.statistics.has_value() && !observation.result.error.has_value() &&
                    observation.result.runs.size() == plan.config.runs,
                "Completed reuse result violated its invariants");
        for (std::size_t index = 0; index < observation.result.runs.size(); ++index) {
            require(observation.result.runs[index].runIndex == index,
                    "Completed reuse runs were not a sequential prefix");
        }
    } else if (plan.expectedStatus == core::BenchmarkStatus::Cancelled) {
        require(!observation.result.statistics.has_value() && !observation.result.error.has_value() &&
                    observation.result.runs.empty(),
                "Cancelled reuse result contained official partial data");
    } else {
        require(observation.result.statistics.has_value() == false && observation.result.error.has_value() &&
                    observation.result.runs.empty(),
                "Failed reuse result violated its invariants");
    }
}

std::vector<ReuseSessionObservation> runReuseSequence(
    const std::vector<ReuseSessionPlan>& plans)
{
    require(!plans.empty(), "reuse sequence must contain at least one session");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::vector<ReuseSessionObservation> observations;
    std::vector<QString> signalPaths;
    signalPaths.reserve(plans.size());
    for (const auto& plan : plans) signalPaths.push_back(signalFilePath());
    std::size_t current = 0;
    bool cancelRequested = false;

    const auto prepareCurrentSession = [&] {
        QFile::remove(signalPaths[current]);
        beginScenario(plans[current].scenario);
        require(qputenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE",
                        signalPaths[current].toLocal8Bit()),
                "failed to configure reuse session signal file");
        cancelRequested = false;
    };

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
                     [&](const core::ProgressInfo&) {
                         if (plans[current].cancelOnProgress && !cancelRequested) {
                             cancelRequested = true;
                             controller.requestCancel();
                         }
                     });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& result) {
                         observations.push_back({result, !controller.isBusy(), 0});
                         if (++current == plans.size()) {
                             loop.quit();
                             return;
                         }
                         prepareCurrentSession();
                         controller.start(plans[current].config);
                     });

    prepareCurrentSession();
    controller.start(plans.front().config);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(15'000);
    loop.exec();
    require(observations.size() == plans.size(), "reuse sequence did not finish every session exactly once");
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(observations.size() == plans.size() && !controller.isBusy(),
            "reuse sequence produced a late terminal callback or remained busy");

    std::set<std::uint32_t> workerPids;
    for (std::size_t index = 0; index < plans.size(); ++index) {
        observations[index].workerPid = readWorkerPid(signalPaths[index]);
        require(workerPids.insert(observations[index].workerPid).second,
                "sequential sessions reused a worker process");
        requireReuseResult(observations[index], plans[index]);
    }
    endScenario();
    return observations;
}

void testSequentialReuseTransitionMatrix()
{
    struct Transition {
        const char* previous;
        const char* next;
        core::BenchmarkStatus previousStatus;
        core::BenchmarkStatus nextStatus;
    };
    const std::vector<Transition> transitions = {
        {"completed", "completed", core::BenchmarkStatus::Completed, core::BenchmarkStatus::Completed},
        {"completed", "wait-before-measurement", core::BenchmarkStatus::Completed, core::BenchmarkStatus::Cancelled},
        {"completed", "failed-disconnect-immediately", core::BenchmarkStatus::Completed, core::BenchmarkStatus::Failed},
        {"wait-before-measurement", "completed", core::BenchmarkStatus::Cancelled, core::BenchmarkStatus::Completed},
        {"wait-before-measurement", "wait-before-measurement", core::BenchmarkStatus::Cancelled, core::BenchmarkStatus::Cancelled},
        {"wait-before-measurement", "failed-disconnect-immediately", core::BenchmarkStatus::Cancelled, core::BenchmarkStatus::Failed},
        {"failed-disconnect-immediately", "completed", core::BenchmarkStatus::Failed, core::BenchmarkStatus::Completed},
        {"failed-disconnect-immediately", "wait-before-measurement", core::BenchmarkStatus::Failed, core::BenchmarkStatus::Cancelled},
        {"failed-disconnect-immediately", "failed-disconnect-immediately", core::BenchmarkStatus::Failed, core::BenchmarkStatus::Failed}
    };

    for (std::size_t index = 0; index < transitions.size(); ++index) {
        const auto& transition = transitions[index];
        runReuseSequence({
            {transition.previous, transition.previousStatus, matrixConfig(index * 2),
             transition.previousStatus == core::BenchmarkStatus::Cancelled},
            {transition.next, transition.nextStatus, matrixConfig(index * 2 + 1),
             transition.nextStatus == core::BenchmarkStatus::Cancelled}
        });
    }
}

void testMixedSequentialReuseChain()
{
    runReuseSequence({
        {"completed", core::BenchmarkStatus::Completed, matrixConfig(30)},
        {"wait-before-measurement", core::BenchmarkStatus::Cancelled, matrixConfig(31), true},
        {"failed-disconnect-immediately", core::BenchmarkStatus::Failed, matrixConfig(32)},
        {"completed", core::BenchmarkStatus::Completed, matrixConfig(33)}
    });
}

void testIdleCancellationIsHarmless()
{
    application::BenchmarkController controller;
    int resultCount = 0;
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult&) { ++resultCount; });

    controller.requestCancel();
    require(!controller.isBusy() && resultCount == 0,
            "idle cancellation changed controller state");
}

void testCancelWhileWaitingForWorkerReady()
{
    beginScenario("wait");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(1));
    controller.requestCancel();
    waitForResult(loop, timeout, result);
    require(resultCount == 1 && result->status == core::BenchmarkStatus::Cancelled,
            "startup cancellation did not produce one Cancelled result");
    require(!result->statistics && !result->error && result->runs.empty(),
            "startup cancellation published incomplete data");
    require(!controller.isBusy(), "controller remained busy after startup cancellation");
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(resultCount == 1, "startup cancellation published a duplicate terminal result");
    endScenario();
}

void testCancelBeforeMeasurementAndReuse()
{
    beginScenario("wait-before-measurement");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    const auto config = configFor(1);
    int resultCount = 0;
    std::optional<core::BenchmarkResult> firstResult;
    std::optional<core::BenchmarkResult> secondResult;
    bool firstSession = true;

    QObject::connect(&controller, &application::BenchmarkController::progressChanged,
                     [&](const core::ProgressInfo&) {
                         if (firstSession) {
                             controller.requestCancel();
                             controller.requestCancel();
                         } else {
                             controller.requestCancel();
                         }
                     });
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& result) {
                         ++resultCount;
                         if (firstSession) {
                             firstResult = result;
                             firstSession = false;
                             controller.start(config);
                         } else {
                             secondResult = result;
                             loop.quit();
                         }
                     });

    controller.start(config);
    waitForResult(loop, timeout, firstResult);
    require(resultCount == 2, "reuse cancellation did not produce two terminal results");
    require(firstResult->status == core::BenchmarkStatus::Cancelled &&
                !firstResult->statistics && !firstResult->error && firstResult->runs.empty(),
            "pre-measurement cancellation result was invalid");
    require(secondResult.has_value() && secondResult->status == core::BenchmarkStatus::Cancelled &&
                !secondResult->statistics && !secondResult->error && secondResult->runs.empty(),
            "reused cancellation session did not produce a valid Cancelled result");
    endScenario();
}

void testCancelDuringMeasurement()
{
    const auto signalPath = signalFilePath();
    QFile::remove(signalPath);
    beginScenario("wait-during-measurement");
    require(qputenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE", signalPath.toLocal8Bit()),
            "failed to configure active measurement signal file");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(1));
    waitForMarker(signalPath, "started 0", &result);
    controller.requestCancel();
    controller.requestCancel();
    waitForResult(loop, timeout, result);
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(resultCount == 1 && result->status == core::BenchmarkStatus::Cancelled,
            "active-sampler cancellation did not produce one Cancelled result");
    require(!result->statistics && !result->error && result->runs.empty(),
            "active-sampler cancellation published incomplete data");
    require(!controller.isBusy(), "controller remained busy after active cancellation");
    endScenario();
}

void testCompletedPrefixCancellation()
{
    const auto signalPath = signalFilePath();
    QFile::remove(signalPath);
    beginScenario("complete-one-run-then-wait-during-next");
    require(qputenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE", signalPath.toLocal8Bit()),
            "failed to configure prefix measurement signal file");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(2));
    waitForMarker(signalPath, "started 1", &result);
    controller.requestCancel();
    waitForResult(loop, timeout, result);
    require(resultCount == 1 && result->status == core::BenchmarkStatus::Cancelled,
            "prefix cancellation did not produce one Cancelled result");
    require(!result->statistics && !result->error && result->runs.size() == 1 &&
                result->runs.front().runIndex == 0,
            "completed prefix or interrupted run was assembled incorrectly");
    endScenario();
}

void requireFailedResult(const core::BenchmarkResult& result, std::size_t expectedRuns)
{
    require(result.status == core::BenchmarkStatus::Failed, "failure scenario did not fail");
    require(result.error.has_value(), "Failed result has no error");
    require(!result.statistics.has_value(), "Failed result contains statistics");
    require(result.runs.size() == expectedRuns, "Failed result contains an incomplete run");
}

void requireScriptedWorkerError(const core::BenchmarkResult& result)
{
    require(result.error->code == core::ErrorCode::CryptoOperationFailed &&
                result.error->stage == core::FailureStage::Measurement &&
                result.error->runIndex == 0 &&
                result.error->technicalMessage == "scripted worker failure" &&
                result.error->libraryDetails == "scripted-library-details",
            "worker ErrorInfo was not preserved exactly");
}

void testWorkerFailurePreservesErrorAndAllowsReuse()
{
    beginScenario("failed-disconnect-immediately");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> firstResult;
    std::optional<core::BenchmarkResult> secondResult;
    int resultCount = 0;
    bool firstSession = true;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& result) {
                         ++resultCount;
                         if (firstSession) {
                             firstSession = false;
                             firstResult = result;
                             controller.start(configFor(1));
                         } else {
                             secondResult = result;
                             loop.quit();
                         }
                     });

    controller.start(configFor(1));
    waitForResult(loop, timeout, firstResult);
    require(resultCount == 2, "worker failure reuse did not produce two terminal results");
    requireFailedResult(*firstResult, 0);
    requireScriptedWorkerError(*firstResult);
    requireFailedResult(*secondResult, 0);
    requireScriptedWorkerError(*secondResult);
    endScenario();
}

void testWorkerFailureDuringMeasurement()
{
    const auto signalPath = signalFilePath();
    QFile::remove(signalPath);
    beginScenario("failed-during-measurement");
    require(qputenv("CRYPTOBENCH_TEST_WORKER_SIGNAL_FILE", signalPath.toLocal8Bit()),
            "failed to configure active failure signal file");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(1));
    waitForMarker(signalPath, "started 0", &result);
    waitForResult(loop, timeout, result);
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(resultCount == 1, "active worker failure produced duplicate results");
    requireFailedResult(*result, 0);
    endScenario();
}

void testWorkerFailureSurvivesImmediateDisconnect()
{
    beginScenario("failed-disconnect-immediately");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(1));
    waitForResult(loop, timeout, result);
    require(resultCount == 1, "immediate disconnect produced duplicate results");
    requireFailedResult(*result, 0);
    require(result->error->code == core::ErrorCode::CryptoOperationFailed &&
                result->error->stage == core::FailureStage::Measurement &&
                result->error->runIndex == 0 &&
                result->error->technicalMessage == "scripted worker failure" &&
                result->error->libraryDetails == "scripted-library-details",
            "buffered worker ErrorInfo was not preserved after disconnect");
    endScenario();
}

void testWorkerFailureDiscardsPendingMemory()
{
    beginScenario("failed-after-memory-window-closed");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(1));
    waitForResult(loop, timeout, result);
    requireFailedResult(*result, 0);
    require(result->error->technicalMessage == "scripted pending-memory failure",
            "pending-memory failure error was not preserved");
    endScenario();
}

void testFinalRunWithoutOutcomeFailsAndReusesController()
{
    beginScenario("final-run-no-outcome");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> firstResult;
    std::optional<core::BenchmarkResult> secondResult;
    int resultCount = 0;
    bool firstSession = true;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& result) {
                         ++resultCount;
                         if (firstSession) {
                             firstSession = false;
                             firstResult = result;
                             controller.start(configFor(2));
                         } else {
                             secondResult = result;
                             loop.quit();
                         }
                     });

    controller.start(configFor(2));
    waitForResult(loop, timeout, firstResult);
    require(resultCount == 2, "final-run timeout reuse did not produce two terminal results");
    requireFailedResult(*firstResult, 2);
    requireFailedResult(*secondResult, 2);
    require(firstResult->error->code == core::ErrorCode::WorkerCommunicationFailed &&
                firstResult->error->stage == core::FailureStage::WorkerCommunication,
            "final-run timeout used the wrong canonical error classification");
    require(!controller.isBusy(), "final-run timeout left the controller busy");
    endScenario();
}

void testCompletedOutcomeWithoutExitFails()
{
    beginScenario("completed-no-exit");
    application::BenchmarkController controller;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    std::optional<core::BenchmarkResult> result;
    int resultCount = 0;

    QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                     [&](const core::BenchmarkResult& value) {
                         ++resultCount;
                         result = value;
                         loop.quit();
                     });

    controller.start(configFor(2));
    waitForResult(loop, timeout, result);
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    require(resultCount == 1, "completed-without-exit timeout produced duplicate results");
    requireFailedResult(*result, 2);
    require(result->error->code == core::ErrorCode::WorkerCommunicationFailed &&
                result->error->stage == core::FailureStage::WorkerCommunication,
            "completed-without-exit timeout used the wrong canonical error classification");
    require(!controller.isBusy(), "completed-without-exit timeout left the controller busy");
    endScenario();
}

void testParentDetectedFailureScenarios()
{
    for (const auto scenario : {"crash-during-measurement", "actual-crash-during-measurement",
                                "unexpected-disconnect", "protocol-error"}) {
        beginScenario(scenario);
        application::BenchmarkController controller;
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        std::optional<core::BenchmarkResult> result;
        int resultCount = 0;
        QObject::connect(&controller, &application::BenchmarkController::benchmarkFinished,
                         [&](const core::BenchmarkResult& value) {
                             ++resultCount;
                             result = value;
                             loop.quit();
                         });

        controller.start(configFor(1));
        waitForResult(loop, timeout, result);
        QCoreApplication::processEvents(QEventLoop::AllEvents);
        require(resultCount == 1, "parent failure produced duplicate results");
        requireFailedResult(*result, 0);
        if (std::string_view(scenario) == "actual-crash-during-measurement") {
            require(result->error->technicalMessage.find("crashed") != std::string::npos,
                "actual crash evidence was: " + result->error->technicalMessage);
        }
        endScenario();
    }
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testIdleCancellationIsHarmless();
        testCancelWhileWaitingForWorkerReady();
        testCancelBeforeMeasurementAndReuse();
        testCancelDuringMeasurement();
        testCompletedPrefixCancellation();
        testWorkerFailurePreservesErrorAndAllowsReuse();
        testWorkerFailureDuringMeasurement();
        testWorkerFailureSurvivesImmediateDisconnect();
        testWorkerFailureDiscardsPendingMemory();
        testFinalRunWithoutOutcomeFailsAndReusesController();
        testCompletedOutcomeWithoutExitFails();
        testParentDetectedFailureScenarios();
        testSequentialReuseTransitionMatrix();
        testMixedSequentialReuseChain();
        endScenario();
        std::cout << "Benchmark cancellation tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        endScenario();
        std::cerr << "Benchmark cancellation tests failed: " << error.what() << '\n';
        return 1;
    }
}
