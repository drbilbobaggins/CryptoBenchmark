#include "MemoryV2SamplingOverhead.h"

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/WorkerRunSession.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QSysInfo>
#include <QTimer>
#include <QUuid>

#include <windows.h>
#include <psapi.h>

#include <stdexcept>
#include <algorithm>
#include <array>
#include <functional>
#include <map>
#include <random>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

QString workerPath()
{
    const auto candidate = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(candidate), "real production worker is missing");
    return QFileInfo(candidate).absoluteFilePath();
}

std::uint64_t currentProcessCpuNanoseconds()
{
    FILETIME creation{}, exit{}, kernel{}, user{};
    require(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE,
            "GetProcessTimes failed for parent process");
    const auto ticks = [](const FILETIME& value) {
        return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(value.dwLowDateTime);
    };
    return (ticks(kernel) + ticks(user)) * 100U;
}

std::uint64_t processCreationTime100ns(std::uint32_t processId)
{
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    require(handle != nullptr, "could not open real worker for process identity");
    FILETIME creation{}, exit{}, kernel{}, user{};
    const auto success = GetProcessTimes(handle, &creation, &exit, &kernel, &user);
    CloseHandle(handle);
    require(success != FALSE, "GetProcessTimes failed for real worker identity");
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
        static_cast<std::uint64_t>(creation.dwLowDateTime);
}

std::uint64_t privateUsage(std::uint32_t processId)
{
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    require(handle != nullptr, "could not open real worker for PrivateUsage");
    PROCESS_MEMORY_COUNTERS_EX counters{};
    const auto ok = GetProcessMemoryInfo(
        handle, reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters), sizeof(counters));
    CloseHandle(handle);
    require(ok != FALSE, "GetProcessMemoryInfo failed for real worker");
    return static_cast<std::uint64_t>(counters.PrivateUsage);
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M19_3_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

QString sourceRoot()
{
    QDir directory(QCoreApplication::applicationDirPath());
    while (!directory.isRoot()) {
        if (QFileInfo::exists(directory.filePath(QStringLiteral(".git")))) {
            return directory.absolutePath();
        }
        directory.cdUp();
    }
    return {};
}

QString gitValue(const QStringList& arguments)
{
    const auto root = sourceRoot();
    if (root.isEmpty()) return {};
    QProcess process;
    process.setWorkingDirectory(root);
    process.start(QStringLiteral("git"), arguments);
    if (!process.waitForFinished(5'000) || process.exitCode() != 0) return {};
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString executableSha256(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not open real worker for SHA-256");
    return QString::fromLatin1(
        QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

QJsonValue optionalU64(const std::optional<std::uint64_t>& value)
{
    return value ? QJsonValue(QString::number(*value)) : QJsonValue(QJsonValue::Null);
}

QString modeName(SamplingOverheadMode mode)
{
    return mode == SamplingOverheadMode::BoundaryOnlyControl
        ? QStringLiteral("boundaryOnlyControl") : QStringLiteral("periodic");
}

QString workloadName(SamplingOverheadWorkload workload)
{
    return workload == SamplingOverheadWorkload::Sha256
        ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm-encrypt");
}

void enterEventLoopUnlessTerminal(
    QEventLoop& loop,
    const std::function<bool()>& terminalObserved,
    const std::function<void()>& beforeEntry)
{
    if (!terminalObserved()) {
        beforeEntry();
        loop.exec();
    }
}

SamplingOverheadWorkloadSpec workloadSpec(SamplingOverheadWorkload workload)
{
    if (workload == SamplingOverheadWorkload::Sha256) {
        return {workload, QStringLiteral("sha256"), QStringLiteral("sha256"),
                QStringLiteral("hash"), 8};
    }
    return {workload, QStringLiteral("aes256-gcm-encrypt"), QStringLiteral("aes256-gcm"),
            QStringLiteral("encrypt"), 16};
}

core::BenchmarkConfig workloadConfig(SamplingOverheadWorkload workload,
                                     std::uint64_t iterationsPerRun)
{
    const auto spec = workloadSpec(workload);
    if (workload == SamplingOverheadWorkload::Sha256) {
        return {core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash,
                iterationsPerRun, 1, core::HashConfig{spec.inputBytes}};
    }
    return {core::AlgorithmProfileId::Aes256Gcm, core::BenchmarkOperation::Encrypt,
            iterationsPerRun, 1, core::AeadConfig{spec.inputBytes}};
}

} // namespace

SamplingOverheadWorkloadSpec samplingOverheadWorkloadSpec(SamplingOverheadWorkload workload)
{
    return workloadSpec(workload);
}

std::vector<SamplingOverheadWorkloadSpec> supportedSamplingOverheadWorkloads()
{
    return {workloadSpec(SamplingOverheadWorkload::Sha256),
            workloadSpec(SamplingOverheadWorkload::Aes256GcmEncrypt)};
}

SamplingOverheadRun runRealSamplingOverheadSmoke(
    SamplingOverheadMode mode,
    std::uint32_t intervalMilliseconds,
    std::uint64_t iterationsPerRun,
    std::uint32_t executionOrder,
    SamplingOverheadWorkload workload,
    std::uint32_t watchdogMilliseconds)
{
    if (mode != SamplingOverheadMode::BoundaryOnlyControl &&
        !(intervalMilliseconds == 1 || intervalMilliseconds == 2 || intervalMilliseconds == 5)) {
        throw std::invalid_argument("sampling-overhead interval is invalid");
    }
    if (iterationsPerRun == 0) throw std::invalid_argument("sampling-overhead iterations must be positive");
    if (watchdogMilliseconds == 0) throw std::invalid_argument("sampling-overhead watchdog must be positive");

    const auto workerExecutable = workerPath();
    const auto endpointName = endpoint();
    const auto spec = workloadSpec(workload);
    const auto config = workloadConfig(workload, iterationsPerRun);
    application::WorkerRunSessionTestHooks hooks;
    platform::windows::WorkerMemorySampler sampler;
    SamplingOverheadRun result;
    result.workerExecutablePath = workerExecutable;
    result.workerExecutableSha256 = executableSha256(workerExecutable);
    result.gitHead = gitValue({QStringLiteral("rev-parse"), QStringLiteral("HEAD")});
    result.gitDirty = !gitValue({QStringLiteral("status"), QStringLiteral("--porcelain")}).isEmpty();
    result.buildType = QString::fromStdString(std::string(application::build_info::buildType));
    result.operatingSystem = QSysInfo::prettyProductName();
    result.architecture = QSysInfo::currentCpuArchitecture();
    result.iterationsPerRun = iterationsPerRun;
    result.executionOrder = executionOrder;
    result.workload = workload;
    result.algorithmProfile = spec.algorithmProfile;
    result.operation = spec.operation;
    result.inputBytes = spec.inputBytes;
    bool samplerActive = false;
    std::uint32_t workerPid = 0;
    QElapsedTimer sessionTimer;
    std::uint64_t parentCpuBefore = 0;
    std::uint64_t parentCpuAfter = 0;
    bool parentCpuBeforeObserved = false;
    bool parentCpuAfterObserved = false;
    core::MemoryV2RawObservations boundaryOnlyMemory{};
    hooks.endpointFactory = endpoint;
    hooks.workerStarted = [&](qint64 pid) {
        workerPid = static_cast<std::uint32_t>(pid);
        result.workerPid = workerPid;
        result.workerCreationTime100ns = processCreationTime100ns(workerPid);
        sessionTimer.start();
        parentCpuBefore = currentProcessCpuNanoseconds();
        parentCpuBeforeObserved = true;
    };
    hooks.processFinishedObserved = [&] {
        if (sessionTimer.isValid()) {
            result.parentSessionWallNanoseconds = static_cast<std::uint64_t>(sessionTimer.nsecsElapsed());
        }
        parentCpuAfter = currentProcessCpuNanoseconds();
        parentCpuAfterObserved = true;
    };
    if (mode == SamplingOverheadMode::BoundaryOnlyControl) {
        hooks.startSampler = [&](std::uint32_t pid, const core::MeasurementSettings&) {
            boundaryOnlyMemory.baselinePrivateUsageBytes = privateUsage(pid);
            samplerActive = true;
        };
        hooks.markExecutionBoundary = [&] {
            boundaryOnlyMemory.readyPrivateUsageBytes = privateUsage(workerPid);
        };
        hooks.stopAndCollectSampler = [&] {
            boundaryOnlyMemory.finalPrivateUsageBytes = privateUsage(workerPid);
            samplerActive = false;
            return boundaryOnlyMemory;
        };
        hooks.stopAndDiscardSampler = [&] { samplerActive = false; };
        hooks.samplerIsActive = [&] { return samplerActive; };
    } else {
        hooks.startSampler = [&](std::uint32_t pid, const core::MeasurementSettings& settings) {
            sampler.startV2(pid, settings);
        };
        hooks.markExecutionBoundary = [&] { sampler.markExecutionBoundaryV2(); };
        hooks.stopAndCollectSampler = [&] { return sampler.stopAndCollectV2(); };
        hooks.stopAndDiscardSampler = [&] { sampler.stopAndDiscard(); };
        hooks.samplerIsActive = [&] { return sampler.isActive(); };
    }

    application::WorkerRunSession session(nullptr, workerExecutable, std::move(hooks));
    bool terminal = false;
    bool deadlineExpired = false;
    QEventLoop waitLoop;
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&] (const application::WorkerRunSessionResult& value) {
                         if (!deadlineExpired) {
                             result.memory = value.memory;
                             result.memoryObserved = true;
                             result.workerMeasurement = value.workerMeasurement;
                             result.workerMeasurementObserved = true;
                             result.normalExit = true;
                             result.status = QStringLiteral("completed");
                         }
                         terminal = true;
                         waitLoop.quit();
                     });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&] (const core::ErrorInfo& error) {
                         if (!deadlineExpired) {
                             result.status = QStringLiteral("failed");
                             result.error = QString::fromStdString(error.technicalMessage);
                         }
                         terminal = true;
                         waitLoop.quit();
                     });
    QObject::connect(&watchdog, &QTimer::timeout, [&] {
        deadlineExpired = true;
        result.status = QStringLiteral("incomplete");
        result.error = QStringLiteral("real-worker session watchdog deadline expired");
        session.cancel();
        waitLoop.quit();
    });
    watchdog.start(static_cast<int>(watchdogMilliseconds));
    session.start(config, 0, {intervalMilliseconds});
    enterEventLoopUnlessTerminal(
        waitLoop, [&] { return terminal || deadlineExpired; }, [] {});
    watchdog.stop();
    if (deadlineExpired && session.isActive()) {
        QEventLoop cleanupLoop;
        QTimer cleanupWatchdog;
        cleanupWatchdog.setSingleShot(true);
        QObject::connect(&session, &application::WorkerRunSession::completed,
                         &cleanupLoop, &QEventLoop::quit);
        QObject::connect(&session, &application::WorkerRunSession::failed,
                         &cleanupLoop, &QEventLoop::quit);
        QObject::connect(&session, &application::WorkerRunSession::cancelled,
                         &cleanupLoop, &QEventLoop::quit);
        QObject::connect(&cleanupWatchdog, &QTimer::timeout,
                         &cleanupLoop, &QEventLoop::quit);
        cleanupWatchdog.start(5'000);
        cleanupLoop.exec();
    }
    require(!session.isActive(), "real sampling-overhead smoke cleanup did not terminate");
    require(terminal || deadlineExpired, "real sampling-overhead smoke had no terminal result");
    result.mode = mode;
    result.intervalMilliseconds = intervalMilliseconds;
    if (parentCpuBeforeObserved && parentCpuAfterObserved && parentCpuAfter >= parentCpuBefore) {
        result.parentSessionCpuNanoseconds = parentCpuAfter - parentCpuBefore;
    }
    if (result.status == QStringLiteral("completed")) {
        require(result.workerMeasurementObserved && result.normalExit,
                "real sampling-overhead smoke did not observe canonical worker timing");
        require(result.memoryObserved && result.memory.baselinePrivateUsageBytes > 0 &&
                    result.memory.readyPrivateUsageBytes > 0 && result.memory.finalPrivateUsageBytes > 0,
                "real sampling-overhead smoke did not observe B0/B1/E");
    }
    return result;
}

QJsonDocument samplingOverheadRunArtifact(const SamplingOverheadRun& run)
{
    QJsonObject object{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead"},
        {"schemaVersion", 1}, {"status", run.status}, {"error", run.error},
        {"samplingMode", modeName(run.mode)},
        {"workload", workloadName(run.workload)},
        {"intervalMilliseconds", static_cast<qint64>(run.intervalMilliseconds)},
        {"logicalRunIndex", static_cast<qint64>(run.logicalRunIndex)},
        {"executionOrder", static_cast<qint64>(run.executionOrder)},
        {"workerPid", static_cast<qint64>(run.workerPid)},
        {"workerCreationTime100ns", optionalU64(run.workerCreationTime100ns)},
        {"workerMeasurementObserved", run.workerMeasurementObserved},
        {"normalExit", run.normalExit},
        {"memoryObserved", run.memoryObserved},
        {"provenance", QJsonObject{
            {"workerExecutablePath", run.workerExecutablePath},
            {"workerExecutableSha256", run.workerExecutableSha256},
            {"gitHead", run.gitHead}, {"gitDirty", run.gitDirty},
            {"buildType", run.buildType}, {"operatingSystem", run.operatingSystem},
            {"architecture", run.architecture}}},
        {"configuration", QJsonObject{
            {"algorithmProfile", run.algorithmProfile}, {"operation", run.operation},
            {"inputBytes", QString::number(run.inputBytes)},
            {"iterationsPerRun", QString::number(run.iterationsPerRun)},
            {"runs", static_cast<qint64>(run.runs)}}},
        {"measurementWindows", QJsonObject{
            {"definition", run.measurementWindowDefinition},
            {"parentSessionWallNanoseconds", optionalU64(run.parentSessionWallNanoseconds)},
            {"parentSessionCpuNanoseconds", optionalU64(run.parentSessionCpuNanoseconds)},
            {"workerElapsedNanoseconds", run.workerMeasurementObserved
                ? QJsonValue(QString::number(run.workerMeasurement.elapsedNanoseconds)) : QJsonValue(QJsonValue::Null)},
            {"workerProcessCpuNanoseconds", run.workerMeasurementObserved
                ? QJsonValue(QString::number(run.workerMeasurement.processCpuNanoseconds)) : QJsonValue(QJsonValue::Null)},
            {"parentCpuUnit", "nanoseconds, FILETIME 100 ns ticks converted to ns"},
            {"workerCpuUnit", "nanoseconds, worker FILETIME 100 ns ticks converted to ns"}}},
        {"memory", QJsonObject{
            {"b0PrivateUsageBytes", run.memoryObserved ? QJsonValue(QString::number(run.memory.baselinePrivateUsageBytes)) : QJsonValue(QJsonValue::Null)},
            {"b1PrivateUsageBytes", run.memoryObserved ? QJsonValue(QString::number(run.memory.readyPrivateUsageBytes)) : QJsonValue(QJsonValue::Null)},
            {"ePrivateUsageBytes", run.memoryObserved ? QJsonValue(QString::number(run.memory.finalPrivateUsageBytes)) : QJsonValue(QJsonValue::Null)},
            {"preparationSampleCount", run.memoryObserved ? QJsonValue(QString::number(run.memory.preparationSampleCount)) : QJsonValue(QJsonValue::Null)},
            {"executionSampleCount", run.memoryObserved ? QJsonValue(QString::number(run.memory.executionSampleCount)) : QJsonValue(QJsonValue::Null)},
            {"preparationPeakSampledPrivateUsageBytes", run.memoryObserved && run.memory.preparationPeakSampledPrivateUsageBytes
                ? QJsonValue(QString::number(*run.memory.preparationPeakSampledPrivateUsageBytes)) : QJsonValue(QJsonValue::Null)},
            {"executionPeakSampledPrivateUsageBytes", run.memoryObserved && run.memory.executionPeakSampledPrivateUsageBytes
                ? QJsonValue(QString::number(*run.memory.executionPeakSampledPrivateUsageBytes)) : QJsonValue(QJsonValue::Null)}}}};
    return QJsonDocument(object);
}

QJsonDocument samplingOverheadBatchArtifact(const std::vector<SamplingOverheadRun>& runs)
{
    QJsonArray encodedRuns;
    for (const auto& run : runs) {
        encodedRuns.append(samplingOverheadRunArtifact(run).object());
    }
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-batch"},
        {"schemaVersion", 1},
        {"runCount", static_cast<qint64>(runs.size())},
        {"runs", encodedRuns}});
}

void validateSamplingOverheadRunArtifact(const QJsonDocument& document)
{
    require(document.isObject(), "sampling-overhead artifact is not an object");
    const auto object = document.object();
    require(object.value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead"),
            "sampling-overhead artifact format mismatch");
    require(object.value("schemaVersion").toInt() == 1, "sampling-overhead artifact schema mismatch");
    const auto status = object.value("status").toString();
    require(status == QStringLiteral("completed") || status == QStringLiteral("failed") ||
                status == QStringLiteral("incomplete"), "sampling-overhead status is invalid");
    require(object.value("error").isString(), "sampling-overhead error field is malformed");
    if (status != QStringLiteral("completed")) {
        require(!object.value("error").toString().isEmpty(), "failed artifact has no error");
    }
    require(object.value("workerPid").toInt() >= 0 && object.value("provenance").isObject() &&
                object.value("configuration").isObject() && object.value("measurementWindows").isObject(),
            "sampling-overhead provenance is incomplete");
    const auto windows = object.value("measurementWindows").toObject();
    require(windows.value("parentSessionWallNanoseconds").isString() ||
                windows.value("parentSessionWallNanoseconds").isNull(),
            "parent wall timing is malformed");
    require(windows.value("parentSessionCpuNanoseconds").isString() ||
                windows.value("parentSessionCpuNanoseconds").isNull(),
            "parent CPU timing is malformed");
    require(windows.value("workerElapsedNanoseconds").isString() ||
                windows.value("workerElapsedNanoseconds").isNull(),
            "worker wall timing is malformed");
    require(windows.value("workerProcessCpuNanoseconds").isString() ||
                windows.value("workerProcessCpuNanoseconds").isNull(),
            "worker CPU timing is malformed");
    const auto memory = object.value("memory").toObject();
    for (const auto key : {"b0PrivateUsageBytes", "b1PrivateUsageBytes", "ePrivateUsageBytes",
                           "preparationSampleCount", "executionSampleCount"}) {
        require(memory.value(key).isString() || memory.value(key).isNull(),
                "sampling-overhead memory field is malformed");
    }
    if (status == QStringLiteral("completed")) {
        require(object.value("workerMeasurementObserved").toBool() &&
                    object.value("memoryObserved").toBool(),
                "completed sampling-overhead artifact is incomplete");
        const auto provenance = object.value("provenance").toObject();
        require(object.value("workerCreationTime100ns").isString() &&
                    !provenance.value("workerExecutableSha256").toString().isEmpty() &&
                    !provenance.value("gitHead").toString().isEmpty() &&
                    !provenance.value("buildType").toString().isEmpty() &&
                    !provenance.value("operatingSystem").toString().isEmpty() &&
                    !provenance.value("architecture").toString().isEmpty(),
                "completed sampling-overhead artifact lacks provenance");
        const auto configuration = object.value("configuration").toObject();
        require(!configuration.value("algorithmProfile").toString().isEmpty() &&
                    !configuration.value("operation").toString().isEmpty() &&
                    configuration.value("inputBytes").isString() &&
                    configuration.value("iterationsPerRun").isString() &&
                    configuration.value("runs").toInt() == 1,
                "completed sampling-overhead artifact lacks configuration");
    }
}

void validateSamplingOverheadBatchArtifact(const QJsonDocument& document)
{
    require(document.isObject(), "sampling-overhead batch is not an object");
    const auto object = document.object();
    require(object.value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-batch") &&
                object.value("schemaVersion").toInt() == 1,
            "sampling-overhead batch format mismatch");
    const auto runs = object.value("runs").toArray();
    require(!runs.isEmpty() && object.value("runCount").toInt() == runs.size(),
            "sampling-overhead batch run count is invalid");
    for (const auto& value : runs) {
        validateSamplingOverheadRunArtifact(QJsonDocument(value.toObject()));
    }
}

bool eventDrivenWatchdogSelfTest(std::uint32_t deadlineMilliseconds, QString* diagnostic)
{
    if (deadlineMilliseconds == 0) throw std::invalid_argument("watchdog deadline must be positive");
    QEventLoop loop;
    QTimer watchdog;
    watchdog.setSingleShot(true);
    watchdog.setTimerType(Qt::PreciseTimer);
    bool timedOut = false;
    QObject::connect(&watchdog, &QTimer::timeout, [&] {
        timedOut = true;
        loop.quit();
    });
    QElapsedTimer elapsed;
    elapsed.start();
    watchdog.start(static_cast<int>(deadlineMilliseconds));
    bool loopExited = false;
    loop.exec();
    loopExited = true;
    const auto elapsedMilliseconds = elapsed.elapsed();
    const auto passed = timedOut && loopExited &&
        elapsedMilliseconds > 0 &&
        elapsedMilliseconds < static_cast<qint64>(deadlineMilliseconds) + 5'000;
    if (diagnostic != nullptr) {
        *diagnostic = QStringLiteral("timedOut=%1 elapsedMilliseconds=%2 requestedDeadlineMilliseconds=%3 "
                                     "timerType=PreciseTimer loopExited=%4")
            .arg(timedOut).arg(elapsedMilliseconds).arg(deadlineMilliseconds).arg(loopExited);
    }
    return passed;
}

bool eventDrivenTerminalBeforeExecSelfTest()
{
    QEventLoop loop;
    bool terminal = false;
    bool entered = false;
    terminal = true;
    enterEventLoopUnlessTerminal(loop, [&] { return terminal; }, [&] { entered = true; });
    return terminal && !entered;
}

bool calibrationSelectionSelfTest()
{
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> observations{
        {1'000, 100'000'000}, {10'000, 950'000'000}, {100'000, 1'200'000'000}};
    std::optional<std::uint64_t> selected;
    std::size_t attempted = 0;
    for (const auto& [iterations, elapsed] : observations) {
        ++attempted;
        if (elapsed >= 900'000'000) {
            selected = iterations;
            break;
        }
    }
    return selected == 10'000 && attempted == 2;
}

QString calibrationStatusForRunStatus(const QString& runStatus)
{
    return runStatus == QStringLiteral("incomplete")
        ? QStringLiteral("deadline") : QStringLiteral("failedWorker");
}

bool calibrationStatusMappingSelfTest()
{
    return calibrationStatusForRunStatus(QStringLiteral("incomplete")) == QStringLiteral("deadline") &&
        calibrationStatusForRunStatus(QStringLiteral("failed")) == QStringLiteral("failedWorker");
}

QJsonDocument runSamplingOverheadCalibration(
    SamplingOverheadWorkload workload,
    const std::vector<std::uint64_t>& candidates,
    std::uint32_t maxWorkers,
    std::uint32_t maxSeconds)
{
    require(!candidates.empty() && candidates.size() <= 8,
            "calibration candidate count is outside the bounded limit");
    require(maxWorkers > 0 && maxWorkers <= candidates.size() && maxSeconds > 0 && maxSeconds <= 120,
            "calibration limits are outside the bounded range");
    for (const auto candidate : candidates) require(candidate > 0, "calibration candidate N must be positive");

    QJsonArray observations;
    QElapsedTimer budget;
    budget.start();
    std::optional<std::uint64_t> selectedIterations;
    QString calibrationStatus = QStringLiteral("noSuitableCandidate");
    std::uint32_t workers = 0;
    for (const auto candidate : candidates) {
        const auto remainingMilliseconds = static_cast<qint64>(maxSeconds) * 1'000 - budget.elapsed();
        if (workers >= maxWorkers) {
            calibrationStatus = QStringLiteral("noSuitableCandidate");
            break;
        }
        if (remainingMilliseconds <= 5'000) {
            calibrationStatus = QStringLiteral("deadline");
            break;
        }
        const auto run = runRealSamplingOverheadSmoke(
            SamplingOverheadMode::BoundaryOnlyControl, 5, candidate, workers, workload,
            static_cast<std::uint32_t>(std::min<qint64>(remainingMilliseconds - 5'000, 30'000)));
        ++workers;
        auto observation = samplingOverheadRunArtifact(run).object();
        observation.insert(QStringLiteral("calibrationCandidateIterations"),
                           QString::number(candidate));
        observations.append(observation);
        if (run.status != QStringLiteral("completed")) {
            calibrationStatus = calibrationStatusForRunStatus(run.status);
            break;
        }
        if (run.workerMeasurement.elapsedNanoseconds >= 900'000'000) {
            selectedIterations = candidate;
            calibrationStatus = QStringLiteral("success");
            break;
        }
        if (budget.elapsed() >= static_cast<qint64>(maxSeconds) * 1'000) {
            calibrationStatus = QStringLiteral("deadline");
            break;
        }
    }
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-calibration"},
        {"schemaVersion", 1}, {"workload", workloadName(workload)},
        {"targetCanonicalMeasuredWallNanoseconds", "1000000000"},
        {"selectedIterationsPerRun", optionalU64(selectedIterations)},
        {"status", calibrationStatus},
        {"maxWorkers", static_cast<qint64>(maxWorkers)},
        {"maxSeconds", static_cast<qint64>(maxSeconds)},
        {"observations", observations}});
}

QJsonDocument prepareSamplingOverheadPilot(
    std::uint64_t seed,
    std::uint32_t repetitions,
    std::uint64_t sha256Iterations,
    std::uint64_t aes256GcmIterations)
{
    require(repetitions > 0 && repetitions <= 16 && sha256Iterations > 0 &&
                aes256GcmIterations > 0,
            "pilot preparation parameters are outside the bounded range");
    struct Trial {
        SamplingOverheadWorkload workload;
        SamplingOverheadMode mode;
        std::uint32_t repetition;
        std::uint32_t intervalMilliseconds;
    };
    std::vector<Trial> trials;
    for (std::uint32_t repetition = 0; repetition < repetitions; ++repetition) {
        for (const auto workload : {SamplingOverheadWorkload::Sha256,
                                    SamplingOverheadWorkload::Aes256GcmEncrypt}) {
            trials.push_back({workload, SamplingOverheadMode::BoundaryOnlyControl, repetition, 0});
            trials.push_back({workload, SamplingOverheadMode::Periodic, repetition, 5});
            trials.push_back({workload, SamplingOverheadMode::Periodic, repetition, 2});
            trials.push_back({workload, SamplingOverheadMode::Periodic, repetition, 1});
        }
    }
    std::mt19937_64 generator(seed);
    std::shuffle(trials.begin(), trials.end(), generator);
    QJsonArray encoded;
    std::uint32_t executionOrder = 0;
    for (std::uint32_t trialIndex = 0; trialIndex < trials.size(); ++trialIndex) {
        const auto& trial = trials[trialIndex];
        const auto spec = workloadSpec(trial.workload);
        const auto iterations = trial.workload == SamplingOverheadWorkload::Sha256
            ? sha256Iterations : aes256GcmIterations;
        encoded.append(QJsonObject{
            {"trialIndex", static_cast<qint64>(trialIndex)},
            {"executionOrder", static_cast<qint64>(executionOrder++)},
            {"repetition", static_cast<qint64>(trial.repetition)},
            {"workload", spec.stableId}, {"samplingMode", modeName(trial.mode)},
            {"intervalMilliseconds", static_cast<qint64>(trial.intervalMilliseconds)},
            {"iterationsPerRun", QString::number(iterations)},
            {"status", "notExecuted"}, {"executed", false}});
    }
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-plan"},
        {"schemaVersion", 1}, {"seed", QString::number(seed)},
        {"executed", false}, {"repetitions", static_cast<qint64>(repetitions)},
        {"trialCount", static_cast<qint64>(encoded.size())}, {"trials", encoded}});
}

void validateSamplingOverheadCalibration(const QJsonDocument& document)
{
    require(document.isObject() && document.object().value("format") ==
                QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-calibration") &&
                document.object().value("schemaVersion").toInt() == 1,
            "calibration artifact format mismatch");
    const auto object = document.object();
    const auto status = object.value("status").toString();
    require(status == QStringLiteral("success") || status == QStringLiteral("noSuitableCandidate") ||
                status == QStringLiteral("deadline") || status == QStringLiteral("failedWorker"),
            "calibration status is invalid");
    const auto observations = object.value("observations").toArray();
    require(!observations.isEmpty() && observations.size() <= object.value("maxWorkers").toInt(),
            "calibration artifact worker bound is invalid");
    for (const auto& observation : observations) {
        const auto run = observation.toObject();
        validateSamplingOverheadRunArtifact(QJsonDocument(run));
        require(run.value("calibrationCandidateIterations").isString(),
                "calibration candidate is missing");
    }
    require(status == QStringLiteral("success")
                ? object.value("selectedIterationsPerRun").isString()
                : object.value("selectedIterationsPerRun").isNull(),
            "calibration selection does not match its status");
}

void validateSamplingOverheadPilot(const QJsonDocument& document)
{
    require(document.isObject() && document.object().value("format") ==
                QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-pilot-plan") &&
                document.object().value("schemaVersion").toInt() == 1 &&
                !document.object().value("executed").toBool(),
            "pilot plan is invalid or already executed");
    const auto object = document.object();
    const auto trials = object.value("trials").toArray();
    const auto repetitions = object.value("repetitions").toInt();
    require(repetitions > 0 && trials.size() == object.value("trialCount").toInt() &&
                trials.size() == repetitions * 8 && !trials.isEmpty(),
            "pilot trial count is invalid");
    std::vector<bool> orders(static_cast<std::size_t>(trials.size()), false);
    std::vector<bool> indexes(static_cast<std::size_t>(trials.size()), false);
    std::map<std::string, std::uint32_t> conditionCounts;
    std::map<std::string, std::string> workloadIterations;
    for (const auto& value : trials) {
        const auto trial = value.toObject();
        const auto order = trial.value("executionOrder").toInt(-1);
        const auto index = trial.value("trialIndex").toInt(-1);
        const auto repetition = trial.value("repetition").toInt(-1);
        const auto workload = trial.value("workload").toString().toStdString();
        const auto mode = trial.value("samplingMode").toString();
        const auto interval = trial.value("intervalMilliseconds").toInt(-1);
        const auto iterationsValue = trial.value("iterationsPerRun");
        bool iterationsOk = false;
        const auto iterations = iterationsValue.toString().toULongLong(&iterationsOk);
        const auto iterationsText = iterationsValue.toString().toStdString();
        require(order >= 0 && order < static_cast<int>(orders.size()) && !orders[order] &&
                    index >= 0 && index < static_cast<int>(indexes.size()) && !indexes[index] &&
                    repetition >= 0 && repetition < repetitions &&
                    (workload == "sha256" || workload == "aes256-gcm-encrypt") &&
                    ((mode == QStringLiteral("boundaryOnlyControl") && interval == 0) ||
                     (mode == QStringLiteral("periodic") &&
                      (interval == 5 || interval == 2 || interval == 1))) &&
                                        iterationsValue.isString() && iterationsOk && iterations > 0 &&
                                        QString::number(iterations) == iterationsValue.toString() &&
                    !trial.value("executed").toBool() &&
                    trial.value("status") == QStringLiteral("notExecuted"),
                "pilot trial ordering or execution state is invalid");
        orders[order] = true;
        indexes[index] = true;
        const auto previousIterations = workloadIterations.find(workload);
        if (previousIterations == workloadIterations.end()) {
            workloadIterations.emplace(workload, iterationsText);
        } else {
            require(previousIterations->second == iterationsText,
                    "pilot workload iterationsPerRun is inconsistent");
        }
        const auto condition = mode == QStringLiteral("boundaryOnlyControl")
            ? std::string("off") : "periodic:" + std::to_string(interval);
        ++conditionCounts[workload + ":" + std::to_string(repetition) + ":" + condition];
    }
    for (const auto workload : {std::string("sha256"), std::string("aes256-gcm-encrypt")}) {
        for (int repetition = 0; repetition < repetitions; ++repetition) {
            for (const auto condition : {std::string("off"), std::string("periodic:5"),
                                         std::string("periodic:2"), std::string("periodic:1")}) {
                require(conditionCounts[workload + ":" + std::to_string(repetition) + ":" + condition] == 1,
                        "pilot condition matrix is unbalanced");
            }
        }
    }
}

void writeSamplingOverheadArtifact(const QString& destination, const QJsonDocument& document)
{
    require(!destination.isEmpty(), "sampling-overhead artifact destination is empty");
    require(!QFileInfo::exists(destination), "sampling-overhead artifact destination already exists");
    if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-batch")) {
        validateSamplingOverheadBatchArtifact(document);
    } else if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-calibration")) {
        validateSamplingOverheadCalibration(document);
    } else if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-pilot-plan")) {
        validateSamplingOverheadPilot(document);
    } else {
        validateSamplingOverheadRunArtifact(document);
    }
    const auto result = application::AtomicFileWriter{}.writeAtomically(
        destination, document.toJson(QJsonDocument::Indented));
    if (!result.success) throw std::runtime_error(result.technicalMessage.toStdString());
}

QJsonDocument readSamplingOverheadArtifact(const QString& source)
{
    QFile file(source);
    require(file.open(QIODevice::ReadOnly), "could not open sampling-overhead artifact");
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(file.readAll(), &error);
    require(error.error == QJsonParseError::NoError, "sampling-overhead artifact JSON is malformed");
    if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-batch")) {
        validateSamplingOverheadBatchArtifact(document);
    } else if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-calibration")) {
        validateSamplingOverheadCalibration(document);
    } else if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-pilot-plan")) {
        validateSamplingOverheadPilot(document);
    } else {
        validateSamplingOverheadRunArtifact(document);
    }
    return document;
}

} // namespace cryptobench::tests
