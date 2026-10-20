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
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>

#include <windows.h>
#include <psapi.h>

#include <stdexcept>
#include <iostream>
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

std::uint64_t requiredDecimalU64(const QJsonValue& value, const char* field)
{
    bool ok = false;
    const auto text = value.toString();
    const auto parsed = text.toULongLong(&ok);
    require(value.isString() && ok && !text.isEmpty() &&
                QString::number(parsed) == text,
            field);
    return parsed;
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
        {"workerPid", QString::number(run.workerPid)},
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
    require((object.value("workerPid").isString() || object.value("workerPid").isNull()) &&
                object.value("provenance").isObject() &&
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
        if (!(object.value("workerCreationTime100ns").isString() &&
              !provenance.value("workerExecutableSha256").toString().isEmpty() &&
              !provenance.value("gitHead").toString().isEmpty() &&
              !provenance.value("buildType").toString().isEmpty() &&
              !provenance.value("operatingSystem").toString().isEmpty() &&
              !provenance.value("architecture").toString().isEmpty())) {
            throw std::runtime_error(
                "completed sampling-overhead artifact lacks provenance: " +
                object.value("workerCreationTime100ns").toString().toStdString() + "," +
                provenance.value("workerExecutableSha256").toString().toStdString() + "," +
                provenance.value("gitHead").toString().toStdString() + "," +
                provenance.value("buildType").toString().toStdString() + "," +
                provenance.value("operatingSystem").toString().toStdString() + "," +
                provenance.value("architecture").toString().toStdString());
        }
        const auto configuration = object.value("configuration").toObject();
        require(!configuration.value("algorithmProfile").toString().isEmpty() &&
                    !configuration.value("operation").toString().isEmpty() &&
                    configuration.value("inputBytes").isString() &&
                    configuration.value("iterationsPerRun").isString() &&
                    configuration.value("runs").toInt() == 1,
                "completed sampling-overhead artifact lacks configuration");
        const auto workerPid = requiredDecimalU64(object.value("workerPid"),
                                                  "worker PID is malformed");
        const auto creation = requiredDecimalU64(object.value("workerCreationTime100ns"),
                                                 "worker creation identity is malformed");
        require(workerPid > 0 && creation > 0, "worker process identity is invalid");
        const auto windows = object.value("measurementWindows").toObject();
        const auto workerWall = requiredDecimalU64(
            windows.value("workerElapsedNanoseconds"), "worker wall time is malformed");
        const auto workerCpu = requiredDecimalU64(
            windows.value("workerProcessCpuNanoseconds"), "worker CPU time is malformed");
        static_cast<void>(workerWall);
        static_cast<void>(workerCpu);
        const auto memory = object.value("memory").toObject();
        const auto b0 = requiredDecimalU64(memory.value("b0PrivateUsageBytes"), "B0 is malformed");
        const auto b1 = requiredDecimalU64(memory.value("b1PrivateUsageBytes"), "B1 is malformed");
        const auto e = requiredDecimalU64(memory.value("ePrivateUsageBytes"), "E is malformed");
        require(b0 > 0 && b1 > 0 && e > 0, "boundary memory observations are invalid");
        const auto preparationSamples = requiredDecimalU64(
            memory.value("preparationSampleCount"), "preparation sample count is malformed");
        const auto executionSamples = requiredDecimalU64(
            memory.value("executionSampleCount"), "execution sample count is malformed");
        const auto preparationPeak = memory.value("preparationPeakSampledPrivateUsageBytes");
        const auto executionPeak = memory.value("executionPeakSampledPrivateUsageBytes");
        require(preparationSamples == 0 ? preparationPeak.isNull() : preparationPeak.isString(),
                "preparation peak/sample consistency is invalid");
        require(executionSamples == 0 ? executionPeak.isNull() : executionPeak.isString(),
                "execution peak/sample consistency is invalid");
        if (preparationPeak.isString()) static_cast<void>(requiredDecimalU64(
            preparationPeak, "preparation peak is malformed"));
        if (executionPeak.isString()) static_cast<void>(requiredDecimalU64(
            executionPeak, "execution peak is malformed"));
        require(windows.value("parentSessionWallNanoseconds").isString(),
                "parent session wall time is unavailable");
        static_cast<void>(requiredDecimalU64(
            windows.value("parentSessionWallNanoseconds"), "parent session wall time is malformed"));
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

namespace {

struct PilotTrialDetails {
    SamplingOverheadWorkload workload;
    SamplingOverheadMode mode;
    std::uint32_t intervalMilliseconds;
    std::uint64_t iterationsPerRun;
    std::uint32_t trialIndex;
    std::uint32_t executionOrder;
    std::uint32_t repetition;
    QString workloadId;
};

QString fileSha256(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not open pilot input for SHA-256");
    return QString::fromLatin1(
        QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

QString strictGitValue(const QStringList& arguments)
{
    const auto root = sourceRoot();
    require(!root.isEmpty(), "Git repository root is unavailable");
    QProcess process;
    process.setWorkingDirectory(root);
    process.start(QStringLiteral("git"), arguments);
    require(process.waitForFinished(5'000), "Git query timed out");
    require(process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
            "Git query failed");
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

PilotTrialDetails pilotTrial(const QJsonObject& value)
{
    const auto workloadId = value.value("workload").toString();
    const auto workload = workloadId == QStringLiteral("sha256")
        ? SamplingOverheadWorkload::Sha256
        : workloadId == QStringLiteral("aes256-gcm-encrypt")
            ? SamplingOverheadWorkload::Aes256GcmEncrypt
            : throw std::invalid_argument("pilot plan contains an unsupported workload");
    const auto modeNameValue = value.value("samplingMode").toString();
    const auto mode = modeNameValue == QStringLiteral("boundaryOnlyControl")
        ? SamplingOverheadMode::BoundaryOnlyControl
        : modeNameValue == QStringLiteral("periodic")
            ? SamplingOverheadMode::Periodic
            : throw std::invalid_argument("pilot plan contains an unsupported sampling mode");
    bool iterationsOk = false;
    const auto iterations = value.value("iterationsPerRun").toString().toULongLong(&iterationsOk);
    require(iterationsOk && iterations > 0, "pilot plan iterations are invalid");
    return {workload, mode,
            static_cast<std::uint32_t>(value.value("intervalMilliseconds").toInt()), iterations,
            static_cast<std::uint32_t>(value.value("trialIndex").toInt()),
            static_cast<std::uint32_t>(value.value("executionOrder").toInt()),
            static_cast<std::uint32_t>(value.value("repetition").toInt()), workloadId};
}

std::vector<PilotTrialDetails> validatedPilotTrials(const QJsonDocument& document)
{
    validateSamplingOverheadPilot(document);
    const auto object = document.object();
    require(object.value("repetitions").toInt() == 3 &&
                object.value("trialCount").toInt() == 24,
            "pilot executor requires exactly 3 repetitions and 24 trials");
    std::vector<PilotTrialDetails> trials;
    for (const auto& value : object.value("trials").toArray()) {
        trials.push_back(pilotTrial(value.toObject()));
    }
    require(trials.size() == 24, "pilot executor trial count is invalid");
    std::sort(trials.begin(), trials.end(),
              [](const auto& left, const auto& right) {
                  return left.executionOrder < right.executionOrder;
              });
    for (std::size_t index = 0; index < trials.size(); ++index) {
        require(trials[index].executionOrder == index,
                "pilot execution order is not a complete canonical sequence");
    }
    return trials;
}

struct CalibrationSelection {
    std::uint64_t iterationsPerRun;
    QString historicGitHead;
    QString calibrationHash;
    QString workerHash;
};

CalibrationSelection validateSuccessfulCalibration(
    const QString& path,
    const QString& expectedWorkload,
    const QString& currentWorkerHash)
{
    const auto document = readSamplingOverheadArtifact(path);
    validateSamplingOverheadCalibration(document);
    const auto object = document.object();
    require(object.value("status") == QStringLiteral("success") &&
                object.value("workload") == expectedWorkload,
            "calibration is not a successful matching workload");
    bool selectedOk = false;
    const auto selected = object.value("selectedIterationsPerRun").toString().toULongLong(&selectedOk);
    require(selectedOk && selected > 0, "calibration selected N is invalid");
    bool found = false;
    QString historicGitHead;
    QString workerHash;
    for (const auto& value : object.value("observations").toArray()) {
        const auto run = value.toObject();
        if (run.value("calibrationCandidateIterations").toString() != QString::number(selected) ||
            run.value("status") != QStringLiteral("completed")) continue;
        const auto timing = run.value("measurementWindows").toObject();
        bool wallOk = false;
        const auto wall = timing.value("workerElapsedNanoseconds").toString().toULongLong(&wallOk);
        const auto provenance = run.value("provenance").toObject();
                const auto configuration = run.value("configuration").toObject();
                const auto memory = run.value("memory").toObject();
                require(wallOk && wall >= 900'000'000 &&
                                        run.value("workload") == expectedWorkload &&
                                        run.value("samplingMode") == QStringLiteral("boundaryOnlyControl") &&
                                        run.value("intervalMilliseconds").toInt() == 5 &&
                                        configuration.value("iterationsPerRun").toString() == QString::number(selected) &&
                                        configuration.value("runs").toInt() == 1 &&
                                        ((expectedWorkload == QStringLiteral("sha256") &&
                                            configuration.value("algorithmProfile") == QStringLiteral("sha256") &&
                                            configuration.value("operation") == QStringLiteral("hash") &&
                                            configuration.value("inputBytes").toString() == QStringLiteral("8")) ||
                                         (expectedWorkload == QStringLiteral("aes256-gcm-encrypt") &&
                                            configuration.value("algorithmProfile") == QStringLiteral("aes256-gcm") &&
                                            configuration.value("operation") == QStringLiteral("encrypt") &&
                                            configuration.value("inputBytes").toString() == QStringLiteral("16"))) &&
                                        memory.value("preparationSampleCount").toString() == QStringLiteral("0") &&
                                        memory.value("executionSampleCount").toString() == QStringLiteral("0") &&
                                        memory.value("preparationPeakSampledPrivateUsageBytes").isNull() &&
                                        memory.value("executionPeakSampledPrivateUsageBytes").isNull() &&
                    !provenance.value("gitHead").toString().isEmpty() &&
                                        provenance.value("gitDirty").toBool() == false &&
                                        !provenance.value("buildType").toString().isEmpty() &&
                    provenance.value("workerExecutableSha256").toString() == currentWorkerHash,
                "selected calibration observation lacks valid provenance or duration");
        historicGitHead = provenance.value("gitHead").toString();
        workerHash = provenance.value("workerExecutableSha256").toString();
        found = true;
        break;
    }
    require(found, "selected calibration observation was not found");
    return {selected, historicGitHead, fileSha256(path), workerHash};
}

void persistPilotJson(const QString& path, const QJsonDocument& document)
{
    require(!QFileInfo::exists(path), "pilot output destination already exists");
    const auto result = application::AtomicFileWriter{}.writeAtomically(
        path, document.toJson(QJsonDocument::Indented));
    if (!result.success) throw std::runtime_error(result.technicalMessage.toStdString());
}

void validatePersistedPilotRecords(
    const QString& outputDirectory,
    const std::vector<PilotTrialDetails>& trials,
    const QJsonObject& manifest)
{
    const auto files = QDir(outputDirectory).entryList(
        {QStringLiteral("trial-*.json")}, QDir::Files, QDir::Name);
    require(files.size() == 24, "pilot terminal record count is not 24");
    for (const auto& trial : trials) {
        const auto path = QDir(outputDirectory).filePath(
            QStringLiteral("trial-%1.json").arg(trial.executionOrder, 3, 10, QLatin1Char('0')));
        QFile file(path);
        require(file.open(QIODevice::ReadOnly), "pilot terminal record cannot be read back");
        QJsonParseError parseError{};
        const auto document = QJsonDocument::fromJson(file.readAll(), &parseError);
        require(parseError.error == QJsonParseError::NoError && document.isObject(),
                "pilot terminal record JSON is malformed");
        const auto object = document.object();
        const auto expectedPeriodic = trial.mode == SamplingOverheadMode::Periodic;
        const auto result = object.value("result").toObject();
        const auto configuration = result.value("configuration").toObject();
        const auto provenance = result.value("provenance").toObject();
        const auto memory = result.value("memory").toObject();
        require(object.value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-pilot-trial") &&
                    object.value("schemaVersion").toInt() == 1 &&
                    object.value("trialIndex").toInt() == static_cast<int>(trial.trialIndex) &&
                    object.value("executionOrder").toInt() == static_cast<int>(trial.executionOrder) &&
                    object.value("repetition").toInt() == static_cast<int>(trial.repetition) &&
                    object.value("workload").toString() == trial.workloadId &&
                    object.value("samplingMode").toString() == modeName(trial.mode) &&
                    object.value("intervalMilliseconds").toInt() ==
                        static_cast<int>(trial.intervalMilliseconds) &&
                    object.value("periodicSamplingEnabled").toBool() == expectedPeriodic &&
                    object.value("iterationsPerRun").toString() == QString::number(trial.iterationsPerRun) &&
                    object.value("status").toString() == QStringLiteral("completed"),
                "pilot terminal record identity is inconsistent");
        validateSamplingOverheadRunArtifact(QJsonDocument(result));
        require(result.value("status") == QStringLiteral("completed") &&
                    result.value("normalExit").toBool() &&
                    result.value("workerMeasurementObserved").toBool() &&
                    result.value("memoryObserved").toBool() &&
                    result.value("samplingMode").toString() == modeName(trial.mode) &&
                    result.value("workload").toString() == trial.workloadId &&
                    result.value("periodicSamplingEnabled").toBool() == expectedPeriodic &&
                    result.value("intervalMilliseconds").toInt() ==
                        static_cast<int>(trial.intervalMilliseconds) &&
                    result.value("executionOrder").toInt() == static_cast<int>(trial.executionOrder) &&
                    configuration.value("iterationsPerRun").toString() == QString::number(trial.iterationsPerRun) &&
                    configuration.value("runs").toInt() == 1 &&
                    configuration.value("algorithmProfile").toString() ==
                        (trial.workload == SamplingOverheadWorkload::Sha256 ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm")) &&
                    configuration.value("operation").toString() ==
                        (trial.workload == SamplingOverheadWorkload::Sha256 ? QStringLiteral("hash") : QStringLiteral("encrypt")) &&
                    configuration.value("inputBytes").toString() ==
                        QString::number(trial.workload == SamplingOverheadWorkload::Sha256 ? 8 : 16),
                "pilot terminal result is not completed or misordered");
        const auto simulated = manifest.value("simulated").toBool();
        require(provenance.value("workerExecutableSha256") ==
                    manifest.value("workerExecutableSha256") &&
                    provenance.value("gitHead") == manifest.value("currentGitHead") &&
                    provenance.value("gitDirty").toBool() == false &&
                    provenance.value("buildType") == manifest.value("buildType"),
                "pilot terminal provenance does not match manifest");
        if (simulated) {
            require(provenance.value("workerExecutablePath") == QStringLiteral("simulated-worker"),
                    "simulated terminal provenance is not explicit");
        } else {
            require(provenance.value("workerExecutableSha256").toString() ==
                        manifest.value("workerExecutableSha256").toString() &&
                        requiredDecimalU64(result.value("workerPid"), "worker PID is malformed") > 0 &&
                        result.value("workerCreationTime100ns").isString(),
                    "real terminal worker identity is unavailable");
        }
        require(result.value("workerCreationTime100ns").isString() &&
                    !result.value("measurementWindows").toObject()
                        .value("workerElapsedNanoseconds").toString().isEmpty() &&
                    !result.value("measurementWindows").toObject()
                        .value("workerProcessCpuNanoseconds").toString().isEmpty(),
                "canonical worker measurement is unavailable");
        if (!expectedPeriodic) {
            require(memory.value("preparationSampleCount") == QStringLiteral("0") &&
                        memory.value("executionSampleCount") == QStringLiteral("0") &&
                        memory.value("preparationPeakSampledPrivateUsageBytes").isNull() &&
                        memory.value("executionPeakSampledPrivateUsageBytes").isNull(),
                    "OFF terminal record contains periodic sampling evidence");
        }
    }
}

QJsonObject simulationSummary(
    const std::vector<QString>& terminalStatuses,
    std::uint32_t attempted,
    std::uint32_t completed,
    std::uint32_t persisted,
    bool interrupted,
    bool persistenceFailed,
    bool validationFailed = false)
{
    const auto planned = 24U;
    return QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-summary"},
        {"schemaVersion", 1}, {"complete", completed == planned && persisted == planned &&
                                     !interrupted && !persistenceFailed && !validationFailed},
        {"status", completed == planned && persisted == planned && !interrupted &&
                    !persistenceFailed && !validationFailed
            ? QJsonValue("completed") : QJsonValue("incomplete")},
        {"plannedCount", static_cast<qint64>(planned)},
        {"attemptedCount", static_cast<qint64>(attempted)},
        {"completedCount", static_cast<qint64>(completed)},
        {"persistedCount", static_cast<qint64>(persisted)},
        {"notStartedCount", static_cast<qint64>(planned - attempted)},
        {"interrupted", interrupted}, {"persistenceFailed", persistenceFailed},
        {"validationFailed", validationFailed},
        {"terminalStatuses", [&] {
            QJsonArray values;
            for (const auto& status : terminalStatuses) values.append(status);
            return values;
        }()}};
}

using PilotWorkerCallback = std::function<SamplingOverheadRun(const PilotTrialDetails&)>;

SamplingOverheadRun simulatedRun(const PilotTrialDetails& trial, const QString& status)
{
    SamplingOverheadRun run;
    run.mode = trial.mode;
    run.intervalMilliseconds = trial.intervalMilliseconds;
    run.logicalRunIndex = 0;
    run.executionOrder = trial.executionOrder;
    run.workload = trial.workload;
    run.workerPid = 10'000 + trial.executionOrder;
    run.workerCreationTime100ns = 100'000 + trial.executionOrder;
    run.parentSessionWallNanoseconds = 1'000'000;
    run.parentSessionCpuNanoseconds = 100'000;
    run.workerExecutablePath = QStringLiteral("simulated-worker");
    run.workerExecutableSha256 = QStringLiteral("simulated-worker-sha256");
    run.gitHead = QStringLiteral("simulated-git-head");
    run.buildType = QStringLiteral("Simulation");
    run.operatingSystem = QStringLiteral("simulated");
    run.architecture = QStringLiteral("simulated");
    run.algorithmProfile = trial.workload == SamplingOverheadWorkload::Sha256
        ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm");
    run.operation = trial.workload == SamplingOverheadWorkload::Sha256
        ? QStringLiteral("hash") : QStringLiteral("encrypt");
    run.inputBytes = trial.workload == SamplingOverheadWorkload::Sha256 ? 8 : 16;
    run.iterationsPerRun = trial.iterationsPerRun;
    run.status = status;
    run.error = status == QStringLiteral("completed") ? QString{} : QStringLiteral("simulated failure");
    if (status == QStringLiteral("completed")) {
        run.workerMeasurementObserved = true;
        run.memoryObserved = true;
        run.normalExit = true;
        run.workerMeasurement = {0, 1'000'000, 100'000};
        run.memory = {1, 2, std::nullopt, std::nullopt, 3, 0, 0};
    }
    return run;
}

int runPilotOrchestration(
    const std::vector<PilotTrialDetails>& trials,
    const QString& outputDirectory,
    const QJsonDocument& manifest,
    const PilotWorkerCallback& workerCallback,
    std::optional<std::uint32_t> failPersistenceAfter = {},
    std::optional<std::uint32_t> stopBeforeTrial = {},
    bool failFinalValidation = false,
    bool failAfterSummaryBeforeMarker = false)
{
    bool outputCreated = false;
    std::uint32_t attempted = 0;
    std::uint32_t completed = 0;
    std::uint32_t persisted = 0;
    bool persistenceFailed = false;
    bool interrupted = false;
    bool validationFailed = false;
    std::vector<QString> terminalStatuses;
    try {
        require(!QFileInfo::exists(outputDirectory), "pilot output directory already exists");
        require(QDir().mkpath(outputDirectory), "could not create pilot output directory");
        outputCreated = true;
        persistPilotJson(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")), manifest);
        QFile manifestFile(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")));
        require(manifestFile.open(QIODevice::ReadOnly), "pilot manifest could not be read back");
        QJsonParseError manifestError{};
        const auto manifestRoundTrip = QJsonDocument::fromJson(manifestFile.readAll(), &manifestError);
        require(manifestError.error == QJsonParseError::NoError &&
            manifestRoundTrip.object() == manifest.object(),
            "pilot manifest read-back validation failed");
        QElapsedTimer totalTimer;
        totalTimer.start();
        for (const auto& trial : trials) {
            if (stopBeforeTrial && trial.executionOrder >= *stopBeforeTrial) {
                interrupted = true;
                throw std::runtime_error("pilot execution interrupted before next trial");
            }
            const auto remainingMilliseconds = 240'000 - totalTimer.elapsed();
            if (remainingMilliseconds <= 5'000) {
                interrupted = true;
                throw std::runtime_error("pilot total watchdog deadline expired");
            }
            const QJsonDocument marker(QJsonObject{
                {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-attempt"},
                {"schemaVersion", 1}, {"status", "started"},
                {"trialIndex", static_cast<qint64>(trial.trialIndex)},
                {"executionOrder", static_cast<qint64>(trial.executionOrder)},
                {"repetition", static_cast<qint64>(trial.repetition)},
                {"workload", trial.workloadId},
                {"iterationsPerRun", QString::number(trial.iterationsPerRun)}});
            persistPilotJson(QDir(outputDirectory).filePath(
                QStringLiteral("attempt-%1.json").arg(trial.executionOrder, 3, 10, QLatin1Char('0'))), marker);
            ++attempted;
            SamplingOverheadRun run;
            try {
                run = workerCallback(trial);
            } catch (const std::exception& error) {
                run.status = QStringLiteral("incomplete");
                run.error = QString::fromStdString(error.what());
                run.mode = trial.mode;
                run.intervalMilliseconds = trial.intervalMilliseconds;
                run.logicalRunIndex = 0;
                run.workload = trial.workload;
                run.executionOrder = trial.executionOrder;
                run.iterationsPerRun = trial.iterationsPerRun;
                run.algorithmProfile = trial.workload == SamplingOverheadWorkload::Sha256
                    ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm");
                run.operation = trial.workload == SamplingOverheadWorkload::Sha256
                    ? QStringLiteral("hash") : QStringLiteral("encrypt");
                run.inputBytes = trial.workload == SamplingOverheadWorkload::Sha256 ? 8 : 16;
                run.runs = 1;
                interrupted = true;
            }
            terminalStatuses.push_back(run.status);
            if (run.status == QStringLiteral("completed")) ++completed;
            if (run.status == QStringLiteral("incomplete")) interrupted = true;
            auto resultObject = samplingOverheadRunArtifact(run).object();
            resultObject.insert(QStringLiteral("periodicSamplingEnabled"),
                                trial.mode == SamplingOverheadMode::Periodic);
            if (trial.mode == SamplingOverheadMode::BoundaryOnlyControl) {
                resultObject.insert(QStringLiteral("intervalMilliseconds"), 0);
                resultObject.insert(QStringLiteral("internalMeasurementSettingsIntervalMilliseconds"), 5);
            }
            const QJsonObject record{
                {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-trial"},
                {"schemaVersion", 1}, {"trialIndex", static_cast<qint64>(trial.trialIndex)},
                {"executionOrder", static_cast<qint64>(trial.executionOrder)},
                {"status", run.status}, {"error", run.error},
                {"workload", trial.workloadId}, {"repetition", static_cast<qint64>(trial.repetition)},
                {"samplingMode", modeName(trial.mode)},
                {"intervalMilliseconds", static_cast<qint64>(trial.intervalMilliseconds)},
                {"periodicSamplingEnabled", trial.mode == SamplingOverheadMode::Periodic},
                {"iterationsPerRun", QString::number(trial.iterationsPerRun)},
                {"result", resultObject}};
            if (failPersistenceAfter && persisted >= *failPersistenceAfter) {
                QFile collision(QDir(outputDirectory).filePath(
                    QStringLiteral("trial-%1.json").arg(trial.executionOrder, 3, 10, QLatin1Char('0'))));
                require(collision.open(QIODevice::WriteOnly), "could not inject persistence collision");
                require(collision.write("collision") == 9, "could not write persistence collision");
                collision.close();
            }
            try {
                persistPilotJson(QDir(outputDirectory).filePath(
                    QStringLiteral("trial-%1.json").arg(trial.executionOrder, 3, 10, QLatin1Char('0'))),
                    QJsonDocument(record));
                ++persisted;
            } catch (...) {
                persistenceFailed = true;
                throw;
            }
            if (run.status != QStringLiteral("completed")) {
                throw std::runtime_error("pilot trial failed: " + run.error.toStdString());
            }
        }
        validatePersistedPilotRecords(outputDirectory, trials, manifest.object());
        if (failFinalValidation) {
            throw std::runtime_error("simulated final validation failure");
        }
        require(attempted == 24 && completed == 24 && persisted == 24,
                "pilot did not complete all planned trials");
        const auto summary = QJsonDocument(simulationSummary(
            terminalStatuses, attempted, completed, persisted, false, false));
        persistPilotJson(QDir(outputDirectory).filePath(QStringLiteral("summary.json")), summary);
        QFile summaryFile(QDir(outputDirectory).filePath(QStringLiteral("summary.json")));
        require(summaryFile.open(QIODevice::ReadOnly), "pilot summary could not be read back");
        QJsonParseError summaryError{};
        const auto summaryRoundTrip = QJsonDocument::fromJson(summaryFile.readAll(), &summaryError);
        require(summaryError.error == QJsonParseError::NoError &&
                    summaryRoundTrip.object().value("complete").toBool() &&
                    summaryRoundTrip.object().value("plannedCount").toInt() == 24 &&
                    summaryRoundTrip.object().value("attemptedCount").toInt() == 24 &&
                    summaryRoundTrip.object().value("completedCount").toInt() == 24 &&
                    summaryRoundTrip.object().value("persistedCount").toInt() == 24,
                "pilot summary read-back validation failed");
            if (failAfterSummaryBeforeMarker) {
                throw std::runtime_error("simulated post-summary validation failure");
            }
        const QJsonDocument successMarker(QJsonObject{
            {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-success"},
            {"schemaVersion", 1}, {"complete", true}, {"plannedCount", 24},
            {"manifestSha256", fileSha256(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")))},
            {"summarySha256", fileSha256(QDir(outputDirectory).filePath(QStringLiteral("summary.json")))}});
        persistPilotJson(QDir(outputDirectory).filePath(QStringLiteral("success.marker")), successMarker);
        QFile markerFile(QDir(outputDirectory).filePath(QStringLiteral("success.marker")));
        require(markerFile.open(QIODevice::ReadOnly), "pilot success marker could not be read back");
        QJsonParseError markerError{};
        const auto markerRoundTrip = QJsonDocument::fromJson(markerFile.readAll(), &markerError);
        require(markerError.error == QJsonParseError::NoError &&
                    markerRoundTrip.object() == successMarker.object(),
                "pilot success marker read-back validation failed");
        return 0;
    } catch (const std::exception& error) {
        validationFailed = true;
        std::cerr << "pilot orchestration simulation/runner failure: " << error.what() << '\n';
        if (outputCreated && !QFileInfo::exists(QDir(outputDirectory).filePath(QStringLiteral("summary.json")))) {
            auto summary = simulationSummary(
                terminalStatuses, attempted, completed, persisted, interrupted, persistenceFailed,
                validationFailed);
            summary.insert(QStringLiteral("error"), QString::fromStdString(error.what()));
            try { persistPilotJson(QDir(outputDirectory).filePath(QStringLiteral("summary.json")), QJsonDocument(summary)); }
            catch (...) { }
        }
        return 1;
    }
}

} // namespace

QJsonDocument simulateSamplingOverheadPilot(
    const QJsonDocument& plan,
    const std::vector<QString>& terminalStatuses,
    std::optional<std::uint32_t> failPersistenceAfter,
    bool interrupted,
    const QString& outputDirectory,
    bool failFinalValidation,
    bool failAfterSummaryBeforeMarker)
{
    const auto trials = validatedPilotTrials(plan);
    if (!outputDirectory.isEmpty()) {
        require(!QFileInfo::exists(outputDirectory), "simulation output directory already exists");
    }
    require(terminalStatuses.size() <= trials.size(), "simulation status count exceeds plan");
    QTemporaryDir temporaryDirectory;
    require(!temporaryDirectory.path().isEmpty(), "simulation temporary directory was not created");
    const auto destination = outputDirectory.isEmpty()
        ? temporaryDirectory.filePath(QStringLiteral("pilot")) : outputDirectory;
    const auto manifest = QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-manifest"},
        {"schemaVersion", 1}, {"simulated", true}, {"plannedCount", 24},
        {"complete", false}, {"currentGitHead", "simulated-git-head"},
        {"workerExecutableSha256", "simulated-worker-sha256"}, {"buildType", "Simulation"}});
    std::size_t callbackIndex = 0;
    const auto callback = [&](const PilotTrialDetails& trial) {
        const auto status = callbackIndex < terminalStatuses.size()
            ? terminalStatuses[callbackIndex++] : QStringLiteral("completed");
        if (status == QStringLiteral("throw")) throw std::runtime_error("simulated worker callback throw");
        return simulatedRun(trial, status);
    };
    const auto result = runPilotOrchestration(
        trials, destination, manifest, callback, failPersistenceAfter,
        interrupted ? std::optional<std::uint32_t>{0} : std::nullopt,
        failFinalValidation, failAfterSummaryBeforeMarker);
        require(result == 0 || QFileInfo::exists(QDir(destination).filePath(QStringLiteral("summary.json"))),
            "simulated pilot orchestration failed");
    QFile summaryFile(QDir(destination).filePath(QStringLiteral("summary.json")));
    require(summaryFile.open(QIODevice::ReadOnly), "simulation summary was not persisted");
    QJsonParseError parseError{};
    const auto summary = QJsonDocument::fromJson(summaryFile.readAll(), &parseError);
    require(parseError.error == QJsonParseError::NoError, "simulation summary is malformed");
    return summary;
}

void validateSamplingOverheadPilotOutput(
    const QString& outputDirectory,
    const QJsonDocument& plan,
    const QJsonDocument& trustedManifest)
{
    const auto trials = validatedPilotTrials(plan);
    QFile manifestFile(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")));
    require(manifestFile.open(QIODevice::ReadOnly), "pilot manifest cannot be opened for validation");
    QJsonParseError parseError{};
    const auto manifest = QJsonDocument::fromJson(manifestFile.readAll(), &parseError);
    require(parseError.error == QJsonParseError::NoError && manifest.isObject() &&
                trustedManifest.isObject() && manifest.object() == trustedManifest.object(),
            "pilot manifest is malformed");
    validatePersistedPilotRecords(outputDirectory, trials, trustedManifest.object());
    QFile summaryFile(QDir(outputDirectory).filePath(QStringLiteral("summary.json")));
    require(summaryFile.open(QIODevice::ReadOnly), "pilot summary is missing");
    QJsonParseError summaryError{};
    const auto summary = QJsonDocument::fromJson(summaryFile.readAll(), &summaryError);
    require(summaryError.error == QJsonParseError::NoError &&
                summary.object().value("complete").toBool() &&
                summary.object().value("plannedCount").toInt() == 24 &&
                summary.object().value("attemptedCount").toInt() == 24 &&
                summary.object().value("completedCount").toInt() == 24 &&
                summary.object().value("persistedCount").toInt() == 24,
            "pilot summary is incomplete or malformed");
    QFile markerFile(QDir(outputDirectory).filePath(QStringLiteral("success.marker")));
    require(markerFile.open(QIODevice::ReadOnly), "pilot success marker is missing");
    QJsonParseError markerError{};
    const auto marker = QJsonDocument::fromJson(markerFile.readAll(), &markerError);
    require(markerError.error == QJsonParseError::NoError &&
                marker.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-pilot-success") &&
                marker.object().value("complete").toBool() &&
                marker.object().value("summarySha256") == fileSha256(summaryFile.fileName()) &&
                marker.object().value("manifestSha256") == fileSha256(manifestFile.fileName()),
            "pilot success marker is missing, malformed or inconsistent");
}

int executeSamplingOverheadPilot(
    const QString& planPath,
    const QString& sha256CalibrationPath,
    const QString& aes256GcmCalibrationPath,
    const QString& outputDirectory)
{
    try {
        require(!QFileInfo::exists(outputDirectory), "pilot output directory already exists");
        const auto plan = readSamplingOverheadArtifact(planPath);
        const auto trials = validatedPilotTrials(plan);
        const auto workerExecutable = workerPath();
        const auto workerHash = executableSha256(workerExecutable);
        const auto shaSelection = validateSuccessfulCalibration(
            sha256CalibrationPath, QStringLiteral("sha256"), workerHash);
        const auto aesSelection = validateSuccessfulCalibration(
            aes256GcmCalibrationPath, QStringLiteral("aes256-gcm-encrypt"), workerHash);
        for (const auto& trial : trials) {
            const auto expectedIterations = trial.workload == SamplingOverheadWorkload::Sha256
                ? shaSelection.iterationsPerRun : aesSelection.iterationsPerRun;
            require(trial.iterationsPerRun == expectedIterations,
                    "pilot plan N does not match accepted calibration N");
        }
        const auto currentGitHead = strictGitValue({QStringLiteral("rev-parse"), QStringLiteral("HEAD")});
        const auto currentGitStatus = strictGitValue({QStringLiteral("status"), QStringLiteral("--porcelain")});
        require(!currentGitHead.isEmpty() && currentGitStatus.isEmpty(),
                "pilot execution requires a clean Git worktree");
        require(QString::fromStdString(std::string(application::build_info::buildType)) ==
                QStringLiteral("Release"),
            "execute-pilot requires a Release qualification build");
        const auto planHash = fileSha256(planPath);
        const auto manifest = QJsonDocument(QJsonObject{
            {"format", "cryptobenchmark-memory-v2-sampling-overhead-pilot-manifest"},
            {"schemaVersion", 1}, {"status", "inProgress"}, {"complete", false},
            {"plannedCount", 24}, {"seed", plan.object().value("seed")},
            {"planSha256", planHash}, {"sha256CalibrationSha256", shaSelection.calibrationHash},
            {"sha256CalibrationHistoricGitHead", shaSelection.historicGitHead},
            {"aes256GcmCalibrationSha256", aesSelection.calibrationHash},
            {"aes256GcmCalibrationHistoricGitHead", aesSelection.historicGitHead},
            {"currentGitHead", currentGitHead}, {"workerExecutablePath", workerExecutable},
            {"workerExecutableSha256", workerHash},
            {"buildType", QString::fromStdString(std::string(application::build_info::buildType))},
            {"operatingSystem", QSysInfo::prettyProductName()},
            {"architecture", QSysInfo::currentCpuArchitecture()}});
        const auto callback = [](const PilotTrialDetails& trial) {
            return runRealSamplingOverheadSmoke(
                trial.mode, trial.mode == SamplingOverheadMode::BoundaryOnlyControl ? 5 : trial.intervalMilliseconds,
                trial.iterationsPerRun, trial.executionOrder, trial.workload, 30'000);
        };
        return runPilotOrchestration(trials, outputDirectory, manifest, callback);
    } catch (const std::exception& error) {
        std::cerr << "FAIL execute-pilot: " << error.what() << '\n';
        return 1;
    }
}

} // namespace cryptobench::tests
