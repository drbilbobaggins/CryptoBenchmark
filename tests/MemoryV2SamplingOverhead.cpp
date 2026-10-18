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

} // namespace

SamplingOverheadRun runRealSamplingOverheadSmoke(
    SamplingOverheadMode mode,
    std::uint32_t intervalMilliseconds,
    std::uint64_t iterationsPerRun,
    std::uint32_t executionOrder)
{
    if (mode != SamplingOverheadMode::BoundaryOnlyControl &&
        !(intervalMilliseconds == 1 || intervalMilliseconds == 2 || intervalMilliseconds == 5)) {
        throw std::invalid_argument("sampling-overhead interval is invalid");
    }
    if (iterationsPerRun == 0) throw std::invalid_argument("sampling-overhead iterations must be positive");

    const auto workerExecutable = workerPath();
    const auto endpointName = endpoint();
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        core::BenchmarkOperation::Hash,
        iterationsPerRun,
        1,
        core::HashConfig{8}};
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
    bool samplerActive = false;
    std::uint32_t workerPid = 0;
    QElapsedTimer sessionTimer;
    std::uint64_t parentCpuBefore = 0;
    std::uint64_t parentCpuAfter = 0;
    core::MemoryV2RawObservations boundaryOnlyMemory{};
    hooks.endpointFactory = endpoint;
    hooks.workerStarted = [&](qint64 pid) {
        workerPid = static_cast<std::uint32_t>(pid);
        result.workerPid = workerPid;
        result.workerCreationTime100ns = processCreationTime100ns(workerPid);
        sessionTimer.start();
        parentCpuBefore = currentProcessCpuNanoseconds();
    };
    hooks.processFinishedObserved = [&] {
        if (sessionTimer.isValid()) {
            result.parentSessionWallNanoseconds = static_cast<std::uint64_t>(sessionTimer.nsecsElapsed());
        }
        parentCpuAfter = currentProcessCpuNanoseconds();
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
                         result.memory = value.memory;
                         result.memoryObserved = true;
                         result.workerMeasurement = value.workerMeasurement;
                         result.workerMeasurementObserved = true;
                         result.normalExit = true;
                         result.status = QStringLiteral("completed");
                         terminal = true;
                         waitLoop.quit();
                     });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&] (const core::ErrorInfo& error) {
                         result.status = QStringLiteral("failed");
                         result.error = QString::fromStdString(error.technicalMessage);
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
    session.start(config, 0, {intervalMilliseconds});
    watchdog.start(30'000);
    waitLoop.exec();
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
    if (parentCpuAfter >= parentCpuBefore) {
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

bool eventDrivenWatchdogSelfTest(std::uint32_t deadlineMilliseconds)
{
    if (deadlineMilliseconds == 0) throw std::invalid_argument("watchdog deadline must be positive");
    QEventLoop loop;
    QTimer watchdog;
    watchdog.setSingleShot(true);
    bool timedOut = false;
    QObject::connect(&watchdog, &QTimer::timeout, [&] {
        timedOut = true;
        loop.quit();
    });
    QElapsedTimer elapsed;
    elapsed.start();
    watchdog.start(static_cast<int>(deadlineMilliseconds));
    loop.exec();
    const auto elapsedMilliseconds = elapsed.elapsed();
    const auto lowerBound = deadlineMilliseconds > 5 ? deadlineMilliseconds - 5U : 0U;
    return timedOut && elapsedMilliseconds >= static_cast<qint64>(lowerBound) &&
        elapsedMilliseconds < static_cast<qint64>(deadlineMilliseconds) + 5'000;
}

void writeSamplingOverheadArtifact(const QString& destination, const QJsonDocument& document)
{
    require(!destination.isEmpty(), "sampling-overhead artifact destination is empty");
    require(!QFileInfo::exists(destination), "sampling-overhead artifact destination already exists");
    if (document.object().value("format") == QStringLiteral("cryptobenchmark-memory-v2-sampling-overhead-batch")) {
        validateSamplingOverheadBatchArtifact(document);
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
    } else {
        validateSamplingOverheadRunArtifact(document);
    }
    return document;
}

} // namespace cryptobench::tests
