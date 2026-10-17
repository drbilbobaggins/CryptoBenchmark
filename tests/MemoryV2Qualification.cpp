#include "MemoryV2Qualification.h"

#include <cryptobench/application/WorkerRunSession.h>
#include <cryptobench/core/MemoryV2Calculator.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonObject>
#include <QProcess>
#include <QSaveFile>
#include <QSysInfo>
#include <QUuid>

#include <windows.h>
#include <psapi.h>

#include <functional>
#include <stdexcept>

namespace cryptobench::tests {
namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

class EnvironmentGuard final {
public:
    EnvironmentGuard()
        : wasSet_(qEnvironmentVariableIsSet("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO")),
          previous_(qgetenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO"))
    {
    }

    ~EnvironmentGuard()
    {
        if (wasSet_) qputenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO", previous_);
        else qunsetenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO");
    }

private:
    bool wasSet_;
    QByteArray previous_;
};

struct ProcessIdentity {
    std::uint32_t pid = 0;
    std::uint64_t creationTime100ns = 0;
    bool creationTimeObserved = false;
};

struct GitQuery {
    bool succeeded = false;
    QString output;
};

ProcessIdentity processIdentity(qint64 pid)
{
    ProcessIdentity result{static_cast<std::uint32_t>(pid), 0, false};
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                    static_cast<DWORD>(pid));
    if (handle == nullptr) return result;
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (GetProcessTimes(handle, &creation, &exit, &kernel, &user)) {
        result.creationTime100ns = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(creation.dwLowDateTime);
        result.creationTimeObserved = true;
    }
    CloseHandle(handle);
    return result;
}

std::uint64_t privateUsage(std::uint32_t processId)
{
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    require(handle != nullptr, "qualification could not open worker for PrivateUsage");
    PROCESS_MEMORY_COUNTERS_EX counters{};
    const auto success = GetProcessMemoryInfo(
        handle, reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters), sizeof(counters));
    CloseHandle(handle);
    require(success != FALSE, "qualification PrivateUsage read failed");
    return static_cast<std::uint64_t>(counters.PrivateUsage);
}

void processEventsUntil(application::WorkerRunSession& session,
                        const std::function<bool()>& condition)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < 20'000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    if (condition()) return;
    session.cancel();
    QElapsedTimer cleanupTimer;
    cleanupTimer.start();
    while (session.isActive() && cleanupTimer.elapsed() < 5'000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(!session.isActive(), "qualification session timeout cleanup did not terminate");
    throw std::runtime_error("qualification WorkerRunSession timed out");
}

QString endpoint()
{
    return QStringLiteral("CryptoBenchmark_M19_1_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

QString modeName(QualificationSamplingMode mode)
{
    return mode == QualificationSamplingMode::Periodic
        ? QStringLiteral("periodic")
        : QStringLiteral("boundaryOnlyControl");
}

QString terminationStatusName(ProcessTerminationStatus status)
{
    switch (status) {
    case ProcessTerminationStatus::Exited: return QStringLiteral("exited");
    case ProcessTerminationStatus::Running: return QStringLiteral("running");
    case ProcessTerminationStatus::Indeterminate: return QStringLiteral("indeterminate");
    }
    return QStringLiteral("indeterminate");
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

GitQuery gitValue(const QStringList& arguments)
{
    const auto root = sourceRoot();
    if (root.isEmpty()) return {};
    QProcess process;
    process.setWorkingDirectory(root);
    process.start(QStringLiteral("git"), arguments);
    if (!process.waitForFinished(5'000) || process.exitCode() != 0) return {};
    return {true, QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed()};
}

QJsonObject executableIdentity(const QString& path)
{
    const QFileInfo info(path);
    QJsonObject result{{"path", info.absoluteFilePath()}, {"sizeBytes", QString::number(info.size())}};
    QFile file(info.absoluteFilePath());
    if (file.open(QIODevice::ReadOnly)) {
        result.insert("sha256", QString::fromLatin1(
            QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex()));
        result.insert("hashObserved", true);
    } else {
        result.insert("hashObserved", false);
    }
    return result;
}

std::uint64_t committedBytes(std::uint64_t requested, std::uint32_t pageSize)
{
    if (requested == 0) return 0;
    return ((requested + pageSize - 1U) / pageSize) * pageSize;
}

QJsonValue optionalU64(const std::optional<std::uint64_t>& value)
{
    return value ? QJsonValue(QString::number(*value)) : QJsonValue(QJsonValue::Null);
}

} // namespace

QString syntheticWorkerPath()
{
    return QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("SyntheticMemoryV2Worker.exe"));
}

core::BenchmarkConfig qualificationConfig()
{
    return {core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash,
            1, 1, core::HashConfig{8}};
}

QualificationRun runQualification(QualificationSamplingMode mode,
                                  const SyntheticScenario& scenario,
                                  std::uint32_t intervalMilliseconds,
                                  const QualificationIdentity& identity)
{
    validateSyntheticScenario(scenario);
    require(QFileInfo::exists(syntheticWorkerPath()), "synthetic qualification worker is missing");
    if (mode == QualificationSamplingMode::Periodic &&
        !core::isValidMeasurementSettings({intervalMilliseconds})) {
        throw std::invalid_argument("qualification sampling interval is invalid");
    }

    EnvironmentGuard environmentGuard;
    qputenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO",
            encodeSyntheticScenario(scenario).toJson(QJsonDocument::Compact));

    std::uint32_t workerPid = 0;
    bool samplerActive = false;
    std::uint32_t eventOrdinal = 0;
    core::MemoryV2RawObservations boundaryOnlyRaw{};
    platform::windows::WorkerMemorySampler sampler;
    application::WorkerRunSessionTestHooks hooks;
    QualificationRun result;
    hooks.endpointFactory = endpoint;
    hooks.cleanupTimeoutMilliseconds = [] { return 1'000; };
    hooks.workerStarted = [&](qint64 pid) {
        ++eventOrdinal;
        const auto identityValue = processIdentity(pid);
        workerPid = identityValue.pid;
        result.workerPid = identityValue.pid;
        result.processCreationTime100ns = identityValue.creationTime100ns;
        result.processCreationTimeObserved = identityValue.creationTimeObserved;
        result.workerStarted = true;
        result.startEventOrdinal = eventOrdinal;
    };
    hooks.processFinishedObserved = [&] {
        ++eventOrdinal;
        result.processFinishedObserved = true;
        result.finishEventOrdinal = eventOrdinal;
    };
    if (mode == QualificationSamplingMode::BoundaryOnlyControl) {
        hooks.startSampler = [&](std::uint32_t pid, const core::MeasurementSettings&) {
            boundaryOnlyRaw.baselinePrivateUsageBytes = privateUsage(pid);
            samplerActive = true;
        };
        hooks.markExecutionBoundary = [&] {
            boundaryOnlyRaw.readyPrivateUsageBytes = privateUsage(workerPid);
        };
        hooks.stopAndCollectSampler = [&] {
            boundaryOnlyRaw.finalPrivateUsageBytes = privateUsage(workerPid);
            samplerActive = false;
            return boundaryOnlyRaw;
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

    application::WorkerRunSession session(nullptr, syntheticWorkerPath(), std::move(hooks));
    QObject::connect(&session, &application::WorkerRunSession::completed,
                     [&](const application::WorkerRunSessionResult& value) {
                         result.logicalRunIndex = value.logicalRunIndex;
                         result.workerMeasurement = value.workerMeasurement;
                         result.workerMeasurementObserved = true;
                         result.raw = value.memory;
                         result.status = QStringLiteral("completed");
                         result.normalExit = true;
                     });
    QObject::connect(&session, &application::WorkerRunSession::failed,
                     [&](const core::ErrorInfo& value) {
                         result.status = QStringLiteral("failed");
                         result.error = QString::fromStdString(value.technicalMessage);
                     });
    bool cancelled = false;
    QObject::connect(&session, &application::WorkerRunSession::cancelled,
                     [&] { cancelled = true; result.status = QStringLiteral("cancelled"); });
    session.start(qualificationConfig(), 0, {intervalMilliseconds});
    if (scenario.outcome == SyntheticOutcome::WaitForCancellation) {
        QTimer::singleShot(100, &session, &application::WorkerRunSession::cancel);
    }
    processEventsUntil(session, [&] { return !session.isActive(); });
    result.workerPid = workerPid;
    result.terminationStatus = workerProcessTerminationStatus(workerPid);
    if (cancelled) result.status = QStringLiteral("cancelled");
    if (result.status == QStringLiteral("completed")) {
        result.derived = core::calculateMemoryV2DerivedMetrics(result.raw);
        require(result.derived.has_value(), "qualification raw observations were invalid");
    }
    return result;
}

ProcessTerminationStatus workerProcessTerminationStatus(std::uint32_t processId)
{
    SetLastError(ERROR_SUCCESS);
    const auto handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, processId);
    if (handle == nullptr) {
        return GetLastError() == ERROR_INVALID_PARAMETER
            ? ProcessTerminationStatus::Exited
            : ProcessTerminationStatus::Indeterminate;
    }
    DWORD exitCode = STILL_ACTIVE;
    const auto queried = GetExitCodeProcess(handle, &exitCode);
    CloseHandle(handle);
    if (!queried) return ProcessTerminationStatus::Indeterminate;
    return exitCode == STILL_ACTIVE
        ? ProcessTerminationStatus::Running
        : ProcessTerminationStatus::Exited;
}

QJsonDocument makeQualificationArtifact(const QualificationRun& run,
                                        QualificationSamplingMode mode,
                                        const SyntheticScenario& scenario,
                                        std::uint32_t intervalMilliseconds,
                                        const QualificationIdentity& identity)
{
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const auto pageSize = systemInfo.dwPageSize == 0 ? 4096U : systemInfo.dwPageSize;
    const auto gitHead = gitValue({QStringLiteral("rev-parse"), QStringLiteral("HEAD")});
    const auto worktreeStatus = gitValue({QStringLiteral("status"), QStringLiteral("--porcelain")});
    QJsonObject provenance{
        {"gitHead", gitHead.succeeded ? QJsonValue(gitHead.output) : QJsonValue(QJsonValue::Null)},
        {"gitHeadQuerySucceeded", gitHead.succeeded},
        {"worktreeStatus", worktreeStatus.succeeded
            ? QJsonValue(worktreeStatus.output) : QJsonValue(QJsonValue::Null)},
        {"worktreeQuerySucceeded", worktreeStatus.succeeded},
        {"worktreeDirty", worktreeStatus.succeeded
            ? QJsonValue(!worktreeStatus.output.isEmpty()) : QJsonValue(QJsonValue::Null)},
        {"buildType", QStringLiteral(CRYPTOBENCH_QUALIFICATION_BUILD_TYPE)},
        {"provenanceVerified", gitHead.succeeded && worktreeStatus.succeeded},
        {"os", QSysInfo::prettyProductName()}, {"kernel", QSysInfo::kernelVersion()},
        {"architecture", QSysInfo::currentCpuArchitecture()},
        {"pageSizeBytes", static_cast<qint64>(pageSize)},
        {"syntheticExecutable", executableIdentity(syntheticWorkerPath())}
    };
    QJsonObject scenarioObject{
        {"requestedPreparationBytes", QString::number(scenario.preparationBytes)},
        {"nominalCommittedPreparationBytes", QString::number(committedBytes(scenario.preparationBytes, pageSize))},
        {"requestedExecutionBytes", QString::number(scenario.executionBytes)},
        {"nominalCommittedExecutionBytes", QString::number(committedBytes(scenario.executionBytes, pageSize))},
        {"allocationValueSemantics", "requested is logical input; nominal committed is page-rounded VirtualAlloc accounting, not an observed PrivateUsage value"},
        {"preparationHoldMilliseconds", static_cast<qint64>(scenario.preparationHoldMilliseconds)},
        {"executionHoldMilliseconds", static_cast<qint64>(scenario.executionHoldMilliseconds)},
        {"releasePreparationBeforeBoundary", scenario.releasePreparationBeforeBoundary},
        {"releaseExecutionBeforeEnd", scenario.releaseExecutionBeforeEnd},
        {"outcome", syntheticOutcomeName(scenario.outcome)}
    };
    QJsonObject lifecycle{
        {"workerPid", static_cast<qint64>(run.workerPid)},
        {"processCreationTime100ns", QString::number(run.processCreationTime100ns)},
        {"processCreationTimeObserved", run.processCreationTimeObserved},
        {"workerStarted", run.workerStarted}, {"processFinishedObserved", run.processFinishedObserved},
        {"startEventOrdinal", static_cast<qint64>(run.startEventOrdinal)},
        {"finishEventOrdinal", static_cast<qint64>(run.finishEventOrdinal)},
        {"normalExit", run.normalExit},
        {"terminationStatus", terminationStatusName(run.terminationStatus)},
        {"individualLifecycleProof", run.workerStarted && run.processFinishedObserved &&
            run.finishEventOrdinal > run.startEventOrdinal},
        {"crossRunFreshWorkerProof", false},
        {"crossRunFreshWorkerProofStatus", "unavailable-single-run-artifact"}
    };
    QJsonObject root{
        {"format", "cryptobenchmark-memory-v2-qualification"}, {"schemaVersion", 1},
        {"status", run.status}, {"error", run.error.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(run.error)},
        {"provenance", provenance},
        {"identity", QJsonObject{{"campaignId", identity.campaignId}, {"caseId", identity.caseId},
            {"repetitionId", identity.repetitionId}, {"executionOrder", static_cast<qint64>(identity.executionOrder)}}},
        {"runConfig", QJsonObject{{"profileId", "sha256"}, {"operation", "hash"},
            {"iterationsPerRun", "1"}, {"runs", 1}, {"workloadBytes", "8"}}},
        {"sampling", QJsonObject{{"mode", modeName(mode)},
            {"intervalMilliseconds", static_cast<qint64>(intervalMilliseconds)},
            {"boundaryOnlyIsNoncanonicalReference", mode == QualificationSamplingMode::BoundaryOnlyControl}}},
        {"scenario", scenarioObject}, {"lifecycle", lifecycle},
        {"timing", QJsonObject{{"kind", "synthetic workload timing; not canonical cryptographic benchmark performance"},
            {"window", "StartMeasurement acknowledgement through execution allocation, hold, release, and CPU/wall stop"},
            {"observationStatus", run.workerMeasurementObserved ? "observed" : "unavailable"},
            {"wallClockNanoseconds", run.workerMeasurementObserved
                ? QJsonValue(QString::number(run.workerMeasurement.elapsedNanoseconds))
                : QJsonValue(QJsonValue::Null)},
            {"processCpuNanoseconds", run.workerMeasurementObserved
                ? QJsonValue(QString::number(run.workerMeasurement.processCpuNanoseconds))
                : QJsonValue(QJsonValue::Null)}}}
    };
    if (run.status == QStringLiteral("completed")) {
        const auto& raw = run.raw;
        const auto& derived = *run.derived;
        root.insert("observations", QJsonObject{
            {"b0PrivateUsageBytes", QString::number(raw.baselinePrivateUsageBytes)},
            {"b1PrivateUsageBytes", QString::number(raw.readyPrivateUsageBytes)},
            {"preparationPeakSampledPrivateUsageBytes", optionalU64(raw.preparationPeakSampledPrivateUsageBytes)},
            {"executionPeakSampledPrivateUsageBytes", optionalU64(raw.executionPeakSampledPrivateUsageBytes)},
            {"ePrivateUsageBytes", QString::number(raw.finalPrivateUsageBytes)},
            {"preparationSampleCount", QString::number(raw.preparationSampleCount)},
            {"executionSampleCount", QString::number(raw.executionSampleCount)}});
        root.insert("derived", QJsonObject{
            {"readyStateDeltaBytes", QString::number(derived.readyStateDelta)},
            {"preparationPeakDeltaBytes", QString::number(derived.preparationPeakDelta)},
            {"executionPeakDeltaBytes", QString::number(derived.executionPeakDelta)},
            {"operationalPeakDeltaBytes", QString::number(derived.operationalPeakDelta)}});
    }
    return QJsonDocument(root);
}

void requireQualificationArtifact(const QJsonDocument& document)
{
    require(document.isObject(), "qualification artifact is not an object");
    const auto object = document.object();
    require(object.value("format") == "cryptobenchmark-memory-v2-qualification",
            "qualification artifact format mismatch");
    require(object.value("schemaVersion").toInt() == 1, "qualification artifact schema mismatch");
    require(object.value("provenance").toObject().contains("gitHead"),
            "qualification artifact omitted provenance");
    require(object.value("identity").toObject().contains("repetitionId"),
            "qualification artifact omitted run identity");
    const auto timing = object.value("timing").toObject();
    if (object.value("status") == QStringLiteral("completed")) {
        require(timing.value("observationStatus") == QStringLiteral("observed") &&
                    timing.value("wallClockNanoseconds").isString() &&
                    timing.value("processCpuNanoseconds").isString(),
                "completed artifact omitted observed timing");
        const auto observations = object.value("observations").toObject();
        require(observations.value("b0PrivateUsageBytes").isString() &&
                    observations.value("b1PrivateUsageBytes").isString() &&
                    observations.value("ePrivateUsageBytes").isString(),
                "qualification artifact lost integer precision");
        require(object.value("derived").toObject().contains("operationalPeakDeltaBytes"),
                "qualification artifact omitted derived metrics");
    } else {
        require(timing.value("observationStatus") == QStringLiteral("unavailable") &&
                    timing.value("wallClockNanoseconds").isNull() &&
                    timing.value("processCpuNanoseconds").isNull(),
                "incomplete artifact fabricated timing");
        require(!object.contains("observations") && !object.contains("derived"),
                "incomplete qualification artifact fabricated observations");
    }
}

void writeQualificationArtifact(const QString& path, const QJsonDocument& document)
{
    QSaveFile file(path);
    require(file.open(QIODevice::WriteOnly), "qualification artifact could not be opened");
    const auto bytes = document.toJson(QJsonDocument::Indented);
    require(file.write(bytes) == bytes.size(), "qualification artifact could not be written");
    require(file.commit(), "qualification artifact commit failed");
}

} // namespace cryptobench::tests
