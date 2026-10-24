#include "M19_4RealWorkerQualification.h"

#include "BackendIntegrationTestSupport.h"

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BenchmarkController.h>
#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/MemoryV2Calculator.h>
#include <cryptobench/platform/windows/WindowsProcessCpuTimeSource.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QJsonArray>
#include <QJsonObject>
#include <QSaveFile>
#include <QSysInfo>
#include <QTimer>

#include <windows.h>

#include <stdexcept>
#include <chrono>
#include <cstdio>
#include <vector>

namespace cryptobench::tests {
namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

std::vector<M19_4CategorySpec> matrix()
{
    return {
        {QStringLiteral("ed25519-sign"),
            {core::AlgorithmProfileId::Ed25519, core::BenchmarkOperation::Sign,
             2, 2, core::SignatureConfig{core::MessageInput{64}}}},
        {QStringLiteral("x25519-derive"),
            {core::AlgorithmProfileId::X25519, core::BenchmarkOperation::Derive,
             2, 2, core::KeyEstablishmentConfig{}}},
        {QStringLiteral("aes256-gcm-encrypt"),
            {core::AlgorithmProfileId::Aes256Gcm, core::BenchmarkOperation::Encrypt,
             100'000, 2, core::AeadConfig{16}}},
        {QStringLiteral("sha256-hash"),
            {core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash,
             100'000, 2, core::HashConfig{8}}}
    };
}

QJsonObject parameters(const core::PrimitiveConfig& value)
{
    if (const auto* signature = std::get_if<core::SignatureConfig>(&value)) {
        const auto* message = std::get_if<core::MessageInput>(&signature->input);
        return message ? QJsonObject{{"kind", "message"}, {"size", QString::number(message->messageSize)}}
                       : QJsonObject{{"kind", "other-signature-input"}};
    }
    if (std::holds_alternative<core::KeyEstablishmentConfig>(value)) {
        return QJsonObject{{"kind", "default-key-establishment"}};
    }
    if (const auto* aead = std::get_if<core::AeadConfig>(&value)) {
        return QJsonObject{{"kind", "plaintext"}, {"size", QString::number(aead->plaintextSize)}};
    }
    const auto& hash = std::get<core::HashConfig>(value);
    return QJsonObject{{"kind", "input"}, {"size", QString::number(hash.inputSize)}};
}

QJsonObject matrixEntry(const M19_4CategorySpec& item)
{
    return QJsonObject{
        {"category", item.id},
        {"profile", QString::fromStdString(std::string(core::toStableProfileId(item.config.profile)))},
        {"operation", static_cast<qint64>(item.config.operation)},
        {"parameters", parameters(item.config.parameters)},
        {"iterationsPerRun", QString::number(item.config.iterationsPerRun)},
        {"runs", static_cast<qint64>(item.config.runs)}};
}

std::uint64_t processCreationTime100ns(std::uint32_t pid)
{
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    require(handle != nullptr, "M19.4 could not open worker identity");
    FILETIME creation{}, exit{}, kernel{}, user{};
    const auto success = GetProcessTimes(handle, &creation, &exit, &kernel, &user);
    CloseHandle(handle);
    require(success != FALSE, "M19.4 GetProcessTimes failed");
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
        static_cast<std::uint64_t>(creation.dwLowDateTime);
}

QString workerPath()
{
    const auto path = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(path), "M19.4 production worker is missing");
    return QFileInfo(path).absoluteFilePath();
}

QString gitValue(const QStringList& arguments, bool& succeeded)
{
    QDir root(QCoreApplication::applicationDirPath());
    while (!root.isRoot() && !QFileInfo::exists(root.filePath(QStringLiteral(".git")))) {
        root.cdUp();
    }
    if (!QFileInfo::exists(root.filePath(QStringLiteral(".git")))) {
        succeeded = false;
        return {};
    }
    QProcess process;
    process.setWorkingDirectory(root.absolutePath());
    process.start(QStringLiteral("git"), arguments);
    succeeded = process.waitForFinished(5000) && process.exitCode() == 0;
    return succeeded ? QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed() : QString{};
}

QString workerSha256(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M19.4 could not hash production worker");
    return QString::fromLatin1(
        QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

QString fileSha256(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M19.4 evidence file could not be hashed");
    return QString::fromLatin1(
        QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

bool uniqueIdentities(const QStringList& identities)
{
    for (qsizetype left = 0; left < identities.size(); ++left) {
        for (qsizetype right = left + 1; right < identities.size(); ++right) {
            if (identities[left] == identities[right]) return false;
        }
    }
    return true;
}

void persistJson(const QString& path, const QJsonDocument& document)
{
    const auto result = application::AtomicFileWriter{}.writeAtomically(
        path, document.toJson(QJsonDocument::Indented));
    require(result.success, "M19.4 atomic persistence failed: " +
        result.technicalMessage.toStdString());
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M19.4 persisted evidence could not be read");
    QJsonParseError error{};
    const auto roundTrip = QJsonDocument::fromJson(file.readAll(), &error);
    require(error.error == QJsonParseError::NoError && roundTrip == document,
            "M19.4 persisted evidence read-back mismatch");
}

QJsonDocument readJson(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M19.4 evidence file is missing: " + path.toStdString());
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(file.readAll(), &error);
    require(error.error == QJsonParseError::NoError && document.isObject(),
            "M19.4 evidence JSON is malformed: " + path.toStdString());
    return document;
}

QJsonValue optionalU64(const std::optional<std::uint64_t>& value)
{
    return value ? QJsonValue(QString::number(*value)) : QJsonValue(QJsonValue::Null);
}

void validateMemory(const core::MemoryV2RunMeasurement& memory)
{
    const auto& raw = memory.raw;
    require(raw.baselinePrivateUsageBytes > 0 && raw.readyPrivateUsageBytes > 0 &&
                raw.finalPrivateUsageBytes > 0,
            "M19.4 Memory v2 boundary PrivateUsage is not positive");
    require((raw.preparationSampleCount == 0) ==
                !raw.preparationPeakSampledPrivateUsageBytes.has_value() &&
                (raw.executionSampleCount == 0) ==
                !raw.executionPeakSampledPrivateUsageBytes.has_value(),
            "M19.4 Memory v2 sample and optional-peak contract is invalid");
    const auto derived = core::calculateMemoryV2DerivedMetrics(raw);
    require(derived.has_value(), "M19.4 production Memory v2 derivation rejected raw observations");
    require(derived->readyStateDelta == memory.derived.readyStateDelta &&
                derived->preparationPeakDelta == memory.derived.preparationPeakDelta &&
                derived->executionPeakDelta == memory.derived.executionPeakDelta &&
                derived->operationalPeakDelta == memory.derived.operationalPeakDelta,
            "M19.4 Memory v2 derived values do not match production calculation");
}

void validateResult(const M19_4CategorySpec& spec, const core::BenchmarkResult& result,
                    const std::vector<std::uint32_t>& pids,
                    const std::vector<std::uint64_t>& creations,
                    std::chrono::system_clock::time_point started,
                    std::chrono::system_clock::time_point completed)
{
    test_support::assertCompletedResult(result, spec.config, started, completed);
    require(result.runs.size() == 2 && pids.size() == 2 && creations.size() == 2,
            "M19.4 expected exactly two completed worker runs");
    require(result.config.profile == spec.config.profile &&
                result.config.operation == spec.config.operation &&
                result.config.iterationsPerRun == spec.config.iterationsPerRun &&
                result.config.runs == 2,
            "M19.4 completed result configuration differs from matrix");
    for (std::size_t index = 0; index < result.runs.size(); ++index) {
        const auto& run = result.runs[index];
        require(run.runIndex == index && run.totalElapsedTime.count() > 0 &&
                    run.totalCpuTime.count() >= 0,
                "M19.4 run index or timing fields are invalid");
        const auto* memory = std::get_if<core::MemoryV2RunMeasurement>(&run.memory);
        require(memory != nullptr, "M19.4 run does not contain Memory v2");
        validateMemory(*memory);
    }
    require(pids[0] != pids[1] && creations[0] != creations[1],
            "M19.4 worker PID and creation-time identities were reused");
}

QJsonDocument runArtifact(const M19_4CategorySpec& spec,
                          const core::BenchmarkResult& result,
                          const std::vector<std::uint32_t>& pids,
                          const std::vector<std::uint64_t>& creations,
                          const QString& workerHash,
                          const QString& gitHead,
                          bool gitDirty)
{
    QJsonArray runs;
    for (std::size_t index = 0; index < result.runs.size(); ++index) {
        const auto& run = result.runs[index];
        const auto& memory = std::get<core::MemoryV2RunMeasurement>(run.memory);
        runs.append(QJsonObject{
            {"runIndex", static_cast<qint64>(run.runIndex)},
            {"workerPid", QString::number(pids[index])},
            {"workerCreationTime100ns", QString::number(creations[index])},
            {"workerWallNanoseconds", QString::number(run.totalElapsedTime.count())},
            {"workerCpuNanoseconds", QString::number(run.totalCpuTime.count())},
            {"memory", QJsonObject{
                {"b0", QString::number(memory.raw.baselinePrivateUsageBytes)},
                {"b1", QString::number(memory.raw.readyPrivateUsageBytes)},
                {"e", QString::number(memory.raw.finalPrivateUsageBytes)},
                {"preparationSampleCount", QString::number(memory.raw.preparationSampleCount)},
                {"executionSampleCount", QString::number(memory.raw.executionSampleCount)},
                {"preparationPeak", optionalU64(memory.raw.preparationPeakSampledPrivateUsageBytes)},
                {"executionPeak", optionalU64(memory.raw.executionPeakSampledPrivateUsageBytes)},
                {"readyStateDelta", QString::number(memory.derived.readyStateDelta)},
                {"preparationPeakDelta", QString::number(memory.derived.preparationPeakDelta)},
                {"executionPeakDelta", QString::number(memory.derived.executionPeakDelta)},
                {"operationalPeakDelta", QString::number(memory.derived.operationalPeakDelta)}}}});
    }
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-4-real-worker-qualification"},
        {"schemaVersion", 1}, {"category", spec.id}, {"status", "completed"},
        {"profile", QString::fromStdString(std::string(core::toStableProfileId(spec.config.profile)))},
        {"operation", static_cast<qint64>(spec.config.operation)},
        {"iterationsPerRun", QString::number(spec.config.iterationsPerRun)},
        {"runs", static_cast<qint64>(spec.config.runs)},
        {"samplingIntervalMilliseconds", 2}, {"result", runs},
        {"workerExecutableSha256", workerHash}, {"gitDirty", gitDirty},
        {"gitHead", gitHead}, {"operatingSystem", QSysInfo::prettyProductName()},
        {"architecture", QSysInfo::currentCpuArchitecture()},
        {"buildType", QString::fromStdString(std::string(application::build_info::buildType))},
        {"workerExecutablePath", workerPath()}});
}

} // namespace

QString m19_4ProductionWorkerPath()
{
    return workerPath();
}

QJsonDocument m19_4QualificationMatrix()
{
    QJsonArray entries;
    for (const auto& item : matrix()) {
        entries.append(matrixEntry(item));
    }
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-4-qualification-matrix"},
        {"schemaVersion", 1}, {"samplingIntervalMilliseconds", 2},
        {"entries", entries}});
}

void validateM19_4QualificationMatrix(const QJsonDocument& document)
{
    require(document == m19_4QualificationMatrix(),
            "M19.4 matrix does not exactly match the canonical contract");
}

namespace {

void validateCampaignEvidenceBeforeMarker(const QString& outputDirectory)
{
    const auto manifest = readJson(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")));
    require(manifest.object().value("format") == QStringLiteral("cryptobenchmark-m19-4-real-worker-manifest") &&
                manifest.object().value("matrix").toObject() == m19_4QualificationMatrix().object(),
            "M19.4 manifest is not the immutable canonical manifest");
    require(!manifest.object().value("gitHead").toString().isEmpty() &&
                !manifest.object().value("workerExecutableSha256").toString().isEmpty() &&
                manifest.object().value("gitDirty").toBool() == false &&
                manifest.object().value("buildType") == QStringLiteral("Release"),
            "M19.4 manifest provenance is incomplete");

    const auto summary = readJson(QDir(outputDirectory).filePath(QStringLiteral("summary.json")));
    require(summary.object().value("format") == QStringLiteral("cryptobenchmark-m19-4-real-worker-summary") &&
                summary.object().value("complete").toBool() &&
                summary.object().value("completedCategories").toInt() == 4 &&
                summary.object().value("workerExecutions").toInt() == 8,
            "M19.4 completion summary is incomplete");
    const auto entries = summary.object().value("categoryArtifacts").toArray();
    require(entries.size() == 4, "M19.4 summary does not list four category artifacts");
    QStringList identities;
    for (const auto& value : entries) {
        const auto entry = value.toObject();
        const auto path = QDir(outputDirectory).filePath(entry.value("file").toString());
        require(entry.value("sha256") == fileSha256(path), "M19.4 category artifact hash mismatch");
        const auto document = readJson(path);
        require(document.object().value("status") == QStringLiteral("completed"),
                "M19.4 category artifact is not completed");
        for (const auto& run : document.object().value("result").toArray()) {
            const auto object = run.toObject();
            identities.append(object.value("workerPid").toString() + QStringLiteral("/") +
                             object.value("workerCreationTime100ns").toString());
        }
    }
    require(identities.size() == 8 && uniqueIdentities(identities),
            "M19.4 evidence does not contain eight distinct worker identities");
}

} // namespace

void validateM19_4CampaignEvidence(const QString& outputDirectory)
{
    validateCampaignEvidenceBeforeMarker(outputDirectory);
    const auto marker = readJson(QDir(outputDirectory).filePath(QStringLiteral("success.marker")));
    require(marker.object().value("format") == QStringLiteral("cryptobenchmark-m19-4-real-worker-success") &&
                marker.object().value("complete").toBool() &&
                marker.object().value("manifestSha256") == fileSha256(QDir(outputDirectory).filePath("manifest.json")) &&
                marker.object().value("summarySha256") == fileSha256(QDir(outputDirectory).filePath("summary.json")),
            "M19.4 success marker is missing or inconsistent");
}

const char* benchmarkStatusName(core::BenchmarkStatus status)
{
    switch (status) {
    case core::BenchmarkStatus::Completed: return "Completed";
    case core::BenchmarkStatus::Cancelled: return "Cancelled";
    case core::BenchmarkStatus::Failed: return "Failed";
    }
    return "Unknown";
}

void logIncompleteResult(const QString& category, const core::BenchmarkResult& result)
{
    if (result.status == core::BenchmarkStatus::Completed) return;
    std::fprintf(stderr, "M19.4 category=%s status=%s observedRuns=%zu\n",
                 category.toUtf8().constData(), benchmarkStatusName(result.status),
                 result.runs.size());
    for (const auto& run : result.runs) {
        std::fprintf(stderr, "M19.4 category=%s observedRunIndex=%u\n",
                     category.toUtf8().constData(), run.runIndex);
    }
    if (!result.error.has_value()) {
        std::fprintf(stderr, "M19.4 category=%s error=<none>\n",
                     category.toUtf8().constData());
        return;
    }
    const auto& error = *result.error;
    std::fprintf(stderr, "M19.4 category=%s errorTechnicalMessage=%s\n",
                 category.toUtf8().constData(), error.technicalMessage.c_str());
    if (error.runIndex.has_value()) {
        std::fprintf(stderr, "M19.4 category=%s errorRunIndex=%u\n",
                     category.toUtf8().constData(), *error.runIndex);
    }
    if (error.libraryDetails.has_value()) {
        std::fprintf(stderr, "M19.4 category=%s errorLibraryDetails=%s\n",
                     category.toUtf8().constData(), error.libraryDetails->c_str());
    }
}

int executeM19_4Qualification(const QString& outputDirectory)
{
    try {
        require(!QFileInfo::exists(outputDirectory), "M19.4 output directory already exists");
        require(core::isValidMeasurementSettings({2}), "M19.4 sampling interval is invalid");
        require(QDir().mkpath(outputDirectory), "M19.4 output directory could not be created");
        const auto executable = m19_4ProductionWorkerPath();
        const auto workerHash = workerSha256(executable);
        bool headSucceeded = false;
        const auto gitHead = gitValue({QStringLiteral("rev-parse"), QStringLiteral("HEAD")}, headSucceeded);
        bool statusSucceeded = false;
        const auto gitDirty = gitValue({QStringLiteral("status"), QStringLiteral("--porcelain")}, statusSucceeded);
        require(!workerHash.isEmpty() && headSucceeded && !gitHead.isEmpty() &&
                    statusSucceeded && gitDirty.isEmpty(),
                "M19.4 real campaign requires resolvable clean Git provenance");
        require(QString::fromStdString(std::string(application::build_info::buildType)) ==
                    QStringLiteral("Release"),
                "M19.4 real campaign requires a Release build");
        const auto manifest = QJsonDocument(QJsonObject{
            {"format", "cryptobenchmark-m19-4-real-worker-manifest"}, {"schemaVersion", 1},
            {"matrix", m19_4QualificationMatrix().object()}, {"workerExecutable", executable},
            {"workerExecutableSha256", workerHash}, {"gitHead", gitHead}, {"gitDirty", false},
            {"buildType", "Release"}, {"operatingSystem", QSysInfo::prettyProductName()},
            {"architecture", QSysInfo::currentCpuArchitecture()}});
        persistJson(QDir(outputDirectory).filePath(QStringLiteral("manifest.json")), manifest);
        QJsonArray artifactHashes;
        QStringList identities;
        for (const auto& spec : matrix()) {
            std::vector<std::uint32_t> pids;
            std::vector<std::uint64_t> creations;
            application::WorkerRunSessionTestHooks hooks;
            hooks.workerStarted = [&](qint64 pid) {
                const auto value = static_cast<std::uint32_t>(pid);
                pids.push_back(value);
                creations.push_back(processCreationTime100ns(value));
            };
            application::BenchmarkController controller(
                nullptr, executable, std::move(hooks), {2});
            std::optional<core::BenchmarkResult> result;
            QEventLoop loop;
            QObject::connect(&controller, &application::BenchmarkSessionExecutor::benchmarkFinished,
                             [&](const core::BenchmarkResult& value) {
                                 result = value;
                                 loop.quit();
                             });
            const auto started = std::chrono::system_clock::now();
            controller.start(spec.config);
            QTimer::singleShot(120'000, &loop, &QEventLoop::quit);
            loop.exec();
            const auto completed = std::chrono::system_clock::now();
            if (!result.has_value()) {
                std::fprintf(stderr, "M19.4 category=%s status=<timeout> observedRuns=0\n",
                             spec.id.toUtf8().constData());
                throw std::runtime_error("M19.4 benchmark timed out before completion event");
            }
            logIncompleteResult(spec.id, *result);
            validateResult(spec, *result, pids, creations, started, completed);
            for (std::size_t index = 0; index < pids.size(); ++index) {
                identities.append(QString::number(pids[index]) + QStringLiteral("/") +
                                 QString::number(creations[index]));
            }
            const auto path = QDir(outputDirectory).filePath(spec.id + QStringLiteral(".json"));
            persistJson(path, runArtifact(spec, *result, pids, creations, workerHash, gitHead, false));
            artifactHashes.append(QJsonObject{
                {"category", spec.id}, {"file", QFileInfo(path).fileName()},
                {"sha256", fileSha256(path)}});
        }
        require(identities.size() == 8 && uniqueIdentities(identities),
                "M19.4 campaign did not produce eight distinct worker identities");
        persistJson(QDir(outputDirectory).filePath(QStringLiteral("summary.json")), QJsonDocument(QJsonObject{
            {"format", "cryptobenchmark-m19-4-real-worker-summary"}, {"schemaVersion", 1},
            {"complete", true}, {"completedCategories", 4}, {"workerExecutions", 8},
            {"categoryArtifacts", artifactHashes}}));
        validateCampaignEvidenceBeforeMarker(outputDirectory);
        persistJson(QDir(outputDirectory).filePath(QStringLiteral("success.marker")), QJsonDocument(QJsonObject{
            {"format", "cryptobenchmark-m19-4-real-worker-success"}, {"schemaVersion", 1},
            {"complete", true},
            {"manifestSha256", fileSha256(QDir(outputDirectory).filePath("manifest.json"))},
            {"summarySha256", fileSha256(QDir(outputDirectory).filePath("summary.json"))}}));
        validateM19_4CampaignEvidence(outputDirectory);
        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "M19.4 qualification failed closed: %s\n", error.what());
        return 1;
    }
}

} // namespace cryptobench::tests
