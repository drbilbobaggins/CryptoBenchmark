#include "M19_3ConfirmatorySamplingOverhead.h"

#include "MemoryV2SamplingOverhead.h"

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BuildInfo.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonObject>
#include <QProcess>
#include <QSysInfo>

#include <algorithm>
#include <array>
#include <numeric>
#include <random>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptobench::tests {
namespace {

constexpr auto planFormat = "cryptobenchmark-m19-3-confirmatory-sampling-overhead-plan";
constexpr auto manifestFormat = "cryptobenchmark-m19-3-confirmatory-sampling-overhead-manifest";
constexpr auto recordFormat = "cryptobenchmark-m19-3-confirmatory-sampling-overhead-trial";
constexpr auto summaryFormat = "cryptobenchmark-m19-3-confirmatory-sampling-overhead-summary";
constexpr auto successFormat = "cryptobenchmark-m19-3-confirmatory-sampling-overhead-success";
constexpr std::array<std::uint32_t, 4> intervals{0, 5, 2, 1};

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

QString workerPath()
{
    const auto path = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(path), "confirmatory production worker is missing");
    return QFileInfo(path).absoluteFilePath();
}

QString sha256File(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "confirmatory file could not be hashed");
    return QString::fromLatin1(QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

QString sourceRoot()
{
    QDir root(QCoreApplication::applicationDirPath());
    while (!root.isRoot()) {
        if (QFileInfo::exists(root.filePath(QStringLiteral(".git")))) return root.absolutePath();
        root.cdUp();
    }
    return {};
}

QString gitValue(const QStringList& arguments, bool& succeeded)
{
    QProcess process;
    process.setWorkingDirectory(sourceRoot());
    process.start(QStringLiteral("git"), arguments);
    succeeded = process.waitForFinished(5'000) && process.exitCode() == 0;
    return succeeded ? QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed() : QString{};
}

void persistJson(const QString& path, const QJsonDocument& document)
{
    require(!QFileInfo::exists(path), "confirmatory evidence destination already exists");
    const auto result = application::AtomicFileWriter{}.writeAtomically(
        path, document.toJson(QJsonDocument::Indented));
    require(result.success, "confirmatory atomic persistence failed: " +
        result.technicalMessage.toStdString());
}

QJsonDocument readJson(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "confirmatory evidence is missing: " + path.toStdString());
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(file.readAll(), &error);
    require(error.error == QJsonParseError::NoError && document.isObject(),
            "confirmatory evidence JSON is malformed: " + path.toStdString());
    return document;
}

QString workloadName(std::uint32_t index)
{
    return index == 0 ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm-encrypt");
}

std::uint64_t workloadIterations(const QJsonObject& trial)
{
    bool ok = false;
    const auto value = trial.value(QStringLiteral("iterationsPerRun")).toString().toULongLong(&ok);
    require(ok && value > 0, "confirmatory trial N is invalid");
    return value;
}

QJsonArray expectedTrials(std::uint64_t seed, std::uint32_t repetitions,
                          std::uint64_t sha256Iterations, std::uint64_t aesIterations)
{
    require(repetitions >= 10 && repetitions <= 20,
            "confirmatory repetitions must be between 10 and 20");
    require(sha256Iterations > 0 && aesIterations > 0,
            "confirmatory workload N must be positive");
    QJsonArray trials;
    std::mt19937_64 generator(seed);
    std::uint32_t executionOrder = 0;
    std::uint32_t blockIndex = 0;
    for (std::uint32_t workload = 0; workload < 2; ++workload) {
        for (std::uint32_t repetition = 0; repetition < repetitions; ++repetition) {
            std::array<std::uint32_t, 4> blockOrder{0, 1, 2, 3};
            std::shuffle(blockOrder.begin(), blockOrder.end(), generator);
            const auto blockStart = blockIndex * 4;
            for (std::uint32_t blockPosition = 0; blockPosition < blockOrder.size(); ++blockPosition) {
                const auto interval = intervals[blockOrder[blockPosition]];
                const auto trialIndex = blockStart + blockPosition;
                trials.append(QJsonObject{
                    {"workload", workloadName(workload)},
                    {"samplingMode", interval == 0 ? "off" : "periodic"},
                    {"intervalMilliseconds", static_cast<qint64>(interval)},
                    {"repetition", static_cast<qint64>(repetition)},
                    {"blockIndex", static_cast<qint64>(blockIndex)},
                    {"blockPosition", static_cast<qint64>(blockPosition)},
                    {"iterationsPerRun", QString::number(workload == 0 ? sha256Iterations : aesIterations)},
                    {"trialIndex", static_cast<qint64>(trialIndex)},
                    {"executionOrder", static_cast<qint64>(executionOrder++)},
                    {"status", "notExecuted"}, {"executed", false}});
            }
            ++blockIndex;
        }
    }
    return trials;
}

void validateTrialMatrix(const QJsonArray& trials, std::uint32_t repetitions)
{
    require(trials.size() == static_cast<int>(repetitions * 8),
            "confirmatory trial count is invalid");
    std::vector<bool> orders(trials.size(), false);
    std::vector<bool> trialIndices(trials.size(), false);
    std::map<QString, QString> workloadN;
    for (const auto& value : trials) {
        const auto trial = value.toObject();
        const auto order = trial.value("executionOrder").toInt(-1);
        require(order >= 0 && order < trials.size() && !orders[order],
                "confirmatory execution order is invalid or duplicated");
        orders[order] = true;
        const auto trialIndex = trial.value("trialIndex").toInt(-1);
        require(trialIndex >= 0 && trialIndex < trials.size() && !trialIndices[trialIndex],
            "confirmatory trial index is invalid or duplicated");
        trialIndices[trialIndex] = true;
        const auto workload = trial.value("workload").toString();
        require(workload == "sha256" || workload == "aes256-gcm-encrypt",
                "confirmatory workload is unsupported");
        const auto interval = trial.value("intervalMilliseconds").toInt(-1);
        require(std::find(intervals.begin(), intervals.end(), interval) != intervals.end(),
                "confirmatory interval is unsupported");
        require((interval == 0 && trial.value("samplingMode") == "off") ||
                    (interval != 0 && trial.value("samplingMode") == "periodic"),
                "confirmatory OFF/periodic mode does not match interval");
        const auto repetition = trial.value("repetition").toInt(-1);
        require(repetition >= 0 && repetition < static_cast<int>(repetitions),
                "confirmatory repetition is invalid");
        const auto n = trial.value("iterationsPerRun").toString();
        bool nOk = false;
        require(n.toULongLong(&nOk) > 0 && nOk, "confirmatory trial N is invalid");
        if (workloadN.contains(workload)) {
            require(workloadN[workload] == n, "confirmatory workload N is not shared across modes");
        } else {
            workloadN[workload] = n;
        }
        require(!trial.value("executed").toBool() && trial.value("status") == "notExecuted",
                "confirmatory plan is not frozen as notExecuted");
    }
}

void validatePreMarkerEvidence(const QString& outputDirectory, const QJsonDocument& plan)
{
    const auto manifest = readJson(QDir(outputDirectory).filePath("manifest.json"));
    require(manifest.object().value("format") == manifestFormat &&
                manifest.object().value("planSha256") == sha256File(QDir(outputDirectory).filePath("plan.json")) &&
                manifest.object().value("plan").toObject() == plan.object(),
            "confirmatory manifest does not match the frozen plan");
    require(manifest.object().value("workerExecutablePath") == plan.object().value("workerExecutablePath") &&
                manifest.object().value("workerExecutableSha256") == plan.object().value("workerExecutableSha256") &&
                manifest.object().value("gitHead") == plan.object().value("gitHead") &&
                manifest.object().value("gitDirty") == false &&
                manifest.object().value("buildType") == "Release" &&
                manifest.object().value("sha256CalibrationSha256") == plan.object().value("sha256CalibrationSha256") &&
                manifest.object().value("aes256GcmCalibrationSha256") == plan.object().value("aes256GcmCalibrationSha256"),
            "confirmatory manifest provenance is inconsistent");
    const auto summary = readJson(QDir(outputDirectory).filePath("summary.json"));
    require(summary.object().value("format") == summaryFormat &&
                summary.object().value("complete").toBool() &&
                summary.object().value("plannedCount").toInt() == plan.object().value("trialCount").toInt() &&
                summary.object().value("completedCount").toInt() == plan.object().value("trialCount").toInt(),
            "confirmatory summary is incomplete");
    const auto records = summary.object().value("records").toArray();
    require(records.size() == plan.object().value("trialCount").toInt(),
            "confirmatory summary record count is invalid");
    std::vector<bool> recordOrders(records.size(), false);
        QStringList workerIdentities;
    for (const auto& value : records) {
        const auto entry = value.toObject();
        const auto order = entry.value("executionOrder").toInt(-1);
        require(order >= 0 && order < plan.object().value("trialCount").toInt(),
            "confirmatory record execution order is invalid");
        require(!recordOrders[order], "confirmatory record execution order is duplicated");
        recordOrders[order] = true;
        const auto expectedTrial = plan.object().value("trials").toArray()[order].toObject();
        require(entry.value("workload") == expectedTrial.value("workload") &&
                entry.value("samplingMode") == expectedTrial.value("samplingMode") &&
                entry.value("intervalMilliseconds") == expectedTrial.value("intervalMilliseconds") &&
                entry.value("repetition") == expectedTrial.value("repetition") &&
                    entry.value("blockIndex") == expectedTrial.value("blockIndex") &&
                    entry.value("blockPosition") == expectedTrial.value("blockPosition") &&
                entry.value("iterationsPerRun") == expectedTrial.value("iterationsPerRun"),
            "confirmatory record does not match frozen trial");
        const auto expectedFile = QStringLiteral("trial-%1.json").arg(order, 3, 10, QLatin1Char('0'));
        require(entry.value("file") == expectedFile,
                "confirmatory record filename does not match execution order");
        const auto path = QDir(outputDirectory).filePath(entry.value("file").toString());
        require(entry.value("sha256") == sha256File(path), "confirmatory trial hash mismatch");
        const auto record = readJson(path).object();
        require(record.value("schemaVersion") == 1 &&
                    record.value("executionOrder") == expectedTrial.value("executionOrder") &&
                    record.value("workload") == expectedTrial.value("workload") &&
                    record.value("samplingMode") == expectedTrial.value("samplingMode") &&
                    record.value("intervalMilliseconds") == expectedTrial.value("intervalMilliseconds") &&
                    record.value("repetition") == expectedTrial.value("repetition") &&
                    record.value("blockIndex") == expectedTrial.value("blockIndex") &&
                    record.value("blockPosition") == expectedTrial.value("blockPosition") &&
                    record.value("iterationsPerRun") == expectedTrial.value("iterationsPerRun") &&
                    record.value("internalMeasurementSettingsIntervalMilliseconds") ==
                        (expectedTrial.value("intervalMilliseconds").toInt() == 0
                            ? QJsonValue(5) : expectedTrial.value("intervalMilliseconds")),
                "confirmatory trial wrapper does not match frozen trial");
        require(record.value("format") == recordFormat && record.value("status") == "completed" &&
                    record.value("error").toString().isEmpty() &&
                    record.value("internalMeasurementSettingsIntervalMilliseconds") ==
                        (entry.value("intervalMilliseconds").toInt() == 0 ? QJsonValue(5) : entry.value("intervalMilliseconds")) &&
                    record.value("result").isObject(), "confirmatory trial record is incomplete");
        validateSamplingOverheadRunArtifact(QJsonDocument(record.value("result").toObject()));
        const auto result = record.value("result").toObject();
        const auto expectedInternalInterval = entry.value("intervalMilliseconds").toInt() == 0
            ? 5 : entry.value("intervalMilliseconds").toInt();
        const auto configuration = result.value("configuration").toObject();
        const auto provenance = result.value("provenance").toObject();
        require(result.value("workload") == entry.value("workload") &&
                    result.value("executionOrder") == order &&
                    result.value("logicalRunIndex") == 0 &&
                    result.value("status") == "completed" && result.value("error").toString().isEmpty() &&
                    result.value("samplingMode") == (entry.value("intervalMilliseconds").toInt() == 0
                        ? "boundaryOnlyControl" : "periodic") &&
                    result.value("intervalMilliseconds") == expectedInternalInterval &&
                    configuration.value("iterationsPerRun") == entry.value("iterationsPerRun") &&
                    configuration.value("runs") == 1 &&
                    result.value("workerMeasurementObserved").toBool() &&
                    result.value("memoryObserved").toBool() && result.value("normalExit").toBool() &&
                    ((entry.value("workload") == "sha256" &&
                        configuration.value("algorithmProfile") == "sha256" &&
                        configuration.value("operation") == "hash" &&
                        configuration.value("inputBytes") == "8") ||
                     (entry.value("workload") == "aes256-gcm-encrypt" &&
                        configuration.value("algorithmProfile") == "aes256-gcm" &&
                        configuration.value("operation") == "encrypt" &&
                        configuration.value("inputBytes") == "16")) &&
                    provenance.value("workerExecutablePath") == plan.object().value("workerExecutablePath") &&
                    provenance.value("workerExecutableSha256") == plan.object().value("workerExecutableSha256") &&
                    provenance.value("gitHead") == plan.object().value("gitHead") &&
                    provenance.value("gitDirty") == false && provenance.value("buildType") == "Release",
                "confirmatory nested result does not match frozen provenance/configuration");
        const auto measurementWindows = result.value("measurementWindows").toObject();
        const auto memory = result.value("memory").toObject();
        if (entry.value("intervalMilliseconds").toInt() == 0) {
            require(memory.value("executionSampleCount") == "0" &&
                        memory.value("executionPeakSampledPrivateUsageBytes").isNull(),
                    "confirmatory OFF result contains periodic execution samples");
        } else if (measurementWindows.value("workerElapsedNanoseconds").toString().toULongLong() >= 900'000'000) {
            require(memory.value("executionSampleCount").toString().toULongLong() > 0 &&
                        memory.value("executionPeakSampledPrivateUsageBytes").isString(),
                    "one-second periodic confirmatory result has no execution sample");
        }
        const auto identity = result.value("workerPid").toString() + QStringLiteral("/") +
            result.value("workerCreationTime100ns").toString();
        require(!identity.startsWith("/"), "confirmatory worker identity is missing");
        require(!workerIdentities.contains(identity), "confirmatory worker identity was reused");
        workerIdentities.append(identity);
    }
    require(workerIdentities.size() == plan.object().value("trialCount").toInt(),
            "confirmatory worker identity count is incomplete");
}

void validateCalibrationDocument(const QJsonDocument& document,
                                 const QString& workload,
                                 const QString& workerExecutableSha256,
                                 const QString& gitHead,
                                 const QString& buildType)
{
    validateSamplingOverheadCalibration(document);
    const auto object = document.object();
    require(object.value("format") == "cryptobenchmark-memory-v2-sampling-overhead-calibration" &&
                object.value("status") == "success" && object.value("workload") == workload,
            "confirmatory calibration workload or status is invalid");
    const auto selected = object.value("selectedIterationsPerRun").toString();
    bool selectedOk = false;
    require(selected.toULongLong(&selectedOk) > 0 && selectedOk,
            "confirmatory calibration selected N is invalid");
    bool found = false;
    for (const auto& value : object.value("observations").toArray()) {
        const auto observation = value.toObject();
        if (observation.value("calibrationCandidateIterations").toString() != selected) continue;
        const auto timing = observation.value("measurementWindows").toObject();
        const auto configuration = observation.value("configuration").toObject();
        const auto memory = observation.value("memory").toObject();
        const auto provenance = observation.value("provenance").toObject();
        require(observation.value("status") == "completed" && observation.value("workload") == workload &&
                    observation.value("samplingMode") == "boundaryOnlyControl" &&
                    observation.value("intervalMilliseconds").toInt() == 5 &&
                    configuration.value("iterationsPerRun") == selected && configuration.value("runs").toInt() == 1 &&
                    ((workload == "sha256" && configuration.value("algorithmProfile") == "sha256" &&
                        configuration.value("operation") == "hash" && configuration.value("inputBytes") == "8") ||
                     (workload == "aes256-gcm-encrypt" && configuration.value("algorithmProfile") == "aes256-gcm" &&
                        configuration.value("operation") == "encrypt" && configuration.value("inputBytes") == "16")) &&
                    timing.value("workerElapsedNanoseconds").toString().toULongLong() >= 900'000'000 &&
                    timing.value("workerProcessCpuNanoseconds").isString() &&
                    observation.value("workerMeasurementObserved").toBool() && observation.value("normalExit").toBool() &&
                    observation.value("memoryObserved").toBool() && observation.value("workerPid").toString().toULongLong() > 0 &&
                    observation.value("workerCreationTime100ns").toString().toULongLong() > 0 &&
                    memory.value("preparationSampleCount") == "0" && memory.value("executionSampleCount") == "0" &&
                    memory.value("preparationPeakSampledPrivateUsageBytes").isNull() &&
                    memory.value("executionPeakSampledPrivateUsageBytes").isNull() &&
                    provenance.value("workerExecutableSha256") == workerExecutableSha256 &&
                    provenance.value("gitHead") == gitHead && provenance.value("gitDirty").toBool() == false &&
                    provenance.value("buildType") == buildType,
                "confirmatory calibration selected observation violates strict contract");
        found = true;
    }
    require(found, "confirmatory calibration selected observation was not found");
}

} // namespace

void validateM19_3CalibrationArtifact(
    const QString& path, const QString& workload, const QString& workerExecutableSha256,
    const QString& gitHead, const QString& buildType)
{
    validateCalibrationDocument(readJson(path), workload, workerExecutableSha256, gitHead, buildType);
}

QJsonDocument prepareM19_3ConfirmatoryPlan(
    std::uint64_t seed, std::uint32_t repetitions, std::uint64_t sha256Iterations,
    std::uint64_t aes256GcmIterations, const QString& sha256CalibrationSha256,
    const QString& aes256GcmCalibrationSha256,
    const QJsonDocument& sha256CalibrationArtifact,
    const QJsonDocument& aes256GcmCalibrationArtifact,
    const QByteArray& sha256CalibrationSourceBytes,
    const QByteArray& aes256GcmCalibrationSourceBytes,
    const QString& workerExecutablePath, const QString& workerExecutableSha256,
    const QString& gitHead, const QString& buildType)
{
    require(!sha256CalibrationSha256.isEmpty() && !aes256GcmCalibrationSha256.isEmpty() &&
                sha256CalibrationArtifact.isObject() && aes256GcmCalibrationArtifact.isObject() &&
                QCryptographicHash::hash(sha256CalibrationSourceBytes, QCryptographicHash::Sha256).toHex() == sha256CalibrationSha256 &&
                QCryptographicHash::hash(aes256GcmCalibrationSourceBytes, QCryptographicHash::Sha256).toHex() == aes256GcmCalibrationSha256 &&
                !workerExecutablePath.isEmpty() && !workerExecutableSha256.isEmpty() &&
                !gitHead.isEmpty() && buildType == "Release",
            "confirmatory plan provenance is incomplete");
    const auto trials = expectedTrials(seed, repetitions, sha256Iterations, aes256GcmIterations);
    return QJsonDocument(QJsonObject{
        {"format", planFormat}, {"schemaVersion", 1}, {"status", "frozen"},
        {"seed", QString::number(seed)}, {"repetitions", QString::number(repetitions)},
        {"trialCount", trials.size()}, {"samplingIntervalsMilliseconds", QJsonArray{0, 5, 2, 1}},
        {"workloads", QJsonArray{"sha256", "aes256-gcm-encrypt"}},
        {"sha256CalibrationSha256", sha256CalibrationSha256},
        {"aes256GcmCalibrationSha256", aes256GcmCalibrationSha256},
        {"sha256CalibrationArtifact", sha256CalibrationArtifact.object()},
        {"aes256GcmCalibrationArtifact", aes256GcmCalibrationArtifact.object()},
        {"sha256CalibrationSourceBase64", QString::fromLatin1(sha256CalibrationSourceBytes.toBase64())},
        {"aes256GcmCalibrationSourceBase64", QString::fromLatin1(aes256GcmCalibrationSourceBytes.toBase64())},
        {"workerExecutablePath", workerExecutablePath}, {"workerExecutableSha256", workerExecutableSha256},
        {"gitHead", gitHead}, {"gitDirty", false}, {"buildType", buildType},
        {"trials", trials}});
}

void validateM19_3ConfirmatoryPlan(const QJsonDocument& document)
{
    require(document.isObject() && document.object().value("format") == planFormat &&
                document.object().value("schemaVersion") == 1 &&
                document.object().value("status") == "frozen" &&
                document.object().value("gitDirty") == false &&
                document.object().value("buildType") == "Release" &&
                !document.object().value("workerExecutablePath").toString().isEmpty() &&
                !document.object().value("workerExecutableSha256").toString().isEmpty() &&
                !document.object().value("gitHead").toString().isEmpty() &&
                !document.object().value("sha256CalibrationSha256").toString().isEmpty() &&
                !document.object().value("aes256GcmCalibrationSha256").toString().isEmpty() &&
                document.object().value("sha256CalibrationArtifact").isObject() &&
                document.object().value("aes256GcmCalibrationArtifact").isObject() &&
                document.object().value("sha256CalibrationSourceBase64").isString() &&
                document.object().value("aes256GcmCalibrationSourceBase64").isString() &&
                document.object().value("samplingIntervalsMilliseconds") == QJsonArray{0, 5, 2, 1} &&
                document.object().value("workloads") == QJsonArray{"sha256", "aes256-gcm-encrypt"},
            "confirmatory plan header or provenance is invalid");
    bool ok = false;
    const auto seedText = document.object().value("seed").toString();
    const auto seed = seedText.toULongLong(&ok);
    require(ok && seedText == QString::number(seed), "confirmatory seed is invalid");
    const auto repetitionsText = document.object().value("repetitions").toString();
    const auto repetitions = repetitionsText.toUInt(&ok);
    require(ok && repetitions >= 10 && repetitions <= 20,
            "confirmatory repetitions are invalid");
    require(document.object().value("trialCount").toInt() == repetitions * 8,
            "confirmatory trial count does not match repetitions");
    const auto trials = document.object().value("trials").toArray();
    validateTrialMatrix(trials, repetitions);
    QString shaN;
    QString aesN;
    for (const auto& value : trials) {
        const auto trial = value.toObject();
        if (trial.value("workload") == "sha256") shaN = trial.value("iterationsPerRun").toString();
        if (trial.value("workload") == "aes256-gcm-encrypt") aesN = trial.value("iterationsPerRun").toString();
    }
    bool shaOk = false;
    bool aesOk = false;
    const auto shaIterations = shaN.toULongLong(&shaOk);
    const auto aesIterations = aesN.toULongLong(&aesOk);
    require(shaOk && aesOk, "confirmatory workload N is invalid");
    const auto expected = expectedTrials(seed, repetitions, shaIterations, aesIterations);
    const auto fields = {"workload", "samplingMode", "intervalMilliseconds", "repetition",
                         "blockIndex", "blockPosition", "iterationsPerRun", "trialIndex",
                         "executionOrder", "status", "executed"};
    for (int index = 0; index < trials.size(); ++index) {
        const auto actual = trials[index].toObject();
        const auto expectedTrial = expected[index].toObject();
        for (const auto field : fields) {
            require(actual.value(field) == expectedTrial.value(field),
                    "confirmatory seeded block order or trial identity was altered");
        }
    }
    const auto shaBytes = QByteArray::fromBase64(
        document.object().value("sha256CalibrationSourceBase64").toString().toLatin1());
    const auto aesBytes = QByteArray::fromBase64(
        document.object().value("aes256GcmCalibrationSourceBase64").toString().toLatin1());
    require(QCryptographicHash::hash(shaBytes, QCryptographicHash::Sha256).toHex() ==
                document.object().value("sha256CalibrationSha256").toString().toLatin1() &&
                QCryptographicHash::hash(aesBytes, QCryptographicHash::Sha256).toHex() ==
                document.object().value("aes256GcmCalibrationSha256").toString().toLatin1(),
            "confirmatory calibration source bytes do not match recorded hashes");
    const auto shaCalibration = QJsonDocument::fromJson(shaBytes);
    const auto aesCalibration = QJsonDocument::fromJson(aesBytes);
    require(shaCalibration.object() == document.object().value("sha256CalibrationArtifact").toObject() &&
                aesCalibration.object() == document.object().value("aes256GcmCalibrationArtifact").toObject(),
            "confirmatory embedded calibration object does not match source bytes");
    validateCalibrationDocument(shaCalibration, "sha256",
        document.object().value("workerExecutableSha256").toString(),
        document.object().value("gitHead").toString(), "Release");
    validateCalibrationDocument(aesCalibration, "aes256-gcm-encrypt",
        document.object().value("workerExecutableSha256").toString(),
        document.object().value("gitHead").toString(), "Release");
    require(shaCalibration.object().value("selectedIterationsPerRun").toString() == shaN &&
                aesCalibration.object().value("selectedIterationsPerRun").toString() == aesN,
            "confirmatory calibration selected N does not match frozen trials");
}

std::uint32_t m19_3ConfirmatoryInternalInterval(std::uint32_t plannedIntervalMilliseconds)
{
    require(plannedIntervalMilliseconds == 0 || plannedIntervalMilliseconds == 1 ||
                plannedIntervalMilliseconds == 2 || plannedIntervalMilliseconds == 5,
            "confirmatory interval is unsupported");
    return plannedIntervalMilliseconds == 0 ? 5U : plannedIntervalMilliseconds;
}

void validateM19_3ConfirmatoryProvenance(
    const QJsonDocument& document, const QString& workerExecutablePath,
    const QString& workerExecutableSha256, const QString& gitHead, const QString& buildType)
{
    validateM19_3ConfirmatoryPlan(document);
    const auto object = document.object();
    require(QFileInfo(object.value("workerExecutablePath").toString()).absoluteFilePath() ==
                QFileInfo(workerExecutablePath).absoluteFilePath() &&
                object.value("workerExecutableSha256") == workerExecutableSha256 &&
                object.value("gitHead") == gitHead && object.value("buildType") == buildType,
            "confirmatory plan provenance does not match current execution");
}

void validateM19_3ConfirmatoryOutput(const QString& outputDirectory)
{
    const auto plan = readJson(QDir(outputDirectory).filePath("plan.json"));
    validateM19_3ConfirmatoryPlan(plan);
    validatePreMarkerEvidence(outputDirectory, plan);
    const auto marker = readJson(QDir(outputDirectory).filePath("success.marker"));
    require(marker.object().value("format") == successFormat && marker.object().value("complete").toBool() &&
                marker.object().value("manifestSha256") == sha256File(QDir(outputDirectory).filePath("manifest.json")) &&
                marker.object().value("summarySha256") == sha256File(QDir(outputDirectory).filePath("summary.json")),
            "confirmatory success marker is missing or inconsistent");
}

int executeM19_3Confirmatory(const QString& planPath, const QString& outputDirectory)
{
    QJsonArray persistedRecords;
    int plannedCount = 0;
    try {
        require(!QFileInfo::exists(outputDirectory), "confirmatory output directory already exists");
        const auto plan = readJson(planPath);
        const auto executable = workerPath();
        const auto executableHash = sha256File(executable);
        bool headOk = false;
        const auto head = gitValue({"rev-parse", "HEAD"}, headOk);
        bool statusOk = false;
        const auto dirty = gitValue({"status", "--porcelain"}, statusOk);
        require(headOk && !head.isEmpty() && statusOk && dirty.isEmpty(),
                "confirmatory execution requires a clean Git worktree");
        validateM19_3ConfirmatoryProvenance(
            plan, executable, executableHash, head,
            QString::fromStdString(std::string(application::build_info::buildType)));
        require(QString::fromStdString(std::string(application::build_info::buildType)) == "Release",
                "confirmatory execution requires a Release build");
        require(QDir().mkpath(outputDirectory), "confirmatory output directory could not be created");
        persistJson(QDir(outputDirectory).filePath("plan.json"), plan);
        persistJson(QDir(outputDirectory).filePath("manifest.json"), QJsonDocument(QJsonObject{
            {"format", manifestFormat}, {"schemaVersion", 1}, {"plan", plan.object()},
            {"planSha256", sha256File(QDir(outputDirectory).filePath("plan.json"))}, {"workerExecutablePath", executable},
            {"workerExecutableSha256", executableHash}, {"gitHead", head}, {"gitDirty", false},
            {"sha256CalibrationSha256", plan.object().value("sha256CalibrationSha256")},
            {"aes256GcmCalibrationSha256", plan.object().value("aes256GcmCalibrationSha256")},
            {"buildType", "Release"}, {"operatingSystem", QSysInfo::prettyProductName()},
            {"architecture", QSysInfo::currentCpuArchitecture()}}));
        QJsonArray records;
        const auto trials = plan.object().value("trials").toArray();
        plannedCount = trials.size();
        for (const auto& value : trials) {
            const auto trial = value.toObject();
            const auto order = trial.value("executionOrder").toInt();
            persistJson(QDir(outputDirectory).filePath(QStringLiteral("attempt-%1.json").arg(order, 3, 10, QLatin1Char('0'))),
                QJsonDocument(QJsonObject{{"format", "cryptobenchmark-m19-3-confirmatory-attempt"},
                    {"executionOrder", order}, {"status", "started"}}));
            SamplingOverheadRun run;
            try {
                const auto workload = trial.value("workload") == "sha256"
                    ? SamplingOverheadWorkload::Sha256 : SamplingOverheadWorkload::Aes256GcmEncrypt;
                const auto mode = trial.value("samplingMode") == "off"
                    ? SamplingOverheadMode::BoundaryOnlyControl : SamplingOverheadMode::Periodic;
                run = runRealSamplingOverheadSmoke(mode,
                    m19_3ConfirmatoryInternalInterval(
                        static_cast<std::uint32_t>(trial.value("intervalMilliseconds").toInt())),
                    workloadIterations(trial), static_cast<std::uint32_t>(order), workload, 120'000);
            } catch (const std::exception& error) {
                run.status = QStringLiteral("failed");
                run.error = QString::fromStdString(error.what());
            }
            const auto path = QDir(outputDirectory).filePath(QStringLiteral("trial-%1.json").arg(order, 3, 10, QLatin1Char('0')));
            const auto record = QJsonDocument(QJsonObject{
                {"format", recordFormat}, {"schemaVersion", 1}, {"executionOrder", order},
                {"workload", trial.value("workload")}, {"samplingMode", trial.value("samplingMode")},
                {"intervalMilliseconds", trial.value("intervalMilliseconds")},
                {"repetition", trial.value("repetition")},
                {"blockIndex", trial.value("blockIndex")}, {"blockPosition", trial.value("blockPosition")},
                {"internalMeasurementSettingsIntervalMilliseconds",
                    trial.value("intervalMilliseconds").toInt() == 0 ? QJsonValue(5) : QJsonValue(trial.value("intervalMilliseconds"))},
                {"iterationsPerRun", trial.value("iterationsPerRun")},
                {"status", run.status}, {"error", run.error},
                {"result", samplingOverheadRunArtifact(run).object()}});
            persistJson(path, record);
            records.append(QJsonObject{{"executionOrder", order}, {"workload", trial.value("workload")},
                {"samplingMode", trial.value("samplingMode")},
                {"intervalMilliseconds", trial.value("intervalMilliseconds")},
                {"repetition", trial.value("repetition")},
                {"blockIndex", trial.value("blockIndex")}, {"blockPosition", trial.value("blockPosition")},
                {"internalMeasurementSettingsIntervalMilliseconds",
                    trial.value("intervalMilliseconds").toInt() == 0 ? QJsonValue(5) : QJsonValue(trial.value("intervalMilliseconds"))},
                {"iterationsPerRun", trial.value("iterationsPerRun")},
                {"file", QFileInfo(path).fileName()}, {"sha256", sha256File(path)}});
            persistedRecords = records;
            if (run.status != "completed") {
                throw std::runtime_error("confirmatory trial failed: " + run.error.toStdString());
            }
        }
        persistJson(QDir(outputDirectory).filePath("summary.json"), QJsonDocument(QJsonObject{
            {"format", summaryFormat}, {"schemaVersion", 1}, {"complete", true},
            {"plannedCount", trials.size()}, {"completedCount", records.size()}, {"records", records}}));
        validatePreMarkerEvidence(outputDirectory, plan);
        persistJson(QDir(outputDirectory).filePath("success.marker"), QJsonDocument(QJsonObject{
            {"format", successFormat}, {"schemaVersion", 1}, {"complete", true},
            {"manifestSha256", sha256File(QDir(outputDirectory).filePath("manifest.json"))},
            {"summarySha256", sha256File(QDir(outputDirectory).filePath("summary.json"))}}));
        validateM19_3ConfirmatoryOutput(outputDirectory);
        return 0;
    } catch (const std::exception& error) {
        if (QFileInfo::exists(outputDirectory) &&
            !QFileInfo::exists(QDir(outputDirectory).filePath("summary.json"))) {
            try {
                persistJson(QDir(outputDirectory).filePath("summary.json"), QJsonDocument(QJsonObject{
                    {"format", summaryFormat}, {"schemaVersion", 1}, {"complete", false},
                    {"plannedCount", plannedCount}, {"completedCount", persistedRecords.size()},
                    {"error", QString::fromStdString(error.what())}, {"records", persistedRecords}}));
            } catch (...) {
            }
        }
        fprintf(stderr, "confirmatory qualification failed closed: %s\n", error.what());
        return 1;
    }
}

} // namespace cryptobench::tests
