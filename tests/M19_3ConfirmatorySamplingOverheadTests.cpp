#include "M19_3ConfirmatorySamplingOverhead.h"

#include "MemoryV2SamplingOverhead.h"

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BuildInfo.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QProcess>

#include <iostream>
#include <stdexcept>

using namespace cryptobench;

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

QString workerPath()
{
    const auto path = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(path), "confirmatory worker is missing");
    return QFileInfo(path).absoluteFilePath();
}

QString gitValue(const QStringList& arguments, bool& succeeded)
{
    QDir root(QCoreApplication::applicationDirPath());
    while (!root.isRoot()) {
        if (QFileInfo::exists(root.filePath(QStringLiteral(".git")))) break;
        root.cdUp();
    }
    QProcess process;
    process.setWorkingDirectory(root.absolutePath());
    process.start(QStringLiteral("git"), arguments);
    succeeded = process.waitForFinished(5'000) && process.exitCode() == 0;
    return succeeded ? QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed() : QString{};
}

QString sha256File(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "confirmatory worker could not be hashed");
    return QString::fromLatin1(QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

std::uint64_t argumentU64(const QString& value, const char* name)
{
    bool ok = false;
    const auto parsed = value.toULongLong(&ok);
    require(ok && parsed > 0, name);
    return parsed;
}

void writePlan(const QString& path, const QJsonDocument& document)
{
    require(!QFileInfo::exists(path), "confirmatory plan destination already exists");
    const auto result = cryptobench::application::AtomicFileWriter{}.writeAtomically(
        path, document.toJson(QJsonDocument::Indented));
    require(result.success, "confirmatory plan persistence failed");
}

void writeJson(const QString& path, const QJsonDocument& document)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "confirmatory synthetic file could not be written");
    require(file.write(document.toJson(QJsonDocument::Indented)) > 0,
            "confirmatory synthetic JSON write failed");
}

QString hashFile(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "confirmatory synthetic file could not be hashed");
    return QString::fromLatin1(QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex());
}

QString hashBytes(const QByteArray& bytes)
{
    return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
}

QJsonDocument syntheticCalibration(const QString& workload, std::uint64_t iterations)
{
    tests::SamplingOverheadRun run;
    run.mode = tests::SamplingOverheadMode::BoundaryOnlyControl;
    run.intervalMilliseconds = 5;
    run.workload = workload == "sha256"
        ? tests::SamplingOverheadWorkload::Sha256 : tests::SamplingOverheadWorkload::Aes256GcmEncrypt;
    run.workerPid = 1234;
    run.workerCreationTime100ns = 5678;
    run.workerMeasurementObserved = true;
    run.memoryObserved = true;
    run.normalExit = true;
    run.status = QStringLiteral("completed");
    run.workerMeasurement = {0, 1'000'000'000, 100'000};
    run.parentSessionWallNanoseconds = 1'100'000'000;
    run.parentSessionCpuNanoseconds = 0;
    run.workerExecutablePath = QStringLiteral("C:/worker.exe");
    run.workerExecutableSha256 = QStringLiteral("worker-hash");
    run.gitHead = QStringLiteral("git-head");
    run.buildType = QStringLiteral("Release");
    run.operatingSystem = QStringLiteral("synthetic");
    run.architecture = QStringLiteral("synthetic");
    run.algorithmProfile = workload == "sha256" ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm");
    run.operation = workload == "sha256" ? QStringLiteral("hash") : QStringLiteral("encrypt");
    run.inputBytes = workload == "sha256" ? 8 : 16;
    run.iterationsPerRun = iterations;
    run.runs = 1;
    run.memory = {1, 2, std::nullopt, std::nullopt, 3, 0, 0};
    auto observation = tests::samplingOverheadRunArtifact(run).object();
    observation.insert("calibrationCandidateIterations", QString::number(iterations));
    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-memory-v2-sampling-overhead-calibration"},
        {"schemaVersion", 1}, {"status", "success"}, {"workload", workload},
        {"maxWorkers", 1}, {"selectedIterationsPerRun", QString::number(iterations)},
        {"observations", QJsonArray{observation}}});
}

void expectCalibrationRejected(const QJsonDocument& document, const QString& workload)
{
    QTemporaryDir directory;
    require(directory.isValid(), "calibration rejection directory was not created");
    const auto path = directory.filePath("calibration.json");
    writeJson(path, document);
    bool rejected = false;
    try {
        tests::validateM19_3CalibrationArtifact(
            path, workload, QStringLiteral("worker-hash"), QStringLiteral("git-head"),
            QStringLiteral("Release"));
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "invalid synthetic calibration was accepted");
}

void expectRejected(const QJsonDocument& document)
{
    try {
        cryptobench::tests::validateM19_3ConfirmatoryPlan(document);
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("invalid confirmatory plan was accepted");
}

void testFrozenPlan()
{
    const auto validCalibration = syntheticCalibration(QStringLiteral("sha256"), 10'000'000);
    QTemporaryDir validCalibrationDirectory;
    require(validCalibrationDirectory.isValid(), "valid calibration directory was not created");
    const auto validCalibrationPath = validCalibrationDirectory.filePath("sha256.json");
    writeJson(validCalibrationPath, validCalibration);
    const auto shaCalibrationBytes = validCalibration.toJson(QJsonDocument::Indented);
    const auto aesCalibration = syntheticCalibration(QStringLiteral("aes256-gcm-encrypt"), 3'000'000);
    const auto aesCalibrationBytes = aesCalibration.toJson(QJsonDocument::Indented);
    cryptobench::tests::validateM19_3CalibrationArtifact(
        validCalibrationPath, QStringLiteral("sha256"), QStringLiteral("worker-hash"),
        QStringLiteral("git-head"), QStringLiteral("Release"));
    auto calibrationObject = validCalibration.object();
    auto observations = calibrationObject.value("observations").toArray();
    auto observation = observations[0].toObject();
    auto timing = observation.value("measurementWindows").toObject();
    timing.insert("workerElapsedNanoseconds", QStringLiteral("899999999"));
    observation.insert("measurementWindows", timing);
    observations[0] = observation;
    calibrationObject.insert("observations", observations);
    expectCalibrationRejected(QJsonDocument(calibrationObject), QStringLiteral("sha256"));
    observation = validCalibration.object().value("observations").toArray()[0].toObject();
    observation.insert("workload", QStringLiteral("aes256-gcm-encrypt"));
    observations[0] = observation;
    calibrationObject = validCalibration.object();
    calibrationObject.insert("observations", observations);
    expectCalibrationRejected(QJsonDocument(calibrationObject), QStringLiteral("sha256"));
    observation = validCalibration.object().value("observations").toArray()[0].toObject();
    observation.insert("calibrationCandidateIterations", QStringLiteral("999"));
    observations[0] = observation;
    calibrationObject = validCalibration.object();
    calibrationObject.insert("observations", observations);
    expectCalibrationRejected(QJsonDocument(calibrationObject), QStringLiteral("sha256"));
    observation = validCalibration.object().value("observations").toArray()[0].toObject();
    auto provenance = observation.value("provenance").toObject();
    provenance.insert("gitHead", QStringLiteral("tampered"));
    observation.insert("provenance", provenance);
    observations[0] = observation;
    calibrationObject = validCalibration.object();
    calibrationObject.insert("observations", observations);
    expectCalibrationRejected(QJsonDocument(calibrationObject), QStringLiteral("sha256"));
    require(cryptobench::tests::m19_3ConfirmatoryInternalInterval(0) == 5 &&
                cryptobench::tests::m19_3ConfirmatoryInternalInterval(5) == 5 &&
                cryptobench::tests::m19_3ConfirmatoryInternalInterval(2) == 2 &&
                cryptobench::tests::m19_3ConfirmatoryInternalInterval(1) == 1,
            "confirmatory OFF internal interval mapping is invalid");
    const auto first = cryptobench::tests::prepareM19_3ConfirmatoryPlan(
        42, 10, 10'000'000, 3'000'000,
        hashBytes(shaCalibrationBytes), hashBytes(aesCalibrationBytes), validCalibration, aesCalibration,
        shaCalibrationBytes, aesCalibrationBytes, QStringLiteral("C:/worker.exe"), QStringLiteral("worker-hash"),
        QStringLiteral("git-head"), QStringLiteral("Release"));
    const auto repeated = cryptobench::tests::prepareM19_3ConfirmatoryPlan(
        42, 10, 10'000'000, 3'000'000,
        hashBytes(shaCalibrationBytes), hashBytes(aesCalibrationBytes), validCalibration, aesCalibration,
        shaCalibrationBytes, aesCalibrationBytes, QStringLiteral("C:/worker.exe"), QStringLiteral("worker-hash"),
        QStringLiteral("git-head"), QStringLiteral("Release"));
    require(first == repeated, "confirmatory plan ordering is not deterministic");
    cryptobench::tests::validateM19_3ConfirmatoryPlan(first);
    require(first.object().value("trialCount").toInt() == 80,
            "confirmatory plan trial count is not 80");
    auto embeddedTamper = first.object();
    auto embeddedCalibration = embeddedTamper.value("sha256CalibrationArtifact").toObject();
    embeddedCalibration.insert("status", QStringLiteral("tampered"));
    embeddedTamper.insert("sha256CalibrationArtifact", embeddedCalibration);
    expectRejected(QJsonDocument(embeddedTamper));

    auto alteredObject = first.object();
    alteredObject.insert("workerExecutableSha256", QString{});
    expectRejected(QJsonDocument(alteredObject));
    alteredObject = first.object();
    alteredObject.insert("gitDirty", true);
    expectRejected(QJsonDocument(alteredObject));
    auto trials = first.object().value("trials").toArray();
    trials.removeLast();
    alteredObject = first.object();
    alteredObject.insert("trials", trials);
    expectRejected(QJsonDocument(alteredObject));
    alteredObject = first.object();
    auto duplicate = alteredObject.value("trials").toArray();
    duplicate[1] = duplicate[0];
    alteredObject.insert("trials", duplicate);
    expectRejected(QJsonDocument(alteredObject));
    alteredObject = first.object();
    auto reordered = alteredObject.value("trials").toArray();
    const auto firstBlock = reordered[0];
    reordered[0] = reordered[1];
    reordered[1] = firstBlock;
    alteredObject.insert("trials", reordered);
    expectRejected(QJsonDocument(alteredObject));
    cryptobench::tests::validateM19_3ConfirmatoryProvenance(
        first, QStringLiteral("C:/worker.exe"), QStringLiteral("worker-hash"),
        QStringLiteral("git-head"), QStringLiteral("Release"));
    bool provenanceRejected = false;
    try {
        cryptobench::tests::validateM19_3ConfirmatoryProvenance(
            first, QStringLiteral("C:/worker.exe"), QStringLiteral("tampered-hash"),
            QStringLiteral("git-head"), QStringLiteral("Release"));
    } catch (const std::exception&) {
        provenanceRejected = true;
    }
    require(provenanceRejected, "confirmatory provenance mismatch was accepted");
    QTemporaryDir calibrationDirectory;
    require(calibrationDirectory.isValid(), "calibration test directory was not created");
    const auto invalidCalibration = calibrationDirectory.filePath("invalid.json");
    writeJson(invalidCalibration, QJsonDocument(QJsonObject{{"status", "success"}}));
    bool calibrationRejected = false;
    try {
        cryptobench::tests::validateM19_3CalibrationArtifact(
            invalidCalibration, QStringLiteral("sha256"), QStringLiteral("worker-hash"),
            QStringLiteral("git-head"), QStringLiteral("Release"));
    } catch (const std::exception&) {
        calibrationRejected = true;
    }
    require(calibrationRejected, "invalid confirmatory calibration was accepted");
}

void testEvidenceMarkerAndPartialFailure()
{
    const auto shaCalibration = syntheticCalibration(QStringLiteral("sha256"), 10'000);
    const auto aesCalibration = syntheticCalibration(QStringLiteral("aes256-gcm-encrypt"), 10'000);
    const auto shaBytes = shaCalibration.toJson(QJsonDocument::Indented);
    const auto aesBytes = aesCalibration.toJson(QJsonDocument::Indented);
    const auto plan = cryptobench::tests::prepareM19_3ConfirmatoryPlan(
        99, 10, 10'000, 10'000,
        hashBytes(shaBytes), hashBytes(aesBytes), shaCalibration, aesCalibration,
        shaBytes, aesBytes,
        QStringLiteral("C:/worker.exe"), QStringLiteral("worker-hash"),
        QStringLiteral("git-head"), QStringLiteral("Release"));
    QTemporaryDir directory;
    require(directory.isValid(), "confirmatory temporary directory was not created");
    const auto root = QDir(directory.path());
    writeJson(root.filePath("plan.json"), plan);
    writeJson(root.filePath("manifest.json"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-3-confirmatory-sampling-overhead-manifest"},
        {"schemaVersion", 1}, {"plan", plan.object()},
        {"planSha256", hashFile(root.filePath("plan.json"))}}));
    bool partialRejected = false;
    try {
        cryptobench::tests::validateM19_3ConfirmatoryOutput(directory.path());
    } catch (const std::exception&) {
        partialRejected = true;
    }
    require(partialRejected, "partial confirmatory evidence was accepted");
}

void createSyntheticCompleteEvidence(const QString& directory, const QJsonDocument& plan)
{
    const auto root = QDir(directory);
    require(root.mkpath("."), "synthetic confirmatory output directory was not created");
    writeJson(root.filePath("plan.json"), plan);
    writeJson(root.filePath("manifest.json"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-3-confirmatory-sampling-overhead-manifest"},
        {"schemaVersion", 1}, {"plan", plan.object()},
        {"planSha256", hashFile(root.filePath("plan.json"))},
        {"workerExecutablePath", plan.object().value("workerExecutablePath")},
        {"workerExecutableSha256", plan.object().value("workerExecutableSha256")},
        {"gitHead", plan.object().value("gitHead")}, {"gitDirty", false}, {"buildType", "Release"},
        {"sha256CalibrationSha256", plan.object().value("sha256CalibrationSha256")},
        {"aes256GcmCalibrationSha256", plan.object().value("aes256GcmCalibrationSha256")}}));
    QJsonArray records;
    for (const auto& value : plan.object().value("trials").toArray()) {
        const auto trial = value.toObject();
        const auto order = trial.value("executionOrder").toInt();
        const auto workload = trial.value("workload") == "sha256"
            ? tests::SamplingOverheadWorkload::Sha256 : tests::SamplingOverheadWorkload::Aes256GcmEncrypt;
        tests::SamplingOverheadRun run;
        run.mode = trial.value("intervalMilliseconds").toInt() == 0
            ? tests::SamplingOverheadMode::BoundaryOnlyControl : tests::SamplingOverheadMode::Periodic;
        run.intervalMilliseconds = trial.value("intervalMilliseconds").toInt() == 0
            ? 5U : static_cast<std::uint32_t>(trial.value("intervalMilliseconds").toInt());
        run.workload = workload;
        run.executionOrder = static_cast<std::uint32_t>(order);
        run.logicalRunIndex = 0;
        run.workerPid = 10'000U + static_cast<std::uint32_t>(order);
        run.workerCreationTime100ns = 20'000U + static_cast<std::uint64_t>(order);
        run.workerMeasurementObserved = true;
        run.memoryObserved = true;
        run.normalExit = true;
        run.status = QStringLiteral("completed");
        run.workerMeasurement = {0, static_cast<std::uint64_t>(1'000'000'000), 100'000};
        run.parentSessionWallNanoseconds = 1'100'000'000;
        run.parentSessionCpuNanoseconds = 0;
        run.workerExecutablePath = plan.object().value("workerExecutablePath").toString();
        run.workerExecutableSha256 = plan.object().value("workerExecutableSha256").toString();
        run.gitHead = plan.object().value("gitHead").toString();
        run.buildType = QStringLiteral("Release");
        run.operatingSystem = QStringLiteral("synthetic");
        run.architecture = QStringLiteral("synthetic");
        run.algorithmProfile = workload == tests::SamplingOverheadWorkload::Sha256
            ? QStringLiteral("sha256") : QStringLiteral("aes256-gcm");
        run.operation = workload == tests::SamplingOverheadWorkload::Sha256
            ? QStringLiteral("hash") : QStringLiteral("encrypt");
        run.inputBytes = workload == tests::SamplingOverheadWorkload::Sha256 ? 8 : 16;
        run.iterationsPerRun = trial.value("iterationsPerRun").toString().toULongLong();
        run.runs = 1;
        run.memory = trial.value("intervalMilliseconds").toInt() == 0
            ? core::MemoryV2RawObservations{1, 2, std::nullopt, std::nullopt, 3, 0, 0}
            : core::MemoryV2RawObservations{1, 2, std::nullopt, 3, 3, 0, 1};
        const auto path = root.filePath(QStringLiteral("trial-%1.json").arg(order, 3, 10, QLatin1Char('0')));
        const auto record = QJsonDocument(QJsonObject{
            {"format", "cryptobenchmark-m19-3-confirmatory-sampling-overhead-trial"},
            {"schemaVersion", 1}, {"executionOrder", order}, {"workload", trial.value("workload")},
            {"samplingMode", trial.value("samplingMode")},
            {"intervalMilliseconds", trial.value("intervalMilliseconds")},
            {"repetition", trial.value("repetition")}, {"blockIndex", trial.value("blockIndex")},
            {"blockPosition", trial.value("blockPosition")},
            {"internalMeasurementSettingsIntervalMilliseconds", static_cast<qint64>(run.intervalMilliseconds)},
            {"iterationsPerRun", trial.value("iterationsPerRun")}, {"status", "completed"},
            {"error", ""}, {"result", tests::samplingOverheadRunArtifact(run).object()}});
        writeJson(path, record);
        records.append(QJsonObject{
            {"executionOrder", order}, {"workload", trial.value("workload")},
            {"samplingMode", trial.value("samplingMode")},
            {"intervalMilliseconds", trial.value("intervalMilliseconds")},
            {"repetition", trial.value("repetition")}, {"blockIndex", trial.value("blockIndex")},
            {"blockPosition", trial.value("blockPosition")},
            {"internalMeasurementSettingsIntervalMilliseconds", static_cast<qint64>(run.intervalMilliseconds)},
            {"iterationsPerRun", trial.value("iterationsPerRun")},
            {"file", QFileInfo(path).fileName()}, {"sha256", hashFile(path)}});
    }
    writeJson(root.filePath("summary.json"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-3-confirmatory-sampling-overhead-summary"},
        {"schemaVersion", 1}, {"complete", true}, {"plannedCount", records.size()},
        {"completedCount", records.size()}, {"records", records}}));
    writeJson(root.filePath("success.marker"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-3-confirmatory-sampling-overhead-success"},
        {"schemaVersion", 1}, {"complete", true},
        {"manifestSha256", hashFile(root.filePath("manifest.json"))},
        {"summarySha256", hashFile(root.filePath("summary.json"))}}));
}

void refreshRecordAndMarkerHashes(const QString& directory, int order)
{
    const auto root = QDir(directory);
    auto summary = QJsonDocument::fromJson([&] {
        QFile file(root.filePath("summary.json"));
        require(file.open(QIODevice::ReadOnly), "synthetic summary could not be read");
        return file.readAll();
    }()).object();
    auto records = summary.value("records").toArray();
    for (int index = 0; index < records.size(); ++index) {
        auto entry = records[index].toObject();
        if (entry.value("executionOrder").toInt() == order) {
            entry.insert("sha256", hashFile(root.filePath(entry.value("file").toString())));
            records[index] = entry;
        }
    }
    summary.insert("records", records);
    writeJson(root.filePath("summary.json"), QJsonDocument(summary));
    auto marker = QJsonDocument::fromJson([&] {
        QFile file(root.filePath("success.marker"));
        require(file.open(QIODevice::ReadOnly), "synthetic marker could not be read");
        return file.readAll();
    }()).object();
    marker.insert("summarySha256", hashFile(root.filePath("summary.json")));
    writeJson(root.filePath("success.marker"), QJsonDocument(marker));
}

int findTrialOrder(const QString& directory, bool off)
{
    QFile file(QDir(directory).filePath("summary.json"));
    require(file.open(QIODevice::ReadOnly), "synthetic summary lookup failed");
    const auto summary = QJsonDocument::fromJson(file.readAll()).object();
    for (const auto& value : summary.value("records").toArray()) {
        const auto record = value.toObject();
        if ((record.value("intervalMilliseconds").toInt() == 0) == off) {
            return record.value("executionOrder").toInt();
        }
    }
    throw std::runtime_error("synthetic trial order was not found");
}

void testCompleteEvidenceIntegrity()
{
    const auto shaCalibration = syntheticCalibration(QStringLiteral("sha256"), 10'000);
    const auto aesCalibration = syntheticCalibration(QStringLiteral("aes256-gcm-encrypt"), 10'000);
    const auto shaBytes = shaCalibration.toJson(QJsonDocument::Indented);
    const auto aesBytes = aesCalibration.toJson(QJsonDocument::Indented);
    const auto plan = tests::prepareM19_3ConfirmatoryPlan(
        42, 12, 10'000, 10'000, hashBytes(shaBytes), hashBytes(aesBytes),
        shaCalibration, aesCalibration, shaBytes, aesBytes,
        QStringLiteral("C:/worker.exe"),
        QStringLiteral("worker-hash"), QStringLiteral("git-head"),
        QStringLiteral("Release"));
    QTemporaryDir root;
    require(root.isValid(), "complete synthetic root was not created");
    const auto complete = QDir(root.filePath("complete"));
    createSyntheticCompleteEvidence(complete.path(), plan);
    tests::validateM19_3ConfirmatoryOutput(complete.path());

    auto expectRejected = [](const QString& path, const char* label) {
        try {
            tests::validateM19_3ConfirmatoryOutput(path);
        } catch (const std::exception&) {
            return;
        }
        throw std::runtime_error(std::string("tampered confirmatory evidence was accepted: ") + label);
    };
    QFile::remove(complete.filePath("success.marker"));
    expectRejected(complete.path(), "missing-marker");
    createSyntheticCompleteEvidence(root.filePath("tampered-summary"), plan);
    const auto tamperedSummary = QDir(root.filePath("tampered-summary"));
    auto summary = QJsonDocument(QJsonObject{{"tampered", true}});
    writeJson(tamperedSummary.filePath("summary.json"), summary);
    auto marker = QJsonDocument::fromJson([&] {
        QFile file(tamperedSummary.filePath("success.marker"));
        require(file.open(QIODevice::ReadOnly), "tampered summary marker could not be read");
        return file.readAll();
    }()).object();
    marker.insert("summarySha256", hashFile(tamperedSummary.filePath("summary.json")));
    writeJson(tamperedSummary.filePath("success.marker"), QJsonDocument(marker));
    expectRejected(tamperedSummary.path(), "summary");
    createSyntheticCompleteEvidence(root.filePath("tampered-plan"), plan);
    const auto tamperedPlan = QDir(root.filePath("tampered-plan"));
    auto planObject = plan.object();
    planObject.insert("seed", QStringLiteral("43"));
    writeJson(tamperedPlan.filePath("plan.json"), QJsonDocument(planObject));
    auto manifest = QJsonDocument::fromJson([&] {
        QFile file(tamperedPlan.filePath("manifest.json"));
        require(file.open(QIODevice::ReadOnly), "tampered plan manifest could not be read");
        return file.readAll();
    }()).object();
    manifest.insert("plan", planObject);
    manifest.insert("planSha256", hashFile(tamperedPlan.filePath("plan.json")));
    writeJson(tamperedPlan.filePath("manifest.json"), QJsonDocument(manifest));
    marker = QJsonDocument::fromJson([&] {
        QFile file(tamperedPlan.filePath("success.marker"));
        require(file.open(QIODevice::ReadOnly), "tampered plan marker could not be read");
        return file.readAll();
    }()).object();
    marker.insert("manifestSha256", hashFile(tamperedPlan.filePath("manifest.json")));
    writeJson(tamperedPlan.filePath("success.marker"), QJsonDocument(marker));
    expectRejected(tamperedPlan.path(), "plan");
    createSyntheticCompleteEvidence(root.filePath("tampered-record"), plan);
    const auto tamperedRecord = QDir(root.filePath("tampered-record"));
    writeJson(tamperedRecord.filePath("trial-000.json"), QJsonDocument(QJsonObject{{"tampered", true}}));
    expectRejected(tamperedRecord.path(), "record");
    createSyntheticCompleteEvidence(root.filePath("tampered-wrapper"), plan);
    const auto tamperedWrapper = QDir(root.filePath("tampered-wrapper"));
    const auto wrapperPath = tamperedWrapper.filePath("trial-000.json");
    QFile wrapperFile(wrapperPath);
    require(wrapperFile.open(QIODevice::ReadOnly), "tampered wrapper could not be read");
    auto wrapper = QJsonDocument::fromJson(wrapperFile.readAll()).object();
    wrapper.insert("blockPosition", 99);
    writeJson(wrapperPath, QJsonDocument(wrapper));
    refreshRecordAndMarkerHashes(tamperedWrapper.path(), 0);
    expectRejected(tamperedWrapper.path(), "wrapper");
    createSyntheticCompleteEvidence(root.filePath("reused-identity"), plan);
    const auto reused = QDir(root.filePath("reused-identity"));
    auto recordPath = reused.filePath("trial-001.json");
    QFile recordFile(recordPath);
    require(recordFile.open(QIODevice::ReadOnly), "reused identity record could not be read");
    auto record = QJsonDocument::fromJson(recordFile.readAll()).object();
    auto result = record.value("result").toObject();
    result.insert("workerPid", QStringLiteral("10000"));
    result.insert("workerCreationTime100ns", QStringLiteral("20000"));
    record.insert("result", result);
    writeJson(recordPath, QJsonDocument(record));
    refreshRecordAndMarkerHashes(reused.path(), 1);
    expectRejected(reused.path(), "reused-identity");

    createSyntheticCompleteEvidence(root.filePath("semantic"), plan);
    const auto semantic = QDir(root.filePath("semantic"));
    const auto offOrder = findTrialOrder(semantic.path(), true);
    auto offFile = QFile(semantic.filePath(QStringLiteral("trial-%1.json").arg(offOrder, 3, 10, QLatin1Char('0'))));
    require(offFile.open(QIODevice::ReadOnly), "OFF semantic record could not be read");
    auto offRecord = QJsonDocument::fromJson(offFile.readAll()).object();
    offRecord.insert("internalMeasurementSettingsIntervalMilliseconds", 2);
    writeJson(offFile.fileName(), QJsonDocument(offRecord));
    refreshRecordAndMarkerHashes(semantic.path(), offOrder);
    expectRejected(semantic.path(), "off-placeholder");

    createSyntheticCompleteEvidence(root.filePath("semantic-samples"), plan);
    const auto sampleSemantic = QDir(root.filePath("semantic-samples"));
    const auto periodicOrder = findTrialOrder(sampleSemantic.path(), false);
    const auto periodicPath = sampleSemantic.filePath(
        QStringLiteral("trial-%1.json").arg(periodicOrder, 3, 10, QLatin1Char('0')));
    QFile periodicFile(periodicPath);
    require(periodicFile.open(QIODevice::ReadOnly), "periodic semantic record could not be read");
    auto periodicRecord = QJsonDocument::fromJson(periodicFile.readAll()).object();
    auto periodicResult = periodicRecord.value("result").toObject();
    auto periodicMemory = periodicResult.value("memory").toObject();
    periodicMemory.insert("executionSampleCount", QStringLiteral("0"));
    periodicMemory.remove("executionPeakSampledPrivateUsageBytes");
    periodicResult.insert("memory", periodicMemory);
    periodicRecord.insert("result", periodicResult);
    writeJson(periodicPath, QJsonDocument(periodicRecord));
    refreshRecordAndMarkerHashes(sampleSemantic.path(), periodicOrder);
    expectRejected(sampleSemantic.path(), "sample-semantics");

    createSyntheticCompleteEvidence(root.filePath("nested-config"), plan);
    const auto nestedConfig = QDir(root.filePath("nested-config"));
    const auto nestedPath = nestedConfig.filePath("trial-000.json");
    QFile nestedFile(nestedPath);
    require(nestedFile.open(QIODevice::ReadOnly), "nested configuration record could not be read");
    auto nestedRecord = QJsonDocument::fromJson(nestedFile.readAll()).object();
    auto nestedResult = nestedRecord.value("result").toObject();
    auto configuration = nestedResult.value("configuration").toObject();
    configuration.insert("iterationsPerRun", QStringLiteral("999"));
    nestedResult.insert("configuration", configuration);
    nestedRecord.insert("result", nestedResult);
    writeJson(nestedPath, QJsonDocument(nestedRecord));
    refreshRecordAndMarkerHashes(nestedConfig.path(), 0);
    expectRejected(nestedConfig.path(), "nested-configuration");

    createSyntheticCompleteEvidence(root.filePath("normal-exit"), plan);
    const auto normalExit = QDir(root.filePath("normal-exit"));
    const auto normalPath = normalExit.filePath("trial-000.json");
    QFile normalFile(normalPath);
    require(normalFile.open(QIODevice::ReadOnly), "normal-exit record could not be read");
    auto normalRecord = QJsonDocument::fromJson(normalFile.readAll()).object();
    auto normalResult = normalRecord.value("result").toObject();
    normalResult.insert("normalExit", false);
    normalRecord.insert("result", normalResult);
    writeJson(normalPath, QJsonDocument(normalRecord));
    refreshRecordAndMarkerHashes(normalExit.path(), 0);
    expectRejected(normalExit.path(), "normal-exit");

    createSyntheticCompleteEvidence(root.filePath("tampered-marker"), plan);
    const auto tamperedMarker = QDir(root.filePath("tampered-marker"));
    auto invalidMarker = QJsonDocument::fromJson([&] {
        QFile file(tamperedMarker.filePath("success.marker"));
        require(file.open(QIODevice::ReadOnly), "tampered marker could not be read");
        return file.readAll();
    }()).object();
    invalidMarker.insert("summarySha256", QStringLiteral("tampered"));
    writeJson(tamperedMarker.filePath("success.marker"), QJsonDocument(invalidMarker));
    expectRejected(tamperedMarker.path(), "marker");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        if (argc > 1) {
            const auto command = QString::fromLocal8Bit(argv[1]);
            if (command == QStringLiteral("--prepare-confirmatory")) {
                require(argc == 12, "usage: --prepare-confirmatory --seed S --repetitions R --sha256-calibration PATH --aes256-gcm-calibration PATH --output PATH");
                require(QString::fromLocal8Bit(argv[2]) == "--seed" &&
                            QString::fromLocal8Bit(argv[4]) == "--repetitions" &&
                            QString::fromLocal8Bit(argv[6]) == "--sha256-calibration" &&
                            QString::fromLocal8Bit(argv[8]) == "--aes256-gcm-calibration" &&
                            QString::fromLocal8Bit(argv[10]) == "--output",
                        "confirmatory prepare arguments are invalid");
                const auto executable = workerPath();
                bool headOk = false;
                const auto head = gitValue({"rev-parse", "HEAD"}, headOk);
                bool statusOk = false;
                const auto dirty = gitValue({"status", "--porcelain"}, statusOk);
                require(headOk && statusOk && dirty.isEmpty() &&
                            QString::fromStdString(std::string(cryptobench::application::build_info::buildType)) == "Release",
                        "confirmatory plan preparation requires clean Release provenance");
                const auto shaCalibrationPath = QString::fromLocal8Bit(argv[7]);
                const auto aesCalibrationPath = QString::fromLocal8Bit(argv[9]);
                cryptobench::tests::validateM19_3CalibrationArtifact(
                    shaCalibrationPath, QStringLiteral("sha256"), sha256File(executable),
                    head, QStringLiteral("Release"));
                cryptobench::tests::validateM19_3CalibrationArtifact(
                    aesCalibrationPath, QStringLiteral("aes256-gcm-encrypt"), sha256File(executable),
                    head, QStringLiteral("Release"));
                const auto shaCalibration = [&] {
                    QFile file(shaCalibrationPath);
                    require(file.open(QIODevice::ReadOnly), "SHA calibration could not be read");
                    return QJsonDocument::fromJson(file.readAll()).object();
                }();
                const auto aesCalibration = [&] {
                    QFile file(aesCalibrationPath);
                    require(file.open(QIODevice::ReadOnly), "AES calibration could not be read");
                    return QJsonDocument::fromJson(file.readAll()).object();
                }();
                const auto document = cryptobench::tests::prepareM19_3ConfirmatoryPlan(
                    argumentU64(QString::fromLocal8Bit(argv[3]), "seed"),
                    static_cast<std::uint32_t>(argumentU64(QString::fromLocal8Bit(argv[5]), "repetitions")),
                    argumentU64(shaCalibration.value("selectedIterationsPerRun").toString(), "sha256 selected N"),
                    argumentU64(aesCalibration.value("selectedIterationsPerRun").toString(), "AES selected N"),
                    sha256File(shaCalibrationPath), sha256File(aesCalibrationPath),
                    QJsonDocument(shaCalibration), QJsonDocument(aesCalibration),
                    [&] { QFile file(shaCalibrationPath); require(file.open(QIODevice::ReadOnly), "SHA source could not be read"); return file.readAll(); }(),
                    [&] { QFile file(aesCalibrationPath); require(file.open(QIODevice::ReadOnly), "AES source could not be read"); return file.readAll(); }(),
                    executable, sha256File(executable), head, QStringLiteral("Release"));
                cryptobench::tests::validateM19_3ConfirmatoryPlan(document);
                writePlan(QString::fromLocal8Bit(argv[11]), document);
                return 0;
            }
            if (command == QStringLiteral("--execute-confirmatory")) {
                require(argc == 6 && QString::fromLocal8Bit(argv[2]) == "--plan" &&
                            QString::fromLocal8Bit(argv[4]) == "--output-dir",
                        "usage: --execute-confirmatory --plan PATH --output-dir DIR");
                return cryptobench::tests::executeM19_3Confirmatory(
                    QString::fromLocal8Bit(argv[3]), QString::fromLocal8Bit(argv[5]));
            }
            throw std::runtime_error("unknown confirmatory command");
        }
        testFrozenPlan();
        testEvidenceMarkerAndPartialFailure();
        testCompleteEvidenceIntegrity();
        std::cout << "PASS M19.3 confirmatory plan and fail-closed synthetic tests; real campaign not executed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL M19.3 confirmatory tests: " << error.what() << '\n';
        return 1;
    }
}
