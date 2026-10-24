#include "M19_4RealWorkerQualification.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QTemporaryDir>

#include <iostream>
#include <stdexcept>

namespace {

void expectRejected(const QJsonDocument& document, const char* label)
{
    try {
        cryptobench::tests::validateM19_4QualificationMatrix(document);
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(std::string(label) + " was accepted");
}

void writeText(const QString& path, const QByteArray& content)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(content) != content.size()) {
        throw std::runtime_error("synthetic evidence write failed");
    }
}

void verifyMissingSuccessMarkerIsRejected()
{
    QTemporaryDir directory;
    if (directory.isValid() == false) throw std::runtime_error("temporary directory failed");
    const auto matrix = cryptobench::tests::m19_4QualificationMatrix();
    const auto root = QDir(directory.path());
    writeText(root.filePath("manifest.json"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-4-real-worker-manifest"}, {"gitHead", "synthetic"},
        {"gitDirty", false}, {"workerExecutableSha256", "synthetic"}, {"buildType", "Release"},
        {"matrix", matrix.object()}}).toJson());
    QJsonArray artifacts;
    for (const auto& category : matrix.object().value("entries").toArray()) {
        const auto name = category.toObject().value("category").toString() + QStringLiteral(".json");
        QJsonArray runs;
        for (int index = 0; index < 2; ++index) {
            runs.append(QJsonObject{{"workerPid", QString::number(100 + artifacts.size() * 2 + index)},
                {"workerCreationTime100ns", QString::number(200 + artifacts.size() * 2 + index)}});
        }
        const auto path = root.filePath(name);
        writeText(path, QJsonDocument(QJsonObject{{"status", "completed"}, {"result", runs}}).toJson());
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) throw std::runtime_error("synthetic evidence read failed");
        artifacts.append(QJsonObject{{"file", name}, {"sha256", QString::fromLatin1(
            QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256).toHex())}});
    }
    writeText(root.filePath("summary.json"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-4-real-worker-summary"}, {"complete", true},
        {"completedCategories", 4}, {"workerExecutions", 8}, {"categoryArtifacts", artifacts}}).toJson());
    bool missingMarkerRejected = false;
    try {
        cryptobench::tests::validateM19_4CampaignEvidence(directory.path());
    } catch (const std::exception&) {
        missingMarkerRejected = true;
    }
    if (!missingMarkerRejected) {
        throw std::runtime_error("complete-looking evidence without success marker was accepted");
    }
    const auto hashFile = [](const QString& path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) throw std::runtime_error("synthetic hash read failed");
        return QString::fromLatin1(QCryptographicHash::hash(
            file.readAll(), QCryptographicHash::Sha256).toHex());
    };
    writeText(root.filePath("success.marker"), QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-m19-4-real-worker-success"}, {"complete", true},
        {"manifestSha256", hashFile(root.filePath("manifest.json"))},
        {"summarySha256", hashFile(root.filePath("summary.json"))}}).toJson());
    cryptobench::tests::validateM19_4CampaignEvidence(directory.path());
    const auto firstArtifact = root.filePath(
        matrix.object().value("entries").toArray().first().toObject().value("category").toString() +
        QStringLiteral(".json"));
    QFile originalArtifact(firstArtifact);
    if (!originalArtifact.open(QIODevice::ReadOnly)) throw std::runtime_error("synthetic artifact read failed");
    const auto originalArtifactBytes = originalArtifact.readAll();
    writeText(firstArtifact, QByteArray("tampered artifact"));
    bool artifactTamperRejected = false;
    try {
        cryptobench::tests::validateM19_4CampaignEvidence(directory.path());
    } catch (const std::exception&) {
        artifactTamperRejected = true;
        writeText(firstArtifact, originalArtifactBytes);
        cryptobench::tests::validateM19_4CampaignEvidence(directory.path());
    }
    if (!artifactTamperRejected) throw std::runtime_error("tampered category artifact was accepted");
    writeText(root.filePath("summary.json"), QByteArray("tampered"));
    try {
        cryptobench::tests::validateM19_4CampaignEvidence(directory.path());
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("tampered evidence with stale success marker was accepted");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        if (argc > 1) {
            if (argc != 4 || QString::fromLocal8Bit(argv[1]) != QStringLiteral("--execute-m19-4") ||
                QString::fromLocal8Bit(argv[2]) != QStringLiteral("--output-dir")) {
                throw std::runtime_error(
                    "usage: --execute-m19-4 --output-dir <new-output-directory>");
            }
            return cryptobench::tests::executeM19_4Qualification(
                QString::fromLocal8Bit(argv[3]));
        }
        const auto productionWorker = cryptobench::tests::m19_4ProductionWorkerPath();
        const auto expectedWorker = QFileInfo(QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"))).absoluteFilePath();
        if (productionWorker != expectedWorker || !QFileInfo::exists(productionWorker) ||
            productionWorker == QFileInfo(QDir(QCoreApplication::applicationDirPath())
                .filePath(QStringLiteral("CryptoBenchmarkWorker.exe"))).absoluteFilePath()) {
            throw std::runtime_error("M19.4 resolved the wrong production worker executable");
        }
        const auto matrix = cryptobench::tests::m19_4QualificationMatrix();
        cryptobench::tests::validateM19_4QualificationMatrix(matrix);
        auto malformed = matrix;
        auto malformedObject = malformed.object();
        malformedObject.insert("format", QStringLiteral("wrong-format"));
        malformed = QJsonDocument(malformedObject);
        expectRejected(malformed, "malformed matrix");
        auto duplicate = matrix;
        auto duplicateObject = duplicate.object();
        auto duplicateEntries = duplicateObject.value("entries").toArray();
        duplicateEntries[1] = duplicateEntries[0];
        duplicateObject.insert("entries", duplicateEntries);
        duplicate = QJsonDocument(duplicateObject);
        expectRejected(duplicate, "duplicate matrix");
        auto missing = matrix;
        auto missingObject = missing.object();
        auto missingEntries = missingObject.value("entries").toArray();
        missingEntries.removeLast();
        missingObject.insert("entries", missingEntries);
        missing = QJsonDocument(missingObject);
        expectRejected(missing, "missing matrix");
        auto altered = matrix;
        auto alteredObject = altered.object();
        auto alteredEntries = alteredObject.value("entries").toArray();
        auto alteredEntry = alteredEntries[0].toObject();
        alteredEntry.insert("runs", 3);
        alteredEntries[0] = alteredEntry;
        alteredObject.insert("entries", alteredEntries);
        altered = QJsonDocument(alteredObject);
        expectRejected(altered, "altered matrix");
        verifyMissingSuccessMarkerIsRejected();
        std::cout << "PASS M19.4 matrix and deterministic self-test; real campaign not executed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL M19.4 qualification self-test: " << error.what() << '\n';
        return 1;
    }
}
