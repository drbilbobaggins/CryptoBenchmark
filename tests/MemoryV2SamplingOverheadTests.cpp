#include "MemoryV2SamplingOverhead.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonObject>
#include <QSet>
#include <QTemporaryDir>
#include <QUuid>

#include <iostream>
#include <functional>
#include <stdexcept>
#include <map>
#include <utility>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

std::vector<tests::SamplingOverheadRun> testTimingAndArtifactModes()
{
    const auto off = tests::runRealSamplingOverheadSmoke(
        tests::SamplingOverheadMode::BoundaryOnlyControl, 5, 10'000, 0);
    if (off.status != QStringLiteral("completed")) {
        throw std::runtime_error(
            "OFF smoke did not complete: status=" + off.status.toStdString() +
            " error=" + off.error.toStdString());
    }
    require(off.memory.preparationSampleCount == 0 && off.memory.executionSampleCount == 0 &&
                !off.memory.preparationPeakSampledPrivateUsageBytes.has_value() &&
                !off.memory.executionPeakSampledPrivateUsageBytes.has_value(),
            "OFF reference produced periodic samples");
    require(off.parentSessionWallNanoseconds.has_value() && *off.parentSessionWallNanoseconds > 0,
            "parent session wall timing was not observed");
    require(off.parentSessionCpuNanoseconds.has_value() &&
                *off.parentSessionCpuNanoseconds % 100U == 0,
            "parent CPU timing has invalid FILETIME units");
    require(off.workerMeasurementObserved && off.workerMeasurement.processCpuNanoseconds % 100U == 0,
            "worker canonical CPU timing has invalid FILETIME units");

    std::vector<tests::SamplingOverheadRun> runs;
    runs.push_back(off);
    for (const auto [interval, executionOrder] :
         {std::pair{5U, 1U}, std::pair{2U, 2U}, std::pair{1U, 3U}}) {
        const auto periodic = tests::runRealSamplingOverheadSmoke(
            tests::SamplingOverheadMode::Periodic, interval, 10'000, executionOrder);
        require(periodic.status == QStringLiteral("completed"), "periodic smoke did not complete");
        require(periodic.memoryObserved && periodic.memory.baselinePrivateUsageBytes > 0 &&
                    periodic.memory.readyPrivateUsageBytes > 0 && periodic.memory.finalPrivateUsageBytes > 0,
                "periodic real-worker run missed a boundary observation");
        require(periodic.parentSessionWallNanoseconds.has_value() &&
                    periodic.parentSessionCpuNanoseconds.has_value() &&
                    *periodic.parentSessionCpuNanoseconds % 100U == 0,
                "periodic parent timing has invalid units");
        require(periodic.logicalRunIndex == 0 && periodic.executionOrder == executionOrder,
            "periodic execution order was not distinct from logical run index");
        const auto artifact = tests::samplingOverheadRunArtifact(periodic);
        const auto destination = QDir(QCoreApplication::applicationDirPath()).filePath(
            QStringLiteral("m19.3-stage-a-%1-%2.json")
                .arg(interval).arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
        tests::writeSamplingOverheadArtifact(destination, artifact);
        const auto roundTrip = tests::readSamplingOverheadArtifact(destination);
        require(roundTrip == artifact, "persisted artifact did not round-trip exactly");
        bool overwriteRejected = false;
        try {
            tests::writeSamplingOverheadArtifact(destination, artifact);
        } catch (const std::runtime_error&) {
            overwriteRejected = true;
        }
        require(overwriteRejected, "artifact overwrite was not rejected");
        require(QFile::remove(destination), "persisted Stage A artifact could not be removed");
        runs.push_back(periodic);
    }
    require(runs.size() == 4 && runs[0].executionOrder == 0 && runs[1].executionOrder == 1 &&
                runs[2].executionOrder == 2 && runs[3].executionOrder == 3,
            "Stage A execution order was not unique and stable");
    const auto batch = tests::samplingOverheadBatchArtifact(runs);
    tests::validateSamplingOverheadBatchArtifact(batch);
    return runs;
}

void testArtifactFailureAndMalformedInputs()
{
    tests::SamplingOverheadRun failed;
    failed.status = QStringLiteral("failed");
    failed.error = QStringLiteral("worker startup failed");
    const auto failedArtifact = tests::samplingOverheadRunArtifact(failed);
    tests::validateSamplingOverheadRunArtifact(failedArtifact);
    const auto failedWindows = failedArtifact.object().value("measurementWindows").toObject();
    require(failedWindows.value("parentSessionWallNanoseconds").isNull() &&
                failedWindows.value("workerElapsedNanoseconds").isNull(),
            "failed artifact manufactured unavailable timing values");

    tests::SamplingOverheadRun incomplete;
    incomplete.status = QStringLiteral("incomplete");
    incomplete.error = QStringLiteral("session timed out");
    tests::validateSamplingOverheadRunArtifact(tests::samplingOverheadRunArtifact(incomplete));

    bool malformedRejected = false;
    const auto malformedPath = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("m19.3-stage-a-malformed-%1.json")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    QFile malformedFile(malformedPath);
    require(malformedFile.open(QIODevice::WriteOnly), "could not create malformed artifact");
    require(malformedFile.write("{not-json") == 9, "could not write malformed artifact");
    malformedFile.close();
    try {
        static_cast<void>(tests::readSamplingOverheadArtifact(malformedPath));
    } catch (const std::runtime_error&) {
        malformedRejected = true;
    }
    require(QFile::remove(malformedPath), "malformed artifact could not be removed");
    require(malformedRejected, "malformed artifact was accepted");
}

void testInvalidIntervals()
{
    bool rejected = false;
    try {
        static_cast<void>(tests::runRealSamplingOverheadSmoke(
            tests::SamplingOverheadMode::Periodic, 3, 1));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "unsupported Stage A interval was accepted");
}

void testB1WorkloadsAndPlanning()
{
    const auto workloads = tests::supportedSamplingOverheadWorkloads();
    require(workloads.size() == 2 && workloads[0].stableId == QStringLiteral("sha256") &&
                workloads[0].algorithmProfile == QStringLiteral("sha256") &&
                workloads[0].operation == QStringLiteral("hash") && workloads[0].inputBytes == 8 &&
                workloads[1].stableId == QStringLiteral("aes256-gcm-encrypt") &&
                workloads[1].algorithmProfile == QStringLiteral("aes256-gcm") &&
                workloads[1].operation == QStringLiteral("encrypt") && workloads[1].inputBytes == 16,
            "supported B1 workload identity is not canonical");
    const auto aes = tests::runRealSamplingOverheadSmoke(
        tests::SamplingOverheadMode::BoundaryOnlyControl, 5, 100, 20,
        tests::SamplingOverheadWorkload::Aes256GcmEncrypt);
    require(aes.status == QStringLiteral("completed") && aes.workerMeasurementObserved &&
                aes.algorithmProfile == QStringLiteral("aes256-gcm") &&
                aes.operation == QStringLiteral("encrypt"),
            "canonical AES-256-GCM workload did not complete");

    require(tests::eventDrivenTerminalBeforeExecSelfTest(),
            "synchronous terminal-before-event-loop regression failed");
        require(tests::calibrationSelectionSelfTest(),
            "calibration selection did not stop at the first suitable candidate");
            require(tests::calibrationStatusMappingSelfTest(),
                "calibration incomplete/failed status mapping is incorrect");

    bool rejected = false;
    try {
        static_cast<void>(tests::runSamplingOverheadCalibration(
            tests::SamplingOverheadWorkload::Sha256, {1, 2, 3, 4, 5, 6, 7, 8, 9}, 9, 1));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "calibration candidate bound was not enforced");

    for (const auto seed : {1ULL, 42ULL, 99ULL}) {
        for (const auto repetitions : {1U, 2U, 3U}) {
            const auto pilot = tests::prepareSamplingOverheadPilot(seed, repetitions, 1000, 2000);
            tests::validateSamplingOverheadPilot(pilot);
            require(pilot.object().value("trialCount").toInt() == static_cast<int>(repetitions * 8),
                    "pilot plan did not contain the expected total trial count");
            std::map<QString, int> counts;
            for (const auto& value : pilot.object().value("trials").toArray()) {
                const auto trial = value.toObject();
                const auto condition = trial.value("samplingMode").toString() + QStringLiteral(":") +
                    QString::number(trial.value("intervalMilliseconds").toInt());
                const auto key = trial.value("workload").toString() + QStringLiteral(":") +
                    QString::number(trial.value("repetition").toInt()) + QStringLiteral(":") + condition;
                ++counts[key];
            }
            for (const auto workload : {QStringLiteral("sha256"), QStringLiteral("aes256-gcm-encrypt")}) {
                for (const auto condition : {QStringLiteral("boundaryOnlyControl:0"),
                                             QStringLiteral("periodic:5"), QStringLiteral("periodic:2"),
                                             QStringLiteral("periodic:1")}) {
                    for (unsigned repetition = 0; repetition < repetitions; ++repetition) {
                        require(counts[workload + QStringLiteral(":") + QString::number(repetition) +
                                        QStringLiteral(":") + condition] == 1,
                                "pilot condition matrix is not balanced");
                    }
                }
            }
            const auto repeated = tests::prepareSamplingOverheadPilot(seed, repetitions, 1000, 2000);
            require(pilot == repeated, "pilot seed did not produce deterministic ordering");

            auto tamperedObject = pilot.object();
            auto tamperedTrials = tamperedObject.value("trials").toArray();
            tamperedTrials.removeLast();
            tamperedObject.insert("trials", tamperedTrials);
            tamperedObject.insert("trialCount", tamperedTrials.size());
            bool rejectedTampering = false;
            try {
                tests::validateSamplingOverheadPilot(QJsonDocument(tamperedObject));
            } catch (const std::runtime_error&) {
                rejectedTampering = true;
            }
            require(rejectedTampering, "unbalanced pilot manifest was accepted");

            auto nTamperedObject = pilot.object();
            auto nTamperedTrials = nTamperedObject.value("trials").toArray();
            auto nTamperedTrial = nTamperedTrials[0].toObject();
            nTamperedTrial.insert("iterationsPerRun", QStringLiteral("9999"));
            nTamperedTrials[0] = nTamperedTrial;
            nTamperedObject.insert("trials", nTamperedTrials);
            bool rejectedInconsistentN = false;
            try {
                tests::validateSamplingOverheadPilot(QJsonDocument(nTamperedObject));
            } catch (const std::runtime_error&) {
                rejectedInconsistentN = true;
            }
            require(rejectedInconsistentN, "inconsistent per-workload N was accepted");
        }
    }

    tests::SamplingOverheadRun failed;
    failed.status = QStringLiteral("failed");
    failed.error = QStringLiteral("worker startup failed");
    const auto failedArtifact = tests::samplingOverheadRunArtifact(failed);
    const auto windows = failedArtifact.object().value("measurementWindows").toObject();
    require(windows.value("parentSessionCpuNanoseconds").isNull(),
            "unobserved parent CPU was serialized as zero");

    const auto plan = tests::prepareSamplingOverheadPilot(42, 3, 10'000'000, 3'000'000);
    const auto alternativeNPlan = tests::prepareSamplingOverheadPilot(43, 3, 12'345, 67'890);
    tests::validateSamplingOverheadPilot(alternativeNPlan);
    for (const auto& value : alternativeNPlan.object().value("trials").toArray()) {
        const auto trial = value.toObject();
        const auto expectedN = trial.value("workload") == QStringLiteral("sha256")
            ? QStringLiteral("12345") : QStringLiteral("67890");
        require(trial.value("iterationsPerRun").toString() == expectedN,
                "alternative calibrated N pair was not preserved");
    }
    auto inconsistentNPlan = alternativeNPlan.object();
    auto inconsistentTrials = inconsistentNPlan.value("trials").toArray();
    auto inconsistentTrial = inconsistentTrials[0].toObject();
    inconsistentTrial.insert("iterationsPerRun", QStringLiteral("99999"));
    inconsistentTrials[0] = inconsistentTrial;
    inconsistentNPlan.insert("trials", inconsistentTrials);
    bool inconsistentNRejected = false;
    try {
        tests::validateSamplingOverheadPilot(QJsonDocument(inconsistentNPlan));
    } catch (const std::runtime_error&) {
        inconsistentNRejected = true;
    }
    require(inconsistentNRejected, "inconsistent alternative calibrated N was accepted");
    const std::vector<QString> completedStatuses(24, QStringLiteral("completed"));
    const auto completed = tests::simulateSamplingOverheadPilot(plan, completedStatuses, {}, false);
    require(completed.object().value("complete").toBool() &&
                completed.object().value("plannedCount").toInt() == 24 &&
                completed.object().value("attemptedCount").toInt() == 24 &&
                completed.object().value("completedCount").toInt() == 24 &&
                completed.object().value("notStartedCount").toInt() == 0,
            "simulated complete pilot accounting is incorrect");
    QTemporaryDir simulationDirectory;
    require(simulationDirectory.isValid(), "simulation directory was not created");
    const auto persistedSimulation = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, {}, false,
        simulationDirectory.filePath(QStringLiteral("complete")));
    require(persistedSimulation == completed &&
                QFileInfo::exists(simulationDirectory.filePath(
                    QStringLiteral("complete/summary.json"))),
            "simulated pilot persistence did not round-trip");
    QFile trustedManifestFile(simulationDirectory.filePath(QStringLiteral("complete/manifest.json")));
    require(trustedManifestFile.open(QIODevice::ReadOnly), "trusted manifest could not be read");
    const auto trustedManifest = QJsonDocument::fromJson(trustedManifestFile.readAll());
    tests::validateSamplingOverheadPilotOutput(
        simulationDirectory.filePath(QStringLiteral("complete")), plan, trustedManifest);
    const auto finalValidationFailure = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, {}, false,
        simulationDirectory.filePath(QStringLiteral("final-validation-failure")), true);
    require(!finalValidationFailure.object().value("complete").toBool() &&
                finalValidationFailure.object().value("validationFailed").toBool() &&
                finalValidationFailure.object().value("attemptedCount").toInt() == 24 &&
                finalValidationFailure.object().value("persistedCount").toInt() == 24,
            "post-persistence validation failure was accepted as complete");
    QFile failedManifestFile(simulationDirectory.filePath(
        QStringLiteral("final-validation-failure/manifest.json")));
    require(failedManifestFile.open(QIODevice::ReadOnly),
            "final-validation manifest was not persisted");
    const auto failedManifest = QJsonDocument::fromJson(failedManifestFile.readAll());
    bool finalOutputRejected = false;
    try {
        tests::validateSamplingOverheadPilotOutput(
            simulationDirectory.filePath(QStringLiteral("final-validation-failure")),
            plan, failedManifest);
    } catch (const std::runtime_error&) {
        finalOutputRejected = true;
    }
    require(finalOutputRejected,
            "complete summary without a success marker was accepted");
    const auto markerFailureDirectory = simulationDirectory.filePath(
        QStringLiteral("summary-before-marker-failure"));
    const auto markerFailure = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, {}, false, markerFailureDirectory, false, true);
    require(markerFailure.object().value("complete").toBool() &&
                !QFileInfo::exists(QDir(markerFailureDirectory).filePath(QStringLiteral("success.marker"))),
            "post-summary marker fault did not preserve the expected incomplete evidence state");
    QFile markerFailureManifest(QDir(markerFailureDirectory).filePath(QStringLiteral("manifest.json")));
    require(markerFailureManifest.open(QIODevice::ReadOnly),
            "summary-before-marker manifest was not persisted");
    const auto markerFailureTrustedManifest = QJsonDocument::fromJson(markerFailureManifest.readAll());
    bool markerFailureRejected = false;
    try {
        tests::validateSamplingOverheadPilotOutput(
            markerFailureDirectory, plan, markerFailureTrustedManifest);
    } catch (const std::runtime_error&) {
        markerFailureRejected = true;
    }
    require(markerFailureRejected,
            "summary complete before marker was accepted by the standalone validator");
    const auto expectTamperedRecordRejected = [&](const char* name,
                                                   const std::function<void(QJsonObject&)>& mutate) {
        const auto directory = simulationDirectory.filePath(QString::fromLatin1(name));
        static_cast<void>(tests::simulateSamplingOverheadPilot(
            plan, completedStatuses, {}, false, directory));
        QFile trustedFile(QDir(directory).filePath(QStringLiteral("manifest.json")));
        require(trustedFile.open(QIODevice::ReadOnly), "tamper trusted manifest could not be read");
        const auto trusted = QJsonDocument::fromJson(trustedFile.readAll());
        const auto path = QDir(directory).filePath(QStringLiteral("trial-000.json"));
        QFile file(path);
        require(file.open(QIODevice::ReadOnly), "tamper test could not read trial record");
        QJsonParseError parseError{};
        auto document = QJsonDocument::fromJson(file.readAll(), &parseError);
        file.close();
        require(parseError.error == QJsonParseError::NoError, "tamper test input was malformed");
        auto object = document.object();
        mutate(object);
        require(file.open(QIODevice::WriteOnly | QIODevice::Truncate),
                "tamper test could not rewrite trial record");
        require(file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) > 0,
                "tamper test rewrite failed");
        file.close();
        bool rejected = false;
        try {
            tests::validateSamplingOverheadPilotOutput(directory, plan, trusted);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        if (!rejected) {
            throw std::runtime_error(
                std::string("tampered persisted trial record was accepted: ") + name);
        }
    };
    expectTamperedRecordRejected("tamper-mode", [](QJsonObject& object) {
        object.insert("samplingMode", QStringLiteral("periodic"));
    });
    expectTamperedRecordRejected("tamper-interval", [](QJsonObject& object) {
        object.insert("intervalMilliseconds", 2);
    });
    expectTamperedRecordRejected("tamper-n", [](QJsonObject& object) {
        object.insert("iterationsPerRun", QStringLiteral("999"));
    });
    expectTamperedRecordRejected("tamper-workload", [](QJsonObject& object) {
        object.insert("workload", object.value("workload") == QStringLiteral("sha256")
            ? QStringLiteral("aes256-gcm-encrypt") : QStringLiteral("sha256"));
    });
    expectTamperedRecordRejected("tamper-repetition", [](QJsonObject& object) {
        object.insert("repetition", (object.value("repetition").toInt() + 1) % 3);
    });
    expectTamperedRecordRejected("tamper-configuration", [](QJsonObject& object) {
        auto result = object.value("result").toObject();
        auto configuration = result.value("configuration").toObject();
        configuration.insert("operation", configuration.value("operation") == QStringLiteral("hash")
            ? QStringLiteral("encrypt") : QStringLiteral("hash"));
        result.insert("configuration", configuration);
        object.insert("result", result);
    });
    expectTamperedRecordRejected("tamper-provenance", [](QJsonObject& object) {
        auto result = object.value("result").toObject();
        auto provenance = result.value("provenance").toObject();
        provenance.insert("gitHead", QStringLiteral("tampered"));
        result.insert("provenance", provenance);
        object.insert("result", result);
    });
    expectTamperedRecordRejected("tamper-numeric", [](QJsonObject& object) {
        auto result = object.value("result").toObject();
        auto windows = result.value("measurementWindows").toObject();
        windows.insert("workerElapsedNanoseconds", QStringLiteral("not-a-number"));
        result.insert("measurementWindows", windows);
        object.insert("result", result);
    });
    expectTamperedRecordRejected("tamper-missing-b0", [](QJsonObject& object) {
        auto result = object.value("result").toObject();
        auto memory = result.value("memory").toObject();
        memory.remove("b0PrivateUsageBytes");
        result.insert("memory", memory);
        object.insert("result", result);
    });
    expectTamperedRecordRejected("tamper-sample-peak", [](QJsonObject& object) {
        auto result = object.value("result").toObject();
        auto memory = result.value("memory").toObject();
        memory.insert("preparationSampleCount", QStringLiteral("1"));
        result.insert("memory", memory);
        object.insert("result", result);
    });
    const auto expectTamperedManifestRejected = [&](const char* name,
                                                     const std::function<void(QJsonObject&)>& mutate) {
        const auto directory = simulationDirectory.filePath(QString::fromLatin1(name));
        static_cast<void>(tests::simulateSamplingOverheadPilot(
            plan, completedStatuses, {}, false, directory));
        QFile trustedFile(QDir(directory).filePath(QStringLiteral("manifest.json")));
        require(trustedFile.open(QIODevice::ReadOnly), "manifest tamper input could not be read");
        const auto trusted = QJsonDocument::fromJson(trustedFile.readAll());
        auto tampered = trusted.object();
        mutate(tampered);
        trustedFile.close();
        require(trustedFile.open(QIODevice::WriteOnly | QIODevice::Truncate),
                "manifest tamper rewrite failed");
        trustedFile.write(QJsonDocument(tampered).toJson(QJsonDocument::Compact));
        trustedFile.close();
        bool rejected = false;
        try {
            tests::validateSamplingOverheadPilotOutput(directory, plan, trusted);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        require(rejected, "tampered manifest was accepted");
    };
    expectTamperedManifestRejected("tamper-manifest-plan", [](QJsonObject& object) {
        object.insert("format", QStringLiteral("tampered"));
    });
    expectTamperedManifestRejected("tamper-manifest-head", [](QJsonObject& object) {
        object.insert("currentGitHead", QStringLiteral("tampered"));
    });
    bool duplicateSimulationRejected = false;
    try {
        static_cast<void>(tests::simulateSamplingOverheadPilot(
            plan, completedStatuses, {}, false,
            simulationDirectory.filePath(QStringLiteral("complete"))));
    } catch (const std::runtime_error&) {
        duplicateSimulationRejected = true;
    }
    require(duplicateSimulationRejected, "simulation duplicate destination was accepted");

    std::size_t throwIndex = 0;
    for (const auto& value : plan.object().value("trials").toArray()) {
        const auto trial = value.toObject();
        if (trial.value("workload") == QStringLiteral("aes256-gcm-encrypt") &&
            trial.value("samplingMode") == QStringLiteral("periodic")) {
            throwIndex = static_cast<std::size_t>(trial.value("executionOrder").toInt());
            break;
        }
    }
    std::vector<QString> throwStatuses(throwIndex + 1, QStringLiteral("completed"));
    throwStatuses[throwIndex] = QStringLiteral("throw");
    const auto throwDirectory = simulationDirectory.filePath(QStringLiteral("callback-throw"));
    const auto throwSummary = tests::simulateSamplingOverheadPilot(
        plan, throwStatuses, {}, false, throwDirectory);
    require(!throwSummary.object().value("complete").toBool() &&
                throwSummary.object().value("attemptedCount").toInt() ==
                    static_cast<int>(throwIndex + 1),
            "callback exception did not produce an incomplete summary");
    QFile throwRecord(QDir(throwDirectory).filePath(
        QStringLiteral("trial-%1.json").arg(throwIndex, 3, 10, QLatin1Char('0'))));
    require(throwRecord.open(QIODevice::ReadOnly), "callback exception record was not persisted");
    const auto throwDocument = QJsonDocument::fromJson(throwRecord.readAll());
    const auto throwResult = throwDocument.object().value("result").toObject();
    require(throwResult.value("status") == QStringLiteral("incomplete") &&
                throwResult.value("workload") == QStringLiteral("aes256-gcm-encrypt") &&
                throwResult.value("samplingMode") == QStringLiteral("periodic") &&
                throwResult.value("configuration").toObject().value("operation") == QStringLiteral("encrypt") &&
                throwResult.value("measurementWindows").toObject()
                    .value("workerElapsedNanoseconds").isNull(),
            "callback exception lost planned AES periodic identity or fabricated measurements");

    const auto persistenceDirectory = simulationDirectory.filePath(QStringLiteral("writer-failure"));
    const auto writerFailure = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, 3, false, persistenceDirectory);
    require(!writerFailure.object().value("complete").toBool() &&
                writerFailure.object().value("persistenceFailed").toBool() &&
                writerFailure.object().value("persistedCount").toInt() == 3 &&
                writerFailure.object().value("attemptedCount").toInt() == 4,
            "actual persistence failure accounting is incorrect");

    auto failedStatuses = completedStatuses;
    failedStatuses[5] = QStringLiteral("failed");
    const auto failedSimulation = tests::simulateSamplingOverheadPilot(
        plan, failedStatuses, {}, false);
    require(!failedSimulation.object().value("complete").toBool() &&
                failedSimulation.object().value("attemptedCount").toInt() == 6 &&
                failedSimulation.object().value("completedCount").toInt() == 5 &&
                failedSimulation.object().value("notStartedCount").toInt() == 18,
            "simulated worker failure accounting is incorrect");

    const auto interrupted = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, {}, true);
    require(!interrupted.object().value("complete").toBool() &&
                interrupted.object().value("attemptedCount").toInt() == 0 &&
                interrupted.object().value("notStartedCount").toInt() == 24,
            "simulated interruption accounting is incorrect");

    const auto persistenceFailure = tests::simulateSamplingOverheadPilot(
        plan, completedStatuses, 3, false);
    require(!persistenceFailure.object().value("complete").toBool() &&
                persistenceFailure.object().value("attemptedCount").toInt() == 4 &&
                persistenceFailure.object().value("persistedCount").toInt() == 3 &&
                persistenceFailure.object().value("notStartedCount").toInt() == 20 &&
                persistenceFailure.object().value("persistenceFailed").toBool(),
            "simulated persistence failure accounting is incorrect");
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        QString output;
        QString calibrationWorkload;
        bool preparePilot = false;
        bool executePilot = false;
        QString planPath;
        QString sha256CalibrationPath;
        QString aes256GcmCalibrationPath;
        QString outputDirectory;
        std::uint32_t explicitModeCount = 0;
        QSet<QString> seenArguments;
        std::uint64_t seed = 0;
        std::uint32_t repetitions = 0;
        std::uint64_t sha256Iterations = 0;
        std::uint64_t aes256GcmIterations = 0;
        for (int index = 1; index < argc; ++index) {
            const auto argument = QString::fromLocal8Bit(argv[index]);
            if (seenArguments.contains(argument)) {
                throw std::invalid_argument("duplicate command-line argument");
            }
            seenArguments.insert(argument);
            if (argument == QStringLiteral("--self-test")) {
                ++explicitModeCount;
                continue;
            }
            if (argument == QStringLiteral("--calibrate") && index + 1 < argc) {
                calibrationWorkload = QString::fromLocal8Bit(argv[++index]);
                ++explicitModeCount;
                continue;
            }
            if (argument == QStringLiteral("--prepare-pilot")) {
                preparePilot = true;
                ++explicitModeCount;
                continue;
            }
            if (argument == QStringLiteral("--execute-pilot")) {
                executePilot = true;
                ++explicitModeCount;
                continue;
            }
            if (argument == QStringLiteral("--output") && index + 1 < argc) {
                output = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            if (argument == QStringLiteral("--seed") && index + 1 < argc) {
                seed = QString::fromLocal8Bit(argv[++index]).toULongLong();
                continue;
            }
            if (argument == QStringLiteral("--repetitions") && index + 1 < argc) {
                repetitions = QString::fromLocal8Bit(argv[++index]).toUInt();
                continue;
            }
            if (argument == QStringLiteral("--sha256-n") && index + 1 < argc) {
                sha256Iterations = QString::fromLocal8Bit(argv[++index]).toULongLong();
                continue;
            }
            if (argument == QStringLiteral("--aes256-gcm-n") && index + 1 < argc) {
                aes256GcmIterations = QString::fromLocal8Bit(argv[++index]).toULongLong();
                continue;
            }
            if (argument == QStringLiteral("--plan") && index + 1 < argc) {
                planPath = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            if (argument == QStringLiteral("--sha256-calibration") && index + 1 < argc) {
                sha256CalibrationPath = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            if (argument == QStringLiteral("--aes256-gcm-calibration") && index + 1 < argc) {
                aes256GcmCalibrationPath = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            if (argument == QStringLiteral("--output-dir") && index + 1 < argc) {
                outputDirectory = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            throw std::invalid_argument("usage: --self-test [--output <path>]");
        }
        require(explicitModeCount <= 1, "pilot, calibration and self-test modes are mutually exclusive");
        if (executePilot) {
            require(!planPath.isEmpty() && !sha256CalibrationPath.isEmpty() &&
                        !aes256GcmCalibrationPath.isEmpty() && !outputDirectory.isEmpty(),
                    "execute-pilot requires --plan, both calibration paths and --output-dir");
            require(calibrationWorkload.isEmpty() && !preparePilot && output.isEmpty() &&
                        !seenArguments.contains(QStringLiteral("--output")) &&
                        !seenArguments.contains(QStringLiteral("--seed")) &&
                        !seenArguments.contains(QStringLiteral("--repetitions")) &&
                        !seenArguments.contains(QStringLiteral("--sha256-n")) &&
                        !seenArguments.contains(QStringLiteral("--aes256-gcm-n")),
                    "execute-pilot received an argument for another mode");
            return tests::executeSamplingOverheadPilot(
                planPath, sha256CalibrationPath, aes256GcmCalibrationPath, outputDirectory);
        }
        if (!calibrationWorkload.isEmpty()) {
            require(!output.isEmpty(), "calibration requires --output");
            require(planPath.isEmpty() && sha256CalibrationPath.isEmpty() &&
                        aes256GcmCalibrationPath.isEmpty() && outputDirectory.isEmpty() &&
                        !preparePilot && !seenArguments.contains(QStringLiteral("--seed")) &&
                        !seenArguments.contains(QStringLiteral("--repetitions")) &&
                        !seenArguments.contains(QStringLiteral("--sha256-n")) &&
                        !seenArguments.contains(QStringLiteral("--aes256-gcm-n")),
                    "calibration received an argument for another mode");
            const auto workload = calibrationWorkload == QStringLiteral("sha256")
                ? tests::SamplingOverheadWorkload::Sha256
                : calibrationWorkload == QStringLiteral("aes256-gcm-encrypt")
                    ? tests::SamplingOverheadWorkload::Aes256GcmEncrypt
                    : throw std::invalid_argument("unsupported calibration workload");
            const std::vector<std::uint64_t> candidates = workload ==
                tests::SamplingOverheadWorkload::Sha256
                ? std::vector<std::uint64_t>{1'000, 10'000, 100'000, 1'000'000, 10'000'000, 100'000'000}
                : std::vector<std::uint64_t>{1'000'000, 2'000'000, 3'000'000,
                                             4'000'000, 5'000'000, 6'000'000};
            const auto calibration = tests::runSamplingOverheadCalibration(workload, candidates, 6, 120);
            tests::validateSamplingOverheadCalibration(calibration);
            tests::writeSamplingOverheadArtifact(output, calibration);
            static_cast<void>(tests::readSamplingOverheadArtifact(output));
            std::cout << "PASS bounded calibration artifact\n";
            return 0;
        }
        if (preparePilot) {
            require(!output.isEmpty() && repetitions > 0 && seed > 0 &&
                        sha256Iterations > 0 && aes256GcmIterations > 0,
                    "pilot preparation requires --output, --seed, --repetitions, --sha256-n and --aes256-gcm-n");
            require(planPath.isEmpty() && sha256CalibrationPath.isEmpty() &&
                        aes256GcmCalibrationPath.isEmpty() && outputDirectory.isEmpty() &&
                        calibrationWorkload.isEmpty(),
                    "pilot preparation received an argument for another mode");
            const auto pilot = tests::prepareSamplingOverheadPilot(
                seed, repetitions, sha256Iterations, aes256GcmIterations);
            tests::validateSamplingOverheadPilot(pilot);
            tests::writeSamplingOverheadArtifact(output, pilot);
            static_cast<void>(tests::readSamplingOverheadArtifact(output));
            std::cout << "PASS pilot plan preparation (not executed)\n";
            return 0;
        }
        require(planPath.isEmpty() && sha256CalibrationPath.isEmpty() &&
                    aes256GcmCalibrationPath.isEmpty() && outputDirectory.isEmpty() &&
                    !seenArguments.contains(QStringLiteral("--seed")) &&
                    !seenArguments.contains(QStringLiteral("--repetitions")) &&
                    !seenArguments.contains(QStringLiteral("--sha256-n")) &&
                    !seenArguments.contains(QStringLiteral("--aes256-gcm-n")),
                "self-test received an argument for another mode");
        QString watchdogDiagnostic;
        if (!tests::eventDrivenWatchdogSelfTest(25, &watchdogDiagnostic)) {
            throw std::runtime_error(
                "event-driven watchdog deadline regression failed: " +
                watchdogDiagnostic.toStdString());
        }
        testInvalidIntervals();
        testB1WorkloadsAndPlanning();
        const auto runs = testTimingAndArtifactModes();
        testArtifactFailureAndMalformedInputs();
        if (!output.isEmpty()) {
            const auto batch = tests::samplingOverheadBatchArtifact(runs);
            tests::validateSamplingOverheadBatchArtifact(batch);
            tests::writeSamplingOverheadArtifact(output, batch);
            const auto roundTrip = tests::readSamplingOverheadArtifact(output);
            require(roundTrip == batch, "persisted batch artifact did not round-trip exactly");
        }
        std::cout << "PASS real Memory v2 sampling overhead Stage B1 self-tests\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
