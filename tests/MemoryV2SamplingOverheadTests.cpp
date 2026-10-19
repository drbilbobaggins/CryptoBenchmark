#include "MemoryV2SamplingOverhead.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QUuid>

#include <iostream>
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
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        QString output;
        QString calibrationWorkload;
        bool preparePilot = false;
        std::uint64_t seed = 0;
        std::uint32_t repetitions = 0;
        std::uint64_t sha256Iterations = 0;
        std::uint64_t aes256GcmIterations = 0;
        for (int index = 1; index < argc; ++index) {
            const auto argument = QString::fromLocal8Bit(argv[index]);
            if (argument == QStringLiteral("--self-test")) continue;
            if (argument == QStringLiteral("--calibrate") && index + 1 < argc) {
                calibrationWorkload = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            if (argument == QStringLiteral("--prepare-pilot")) {
                preparePilot = true;
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
            throw std::invalid_argument("usage: --self-test [--output <path>]");
        }
        if (!calibrationWorkload.isEmpty()) {
            require(!output.isEmpty(), "calibration requires --output");
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
            const auto pilot = tests::prepareSamplingOverheadPilot(
                seed, repetitions, sha256Iterations, aes256GcmIterations);
            tests::validateSamplingOverheadPilot(pilot);
            tests::writeSamplingOverheadArtifact(output, pilot);
            static_cast<void>(tests::readSamplingOverheadArtifact(output));
            std::cout << "PASS pilot plan preparation (not executed)\n";
            return 0;
        }
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
