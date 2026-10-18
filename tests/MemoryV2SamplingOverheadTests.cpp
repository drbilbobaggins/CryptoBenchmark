#include "MemoryV2SamplingOverhead.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonObject>
#include <QUuid>

#include <iostream>
#include <stdexcept>
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

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        QString output;
        for (int index = 1; index < argc; ++index) {
            const auto argument = QString::fromLocal8Bit(argv[index]);
            if (argument == QStringLiteral("--self-test")) continue;
            if (argument == QStringLiteral("--output") && index + 1 < argc) {
                output = QString::fromLocal8Bit(argv[++index]);
                continue;
            }
            throw std::invalid_argument("usage: --self-test [--output <path>]");
        }
        require(tests::eventDrivenWatchdogSelfTest(25),
            "event-driven watchdog deadline regression failed");
        testInvalidIntervals();
        const auto runs = testTimingAndArtifactModes();
        testArtifactFailureAndMalformedInputs();
        if (!output.isEmpty()) {
            const auto batch = tests::samplingOverheadBatchArtifact(runs);
            tests::validateSamplingOverheadBatchArtifact(batch);
            tests::writeSamplingOverheadArtifact(output, batch);
            const auto roundTrip = tests::readSamplingOverheadArtifact(output);
            require(roundTrip == batch, "persisted batch artifact did not round-trip exactly");
        }
        std::cout << "PASS real Memory v2 sampling overhead Stage A self-tests\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
