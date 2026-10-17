#include "MemoryV2Qualification.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>

#include <iostream>
#include <stdexcept>
#include <vector>

using namespace cryptobench;

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void requireInvalid(Function&& function, const char* message)
{
    bool rejected = false;
    try {
        function();
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void requireLifecycle(const tests::QualificationRun& run)
{
    require(run.workerPid != 0 && run.workerStarted && run.processFinishedObserved,
            "worker lifecycle events were incomplete");
    require(run.finishEventOrdinal > run.startEventOrdinal,
            "worker exit was not observed after worker start");
    require(run.processCreationTimeObserved,
            "worker process creation identity was unavailable");
    require(tests::workerProcessTerminationStatus(run.workerPid) ==
                tests::ProcessTerminationStatus::Exited,
            "worker termination status was not demonstrably exited");
}

void requireFormulaMatch(const core::MemoryV2RawObservations& raw,
                         const core::MemoryV2DerivedMetrics& derived)
{
    const auto preparationPeak = std::max(
        {raw.baselinePrivateUsageBytes, raw.readyPrivateUsageBytes,
         raw.preparationPeakSampledPrivateUsageBytes.value_or(0)});
    const auto executionPeak = std::max(
        {raw.baselinePrivateUsageBytes, raw.readyPrivateUsageBytes, raw.finalPrivateUsageBytes,
         raw.executionPeakSampledPrivateUsageBytes.value_or(0)});
    const auto operationalPeak = std::max(preparationPeak, executionPeak);
    require(derived.preparationPeakDelta == preparationPeak - raw.baselinePrivateUsageBytes,
            "preparation derived formula mismatch");
    require(derived.executionPeakDelta == executionPeak - raw.baselinePrivateUsageBytes,
            "execution derived formula mismatch");
    require(derived.operationalPeakDelta == operationalPeak - raw.baselinePrivateUsageBytes,
            "operational derived formula mismatch");
    const auto expectedReady = raw.readyPrivateUsageBytes >= raw.baselinePrivateUsageBytes
        ? static_cast<std::int64_t>(raw.readyPrivateUsageBytes - raw.baselinePrivateUsageBytes)
        : -static_cast<std::int64_t>(raw.baselinePrivateUsageBytes - raw.readyPrivateUsageBytes);
    require(derived.readyStateDelta == expectedReady, "ready-state derived formula mismatch");
}

void requireVisible(std::uint64_t value, std::uint64_t baseline, const char* message)
{
    require(value > baseline + 1U * 1024U * 1024U, message);
}

void testNoAllocationBoundaryOnlyAndArtifact()
{
    const tests::SyntheticScenario scenario{0, 0, 160, 160, true, true};
    const tests::QualificationIdentity identity{"m19.1-self-test", "no-allocation-off", "0", 0};
    const auto wasSet = qEnvironmentVariableIsSet("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO");
    const auto previous = qgetenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO");
    qputenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO", "original-environment-value");
    const auto run = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl, scenario, 5, identity);
    require(qgetenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO") ==
                QByteArrayLiteral("original-environment-value"),
            "qualification did not restore the caller environment");
    if (wasSet) qputenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO", previous);
    else qunsetenv("CRYPTOBENCH_M19_SYNTHETIC_SCENARIO");
    require(run.status == QStringLiteral("completed") && run.normalExit,
            "boundary-only no-allocation run did not complete");
    requireLifecycle(run);
    require(run.raw.preparationSampleCount == 0 && run.raw.executionSampleCount == 0,
            "boundary-only control produced periodic samples");
    require(!run.raw.preparationPeakSampledPrivateUsageBytes.has_value() &&
                !run.raw.executionPeakSampledPrivateUsageBytes.has_value(),
            "boundary-only control produced sampled peaks");
    require(run.derived.has_value(), "boundary-only run has no derived metrics");
    requireFormulaMatch(run.raw, *run.derived);

    const auto artifact = tests::makeQualificationArtifact(
        run, tests::QualificationSamplingMode::BoundaryOnlyControl, scenario, 5, identity);
    tests::requireQualificationArtifact(artifact);
    QTemporaryDir directory;
    require(directory.isValid(), "qualification artifact temp directory unavailable");
    const auto path = directory.filePath(QStringLiteral("qualification.json"));
    tests::writeQualificationArtifact(path, artifact);
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "qualification artifact could not be reopened");
    tests::requireQualificationArtifact(QJsonDocument::fromJson(file.readAll()));
}

void testPreparationAndExecutionObservability()
{
    const tests::QualificationIdentity prepIdentity{"m19.1-self-test", "preparation-plateau", "0", 1};
    const auto prep = tests::runQualification(
        tests::QualificationSamplingMode::Periodic,
        {32ULL * 1024U * 1024U, 0, 300, 300, false, true}, 2, prepIdentity);
    requireLifecycle(prep);
    require(prep.raw.preparationSampleCount > 0, "preparation plateau had no periodic samples");
    requireVisible(prep.raw.readyPrivateUsageBytes, prep.raw.baselinePrivateUsageBytes,
                   "B1 did not observe retained preparation allocation");
    require(prep.raw.preparationPeakSampledPrivateUsageBytes.has_value(),
            "preparation plateau had no sampled peak");
    requireFormulaMatch(prep.raw, *prep.derived);

    const auto execution = tests::runQualification(
        tests::QualificationSamplingMode::Periodic,
        {0, 32ULL * 1024U * 1024U, 300, 300, true, false}, 2,
        {"m19.1-self-test", "execution-plateau", "0", 2});
    requireLifecycle(execution);
    require(execution.raw.executionSampleCount > 0, "execution plateau had no periodic samples");
    requireVisible(execution.raw.finalPrivateUsageBytes, execution.raw.baselinePrivateUsageBytes,
                   "E did not observe retained execution allocation");
    require(execution.raw.executionPeakSampledPrivateUsageBytes.has_value(),
            "execution plateau had no sampled peak");
    requireFormulaMatch(execution.raw, *execution.derived);
}

void testReleasedPhaseAllocationsAndIntervals()
{
    const auto releasedPreparation = tests::runQualification(
        tests::QualificationSamplingMode::Periodic,
        {32ULL * 1024U * 1024U, 0, 300, 300, true, true}, 5,
        {"m19.1-self-test", "preparation-release-before-b1", "0", 3});
    require(releasedPreparation.raw.preparationSampleCount > 0 &&
                releasedPreparation.raw.preparationPeakSampledPrivateUsageBytes.has_value(),
            "released preparation phase was not sampled");
    requireVisible(*releasedPreparation.raw.preparationPeakSampledPrivateUsageBytes,
                   releasedPreparation.raw.baselinePrivateUsageBytes,
                   "released preparation plateau was not observed");
    require(releasedPreparation.raw.readyPrivateUsageBytes <
                *releasedPreparation.raw.preparationPeakSampledPrivateUsageBytes,
            "preparation allocation was not released before B1");
    requireFormulaMatch(releasedPreparation.raw, *releasedPreparation.derived);

    const auto releasedExecution = tests::runQualification(
        tests::QualificationSamplingMode::Periodic,
        {0, 32ULL * 1024U * 1024U, 300, 300, true, true}, 5,
        {"m19.1-self-test", "execution-release-before-e", "0", 4});
    require(releasedExecution.raw.executionSampleCount > 0 &&
                releasedExecution.raw.executionPeakSampledPrivateUsageBytes.has_value(),
            "released execution phase was not sampled");
    requireVisible(*releasedExecution.raw.executionPeakSampledPrivateUsageBytes,
                   releasedExecution.raw.baselinePrivateUsageBytes,
                   "released execution plateau was not observed");
    require(releasedExecution.raw.finalPrivateUsageBytes <
                *releasedExecution.raw.executionPeakSampledPrivateUsageBytes,
            "execution allocation was not released before E");
    requireFormulaMatch(releasedExecution.raw, *releasedExecution.derived);

    const tests::SyntheticScenario sustained{8ULL * 1024U * 1024U, 8ULL * 1024U * 1024U,
                                             300, 300, false, false};
    for (const auto interval : {5U, 2U, 1U}) {
        const auto run = tests::runQualification(
            tests::QualificationSamplingMode::Periodic, sustained, interval,
            {"m19.1-self-test", "interval", QString::number(interval), interval});
        require(run.raw.preparationSampleCount > 0 && run.raw.executionSampleCount > 0,
                "sustained phases did not produce positive sample counts");
        require(run.raw.preparationPeakSampledPrivateUsageBytes.has_value() &&
                    run.raw.executionPeakSampledPrivateUsageBytes.has_value(),
                "sustained phases lacked phase peaks");
        requireVisible(*run.raw.preparationPeakSampledPrivateUsageBytes,
                       run.raw.baselinePrivateUsageBytes, "preparation phase peak was not observed");
        requireVisible(*run.raw.executionPeakSampledPrivateUsageBytes,
                       run.raw.baselinePrivateUsageBytes, "execution phase peak was not observed");
        requireFormulaMatch(run.raw, *run.derived);
    }
}

void testTimingAndFreshWorkerRepetitions()
{
    const auto shortRun = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 8ULL * 1024U * 1024U, 60, 60, true, false}, 5,
        {"m19.1-self-test", "timing", "short", 10});
    const auto longRun = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 8ULL * 1024U * 1024U, 220, 220, true, false}, 5,
        {"m19.1-self-test", "timing", "long", 11});
    require(shortRun.workerMeasurement.elapsedNanoseconds > 0 &&
                longRun.workerMeasurement.elapsedNanoseconds > 0,
            "synthetic wall timing was zero");
    require(longRun.workerMeasurement.processCpuNanoseconds > 0,
            "synthetic process CPU timing was zero for the sustained workload");
    require(longRun.workerMeasurement.elapsedNanoseconds > shortRun.workerMeasurement.elapsedNanoseconds,
            "synthetic wall timing did not respond to workload duration");
    require(longRun.workerMeasurement.elapsedNanoseconds != 1'000 &&
                longRun.workerMeasurement.processCpuNanoseconds != 1'000,
            "synthetic timing retained fabricated constant values");

    std::vector<std::uint32_t> pids;
    std::vector<std::uint64_t> creationTimes;
    for (std::uint32_t repetition = 0; repetition < 3; ++repetition) {
        const auto run = tests::runQualification(
            tests::QualificationSamplingMode::BoundaryOnlyControl,
            {0, 0, 100, 100, true, true}, 5,
            {"m19.1-self-test", "repetition", QString::number(repetition), repetition});
        requireLifecycle(run);
        pids.push_back(run.workerPid);
        creationTimes.push_back(run.processCreationTime100ns);
    }
    require(pids[0] != pids[1] && pids[1] != pids[2] && pids[0] != pids[2],
            "repetitions did not use distinct workers");
    require(creationTimes[0] != creationTimes[1] && creationTimes[1] != creationTimes[2],
            "repetitions did not capture distinct process identities");
}

void testFailureCancellationAndParserRejection()
{
    const auto failed = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 80, 80, true, true, tests::SyntheticOutcome::WorkerFailure}, 5,
        {"m19.1-self-test", "worker-failure", "0", 20});
    require(failed.status == QStringLiteral("failed") && !failed.derived.has_value(),
            "worker failure was serialized as completed evidence");
    requireLifecycle(failed);
    tests::requireQualificationArtifact(tests::makeQualificationArtifact(
        failed, tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 80, 80, true, true, tests::SyntheticOutcome::WorkerFailure}, 5,
        {"m19.1-self-test", "worker-failure", "0", 20}));

    const auto abnormal = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 80, 80, true, true, tests::SyntheticOutcome::AbnormalExit}, 5,
        {"m19.1-self-test", "abnormal-exit", "0", 22});
    require(abnormal.status == QStringLiteral("failed") && !abnormal.derived.has_value(),
            "abnormal worker exit was serialized as completed evidence");
    requireLifecycle(abnormal);
    tests::requireQualificationArtifact(tests::makeQualificationArtifact(
        abnormal, tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 80, 80, true, true, tests::SyntheticOutcome::AbnormalExit}, 5,
        {"m19.1-self-test", "abnormal-exit", "0", 22}));

    const auto cancelled = tests::runQualification(
        tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 300, 300, true, true, tests::SyntheticOutcome::WaitForCancellation}, 5,
        {"m19.1-self-test", "cancellation", "0", 21});
    require(cancelled.status == QStringLiteral("cancelled") && !cancelled.derived.has_value(),
            "cancellation was serialized as completed evidence");
    requireLifecycle(cancelled);
    tests::requireQualificationArtifact(tests::makeQualificationArtifact(
        cancelled, tests::QualificationSamplingMode::BoundaryOnlyControl,
        {0, 0, 300, 300, true, true, tests::SyntheticOutcome::WaitForCancellation}, 5,
        {"m19.1-self-test", "cancellation", "0", 21}));

    const auto valid = tests::encodeSyntheticScenario({1, 2, 10, 10, true, true});
    static_cast<void>(valid);
    requireInvalid([] { tests::parseSyntheticScenario("{}"); }, "missing scenario fields accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"preparationBytes\":\"1\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"10\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":true,\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\",\"extra\":1}"); }, "unknown scenario field accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"preparationBytes\":\"1\",\"preparationBytes\":\"2\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"10\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":true,\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\"}"); }, "duplicate scenario field accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"\\u0070reparationBytes\":\"1\",\"preparationBytes\":\"2\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"10\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":true,\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\"}"); }, "escaped duplicate scenario field accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"preparationBytes\":\"not-a-number\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"10\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":true,\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\"}"); }, "invalid numeric scenario field accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"preparationBytes\":\"1\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"0\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":true,\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\"}"); }, "invalid duration accepted");
    requireInvalid([] { tests::parseSyntheticScenario("{\"preparationBytes\":\"1\",\"executionBytes\":\"2\",\"preparationHoldMilliseconds\":\"10\",\"executionHoldMilliseconds\":\"10\",\"releasePreparationBeforeBoundary\":\"true\",\"releaseExecutionBeforeEnd\":true,\"outcome\":\"completed\"}"); }, "invalid boolean accepted");
}

int smokeToPath(const QString& path)
{
    const tests::SyntheticScenario scenario{8ULL * 1024U * 1024U, 8ULL * 1024U * 1024U,
                                            300, 300, false, false};
    const tests::QualificationIdentity identity{"m19.1-smoke", "caller-selected", "0", 0};
    const auto run = tests::runQualification(
        tests::QualificationSamplingMode::Periodic, scenario, 5, identity);
    const auto artifact = tests::makeQualificationArtifact(
        run, tests::QualificationSamplingMode::Periodic, scenario, 5, identity);
    tests::writeQualificationArtifact(path, artifact);
    return run.status == QStringLiteral("completed") ? 0 : 1;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        const auto arguments = application.arguments();
        if (arguments.size() == 3 && arguments[1] == QStringLiteral("--smoke-output")) {
            return smokeToPath(arguments[2]);
        }
        if (arguments.size() != 1) return 2;
        testNoAllocationBoundaryOnlyAndArtifact();
        testPreparationAndExecutionObservability();
        testReleasedPhaseAllocationsAndIntervals();
        testTimingAndFreshWorkerRepetitions();
        testFailureCancellationAndParserRejection();
        std::cout << "PASS Memory v2 qualification foundation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
