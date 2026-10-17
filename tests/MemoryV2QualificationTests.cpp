#include "MemoryV2Qualification.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QSaveFile>
#include <QTemporaryDir>

#include <iostream>
#include <array>
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
            (std::string("boundary-only no-allocation run did not complete: ") +
             run.error.toStdString()).c_str());
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

    void testCampaignManifestSummaryAndCollision()
    {
        auto manifest = tests::defaultExploratoryPilotManifest();
        manifest.repetitions = 1;
        manifest.cases.resize(1);
        manifest.modes.resize(1);
        QTemporaryDir firstDirectory;
        QTemporaryDir secondDirectory;
        require(firstDirectory.isValid() && secondDirectory.isValid(),
            "campaign temporary directories unavailable");
        const auto encoded = tests::encodeQualificationCampaignManifest(manifest);
        const auto parsed = tests::parseQualificationCampaignManifest(encoded);
        require(parsed.campaignId == manifest.campaignId && parsed.seed == manifest.seed &&
            parsed.cases.size() == 1 && parsed.modes.size() == 1,
            "campaign manifest round-trip changed identity or grid");
        const auto first = tests::runQualificationCampaign(parsed, firstDirectory.path());
        const auto second = tests::runQualificationCampaign(parsed, secondDirectory.path());
        tests::verifyQualificationCampaign(firstDirectory.path());
        tests::verifyQualificationCampaign(secondDirectory.path());
        require(first.object().value("manifestSha256") == second.object().value("manifestSha256"),
            "seeded campaign manifest identity was not stable");
        require(first.object().value("runs").toArray().size() == 1 &&
            first.object().value("groups").toObject().size() == 1,
            "campaign summary did not retain one raw run and one group");
        requireInvalid([&] { static_cast<void>(tests::runQualificationCampaign(parsed, firstDirectory.path())); },
               "campaign output collision was silently overwritten");
        auto invalid = encoded.object();
        invalid.insert("modes", QJsonArray{QStringLiteral("3")});
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(invalid))); },
               "unsupported campaign mode was accepted");
        auto duplicateModeObject = encoded.object();
        duplicateModeObject.insert("modes", QJsonArray{QStringLiteral("off"), QStringLiteral("off")});
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(duplicateModeObject))); },
                       "duplicate campaign mode was accepted");
        auto duplicateCaseObject = encoded.object();
        duplicateCaseObject.insert("cases", QJsonArray{
            QJsonObject{{"caseId", "duplicate"}, {"scenario", encoded.object().value("cases").toArray().first().toObject().value("scenario")} },
            QJsonObject{{"caseId", "duplicate"}, {"scenario", encoded.object().value("cases").toArray().first().toObject().value("scenario")} }});
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(duplicateCaseObject))); },
                       "duplicate campaign case was accepted");
        auto unsafeCaseObject = encoded.object();
        auto unsafeCases = unsafeCaseObject.value("cases").toArray();
        auto unsafeCase = unsafeCases.first().toObject();
        unsafeCase.insert("caseId", "../unsafe");
        unsafeCases[0] = unsafeCase;
        unsafeCaseObject.insert("cases", unsafeCases);
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(unsafeCaseObject))); },
                       "unsafe campaign case identifier was accepted");
        const auto duplicateManifest = QStringLiteral(
            "{\"format\":\"cryptobenchmark-memory-v2-campaign\",\"schemaVersion\":1,"
            "\"campaignId\":\"x\",\"phase\":\"pilot\",\"seed\":\"1\","
            "\"repetitions\":1,\"modes\":[\"off\"],\"cases\":[],"
            "\"\\u0063ampaignId\":\"y\"}");
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(duplicateManifest)); },
                       "escaped duplicate manifest field was accepted");
        auto unknownCaseObject = encoded.object();
        auto unknownCases = unknownCaseObject.value("cases").toArray();
        auto unknownCase = unknownCases.first().toObject();
        unknownCase.insert("unexpected", true);
        unknownCases[0] = unknownCase;
        unknownCaseObject.insert("cases", unknownCases);
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(unknownCaseObject))); },
                       "unknown campaign case member was accepted");
        auto reservedCaseObject = encoded.object();
        auto reservedCases = reservedCaseObject.value("cases").toArray();
        auto reservedCase = reservedCases.first().toObject();
        reservedCase.insert("caseId", "CON");
        reservedCases[0] = reservedCase;
        reservedCaseObject.insert("cases", reservedCases);
        requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(reservedCaseObject))); },
                       "reserved Windows case identifier was accepted");
        auto invalidEnum = manifest;
        invalidEnum.modes[0].mode = static_cast<tests::QualificationSamplingMode>(99);
        requireInvalid([&] { static_cast<void>(tests::encodeQualificationCampaignManifest(invalidEnum)); },
                       "invalid direct campaign mode enum was accepted");
        auto invalidOutcome = manifest;
        invalidOutcome.cases[0].scenario.outcome = static_cast<tests::SyntheticOutcome>(99);
        requireInvalid([&] { static_cast<void>(tests::encodeQualificationCampaignManifest(invalidOutcome)); },
                       "invalid direct synthetic outcome enum was accepted");
        auto failedManifest = manifest;
        failedManifest.cases.front().scenario.outcome = tests::SyntheticOutcome::WorkerFailure;
        QTemporaryDir failedDirectory;
        const auto failedSummary = tests::runQualificationCampaign(failedManifest, failedDirectory.path());
        require(failedSummary.object().value("status") == QStringLiteral("failed") &&
                    failedSummary.object().value("failedRuns").toInt() == 1,
                "failed campaign was reported as completed");
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

void testCampaignVerifierRejectsPersistedMutations()
{
    auto manifest = tests::defaultExploratoryPilotManifest();
    manifest.repetitions = 1;
    manifest.cases.resize(1);
    manifest.modes.resize(1);
    QTemporaryDir sourceDirectory;
    require(sourceDirectory.isValid(), "verifier source directory unavailable");
    static_cast<void>(tests::runQualificationCampaign(manifest, sourceDirectory.path()));

    const auto copyCampaign = [&](QTemporaryDir& destination, const QString& source) {
        require(destination.isValid(), "verifier mutation directory unavailable");
        QDir().mkpath(destination.filePath(QStringLiteral("runs")));
        for (const auto& name : {QStringLiteral("manifest.json"), QStringLiteral("summary.json")}) {
            require(QFile::copy(QDir(source).filePath(name), destination.filePath(name)),
                    "verifier fixture copy failed");
        }
        const auto files = QDir(QDir(source).filePath(QStringLiteral("runs")))
            .entryList(QStringList{QStringLiteral("*.json")}, QDir::Files);
        for (const auto& file : files) {
            require(QFile::copy(QDir(QDir(source).filePath(QStringLiteral("runs"))).filePath(file),
                                QDir(destination.filePath(QStringLiteral("runs"))).filePath(file)),
                    "verifier raw fixture copy failed");
        }
    };
    const auto requireRejected = [](const QString& path, const char* message,
                                    const char* expectedDiagnostic = nullptr) {
        bool rejected = false;
        try { tests::verifyQualificationCampaign(path); }
        catch (const std::invalid_argument& error) {
            rejected = expectedDiagnostic == nullptr ||
                QString::fromUtf8(error.what()).contains(QString::fromLatin1(expectedDiagnostic));
        }
        if (!rejected) throw std::runtime_error(message);
    };

    QTemporaryDir aggregateDirectory;
    copyCampaign(aggregateDirectory, sourceDirectory.path());
    {
        QFile file(aggregateDirectory.filePath(QStringLiteral("summary.json")));
        require(file.open(QIODevice::ReadOnly), "summary fixture open failed");
        auto document = QJsonDocument::fromJson(file.readAll());
        file.close();
        auto root = document.object();
        auto groups = root.value("groups").toObject();
        auto group = groups.begin();
        auto groupObject = group.value().toObject();
        groupObject.insert("completed", groupObject.value("completed").toInt() + 1);
        groups.insert(group.key(), groupObject);
        root.insert("groups", groups);
        QSaveFile output(aggregateDirectory.filePath(QStringLiteral("summary.json")));
        require(output.open(QIODevice::WriteOnly), "summary fixture write failed");
        const auto bytes = QJsonDocument(root).toJson(QJsonDocument::Indented);
        require(output.write(bytes) == bytes.size() && output.commit(), "summary fixture commit failed");
    }
    requireRejected(aggregateDirectory.path(), "aggregate statistic tampering was accepted");

    QTemporaryDir corruptDirectory;
    copyCampaign(corruptDirectory, sourceDirectory.path());
    const auto rawFiles = QDir(corruptDirectory.filePath(QStringLiteral("runs"))).entryList(QStringList{"*.json"}, QDir::Files);
    QFile corrupt(QDir(corruptDirectory.filePath(QStringLiteral("runs"))).filePath(rawFiles.front()));
    require(corrupt.open(QIODevice::Append), "raw corruption fixture open failed");
    corrupt.write("x");
    corrupt.close();
    requireRejected(corruptDirectory.path(), "raw corruption was accepted");

    QTemporaryDir missingDirectory;
    copyCampaign(missingDirectory, sourceDirectory.path());
    require(QFile::remove(QDir(missingDirectory.filePath(QStringLiteral("runs"))).filePath(rawFiles.front())),
            "raw removal fixture failed");
    requireRejected(missingDirectory.path(), "missing raw artifact was accepted");

    QTemporaryDir extraDirectory;
    copyCampaign(extraDirectory, sourceDirectory.path());
    require(QFile::copy(QDir(extraDirectory.filePath(QStringLiteral("runs"))).filePath(rawFiles.front()),
                        QDir(extraDirectory.filePath(QStringLiteral("runs"))).filePath(QStringLiteral("extra.json"))),
            "extra raw fixture failed");
    requireRejected(extraDirectory.path(), "extra raw artifact was accepted");

    auto multiManifest = manifest;
    multiManifest.repetitions = 2;
    QTemporaryDir multiDirectory;
    require(multiDirectory.isValid(), "multi-run verifier fixture unavailable");
    static_cast<void>(tests::runQualificationCampaign(multiManifest, multiDirectory.path()));
    const auto multiRawFiles = QDir(multiDirectory.filePath(QStringLiteral("runs")))
        .entryList(QStringList{QStringLiteral("*.json")}, QDir::Files);
    require(multiRawFiles.size() == 2, "multi-run verifier fixture did not produce two runs");

    const auto mutateRawAndUpdateHash = [&](const QString& directory,
                                            const QString& fileName,
                                            const std::function<void(QJsonObject&)>& mutation) {
        const auto rawPath = QDir(directory).filePath(QStringLiteral("runs/") + fileName);
        QFile rawFile(rawPath);
        require(rawFile.open(QIODevice::ReadOnly),
            (std::string("mutation raw open failed: ") + rawPath.toStdString()).c_str());
        auto document = QJsonDocument::fromJson(rawFile.readAll());
        rawFile.close();
        auto root = document.object();
        mutation(root);
        QSaveFile output(rawPath);
        require(output.open(QIODevice::WriteOnly), "mutation raw write failed");
        const auto bytes = QJsonDocument(root).toJson(QJsonDocument::Indented);
        require(output.write(bytes) == bytes.size() && output.commit(), "mutation raw commit failed");
        QFile summaryFile(QDir(directory).filePath(QStringLiteral("summary.json")));
        require(summaryFile.open(QIODevice::ReadOnly), "mutation summary open failed");
        auto summary = QJsonDocument::fromJson(summaryFile.readAll()).object();
        summaryFile.close();
        auto runs = summary.value("runs").toArray();
        for (int index = 0; index < runs.size(); ++index) {
            auto entry = runs[index].toObject();
            if (entry.value("path").toString() == QStringLiteral("runs/") + fileName) {
                entry.insert("sha256", QString::fromLatin1(
                    QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()));
                runs[index] = entry;
            }
        }
        summary.insert("runs", runs);
        QSaveFile summaryOutput(QDir(directory).filePath(QStringLiteral("summary.json")));
        require(summaryOutput.open(QIODevice::WriteOnly), "mutation summary write failed");
        const auto summaryBytes = QJsonDocument(summary).toJson(QJsonDocument::Indented);
        require(summaryOutput.write(summaryBytes) == summaryBytes.size() && summaryOutput.commit(),
                "mutation summary commit failed");
    };

    const auto secondRaw = multiRawFiles[1];
    const auto firstRaw = multiRawFiles[0];
    QTemporaryDir identityDirectory;
    copyCampaign(identityDirectory, multiDirectory.path());
    const auto identitySource = QDir(multiDirectory.path()).filePath(QStringLiteral("runs/") + firstRaw);
    const auto identityTarget = QDir(multiDirectory.path()).filePath(QStringLiteral("runs/") + secondRaw);
    QFile firstIdentityFile(identitySource);
    QFile secondIdentityFile(identityTarget);
    require(firstIdentityFile.open(QIODevice::ReadOnly) && secondIdentityFile.open(QIODevice::ReadOnly),
            "identity fixture open failed");
    const auto firstIdentity = QJsonDocument::fromJson(firstIdentityFile.readAll()).object()
        .value("lifecycle").toObject();
    static_cast<void>(QJsonDocument::fromJson(secondIdentityFile.readAll()));
    secondIdentityFile.close();
    mutateRawAndUpdateHash(identityDirectory.path(), secondRaw, [&](QJsonObject& root) {
        auto lifecycle = root.value("lifecycle").toObject();
        lifecycle.insert("workerPid", firstIdentity.value("workerPid"));
        lifecycle.insert("processCreationTime100ns", firstIdentity.value("processCreationTime100ns"));
        root.insert("lifecycle", lifecycle);
    });
    requireRejected(identityDirectory.path(), "worker identity reuse was accepted", "worker identity was reused");

    QTemporaryDir indeterminateDirectory;
    copyCampaign(indeterminateDirectory, multiDirectory.path());
    mutateRawAndUpdateHash(indeterminateDirectory.path(), secondRaw, [&](QJsonObject& root) {
        auto lifecycle = root.value("lifecycle").toObject();
        lifecycle.insert("terminationStatus", "indeterminate");
        root.insert("lifecycle", lifecycle);
    });
    requireRejected(indeterminateDirectory.path(), "indeterminate termination was accepted", "lifecycle proof");

    QTemporaryDir lifetimeDirectory;
    copyCampaign(lifetimeDirectory, multiDirectory.path());
    mutateRawAndUpdateHash(lifetimeDirectory.path(), firstRaw, [&](QJsonObject& root) {
        auto scenario = root.value("scenario").toObject();
        scenario.remove("observedPreparationLifetimeNanoseconds");
        root.insert("scenario", scenario);
    });
    requireRejected(lifetimeDirectory.path(), "missing lifetime evidence was accepted", "lifetime evidence");

    QTemporaryDir scenarioDirectory;
    copyCampaign(scenarioDirectory, multiDirectory.path());
    mutateRawAndUpdateHash(scenarioDirectory.path(), firstRaw, [&](QJsonObject& root) {
        auto scenario = root.value("scenario").toObject();
        scenario.insert("releasePreparationBeforeBoundary", !scenario.value("releasePreparationBeforeBoundary").toBool());
        root.insert("scenario", scenario);
    });
    requireRejected(scenarioDirectory.path(), "scenario mismatch was accepted", "scenario mismatch");

    auto statisticsManifest = tests::defaultExploratoryPilotManifest();
    statisticsManifest.repetitions = 2;
    statisticsManifest.cases = {
        {QStringLiteral("preparation-retained"), {8ULL * 1024U * 1024U, 0, 80, 80, false, true}},
        {QStringLiteral("execution-retained"), {0, 8ULL * 1024U * 1024U, 80, 80, true, false}},
        {QStringLiteral("preparation-transient"), {8ULL * 1024U * 1024U, 0, 80, 80, true, true}}};
    statisticsManifest.modes = {{tests::QualificationSamplingMode::Periodic, 5}};
    QTemporaryDir statisticsSource;
    require(statisticsSource.isValid(), "statistics fixture unavailable");
    static_cast<void>(tests::runQualificationCampaign(statisticsManifest, statisticsSource.path()));
    const auto mutateGroupsAndReject = [&](const char* name,
                                           const std::function<void(QJsonObject&)>& mutation) {
        QTemporaryDir directory;
        copyCampaign(directory, statisticsSource.path());
        QFile file(directory.filePath(QStringLiteral("summary.json")));
        require(file.open(QIODevice::ReadOnly), "group mutation summary open failed");
        auto root = QJsonDocument::fromJson(file.readAll()).object();
        file.close();
        auto groups = root.value("groups").toObject();
        mutation(groups);
        root.insert("groups", groups);
        QSaveFile output(directory.filePath(QStringLiteral("summary.json")));
        require(output.open(QIODevice::WriteOnly), "group mutation summary write failed");
        const auto bytes = QJsonDocument(root).toJson(QJsonDocument::Indented);
        require(output.write(bytes) == bytes.size() && output.commit(), "group mutation summary commit failed");
        requireRejected(directory.path(), name, "campaign group statistics mismatch");
    };
    mutateGroupsAndReject("group add mutation was accepted", [](QJsonObject& groups) {
        groups.insert("unexpected/5", QJsonObject{});
    });
    mutateGroupsAndReject("group removal mutation was accepted", [](QJsonObject& groups) {
        groups.remove(QStringLiteral("preparation-retained/5"));
    });
    mutateGroupsAndReject("group rename mutation was accepted", [](QJsonObject& groups) {
        const auto value = groups.take(QStringLiteral("preparation-retained/5"));
        groups.insert(QStringLiteral("renamed/5"), value);
    });
    mutateGroupsAndReject("preparation peak ratio mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("preparation-retained/5").toObject();
        auto ratio = value.value("preparationPeakRatio").toObject();
        ratio.insert("median", ratio.value("median").toDouble() + 0.25);
        value.insert("preparationPeakRatio", ratio);
        groups.insert("preparation-retained/5", value);
    });
    mutateGroupsAndReject("execution peak ratio mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("execution-retained/5").toObject();
        auto ratio = value.value("executionPeakRatio").toObject();
        ratio.insert("max", ratio.value("max").toDouble() + 0.25);
        value.insert("executionPeakRatio", ratio);
        groups.insert("execution-retained/5", value);
    });
    mutateGroupsAndReject("Wilson interval mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("preparation-transient/5").toObject();
        auto interval = value.value("transientCaptureWilson95").toObject();
        interval.insert("low", interval.value("low").toDouble() + 0.01);
        value.insert("transientCaptureWilson95", interval);
        groups.insert("preparation-transient/5", value);
    });
    mutateGroupsAndReject("boundary residual mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("execution-retained/5").toObject();
        auto residual = value.value("executionBoundaryResidual").toObject();
        residual.insert("median", QString::number(residual.value("median").toString().toLongLong() + 1));
        value.insert("executionBoundaryResidual", residual);
        groups.insert("execution-retained/5", value);
    });
    mutateGroupsAndReject("sample distribution mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("preparation-retained/5").toObject();
        auto distribution = value.value("preparationSampleCountDistribution").toObject();
        distribution.insert("max", QString::number(distribution.value("max").toString().toULongLong() + 1));
        value.insert("preparationSampleCountDistribution", distribution);
        groups.insert("preparation-retained/5", value);
    });
    mutateGroupsAndReject("phase consistency mutation was accepted", [](QJsonObject& groups) {
        auto value = groups.value("preparation-retained/5").toObject();
        value.insert("phaseConsistencyNumerator", value.value("phaseConsistencyNumerator").toInt() - 1);
        groups.insert("preparation-retained/5", value);
    });
}

void testIndeterminateCountsAndRawCollision()
{
    auto manifest = tests::defaultExploratoryPilotManifest();
    manifest.repetitions = 1;
    manifest.cases.resize(1);
    manifest.modes = {{tests::QualificationSamplingMode::BoundaryOnlyControl, 5}};
    QTemporaryDir indeterminateDirectory;
    require(indeterminateDirectory.isValid(), "indeterminate fixture unavailable");
    qputenv("CRYPTOBENCH_M19_FORCE_INDETERMINATE", "1");
    const auto summary = tests::runQualificationCampaign(manifest, indeterminateDirectory.path());
    qunsetenv("CRYPTOBENCH_M19_FORCE_INDETERMINATE");
    require(summary.object().value("status") == QStringLiteral("failed") &&
                summary.object().value("plannedRuns").toInt() == 1 &&
                summary.object().value("attemptedRuns").toInt() == 1 &&
                summary.object().value("completedRuns").toInt() == 0 &&
                summary.object().value("failedRuns").toInt() == 0 &&
                summary.object().value("cancelledRuns").toInt() == 0 &&
                summary.object().value("missingRuns").toInt() == 0 &&
                summary.object().value("indeterminateRuns").toInt() == 1,
            "indeterminate campaign terminal counts were not mutually exclusive");
    try {
        tests::verifyQualificationCampaign(indeterminateDirectory.path());
    } catch (const std::invalid_argument& error) {
        throw std::runtime_error(std::string("indeterminate verifier rejected truthful campaign: ") + error.what());
    }

    QFile originalSummaryFile(indeterminateDirectory.filePath(QStringLiteral("summary.json")));
    require(originalSummaryFile.open(QIODevice::ReadOnly), "indeterminate summary open failed");
    const auto originalSummaryBytes = originalSummaryFile.readAll();
    originalSummaryFile.close();
    for (const auto field : {"attemptedRuns", "completedRuns", "indeterminateRuns"}) {
        QFile file(indeterminateDirectory.filePath(QStringLiteral("summary.json")));
        require(file.open(QIODevice::ReadOnly), "indeterminate summary mutation open failed");
        auto root = QJsonDocument::fromJson(file.readAll()).object();
        file.close();
        root.insert(QString::fromLatin1(field), root.value(QString::fromLatin1(field)).toInt() + 1);
        QSaveFile output(indeterminateDirectory.filePath(QStringLiteral("summary.json")));
        require(output.open(QIODevice::WriteOnly), "indeterminate summary mutation output failed");
        const auto bytes = QJsonDocument(root).toJson(QJsonDocument::Indented);
        require(output.write(bytes) == bytes.size() && output.commit(), "indeterminate summary mutation failed");
        bool rejected = false;
        try { tests::verifyQualificationCampaign(indeterminateDirectory.path()); }
        catch (const std::invalid_argument& error) {
            rejected = QString::fromUtf8(error.what()).contains(QStringLiteral("terminal counts/status"));
        }
        require(rejected, "indeterminate terminal count mutation was accepted");
        QSaveFile restore(indeterminateDirectory.filePath(QStringLiteral("summary.json")));
        require(restore.open(QIODevice::WriteOnly), "indeterminate summary restore failed");
        require(restore.write(originalSummaryBytes) == originalSummaryBytes.size() && restore.commit(),
                "indeterminate summary restore failed");
    }

    QTemporaryDir collisionDirectory;
    require(collisionDirectory.isValid(), "collision fixture unavailable");
    QDir().mkpath(collisionDirectory.filePath(QStringLiteral("runs")));
    const auto collisionPath = QDir(collisionDirectory.filePath(QStringLiteral("runs")))
        .filePath(QStringLiteral("00000-quiet-off-0.json"));
    QFile collisionFile(collisionPath);
    require(collisionFile.open(QIODevice::WriteOnly), "collision sentinel open failed");
    const QByteArray sentinel = "raw-sentinel";
    require(collisionFile.write(sentinel) == sentinel.size(), "collision sentinel write failed");
    collisionFile.close();
    bool collisionRejected = false;
    try { static_cast<void>(tests::runQualificationCampaign(manifest, collisionDirectory.path())); }
    catch (const std::invalid_argument& error) {
        collisionRejected = QString::fromUtf8(error.what()).contains(QStringLiteral("raw artifact collision"));
    }
    require(collisionRejected, "pre-existing raw artifact was overwritten or accepted");
    QFile verifySentinel(collisionPath);
    require(verifySentinel.open(QIODevice::ReadOnly) && verifySentinel.readAll() == sentinel,
            "pre-existing raw artifact bytes changed");
}

void testExecutionLifetimeStructure()
{
    const auto sourcePath = QFileInfo(
        QDir(QCoreApplication::applicationDirPath()).filePath(
            QStringLiteral("../../tests/MemoryV2SyntheticWorker.cpp"))).absoluteFilePath();
    QFile sourceFile(sourcePath);
    require(sourceFile.open(QIODevice::ReadOnly), "synthetic worker source unavailable for structural test");
    const auto source = QString::fromUtf8(sourceFile.readAll());
    const auto cpuPosition = source.indexOf(QStringLiteral("consumeCpuFor(5);"));
    const auto allocationPosition = source.indexOf(QStringLiteral("Allocation execution(scenario.executionBytes);"));
    const auto timerPosition = source.indexOf(QStringLiteral("executionLifetimeTimer.start();"));
    require(cpuPosition >= 0 && allocationPosition > cpuPosition && timerPosition > allocationPosition,
            "synthetic CPU work is inside the execution allocation lifetime");
}

void testConfirmatoryManifestB0()
{
    auto manifest = tests::defaultExploratoryPilotManifest();
    manifest.phase = QStringLiteral("confirmatory");
    manifest.campaignId = QStringLiteral("in-memory-confirmatory-test");
    manifest.repetitions = 1;
    const auto encoded = tests::encodeQualificationCampaignManifest(manifest);
    const auto reparsed = tests::parseQualificationCampaignManifest(encoded);
    require(reparsed.phase == QStringLiteral("confirmatory") &&
                reparsed.campaignId == manifest.campaignId &&
                reparsed.repetitions == 1 && reparsed.modes.size() == manifest.modes.size() &&
                reparsed.cases.size() == manifest.cases.size(),
            "confirmatory in-memory manifest round-trip changed semantics");
    require(manifest.modes.front().mode == tests::QualificationSamplingMode::BoundaryOnlyControl,
            "confirmatory OFF mode was not preserved");

    auto invalidPhase = encoded.object();
    invalidPhase.insert("phase", QStringLiteral("gate-c"));
    requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(invalidPhase))); },
                   "unsupported manifest phase was accepted");
    auto unknownField = encoded.object();
    unknownField.insert("unexpected", true);
    requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(QJsonDocument(unknownField))); },
                   "unknown confirmatory manifest field was accepted");
    const auto duplicatePhase = QStringLiteral(
        "{\"format\":\"cryptobenchmark-memory-v2-campaign\",\"schemaVersion\":1,"
        "\"campaignId\":\"m19.2-gate-b-confirmatory-v1\",\"phase\":\"confirmatory\","
        "\"\\u0070hase\":\"pilot\",\"seed\":\"2026101701\",\"repetitions\":20,"
        "\"modes\":[],\"cases\":[]}");
    requireInvalid([&] { static_cast<void>(tests::parseQualificationCampaignManifest(duplicatePhase)); },
                   "escaped duplicate phase field was accepted");
}

int validateFrozenManifestFile(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "frozen manifest could not be read");
    const auto bytes = file.readAll();
    const auto expectedHash = QStringLiteral(
        "460B8B483A4A2349EF3B455388C9676EC0DCFC90AF2A8E7643FF70C33274E707");
    require(QString::fromLatin1(
                QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()).toUpper() ==
                expectedHash,
            "frozen confirmatory manifest hash mismatch");
    const auto manifest = tests::parseQualificationCampaignManifest(QString::fromUtf8(bytes));
    require(manifest.campaignId == QStringLiteral("m19.2-gate-b-confirmatory-v1") &&
                manifest.phase == QStringLiteral("confirmatory") &&
                manifest.seed == 2'026'101'701ULL && manifest.repetitions == 20 &&
                manifest.cases.size() == 12 && manifest.modes.size() == 4,
            "frozen confirmatory manifest identity mismatch");
    require(manifest.modes[0].mode == tests::QualificationSamplingMode::BoundaryOnlyControl &&
                manifest.modes[1].intervalMilliseconds == 5 &&
                manifest.modes[2].intervalMilliseconds == 2 &&
                manifest.modes[3].intervalMilliseconds == 1,
            "frozen confirmatory mode ordering mismatch");
    struct ExpectedCase {
        const char* id;
        std::uint64_t preparation;
        std::uint64_t execution;
        std::uint32_t preparationHold;
        std::uint32_t executionHold;
        bool releasePreparation;
        bool releaseExecution;
    };
    const std::array<ExpectedCase, 12> expected{{
        ExpectedCase{"quiet", 0, 0, 80, 80, true, true},
        {"preparation-retained", 8388608, 0, 80, 80, false, true},
        {"execution-retained", 0, 8388608, 80, 80, true, false},
        {"preparation-transient-20ms", 8388608, 0, 20, 80, true, true},
        {"execution-transient-20ms", 0, 8388608, 80, 20, true, true},
        {"distinct-phases", 8388608, 16777216, 80, 80, false, false},
        {"preparation-transient-1ms", 8388608, 0, 1, 80, true, true},
        {"execution-transient-1ms", 0, 8388608, 80, 1, true, true},
        {"preparation-transient-2ms", 8388608, 0, 2, 80, true, true},
        {"execution-transient-2ms", 0, 8388608, 80, 2, true, true},
        {"preparation-transient-5ms", 8388608, 0, 5, 80, true, true},
        {"execution-transient-5ms", 0, 8388608, 80, 5, true, true}}};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto& actual = manifest.cases[index];
        const auto& wanted = expected[index];
        require(actual.caseId == QString::fromLatin1(wanted.id) &&
                    actual.scenario.preparationBytes == wanted.preparation &&
                    actual.scenario.executionBytes == wanted.execution &&
                    actual.scenario.preparationHoldMilliseconds == wanted.preparationHold &&
                    actual.scenario.executionHoldMilliseconds == wanted.executionHold &&
                    actual.scenario.releasePreparationBeforeBoundary == wanted.releasePreparation &&
                    actual.scenario.releaseExecutionBeforeEnd == wanted.releaseExecution,
                "frozen confirmatory case mismatch");
    }
    require(manifest.cases.size() * manifest.modes.size() * manifest.repetitions == 960,
            "frozen confirmatory planned count is not 960");
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        const auto arguments = application.arguments();
        if (arguments.size() == 3 && arguments[1] == QStringLiteral("--validate-frozen-manifest")) {
            return validateFrozenManifestFile(arguments[2]);
        }
        if (arguments.size() == 3 && arguments[1] == QStringLiteral("--smoke-output")) {
            return smokeToPath(arguments[2]);
        }
        if (arguments.size() == 3 && arguments[1] == QStringLiteral("--pilot-output")) {
            const auto summary = tests::runQualificationCampaign(
                tests::defaultExploratoryPilotManifest(), arguments[2]);
            tests::verifyQualificationCampaign(arguments[2]);
            return summary.object().value("status") == QStringLiteral("completed") ? 0 : 1;
        }
        if (arguments.size() == 5 && arguments[1] == QStringLiteral("--manifest") &&
            arguments[3] == QStringLiteral("--output-dir")) {
            QFile file(arguments[2]);
            if (!file.open(QIODevice::ReadOnly)) return 2;
            const auto manifest = tests::parseQualificationCampaignManifest(
                QString::fromUtf8(file.readAll()));
            const auto summary = tests::runQualificationCampaign(manifest, arguments[4]);
            tests::verifyQualificationCampaign(arguments[4]);
            return summary.object().value("status") == QStringLiteral("completed") ? 0 : 1;
        }
        if (arguments.size() != 1) return 2;
        testNoAllocationBoundaryOnlyAndArtifact();
        testPreparationAndExecutionObservability();
        testReleasedPhaseAllocationsAndIntervals();
        testTimingAndFreshWorkerRepetitions();
        testFailureCancellationAndParserRejection();
        testCampaignManifestSummaryAndCollision();
        testCampaignVerifierRejectsPersistedMutations();
        testIndeterminateCountsAndRawCollision();
        testExecutionLifetimeStructure();
        testConfirmatoryManifestB0();
        std::cout << "PASS Memory v2 qualification foundation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
