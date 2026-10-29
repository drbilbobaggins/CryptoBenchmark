#include "M23PilotTests.h"

#include "M23CalibrationHarness.h"
#include "M23PilotAnalyzer.h"
#include "M23PilotPlan.h"

#include <cryptobench/application/RuntimeCalibrationInventory.h>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

namespace application = cryptobench::application;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void expectRejected(
    const std::vector<QJsonObject>& evidence,
    std::string_view message,
    bool allowSynthetic = true)
{
    bool rejected = false;
    try {
        static_cast<void>(analyzeM23PilotEvidence(evidence, allowSynthetic));
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, message);
}

const QJsonObject& findModel(
    const QJsonObject& report,
    std::string_view caseId)
{
    const auto models =
        report.value(QStringLiteral("affineAndExactModelCandidates")).toArray();
    const auto found = std::ranges::find_if(
        models,
        [&](const QJsonValue& value) {
            return value.toObject().value(QStringLiteral("caseId")).toString()
                == QString::fromUtf8(
                    caseId.data(), static_cast<qsizetype>(caseId.size()));
        });
    require(found != models.end(), "pilot analysis omitted an expected model candidate");
    static thread_local QJsonObject result;
    result = found->toObject();
    return result;
}

QJsonObject withEntryMutation(
    QJsonObject evidence,
    const std::function<void(QJsonObject&)>& mutation)
{
    auto entries = evidence.value(QStringLiteral("entries")).toArray();
    auto entry = entries[0].toObject();
    mutation(entry);
    entries[0] = entry;
    evidence.insert("entries", entries);
    return evidence;
}

void verifyExactCaseMatrixAndPlan()
{
    constexpr std::array<std::string_view, 12> expectedCases{
        "rsa-3072-keygen/keyGen/noSignature",
        "rsa-pss-3072-sha256/sign/prehashed",
        "rsa-pss-3072-sha256/verify/message",
        "ed25519/sign/message",
        "ml-dsa-65/sign/message",
        "slh-dsa-sha2-128s/sign/message",
        "x25519/derive/keyEstablishment",
        "ml-kem-768/decapsulate/keyEstablishment",
        "aes-256-gcm/encrypt/aead",
        "aes-256-gcm/decrypt/aead",
        "sha256/hash/hashXof",
        "shake256-64bytes/xof/hashXof"};
    std::set<std::string> seenCases;
    for (const auto& row : m23PilotPlanRows()) {
        seenCases.emplace(application::runtimeCalibrationCaseId(row.calibrationCase));
    }
    require(seenCases.size() == expectedCases.size(),
        "M23.2 pilot matrix does not contain exactly twelve canonical cases");
    for (const auto expected : expectedCases) {
        require(seenCases.contains(std::string(expected)),
            "M23.2 pilot matrix omitted a required canonical typed case");
    }

    const auto planBytes = m23PilotPlanManifest();
    require(planBytes == m23PilotPlanManifest(),
        "M23.2 pilot plan manifest is not deterministic");
    require(m23PilotPlanSha256()
            == "f38e4d0cdeee79fbfe0f68876d5a6fb15bbcd92bd5a2e7cb8df9b524657a34fc",
        "M23.2 pilot plan changed without a reviewed identity update");
    const auto plan = QJsonDocument::fromJson(planBytes).object();
    require(plan.value(QStringLiteral("format"))
            == QStringLiteral("cryptobenchmark-m23-pilot-plan")
            && plan.value(QStringLiteral("measurementAuthorized")) == false
            && plan.value(QStringLiteral("status"))
                == QStringLiteral("CANDIDATE_ONLY_NOT_AUTHORIZED"),
        "M23.2 pilot plan is not explicitly unauthorized");
    require(m23PilotPlanSha256() != m23CalibrationPlanSha256(),
        "M23.2 pilot plan reused the M23.1 candidate-plan identity");

    std::set<std::string> rowIds;
    std::set<std::tuple<std::string, std::string, std::uint64_t,
        std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t>> referenceCoordinates;
    std::set<std::tuple<std::string, std::string, std::uint64_t,
        std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t>> holdoutCoordinates;
    for (const auto& row : m23PilotPlanRows()) {
        require(rowIds.emplace(row.rowId).second,
            "M23.2 pilot plan contains duplicate row IDs");
        if (row.status == M23PilotPlanStatus::Candidate) {
            require(row.iterationsPerRun <= 100
                    && row.runs <= 10
                    && row.samplingIntervalMilliseconds >= 1
                    && row.samplingIntervalMilliseconds <= 5
                    && (!row.inputBytes
                        || *row.inputBytes <= 1'048'576),
                "M23.2 initial candidate row exceeds its conservative cap");
        }
        const auto coordinate = std::tuple{
            application::runtimeCalibrationCaseId(row.calibrationCase),
            toStableString(row.probeKind),
            row.inputBytes.value_or(0),
            row.iterationsPerRun,
            row.runs,
            row.samplingIntervalMilliseconds,
            row.repetition};
        if (row.role == M23PilotRole::Reference) {
            referenceCoordinates.emplace(coordinate);
        } else if (row.role == M23PilotRole::Holdout) {
            holdoutCoordinates.emplace(coordinate);
        }
    }
    for (const auto& coordinate : holdoutCoordinates) {
        require(!referenceCoordinates.contains(coordinate),
            "M23.2 fit/reference and independent holdout coordinates overlap");
    }

    const auto batchShapes = m23PilotBatchShapes();
    require(batchShapes.size() == 4,
        "M23.2 pilot plan must preserve E=1,3,10,20 Batch candidates");
    for (const auto& shape : batchShapes) {
        require(shape.entries.size() == (shape.batchId == "batch-e1-sha256"
                    ? 1U
                    : shape.batchId == "batch-e3-sha256"
                        ? 3U
                        : shape.batchId == "batch-e10-sha256"
                            ? 10U
                            : 20U),
            "M23.2 Batch shape entry count changed");
        require((shape.entries.size() <= 3)
                == (shape.status == M23PilotPlanStatus::Candidate),
            "risky M23.2 Batch shape was not deferred");
    }
    const auto deferred = m23PilotDeferredProbeIds();
    require(std::ranges::any_of(deferred, [](const std::string& value) {
                return value.find("inputBytes=16777216") != std::string::npos;
            })
            && std::ranges::any_of(deferred, [](const std::string& value) {
                return value.find("inputBytes=268435456") != std::string::npos;
            }),
        "larger workload feasibility points were not explicitly deferred");

    const auto dryRun = QJsonDocument::fromJson(
        m23PilotDryRunReport()).object();
    require(dryRun.value(QStringLiteral("reportLabel"))
            == QStringLiteral("DRY RUN - NO OBSERVATIONS")
            && dryRun.value(QStringLiteral("measurementAuthorized")) == false,
        "pilot dry-run report implies authorization or measurement");
    const auto candidateRows =
        dryRun.value(QStringLiteral("candidatePlan")).toObject()
            .value(QStringLiteral("rows")).toArray();
    const auto candidateShapes =
        dryRun.value(QStringLiteral("candidatePlan")).toObject()
            .value(QStringLiteral("batchShapes")).toArray();
    const auto deferredProbes =
        dryRun.value(QStringLiteral("candidatePlan")).toObject()
            .value(QStringLiteral("deferredProbes")).toArray();
    require(candidateRows.size()
                == dryRun.value(QStringLiteral("candidateObservationRowCount")).toInt()
                + dryRun.value(QStringLiteral("deferredObservationRowCount")).toInt()
            && dryRun.value(QStringLiteral("candidateObservationRowCount")).toInt() == 158
            && dryRun.value(QStringLiteral("deferredObservationRowCount")).toInt() == 3
            && candidateShapes.size() == 4
            && deferredProbes.size() > 0,
        "dry-run omitted exact candidate/deferred rows or Batch E shapes");
}

void verifyApprovalValidation()
{
    const auto candidate = QJsonDocument::fromJson(
        m23PilotPlanManifest()).object();
    const auto synthetic = syntheticApprovedM23PilotPlanForTests();
    require(!validateApprovedM23PilotPlan(synthetic).has_value(),
        "synthetic approval wrapper was accepted as a human GO");
    require(validateApprovedM23PilotPlan(synthetic, true).has_value(),
        "synthetic approval wrapper did not validate in test-only mode");

    auto wrongHash = synthetic;
    wrongHash.insert("candidatePlanSha256", QString(64, QLatin1Char('a')));
    require(!validateApprovedM23PilotPlan(wrongHash, true).has_value(),
        "approved pilot plan with wrong candidate SHA was accepted");

    auto alteredPlan = synthetic;
    auto planObject = candidate;
    auto rows = planObject.value(QStringLiteral("rows")).toArray();
    auto row = rows[0].toObject();
    row.insert("inputBytes", QStringLiteral("16777216"));
    rows[0] = row;
    planObject.insert("rows", rows);
    alteredPlan.insert("plan", planObject);
    require(!validateApprovedM23PilotPlan(alteredPlan, true).has_value(),
        "approved pilot plan with an unreviewed row mutation was accepted");

    auto missingGo = synthetic;
    missingGo.insert("approvalStatus", QStringLiteral("REVISE"));
    require(!validateApprovedM23PilotPlan(missingGo, true).has_value(),
        "non-GO pilot plan was accepted");
}

void verifyApprovedGroupsAndDeferredRows()
{
    const auto shapes = m23PilotBatchShapes();
    const auto e3 = m23PilotExecutionGroup("batch-e3-sha256");
    require(e3.has_value() && e3->batchShape && e3->entries.size() == 3,
        "approved E=3 multi-entry Batch shape is unavailable");
    require(!m23PilotExecutionGroup("batch-e10-sha256").has_value()
            && !m23PilotExecutionGroup("batch-e20-sha256").has_value(),
        "deferred E=10/E=20 shapes are executable without feasibility approval");
    require(shapes[0].status == M23PilotPlanStatus::Candidate
            && shapes[1].status == M23PilotPlanStatus::Candidate,
        "E=1/E=3 initial Batch shapes are not candidates");

    const auto rows = m23PilotPlanRows();
    const auto deferredRow = std::ranges::find_if(
        rows,
        [](const M23PilotPlanRow& row) {
            return row.rowId.find("rsa-3072-keygen") != std::string::npos
                && row.role == M23PilotRole::Holdout;
        });
    require(deferredRow != rows.end()
            && deferredRow->status == M23PilotPlanStatus::Deferred
            && !m23PilotExecutionGroup(deferredRow->rowId).has_value(),
        "risky RSA KeyGen N holdout can run before feasibility review");
}

void verifySyntheticPilotAnalysis()
{
    const auto evidence = syntheticM23PilotEvidenceForTests();
    const auto report = analyzeM23PilotEvidence(evidence, true);
    require(report.value(QStringLiteral("evidenceLabel"))
            == QStringLiteral("SYNTHETIC / NOT QUALIFIED"),
        "synthetic pilot analyzer output lacks its nonqualification label");
    require(report.value(QStringLiteral("pilotDecision"))
            == QStringLiteral("PENDING HUMAN REVIEW")
            && report.value(QStringLiteral("modelSelection"))
                == QStringLiteral("DEFERRED TO SEPARATE HUMAN PILOT REVIEW"),
        "synthetic analysis made an unauthorized model or pilot decision");

    const auto& shaModel = findModel(report, "sha256/hash/hashXof");
    require(shaModel.value(QStringLiteral("modelStatus"))
            == QStringLiteral("AFFINE_CANDIDATE"),
        "synthetic affine candidate was not analyzed");
    require(std::abs(shaModel.value(
                QStringLiteral("interceptNanosecondsPerOperation")).toDouble()
                - 10.0) < 1e-8
            && std::abs(shaModel.value(
                QStringLiteral("slopeNanosecondsPerBytePerOperation")).toDouble()
                - 2.0) < 1e-8,
        "synthetic affine fit did not recover its explicit test-only coefficients");
    const auto fitIds = shaModel.value(QStringLiteral("fitRowIds")).toArray();
    const auto holdoutIds = shaModel.value(QStringLiteral("holdoutRowIds")).toArray();
    for (const auto& fitId : fitIds) {
        for (const auto& holdoutId : holdoutIds) {
            require(fitId.toString() != holdoutId.toString(),
                "pilot analyzer leaked a holdout row into its fit");
        }
    }
    require(!holdoutIds.isEmpty(),
        "synthetic analyzer did not evaluate independent size holdouts");
    require(!report.value(QStringLiteral("nScalingDiagnostics")).toArray().isEmpty()
            && !report.value(QStringLiteral("mSensitivityDiagnostics")).toArray().isEmpty()
            && !report.value(QStringLiteral("samplingSensitivityDiagnostics"))
                .toArray().isEmpty(),
        "synthetic analyzer omitted N/M/sampling sensitivity diagnostics");
    const auto nDiagnostics =
        report.value(QStringLiteral("nScalingDiagnostics")).toArray();
    std::set<std::string> nDiagnosticCases;
    for (const auto& diagnostic : nDiagnostics) {
        nDiagnosticCases.emplace(
            diagnostic.toObject().value(QStringLiteral("caseId"))
                .toString().toStdString());
    }
    require(nDiagnosticCases.contains("x25519/derive/keyEstablishment")
            && nDiagnosticCases.contains("ed25519/sign/message"),
        "fixed-mode and variable-size N holdouts lost their diagnostics");
    require(report.value(QStringLiteral("holdoutDiagnosticCount")).toInt() == 4
            && report.value(QStringLiteral("holdoutFactorOutlierCount")).toInt() == 0,
        "fixed-mode N holdout was counted twice or variable-size N holdout was omitted");

    const auto models =
        report.value(QStringLiteral("batchOverheadModelCandidates")).toArray();
    require(models.size() == 3
            && models[2].toObject().value(QStringLiteral("status"))
                == QStringLiteral("INSUFFICIENT_E_SHAPES"),
        "Batch triangular model was prematurely selected or overfit");
    require(report.value(QStringLiteral("resourceAndWallCaps")).isObject(),
        "pilot analysis omitted operational resource guardrails");
    require(report.value(QStringLiteral("minimumObservedAvailableDiskBytes"))
                .toString() == QStringLiteral("2147483648")
            && report.value(QStringLiteral("minimumObservedAvailableMemoryBytes"))
                .toString() == QStringLiteral("4294967296"),
        "synthetic resource feasibility report lost captured preflight bounds");
}

void verifyEvidenceRejections()
{
    auto evidence = syntheticM23PilotEvidenceForTests();
    expectRejected(evidence, "synthetic pilot data was accepted without fixture mode", false);

    auto syntheticClaimedReal = evidence;
    syntheticClaimedReal[0].insert(
        "evidenceKind", QStringLiteral("realPilotObservation"));
    expectRejected(syntheticClaimedReal,
        "synthetic approval reference was accepted as real evidence", false);

    auto incomplete = evidence;
    incomplete[0].insert("status", QStringLiteral("incomplete"));
    expectRejected(incomplete, "incomplete pilot evidence was accepted");

    auto badHash = evidence;
    badHash[0].insert("environmentSha256", QString(64, QLatin1Char('a')));
    expectRejected(badHash, "pilot evidence with a bad environment SHA was accepted");

    auto insufficientResources = evidence;
    auto resourcePreflight =
        insufficientResources[0].value(QStringLiteral("resourcePreflight")).toObject();
    resourcePreflight.insert("availableDiskBytes", QStringLiteral("1"));
    insufficientResources[0].insert("resourcePreflight", resourcePreflight);
    expectRejected(insufficientResources,
        "pilot evidence below the proposed disk cap was accepted");

    auto badRun = evidence;
    auto entries = badRun[0].value(QStringLiteral("entries")).toArray();
    auto entry = entries[0].toObject();
    auto runs = entry.value(QStringLiteral("runObservations")).toArray();
    auto run = runs[0].toObject();
    run.insert("controllerElapsedNanoseconds", QStringLiteral("1"));
    runs[0] = run;
    entry.insert("runObservations", runs);
    entries[0] = entry;
    badRun[0].insert("entries", entries);
    expectRejected(badRun, "pilot evidence with R < B was accepted");

    auto checkpointOverlap = evidence;
    auto batch = checkpointOverlap[0].value(QStringLiteral("batch")).toObject();
    auto checkpoints =
        batch.value(QStringLiteral("checkpointIntervals")).toArray();
    auto initial = checkpoints[0].toObject();
    const auto firstEntryStart = checkpointOverlap[0]
        .value(QStringLiteral("entries")).toArray()[0].toObject()
        .value(QStringLiteral("entryStartOffsetNanoseconds")).toString().toULongLong();
    initial.insert("endOffsetNanoseconds", QString::number(firstEntryStart + 1));
    checkpoints[0] = initial;
    batch.insert("checkpointIntervals", checkpoints);
    checkpointOverlap[0].insert("batch", batch);
    expectRejected(checkpointOverlap,
        "checkpoint ownership overlapping an entry was accepted");

    auto finalCheckpointOverlap = evidence;
    auto finalBatch =
        finalCheckpointOverlap[0].value(QStringLiteral("batch")).toObject();
    auto finalCheckpoints =
        finalBatch.value(QStringLiteral("checkpointIntervals")).toArray();
    const auto evidenceEntries =
        finalCheckpointOverlap[0].value(QStringLiteral("entries")).toArray();
    const auto lastEntry = evidenceEntries
        .at(evidenceEntries.size() - 1).toObject();
    const auto lastEntryEnd = lastEntry
        .value(QStringLiteral("entryEndOffsetNanoseconds")).toString()
        .toULongLong();
    require(lastEntryEnd > 0,
        "synthetic final entry boundary must be nonzero");
    auto finalCheckpoint = finalCheckpoints
        .at(finalCheckpoints.size() - 1).toObject();
    finalCheckpoint.insert(
        "startOffsetNanoseconds", QString::number(lastEntryEnd - 1));
    finalCheckpoints[finalCheckpoints.size() - 1] = finalCheckpoint;
    finalBatch.insert("checkpointIntervals", finalCheckpoints);
    finalCheckpointOverlap[0].insert("batch", finalBatch);
    expectRejected(finalCheckpointOverlap,
        "final checkpoint ownership overlapping the last entry was accepted");

    auto duplicateGroup = evidence;
    duplicateGroup.push_back(duplicateGroup.front());
    expectRejected(duplicateGroup, "duplicate pilot observation group was accepted");
}

} // namespace

void runM23PilotPreparationTests()
{
    verifyExactCaseMatrixAndPlan();
    verifyApprovalValidation();
    verifyApprovedGroupsAndDeferredRows();
    verifySyntheticPilotAnalysis();
    verifyEvidenceRejections();
}

} // namespace cryptobench::tests
