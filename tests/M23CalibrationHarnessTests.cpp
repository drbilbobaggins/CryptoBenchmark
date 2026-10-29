#include "M23CalibrationHarness.h"
#include "M23PilotAnalyzer.h"
#include "M23PilotTests.h"

#include <cryptobench/application/RuntimeCalibrationInventory.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidator.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStringList>

#include <cryptobench/application/StrictJsonPreflight.h>

#include <charconv>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace {

namespace application = cryptobench::application;
namespace core = cryptobench::core;
using cryptobench::tests::M23CalibrationPlanEntry;
using cryptobench::tests::M23ObservationRequest;
using cryptobench::tests::M23ObservationRole;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void expectRejected(
    const QJsonObject& evidence,
    std::string_view message,
    bool allowSyntheticFixture = true)
{
    bool rejected = false;
    try {
        cryptobench::tests::validateM23ObservationEvidence(
            evidence, allowSyntheticFixture);
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, message);
}

std::string planDimension(const M23CalibrationPlanEntry& entry)
{
    return entry.inputBytes
        ? std::to_string(*entry.inputBytes)
        : "N=" + std::to_string(entry.iterationsPerRun);
}

void verifyRegistryInventory()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    require(inventory.profileIds.size() == 72, "registry profile snapshot changed");
    require(inventory.profileOperationCount == 139,
        "registry profile-operation snapshot changed");
    require(inventory.cases.size() == 175,
        "registry typed-case snapshot changed");
    require(inventory.fixedInputCaseCount == 78,
        "registry fixed-input snapshot changed");
    require(inventory.variableInputCaseCount == 97,
        "registry variable-input snapshot changed");

    std::set<std::string> profileIds(
        inventory.profileIds.begin(), inventory.profileIds.end());
    require(profileIds.size() == inventory.profileIds.size(),
        "registry inventory contains duplicate profile IDs");
    std::set<std::tuple<int, int, int>> identities;
    for (const auto& calibrationCase : inventory.cases) {
        require(identities.emplace(
                static_cast<int>(calibrationCase.profileId),
                static_cast<int>(calibrationCase.operation),
                static_cast<int>(calibrationCase.inputKind)).second,
            "registry inventory contains a duplicate typed case");

        core::PrimitiveConfig parameters;
        switch (calibrationCase.inputKind) {
        case application::RuntimeCalibrationInputKind::NoSignature:
            parameters = core::SignatureConfig{core::NoSignatureInput{}};
            break;
        case application::RuntimeCalibrationInputKind::Prehashed:
            parameters = core::SignatureConfig{core::PrehashedInput{}};
            break;
        case application::RuntimeCalibrationInputKind::Message:
            parameters = core::SignatureConfig{core::MessageInput{1}};
            break;
        case application::RuntimeCalibrationInputKind::KeyEstablishment:
            parameters = core::KeyEstablishmentConfig{};
            break;
        case application::RuntimeCalibrationInputKind::Aead:
            parameters = core::AeadConfig{1};
            break;
        case application::RuntimeCalibrationInputKind::HashXof:
            parameters = core::HashConfig{0};
            break;
        }
        const core::BenchmarkConfig config{
            calibrationCase.profileId,
            calibrationCase.operation,
            1,
            1,
            std::move(parameters)};
        core::ValidationResult validation;
        require(core::ConfigValidator{}.validateAndCreate(config, validation).has_value(),
            "registry inventory contains an illegal typed mode");
        const auto expectedVariableSize =
            calibrationCase.inputKind == application::RuntimeCalibrationInputKind::Message
            || calibrationCase.inputKind == application::RuntimeCalibrationInputKind::Aead
            || calibrationCase.inputKind == application::RuntimeCalibrationInputKind::HashXof;
        require(calibrationCase.hasVariableInputSize == expectedVariableSize,
            "registry inventory size classification conflicts with its typed mode");
    }

    const auto manifest = application::runtimeCalibrationInventoryManifest(inventory);
    require(!manifest.isEmpty(), "registry manifest is empty");
    const auto hash = application::runtimeCalibrationInventorySha256(inventory);
    require(hash.size() == 64, "registry manifest SHA-256 is malformed");
    require(hash == QByteArrayLiteral(
                "1fcc10b1d78b45556cf3989125228799952b0bc11aae2c0953401e3b9b090cf1"),
        "registry manifest differs from the reviewed stable snapshot");
}

void verifyCandidatePlan()
{
    const auto entries = cryptobench::tests::m23CalibrationPlanEntries();
    require(entries.size() == 2505,
        "M23 candidate plan row count changed unexpectedly");
    const auto first = cryptobench::tests::m23CalibrationPlanManifest();
    const auto second = cryptobench::tests::m23CalibrationPlanManifest();
    require(first == second, "M23 candidate plan is not deterministic");
    require(cryptobench::tests::m23CalibrationPlanSha256()
            == QByteArrayLiteral(
                "1195c2cfbc932b3b29f5ce1b1f3e07bd0272a37990e58132572ea459695c69c6"),
        "M23 candidate plan differs from its reviewed deterministic snapshot");

    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(first, &error);
    require(error.error == QJsonParseError::NoError && document.isObject(),
        "M23 candidate plan is not valid JSON");
    const auto root = document.object();
    require(root.value(QStringLiteral("measurementAuthorized")) == false,
        "M23 candidate plan unexpectedly authorizes measurements");
    require(root.value(QStringLiteral("status")) == QStringLiteral("candidate-only"),
        "M23 candidate plan is not clearly marked provisional");
    require(root.value(QStringLiteral("entries")).toArray().size()
            == static_cast<qsizetype>(entries.size()),
        "M23 candidate plan manifest lost rows");

    std::set<std::uint32_t> orders;
    std::map<std::string, std::set<std::string>> references;
    std::map<std::string, std::set<std::string>> holdouts;
    for (const auto& entry : entries) {
        require(entry.runs == 1 && entry.samplingIntervalMilliseconds == 5,
            "M23 candidate plan defaults drifted");
        require(entry.repetition > 0 && entry.order > 0,
            "M23 candidate plan omitted repetition or execution order");
        require(orders.emplace(entry.order).second,
            "M23 candidate plan contains a duplicate order index");
        auto& dimensions = entry.role == M23ObservationRole::Reference
            ? references[application::runtimeCalibrationCaseId(entry.calibrationCase)]
            : holdouts[application::runtimeCalibrationCaseId(entry.calibrationCase)];
        dimensions.emplace(planDimension(entry));
    }
    require(orders.size() == entries.size()
            && *orders.begin() == 1
            && *orders.rbegin() == entries.size(),
        "M23 candidate plan order is not a complete permutation");
    require(references.size() == 175 && holdouts.size() == 175,
        "M23 plan does not separate reference and holdout cases");

    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    for (const auto& calibrationCase : inventory.cases) {
        const auto caseId = application::runtimeCalibrationCaseId(calibrationCase);
        const auto reference = references.find(caseId);
        const auto holdout = holdouts.find(caseId);
        require(reference != references.end() && holdout != holdouts.end(),
            "M23 plan omits a canonical case from either split");
        for (const auto& value : reference->second) {
            require(!holdout->second.contains(value),
                "M23 reference and holdout dimensions overlap");
        }
        const auto expectedReferenceDimensions =
            calibrationCase.hasVariableInputSize ? 4U : 1U;
        const auto expectedHoldoutDimensions =
            calibrationCase.hasVariableInputSize ? 3U : 1U;
        require(reference->second.size() == expectedReferenceDimensions
                && holdout->second.size() == expectedHoldoutDimensions,
            "M23 plan does not contain its candidate reference/holdout dimensions");
    }
}

void verifyEvidenceValidation()
{
    const auto valid = cryptobench::tests::syntheticM23ObservationEvidence();
    cryptobench::tests::validateM23ObservationEvidence(valid, true);
    expectRejected(valid,
        "synthetic M23 fixture was accepted as real campaign evidence", false);

    auto failed = valid;
    failed.insert("status", QStringLiteral("failed"));
    expectRejected(failed, "failed M23 evidence was accepted");

    auto incomplete = valid;
    incomplete.insert("runObservations", QJsonArray{});
    expectRejected(incomplete, "incomplete M23 worker evidence was accepted");

    auto smallerControllerTime = valid;
    auto runs = smallerControllerTime.value(
        QStringLiteral("runObservations")).toArray();
    auto run = runs[0].toObject();
    run.insert("controllerElapsedNanoseconds", QStringLiteral("49"));
    runs[0] = run;
    smallerControllerTime.insert("runObservations", runs);
    expectRejected(smallerControllerTime,
        "M23 evidence with controller time below the measured block was accepted");

    auto duplicateWorker = valid;
    runs = duplicateWorker.value(QStringLiteral("runObservations")).toArray();
    run = runs[0].toObject();
    run.insert("runIndex", 1);
    runs.append(run);
    auto duplicateCase = duplicateWorker.value(QStringLiteral("case")).toObject();
    duplicateCase.insert("runs", 2);
    duplicateWorker.insert("case", duplicateCase);
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [&](const application::RuntimeCalibrationCase& value) {
            return application::runtimeCalibrationCaseId(value)
                == duplicateCase.value(QStringLiteral("caseId")).toString().toStdString();
        });
    require(calibrationCase != inventory.cases.end(),
        "M23 duplicate-worker test case is missing");
    const M23ObservationRequest duplicateRequest{
        *calibrationCase, M23ObservationRole::Reference, 32, 1, 2, 5, 1, 1};
    duplicateWorker.insert("observationId", QString::fromStdString(
        cryptobench::tests::m23ObservationIdentity(
            duplicateRequest,
            valid.value(QStringLiteral("applicationSha256")).toString().toStdString(),
            valid.value(QStringLiteral("workerSha256")).toString().toStdString(),
            valid.value(QStringLiteral("environmentSha256")).toString().toStdString())));
    duplicateWorker.insert("entryElapsedNanoseconds", QStringLiteral("225"));
    duplicateWorker.insert("entryEndOffsetNanoseconds", QStringLiteral("265"));
    duplicateWorker.insert("entryOutsideRunNanoseconds", QStringLiteral("25"));
    duplicateWorker.insert("batchElapsedNanoseconds", QStringLiteral("315"));
    duplicateWorker.insert("batchAfterEntryNanoseconds", QStringLiteral("50"));
    duplicateWorker.insert("batchOnlyResidualNanoseconds", QStringLiteral("90"));
    auto checkpointIntervals = duplicateWorker.value(
        QStringLiteral("checkpointIntervals")).toArray();
    auto finalCheckpoint = checkpointIntervals[1].toObject();
    finalCheckpoint.insert("startOffsetNanoseconds", QStringLiteral("275"));
    finalCheckpoint.insert("endOffsetNanoseconds", QStringLiteral("305"));
    checkpointIntervals[1] = finalCheckpoint;
    duplicateWorker.insert("checkpointIntervals", checkpointIntervals);
    duplicateWorker.insert("runObservations", runs);
    expectRejected(duplicateWorker,
        "M23 evidence with repeated worker identity was accepted");

    auto inconsistentEntry = valid;
    inconsistentEntry.insert("entryOutsideRunNanoseconds", QStringLiteral("24"));
    expectRejected(inconsistentEntry,
        "M23 evidence with inconsistent entry timing was accepted");

    auto inconsistentBatch = valid;
    inconsistentBatch.insert("batchOnlyResidualNanoseconds", QStringLiteral("24"));
    expectRejected(inconsistentBatch,
        "M23 evidence with inconsistent Batch timing was accepted");

    auto initialCheckpointOverlap = valid;
    checkpointIntervals = initialCheckpointOverlap.value(
        QStringLiteral("checkpointIntervals")).toArray();
    auto initialCheckpoint = checkpointIntervals[0].toObject();
    initialCheckpoint.insert("endOffsetNanoseconds", QStringLiteral("41"));
    checkpointIntervals[0] = initialCheckpoint;
    initialCheckpointOverlap.insert("checkpointIntervals", checkpointIntervals);
    expectRejected(initialCheckpointOverlap,
        "initial checkpoint work overlapping the entry was accepted");

    auto finalCheckpointOverlap = valid;
    checkpointIntervals = finalCheckpointOverlap.value(
        QStringLiteral("checkpointIntervals")).toArray();
    finalCheckpoint = checkpointIntervals[1].toObject();
    finalCheckpoint.insert("startOffsetNanoseconds", QStringLiteral("149"));
    checkpointIntervals[1] = finalCheckpoint;
    finalCheckpointOverlap.insert("checkpointIntervals", checkpointIntervals);
    expectRejected(finalCheckpointOverlap,
        "final checkpoint work overlapping the entry was accepted");

    auto malformedDecimal = valid;
    malformedDecimal.insert("entryElapsedNanoseconds", QStringLiteral("01"));
    expectRejected(malformedDecimal,
        "M23 evidence with a non-canonical decimal integer was accepted");

    auto invalidSha = valid;
    invalidSha.insert("workerSha256", QStringLiteral("not-a-sha256"));
    expectRejected(invalidSha,
        "M23 evidence with invalid worker provenance was accepted");

    auto invalidRole = valid;
    auto caseObject = invalidRole.value(QStringLiteral("case")).toObject();
    caseObject.insert("role", QStringLiteral("reference-and-holdout"));
    invalidRole.insert("case", caseObject);
    expectRejected(invalidRole, "M23 evidence with an invalid split role was accepted");
}

void verifyStableObservationIdentity()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto found = std::ranges::find_if(
        inventory.cases,
        [](const application::RuntimeCalibrationCase& calibrationCase) {
            return calibrationCase.profileId == core::AlgorithmProfileId::Ed25519
                && calibrationCase.operation == core::BenchmarkOperation::Sign
                && calibrationCase.inputKind
                    == application::RuntimeCalibrationInputKind::Message;
        });
    require(found != inventory.cases.end(), "M23 observation identity case is missing");
    const M23ObservationRequest request{
        *found, M23ObservationRole::Reference, 32, 1, 1, 5, 1, 1};
    constexpr std::string_view hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    constexpr std::string_view environmentHash =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const auto identity =
        cryptobench::tests::m23ObservationIdentity(
            request, hash, hash, environmentHash);
    require(identity == cryptobench::tests::m23ObservationIdentity(
            request, hash, hash, environmentHash),
        "M23 observation identity is not stable");
    auto holdout = request;
    holdout.role = M23ObservationRole::Holdout;
    require(identity != cryptobench::tests::m23ObservationIdentity(
                holdout, hash, hash, environmentHash),
        "M23 observation identity does not distinguish holdouts");
    const auto otherEnvironmentHash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    require(identity != cryptobench::tests::m23ObservationIdentity(
                request, hash, hash, otherEnvironmentHash),
        "M23 observation identity does not distinguish environments");
}

bool hasSingleM23GoAcknowledgment(const QStringList& arguments);

void verifyExplicitOptInGuard()
{
    require(!hasSingleM23GoAcknowledgment(
                {QStringLiteral("--observe-once")}),
        "M23 observation opt-in accepted a command without an acknowledgment");
    require(hasSingleM23GoAcknowledgment({
                QStringLiteral("--observe-once"),
                QStringLiteral("--i-confirm-m23-2-go")}),
        "M23 observation opt-in rejected its explicit acknowledgment");
    require(!hasSingleM23GoAcknowledgment({
                QStringLiteral("--observe-once"),
                QStringLiteral("--i-confirm-m23-2-go"),
                QStringLiteral("--i-confirm-m23-2-go")}),
        "M23 observation opt-in accepted duplicate acknowledgments");
}

void runSelfTests()
{
    verifyRegistryInventory();
    verifyCandidatePlan();
    verifyEvidenceValidation();
    verifyStableObservationIdentity();
    verifyExplicitOptInGuard();
    cryptobench::tests::runM23PilotPreparationTests();
}

bool hasSingleM23GoAcknowledgment(const QStringList& arguments)
{
    return arguments.count(QStringLiteral("--i-confirm-m23-2-go")) == 1;
}

int writeCandidatePlan(const QString& path)
{
    require(QFileInfo(path).isAbsolute(),
        "candidate plan output path must be absolute");
    require(!QFileInfo::exists(path),
        "candidate plan output file already exists");
    QSaveFile file(path);
    require(file.open(QIODevice::WriteOnly),
        "candidate plan output file could not be opened");
    const auto bytes = cryptobench::tests::m23CalibrationPlanManifest();
    require(file.write(bytes) == bytes.size(),
        "candidate plan output write was incomplete");
    require(file.commit(), "candidate plan output commit failed");
    return 0;
}

int writePilotPlan(const QString& path)
{
    require(QFileInfo(path).isAbsolute()
            && !QFileInfo::exists(path),
        "M23 pilot plan output must be a new absolute file");
    QSaveFile file(path);
    require(file.open(QIODevice::WriteOnly),
        "M23 pilot plan output could not be opened");
    const auto bytes = cryptobench::tests::m23PilotPlanManifest();
    require(file.write(bytes) == bytes.size(),
        "M23 pilot plan write was incomplete");
    require(file.commit(), "M23 pilot plan atomic commit failed");
    return 0;
}

QJsonObject readJsonObject(const QString& path, qsizetype maxBytes)
{
    require(QFileInfo(path).isAbsolute(),
        "M23 input JSON path must be absolute");
    QFile file(path);
    require(file.open(QIODevice::ReadOnly),
        "M23 input JSON file could not be opened");
    require(file.size() >= 0 && file.size() <= maxBytes,
        "M23 input JSON exceeds its byte limit");
    const auto bytes = file.read(maxBytes + 1);
    require(file.error() == QFileDevice::NoError
            && bytes.size() == file.size()
            && bytes.size() <= maxBytes,
        "M23 input JSON read was incomplete");
    require(QString::fromUtf8(bytes.constData(), bytes.size()).toUtf8() == bytes,
        "M23 input JSON is not strict UTF-8");
    if (const auto issue = cryptobench::application::strictJsonPreflight(bytes)) {
        throw std::runtime_error(
            "M23 strict JSON preflight failed: " + issue->technicalMessage);
    }
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(bytes, &error);
    require(error.error == QJsonParseError::NoError && document.isObject(),
        "M23 input is not a JSON object");
    return document.object();
}

int dryRunPilotPlan()
{
    const auto report = QJsonDocument::fromJson(
        cryptobench::tests::m23PilotDryRunReport());
    std::cout << report.toJson(QJsonDocument::Indented).constData();
    return 0;
}

int analyzeSyntheticPilot()
{
    const auto report = cryptobench::tests::analyzeM23PilotEvidence(
        cryptobench::tests::syntheticM23PilotEvidenceForTests(), true);
    std::cout << QJsonDocument(report).toJson(QJsonDocument::Indented).constData();
    return 0;
}

int analyzePilotFiles(const QStringList& arguments)
{
    std::vector<QString> evidencePaths;
    QString reportPath;
    std::size_t reportOptionCount = 0;
    for (qsizetype index = 1; index < arguments.size();) {
        const auto option = arguments[index++];
        if (option == QStringLiteral("--evidence")) {
            require(index < arguments.size(),
                "--evidence requires an absolute JSON file");
            evidencePaths.push_back(arguments[index++]);
        } else if (option == QStringLiteral("--report")) {
            require(index < arguments.size(),
                "--report requires a new absolute output file");
            reportPath = arguments[index++];
            ++reportOptionCount;
        } else {
            throw std::runtime_error(
                "unknown --analyze-pilot option: " + option.toStdString());
        }
    }
    require(!evidencePaths.empty() && reportOptionCount == 1
            && QFileInfo(reportPath).isAbsolute()
            && !QFileInfo::exists(reportPath),
        "--analyze-pilot requires evidence file(s) and a new absolute report path");
    std::vector<QJsonObject> evidence;
    evidence.reserve(evidencePaths.size());
    for (const auto& path : evidencePaths) {
        evidence.push_back(readJsonObject(path, 64 * 1024 * 1024));
    }
    const auto report =
        cryptobench::tests::analyzeM23PilotEvidence(evidence, false);
    QSaveFile file(reportPath);
    require(file.open(QIODevice::WriteOnly),
        "M23 pilot report could not be opened");
    const auto bytes = QJsonDocument(report).toJson(QJsonDocument::Indented);
    require(file.write(bytes) == bytes.size(),
        "M23 pilot report write was incomplete");
    require(file.commit(), "M23 pilot report atomic commit failed");
    return 0;
}

int observeApprovedPilotBatch(const QStringList& arguments)
{
    std::map<QString, QString> values;
    std::size_t acknowledgmentCount = 0;
    const auto hasOneGoAcknowledgment =
        hasSingleM23GoAcknowledgment(arguments);
    for (qsizetype index = 1; index < arguments.size();) {
        const auto option = arguments[index++];
        if (option == QStringLiteral("--i-confirm-m23-2-go")) {
            ++acknowledgmentCount;
            continue;
        }
        require(index < arguments.size(),
            "pilot observation option is missing its value");
        require(values.emplace(option, arguments[index++]).second,
            "pilot observation option was supplied more than once");
    }
    constexpr std::array requiredOptions{
        "--approved-plan",
        "--approved-plan-sha256",
        "--batch-id",
        "--output-dir"};
    require(values.size() == requiredOptions.size()
            && acknowledgmentCount == 1
            && hasOneGoAcknowledgment,
        "pilot observation requires an approved plan and exactly one GO acknowledgment");
    for (const auto* option : requiredOptions) {
        require(values.contains(QString::fromLatin1(option)),
            std::string("missing pilot observation option: ") + option);
    }

    const auto planPath = values.at(QStringLiteral("--approved-plan"));
    const auto planObject = readJsonObject(planPath, 1 * 1024 * 1024);
    QFile planFile(planPath);
    require(planFile.open(QIODevice::ReadOnly),
        "approved pilot plan could not be reopened for checksum verification");
    const auto planBytes = planFile.readAll();
    const auto actualPlanSha =
        QCryptographicHash::hash(planBytes, QCryptographicHash::Sha256).toHex();
    require(actualPlanSha == values.at(
                QStringLiteral("--approved-plan-sha256")).toLatin1(),
        "approved pilot plan SHA-256 does not match");
    const auto approval =
        cryptobench::tests::validateApprovedM23PilotPlan(planObject);
    require(approval.has_value(),
        "pilot plan has no valid independent human GO approval");
    const auto group = cryptobench::tests::m23PilotExecutionGroup(
        values.at(QStringLiteral("--batch-id")).toStdString());
    require(group.has_value(),
        "pilot Batch ID is unknown or deferred pending feasibility review");
    return cryptobench::tests::executeApprovedM23PilotBatchObservation(
        *group, *approval, values.at(QStringLiteral("--output-dir")));
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        const auto arguments = application.arguments();
        if (arguments.size() == 1) {
            runSelfTests();
            std::cout << "PASS M23 registry, plan, and evidence self-tests; "
                         "no calibration observation executed\n";
            return 0;
        }
        if (arguments.size() == 3
            && arguments[1] == QStringLiteral("--write-candidate-plan")) {
            return writeCandidatePlan(arguments[2]);
        }
        if (arguments.size() == 2
            && arguments[1] == QStringLiteral("--dry-run-pilot-plan")) {
            return dryRunPilotPlan();
        }
        if (arguments.size() == 3
            && arguments[1] == QStringLiteral("--write-pilot-plan")) {
            return writePilotPlan(arguments[2]);
        }
        if (arguments.size() == 2
            && arguments[1] == QStringLiteral("--analyze-synthetic-pilot")) {
            return analyzeSyntheticPilot();
        }
        if (arguments.size() >= 2
            && arguments[1] == QStringLiteral("--analyze-pilot")) {
            return analyzePilotFiles(arguments.mid(1));
        }
        if (arguments.size() >= 2
            && arguments[1] == QStringLiteral("--observe-pilot-batch")) {
            return observeApprovedPilotBatch(arguments.mid(1));
        }
        if (arguments.size() >= 2
            && arguments[1] == QStringLiteral("--observe-once")) {
            throw std::runtime_error(
                "legacy --observe-once is disabled; only an approved M23.2 pilot plan may be observed");
        }
        throw std::runtime_error(
            "usage: --dry-run-pilot-plan | --write-pilot-plan <file> | "
            "--analyze-synthetic-pilot | --analyze-pilot --evidence <file>... "
            "--report <new-file> | --observe-pilot-batch --approved-plan <file> "
            "--approved-plan-sha256 <sha256> --batch-id <id> "
            "--output-dir <new-directory> --i-confirm-m23-2-go");
    } catch (const std::exception& error) {
        std::cerr << "FAIL M23 calibration harness: " << error.what() << '\n';
        return 1;
    }
}
