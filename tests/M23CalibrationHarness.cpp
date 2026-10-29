#include "M23CalibrationHarness.h"

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchController.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/BenchmarkController.h>
#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>
#include <cryptobench/application/WorkerRunSession.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSysInfo>

#include <openssl/crypto.h>

#include <windows.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <memory>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using cryptobench::application::RuntimeCalibrationInputKind;
using cryptobench::application::RuntimeCalibrationInventory;
using cryptobench::application::RuntimeCalibrationCase;
using cryptobench::application::runtimeCalibrationCaseId;

constexpr std::array<std::uint64_t, 4> kMessageReferenceBytes{
    1, 4'096, 1'048'576, 268'435'456};
constexpr std::array<std::uint64_t, 3> kMessageHoldoutBytes{
    64, 65'536, 16'777'216};
constexpr std::array<std::uint64_t, 4> kHashReferenceBytes{
    0, 4'096, 1'048'576, 268'435'456};
constexpr std::array<std::uint64_t, 3> kHashHoldoutBytes{
    1, 65'536, 16'777'216};
constexpr std::uint32_t kReferenceRepeatCount = 3;
constexpr std::uint64_t kCandidateOrderSeed = 0x4d32332e315f504cULL;

struct CapturedRun {
    std::uint32_t runIndex = 0;
    std::uint64_t controllerElapsedNanoseconds = 0;
    std::uint64_t measuredBlockNanoseconds = 0;
    std::uint32_t workerPid = 0;
    std::uint64_t workerCreationTime100ns = 0;
};

struct RunStart {
    QElapsedTimer timer;
    std::uint32_t workerPid = 0;
    std::uint64_t workerCreationTime100ns = 0;
};

struct CheckpointObservation {
    std::string kind;
    std::uint64_t startOffsetNanoseconds = 0;
    std::uint64_t endOffsetNanoseconds = 0;
};

struct CapturedEnvironment {
    QString operatingSystem;
    QString architecture;
    QString compiler;
    QString processor;
    QString powerPlan;
    std::uint32_t logicalProcessorCount = 0;
    std::uint64_t physicalMemoryBytes = 0;
};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string roleName(M23ObservationRole role)
{
    switch (role) {
    case M23ObservationRole::Reference:
        return "reference";
    case M23ObservationRole::Holdout:
        return "holdout";
    }
    throw std::invalid_argument("unknown M23 observation role");
}

QString qString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QJsonValue sizeValue(const std::optional<std::uint64_t>& value)
{
    return value ? QJsonValue(QString::number(*value)) : QJsonValue(QJsonValue::Null);
}

std::string sha256(const QByteArray& bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256)
        .toHex().toStdString();
}

bool validLowerSha256(std::string_view value)
{
    return value.size() == 64
        && std::ranges::all_of(value, [](char character) {
            return (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f');
        });
}

std::optional<std::uint64_t> parseCanonicalUnsigned(std::string_view text)
{
    if (text.empty() || (text.size() > 1 && text.front() == '0')
        || !std::ranges::all_of(text, [](char character) {
            return character >= '0' && character <= '9';
        })) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::uint64_t requiredUnsignedString(
    const QJsonObject& object,
    const char* field,
    bool permitZero)
{
    const auto value = object.value(QLatin1String(field));
    require(value.isString(), "evidence integer field is not a decimal string");
    const auto parsed = parseCanonicalUnsigned(value.toString().toStdString());
    require(parsed.has_value(), "evidence integer field is malformed or overflowing");
    require(permitZero || *parsed != 0, "evidence integer field must be positive");
    return *parsed;
}

int requiredSmallInteger(const QJsonObject& object, const char* field)
{
    const auto value = object.value(QLatin1String(field));
    require(value.isDouble(), "evidence field is not a JSON number");
    const auto parsed = value.toInt(-1);
    require(parsed >= 0 && static_cast<double>(parsed) == value.toDouble(),
        "evidence field is not an exact nonnegative integer");
    return parsed;
}

QString workerPath()
{
    const auto path = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmarkWorker.exe"));
    require(QFileInfo::exists(path), "M23 worker executable is missing");
    return QFileInfo(path).absoluteFilePath();
}

QString applicationPath()
{
    const auto path = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmark.exe"));
    require(QFileInfo::exists(path), "M23 application executable is missing");
    return QFileInfo(path).absoluteFilePath();
}

std::string fileSha256(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M23 executable could not be opened for hashing");
    const auto digest =
        QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256);
    return digest.toHex().toStdString();
}

QString findRepositoryRoot()
{
    QDir directory(QCoreApplication::applicationDirPath());
    while (true) {
        if (QFileInfo::exists(directory.filePath(QStringLiteral(".git")))) {
            return directory.absolutePath();
        }
        if (!directory.cdUp()) {
            break;
        }
    }
    throw std::runtime_error("M23 could not locate the Git repository");
}

QString gitOutput(const QString& repositoryRoot, const QStringList& arguments)
{
    QProcess process;
    process.setWorkingDirectory(repositoryRoot);
    process.start(QStringLiteral("git"), arguments);
    require(process.waitForFinished(10'000), "M23 Git provenance command timed out");
    require(process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
        "M23 Git provenance command failed");
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString compilerIdentity()
{
#if defined(__clang__)
    return QStringLiteral("Clang ") + QString::fromUtf8(__clang_version__);
#elif defined(__GNUC__)
    return QStringLiteral("GCC ") + QString::fromUtf8(__VERSION__);
#elif defined(_MSC_VER)
    return QStringLiteral("MSVC ") + QString::number(_MSC_VER);
#else
    return QStringLiteral("unknown");
#endif
}

QString activePowerPlan()
{
    QProcess process;
    process.start(QStringLiteral("powercfg"), {QStringLiteral("/GETACTIVESCHEME")});
    require(process.waitForFinished(10'000), "M23 active power-plan query timed out");
    require(process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
        "M23 active power-plan query failed");
    const auto output = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
    require(!output.isEmpty(), "M23 active power-plan query returned no data");
    return output;
}

CapturedEnvironment captureEnvironment()
{
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    require(GlobalMemoryStatusEx(&memoryStatus) != FALSE,
        "M23 could not query physical memory");

    const auto processor = qEnvironmentVariable("PROCESSOR_IDENTIFIER").trimmed();
    require(!processor.isEmpty(), "M23 processor identity is unavailable");

    return {
        QSysInfo::prettyProductName(),
        QSysInfo::currentCpuArchitecture(),
        compilerIdentity(),
        processor,
        activePowerPlan(),
        systemInfo.dwNumberOfProcessors,
        memoryStatus.ullTotalPhys};
}

std::uint64_t processCreationTime100ns(std::uint32_t pid)
{
    using ProcessHandle = std::unique_ptr<void, decltype(&CloseHandle)>;
    ProcessHandle process(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid),
        &CloseHandle);
    require(process != nullptr, "M23 could not open worker identity");

    FILETIME creation{}, exit{}, kernel{}, user{};
    require(GetProcessTimes(
        static_cast<HANDLE>(process.get()),
        &creation,
        &exit,
        &kernel,
        &user) != FALSE,
        "M23 GetProcessTimes failed");
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U)
        | static_cast<std::uint64_t>(creation.dwLowDateTime);
}

QJsonObject planEntryObject(const M23CalibrationPlanEntry& entry)
{
    return {
        {"caseId", qString(runtimeCalibrationCaseId(entry.calibrationCase))},
        {"inputBytes", sizeValue(entry.inputBytes)},
        {"inputKind", qString(
            cryptobench::application::toStableString(entry.calibrationCase.inputKind))},
        {"iterationsPerRun", QString::number(entry.iterationsPerRun)},
        {"operation", qString(
            cryptobench::application::toStableOperationString(entry.calibrationCase.operation))},
        {"order", static_cast<qint64>(entry.order)},
        {"profileId", qString(cryptobench::core::toStableProfileId(
            entry.calibrationCase.profileId))},
        {"repetition", static_cast<qint64>(entry.repetition)},
        {"role", qString(roleName(entry.role))},
        {"runs", static_cast<qint64>(entry.runs)},
        {"samplingIntervalMilliseconds",
            static_cast<qint64>(entry.samplingIntervalMilliseconds)}};
}

void appendSizePlanEntries(
    std::vector<M23CalibrationPlanEntry>& entries,
    const RuntimeCalibrationCase& calibrationCase,
    M23ObservationRole role,
    std::span<const std::uint64_t> sizes,
    std::uint64_t iterationsPerRun)
{
    for (const auto size : sizes) {
        for (std::uint32_t repetition = 1;
             repetition <= kReferenceRepeatCount;
             ++repetition) {
            entries.push_back({
                calibrationCase,
                role,
                size,
                iterationsPerRun,
                1,
                5,
                repetition,
                0});
        }
    }
}

std::vector<M23CalibrationPlanEntry> generatePlanEntries()
{
    std::vector<M23CalibrationPlanEntry> entries;
    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();

    for (const auto& calibrationCase : inventory.cases) {
        if (calibrationCase.hasVariableInputSize) {
            if (calibrationCase.inputKind == RuntimeCalibrationInputKind::HashXof) {
                appendSizePlanEntries(
                    entries,
                    calibrationCase,
                    M23ObservationRole::Reference,
                    kHashReferenceBytes,
                    1);
                appendSizePlanEntries(
                    entries,
                    calibrationCase,
                    M23ObservationRole::Holdout,
                    kHashHoldoutBytes,
                    1);
            } else {
                appendSizePlanEntries(
                    entries,
                    calibrationCase,
                    M23ObservationRole::Reference,
                    kMessageReferenceBytes,
                    1);
                appendSizePlanEntries(
                    entries,
                    calibrationCase,
                    M23ObservationRole::Holdout,
                    kMessageHoldoutBytes,
                    1);
            }
        } else {
            for (std::uint32_t repetition = 1;
                 repetition <= kReferenceRepeatCount;
                 ++repetition) {
                entries.push_back({
                    calibrationCase,
                    M23ObservationRole::Reference,
                    std::nullopt,
                    1,
                    1,
                    5,
                    repetition,
                    0});
                entries.push_back({
                    calibrationCase,
                    M23ObservationRole::Holdout,
                    std::nullopt,
                    2,
                    1,
                    5,
                    repetition,
                    0});
            }
        }
    }

    auto randomState = kCandidateOrderSeed;
    for (std::size_t remaining = entries.size(); remaining > 1; --remaining) {
        randomState ^= randomState << 13U;
        randomState ^= randomState >> 7U;
        randomState ^= randomState << 17U;
        const auto swapIndex = static_cast<std::size_t>(randomState % remaining);
        std::swap(entries[remaining - 1], entries[swapIndex]);
    }
    for (std::size_t index = 0; index < entries.size(); ++index) {
        entries[index].order = static_cast<std::uint32_t>(index + 1);
    }
    return entries;
}

QJsonDocument makePlanDocument(
    const std::vector<M23CalibrationPlanEntry>& entries)
{
    QJsonArray rows;
    for (const auto& entry : entries) {
        rows.append(planEntryObject(entry));
    }
    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();
    return QJsonDocument(QJsonObject{
        {"entries", rows},
        {"format", QStringLiteral("cryptobenchmark-m23-candidate-plan")},
        {"inventorySha256", QString::fromLatin1(
            cryptobench::application::runtimeCalibrationInventorySha256(inventory))},
        {"measurementAuthorized", false},
        {"orderSeed", QString::number(kCandidateOrderSeed)},
        {"schemaVersion", 1},
        {"status", QStringLiteral("candidate-only")}});
}

std::uint64_t checkedSum(
    std::uint64_t left,
    std::uint64_t right,
    std::string_view diagnostic)
{
    require(left <= std::numeric_limits<std::uint64_t>::max() - right, diagnostic);
    return left + right;
}

QJsonObject caseObject(const M23ObservationRequest& request)
{
    return {
        {"caseId", qString(runtimeCalibrationCaseId(request.calibrationCase))},
        {"inputBytes", sizeValue(request.inputBytes)},
        {"inputKind", qString(cryptobench::application::toStableString(
            request.calibrationCase.inputKind))},
        {"iterationsPerRun", QString::number(request.iterationsPerRun)},
        {"operation", qString(cryptobench::application::toStableOperationString(
            request.calibrationCase.operation))},
        {"order", static_cast<qint64>(request.order)},
        {"profileId", qString(cryptobench::core::toStableProfileId(
            request.calibrationCase.profileId))},
        {"repetition", static_cast<qint64>(request.repetition)},
        {"role", qString(roleName(request.role))},
        {"runs", static_cast<qint64>(request.runs)},
        {"samplingIntervalMilliseconds",
            static_cast<qint64>(request.samplingIntervalMilliseconds)}};
}

cryptobench::core::BenchmarkConfig makeConfig(
    const M23ObservationRequest& request)
{
    using namespace cryptobench;
    const auto* profile =
        core::AlgorithmRegistry::find(request.calibrationCase.profileId);
    require(profile != nullptr, "M23 observation references a missing profile");

    core::PrimitiveConfig parameters;
    switch (request.calibrationCase.inputKind) {
    case RuntimeCalibrationInputKind::NoSignature:
        parameters = core::SignatureConfig{core::NoSignatureInput{}};
        break;
    case RuntimeCalibrationInputKind::Prehashed:
        parameters = core::SignatureConfig{core::PrehashedInput{}};
        break;
    case RuntimeCalibrationInputKind::Message:
        require(request.inputBytes.has_value(),
            "M23 message observation requires an exact input size");
        parameters = core::SignatureConfig{
            core::MessageInput{*request.inputBytes}};
        break;
    case RuntimeCalibrationInputKind::KeyEstablishment:
        parameters = core::KeyEstablishmentConfig{};
        break;
    case RuntimeCalibrationInputKind::Aead:
        require(request.inputBytes.has_value(),
            "M23 AEAD observation requires an exact input size");
        parameters = core::AeadConfig{*request.inputBytes};
        break;
    case RuntimeCalibrationInputKind::HashXof:
        require(request.inputBytes.has_value(),
            "M23 Hash/XOF observation requires an exact input size");
        parameters = core::HashConfig{*request.inputBytes};
        break;
    }

    require(
        request.calibrationCase.hasVariableInputSize == request.inputBytes.has_value(),
        "M23 input byte presence does not match the typed input case");
    return {
        request.calibrationCase.profileId,
        request.calibrationCase.operation,
        request.iterationsPerRun,
        request.runs,
        std::move(parameters)};
}

cryptobench::application::BatchDefinition oneEntryDefinition(
    const cryptobench::core::BenchmarkConfig& config)
{
    const QJsonArray entries{cryptobench::application::benchmarkConfigToJson(config)};
    const auto inputDocument = QJsonDocument(QJsonObject{
        {"entries", entries},
        {"format", QStringLiteral("cryptobenchmark-batch-input")},
        {"schemaVersion", 1}});
    const auto parsed =
        cryptobench::application::BatchInputParser{}.parseData(
            inputDocument.toJson(QJsonDocument::Compact));
    require(parsed.issues.empty(),
        "M23 canonical observation config was rejected by the production Batch parser");
    require(parsed.definition.has_value(),
        "M23 canonical observation config produced no BatchDefinition");
    return *parsed.definition;
}

void validateRequest(const M23ObservationRequest& request)
{
    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();
    const auto exists = std::ranges::any_of(
        inventory.cases,
        [&](const RuntimeCalibrationCase& calibrationCase) {
            return calibrationCase.profileId == request.calibrationCase.profileId
                && calibrationCase.operation == request.calibrationCase.operation
                && calibrationCase.inputKind == request.calibrationCase.inputKind
                && calibrationCase.hasVariableInputSize
                    == request.calibrationCase.hasVariableInputSize;
        });
    require(exists, "M23 observation case is not in the live canonical registry");
    require(request.iterationsPerRun > 0, "M23 observation N must be positive");
    require(request.runs > 0, "M23 observation M must be positive");
    require(request.repetition > 0, "M23 observation repetition must be positive");
    require(request.order > 0, "M23 observation order must be positive");
    require(cryptobench::core::isValidMeasurementSettings(
        {request.samplingIntervalMilliseconds}),
        "M23 observation sampling interval is invalid");

    const auto config = makeConfig(request);
    cryptobench::core::ValidationResult validation;
    require(cryptobench::core::ConfigValidator{}.validateAndCreate(
                config, validation).has_value(),
        "M23 observation config violates the canonical core validator");

    const auto planEntries = m23CalibrationPlanEntries();
    const auto isPlanned = std::ranges::any_of(
        planEntries,
        [&](const M23CalibrationPlanEntry& entry) {
            return entry.calibrationCase.profileId == request.calibrationCase.profileId
                && entry.calibrationCase.operation == request.calibrationCase.operation
                && entry.calibrationCase.inputKind == request.calibrationCase.inputKind
                && entry.role == request.role
                && entry.inputBytes == request.inputBytes
                && entry.iterationsPerRun == request.iterationsPerRun
                && entry.runs == request.runs
                && entry.samplingIntervalMilliseconds
                    == request.samplingIntervalMilliseconds
                && entry.repetition == request.repetition
                && entry.order == request.order;
        });
    require(isPlanned,
        "M23 observation does not match an exact candidate-plan row");
}

QJsonObject environmentObject(
    const CapturedEnvironment& environment,
    std::string_view gitCommit,
    bool gitDirty)
{
    return {
        {"applicationVersion",
            qString(cryptobench::application::build_info::applicationVersion)},
        {"architecture", QSysInfo::currentCpuArchitecture()},
        {"buildType", qString(cryptobench::application::build_info::buildType)},
        {"compiler", environment.compiler},
        {"gitCommit", qString(gitCommit)},
        {"gitDirty", gitDirty},
        {"logicalProcessorCount",
            static_cast<qint64>(environment.logicalProcessorCount)},
        {"opensslBuildVersion",
            qString(cryptobench::application::build_info::opensslVersion)},
        {"opensslRuntimeVersion",
            QString::fromLatin1(OpenSSL_version(OPENSSL_VERSION))},
        {"operatingSystem", environment.operatingSystem},
        {"physicalMemoryBytes",
            QString::number(environment.physicalMemoryBytes)},
        {"powerPlan", environment.powerPlan},
        {"processor", environment.processor},
        {"qtVersion", QString::fromLatin1(qVersion())}};
}

void writeJsonAtomically(const QString& path, const QJsonDocument& document)
{
    const auto result = cryptobench::application::AtomicFileWriter{}.writeAtomically(
        path, document.toJson(QJsonDocument::Indented));
    require(result.success, result.technicalMessage.toStdString());
}

std::string fileHash(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "M23 evidence artifact could not be opened");
    return sha256(file.readAll());
}

} // namespace

std::vector<M23CalibrationPlanEntry> m23CalibrationPlanEntries()
{
    return generatePlanEntries();
}

QByteArray m23CalibrationPlanManifest()
{
    const auto entries = m23CalibrationPlanEntries();
    return makePlanDocument(entries).toJson(QJsonDocument::Compact);
}

QByteArray m23CalibrationPlanSha256()
{
    return QCryptographicHash::hash(
        m23CalibrationPlanManifest(), QCryptographicHash::Sha256).toHex();
}

std::string m23ObservationIdentity(
    const M23ObservationRequest& request,
    std::string_view applicationSha256,
    std::string_view workerSha256,
    std::string_view environmentSha256)
{
    require(validLowerSha256(applicationSha256),
        "M23 application hash is not a lowercase SHA-256 digest");
    require(validLowerSha256(workerSha256),
        "M23 worker hash is not a lowercase SHA-256 digest");
    require(validLowerSha256(environmentSha256),
        "M23 environment hash is not a lowercase SHA-256 digest");
    const auto value = runtimeCalibrationCaseId(request.calibrationCase)
        + "\n" + roleName(request.role)
        + "\n" + (request.inputBytes
            ? std::to_string(*request.inputBytes)
            : std::string{"no-size"})
        + "\n" + std::to_string(request.iterationsPerRun)
        + "\n" + std::to_string(request.runs)
        + "\n" + std::to_string(request.samplingIntervalMilliseconds)
        + "\n" + std::to_string(request.repetition)
        + "\n" + std::to_string(request.order)
        + "\n" + std::string(applicationSha256)
        + "\n" + std::string(workerSha256)
        + "\n" + std::string(environmentSha256);
    return sha256(QByteArray::fromStdString(value));
}

QJsonObject syntheticM23ObservationEvidence()
{
    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [](const RuntimeCalibrationCase& value) {
            return value.profileId == cryptobench::core::AlgorithmProfileId::Ed25519
                && value.operation == cryptobench::core::BenchmarkOperation::Sign
                && value.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(calibrationCase != inventory.cases.end(),
        "M23 synthetic fixture case is absent from the registry");

    const M23ObservationRequest request{
        *calibrationCase,
        M23ObservationRole::Reference,
        32,
        1,
        1,
        5,
        1,
        1};
    constexpr std::string_view fakeHash =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const QJsonObject environment{
        {"applicationVersion", QStringLiteral("test-only")},
        {"architecture", QStringLiteral("test-architecture")},
        {"buildType", QStringLiteral("Release")},
        {"compiler", QStringLiteral("test-only")},
        {"gitCommit", QString(40, QLatin1Char('0'))},
        {"gitDirty", false},
        {"logicalProcessorCount", 1},
        {"opensslBuildVersion", QStringLiteral("test-only")},
        {"opensslRuntimeVersion", QStringLiteral("test-only")},
        {"operatingSystem", QStringLiteral("test-only")},
        {"physicalMemoryBytes", QStringLiteral("1")},
        {"powerPlan", QStringLiteral("synthetic test fixture")},
        {"processor", QStringLiteral("synthetic test fixture")},
        {"qtVersion", QStringLiteral("test-only")}};
    const auto environmentHash = sha256(
        QJsonDocument(environment).toJson(QJsonDocument::Compact));
    const auto observationId = m23ObservationIdentity(
        request, fakeHash, fakeHash, environmentHash);
    const QJsonArray runs{
        QJsonObject{
            {"controllerElapsedNanoseconds", QStringLiteral("100")},
            {"measuredBlockNanoseconds", QStringLiteral("70")},
            {"runIndex", 0},
            {"workerCreationTime100ns", QStringLiteral("123")},
            {"workerPid", QStringLiteral("42")}}};
    return {
        {"applicationSha256", qString(fakeHash)},
        {"batchAfterEntryNanoseconds", QStringLiteral("50")},
        {"batchBeforeEntryNanoseconds", QStringLiteral("40")},
        {"batchElapsedNanoseconds", QStringLiteral("200")},
        {"batchOnlyResidualNanoseconds", QStringLiteral("90")},
        {"case", caseObject(request)},
        {"checkpointIntervals", QJsonArray{
            QJsonObject{
                {"endOffsetNanoseconds", QStringLiteral("30")},
                {"kind", QStringLiteral("initial")},
                {"startOffsetNanoseconds", QStringLiteral("10")}},
            QJsonObject{
                {"endOffsetNanoseconds", QStringLiteral("190")},
                {"kind", QStringLiteral("final")},
                {"startOffsetNanoseconds", QStringLiteral("160")}}}},
        {"completedAtUtc", QStringLiteral("2026-10-28T00:00:00.001Z")},
        {"environment", environment},
        {"environmentSha256", qString(environmentHash)},
        {"evidenceKind", QStringLiteral("syntheticTestFixture")},
        {"format", QStringLiteral("cryptobenchmark-m23-observation-evidence")},
        {"inventorySha256", QString::fromLatin1(
            cryptobench::application::runtimeCalibrationInventorySha256(inventory))},
        {"observationId", qString(observationId)},
        {"planSha256", QString::fromLatin1(m23CalibrationPlanSha256())},
        {"runObservations", runs},
        {"schemaVersion", 1},
        {"startedAtUtc", QStringLiteral("2026-10-28T00:00:00.000Z")},
        {"status", QStringLiteral("completed")},
        {"workerSha256", qString(fakeHash)},
        {"entryElapsedNanoseconds", QStringLiteral("110")},
        {"entryEndOffsetNanoseconds", QStringLiteral("150")},
        {"entryOutsideRunNanoseconds", QStringLiteral("10")},
        {"entryStartOffsetNanoseconds", QStringLiteral("40")}};
}

void validateM23ObservationEvidence(
    const QJsonObject& evidence,
    bool allowSyntheticTestFixture)
{
    require(evidence.size() == 24,
        "M23 evidence has missing or unknown top-level fields");
    require(evidence.value(QStringLiteral("format"))
            == QStringLiteral("cryptobenchmark-m23-observation-evidence"),
        "M23 evidence format is invalid");
    require(evidence.value(QStringLiteral("schemaVersion")).toInt(-1) == 1,
        "M23 evidence schema version is unsupported");
    require(evidence.value(QStringLiteral("status")) == QStringLiteral("completed"),
        "M23 incomplete or failed evidence is not accepted");
    const auto kind = evidence.value(QStringLiteral("evidenceKind")).toString();
    require(kind == QStringLiteral("realObservation")
            || (allowSyntheticTestFixture
                && kind == QStringLiteral("syntheticTestFixture")),
        "synthetic fixture evidence cannot qualify an observation");

    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();
    const auto expectedInventoryHash =
        cryptobench::application::runtimeCalibrationInventorySha256(inventory);
    require(evidence.value(QStringLiteral("inventorySha256")).toString().toLatin1()
            == expectedInventoryHash,
        "M23 evidence inventory hash differs from the live registry");
    require(validLowerSha256(
            evidence.value(QStringLiteral("planSha256")).toString().toStdString()),
        "M23 evidence plan hash is malformed");
    require(evidence.value(QStringLiteral("planSha256")).toString().toLatin1()
            == m23CalibrationPlanSha256(),
        "M23 evidence references a different candidate plan");
    require(validLowerSha256(
            evidence.value(QStringLiteral("applicationSha256")).toString().toStdString()),
        "M23 evidence application hash is malformed");
    require(validLowerSha256(
            evidence.value(QStringLiteral("workerSha256")).toString().toStdString()),
        "M23 evidence worker hash is malformed");
    const auto environmentValue =
        evidence.value(QStringLiteral("environment")).toObject();
    constexpr std::array<std::string_view, 14> environmentKeys{
        "applicationVersion",
        "architecture",
        "buildType",
        "compiler",
        "gitCommit",
        "gitDirty",
        "logicalProcessorCount",
        "opensslBuildVersion",
        "opensslRuntimeVersion",
        "operatingSystem",
        "physicalMemoryBytes",
        "powerPlan",
        "processor",
        "qtVersion"};
    require(environmentValue.size()
            == static_cast<qsizetype>(environmentKeys.size()),
        "M23 evidence environment metadata has missing or unknown fields");
    for (const auto key : environmentKeys) {
        require(environmentValue.contains(qString(key)),
            "M23 evidence environment metadata is incomplete");
    }
    require(environmentValue.value(QStringLiteral("gitDirty")).isBool()
            && !environmentValue.value(QStringLiteral("gitDirty")).toBool(),
        "M23 evidence was collected from a dirty worktree");
    require(requiredSmallInteger(
                environmentValue, "logicalProcessorCount") > 0,
        "M23 evidence has no logical-processor count");
    require(requiredUnsignedString(
                environmentValue, "physicalMemoryBytes", false) > 0,
        "M23 evidence has no physical-memory size");
    for (const auto key : {
             "applicationVersion",
             "architecture",
             "buildType",
             "compiler",
             "gitCommit",
             "opensslBuildVersion",
             "opensslRuntimeVersion",
             "operatingSystem",
             "powerPlan",
             "processor",
             "qtVersion"}) {
        const auto value = environmentValue.value(QLatin1String(key));
        require(value.isString() && !value.toString().isEmpty(),
            "M23 evidence environment identity is empty");
    }
    const auto environmentHash =
        evidence.value(QStringLiteral("environmentSha256")).toString().toStdString();
    require(validLowerSha256(environmentHash)
            && environmentHash == sha256(
                QJsonDocument(environmentValue).toJson(QJsonDocument::Compact)),
        "M23 evidence environment SHA-256 is invalid");
    const auto startedAt = evidence.value(QStringLiteral("startedAtUtc")).toString();
    const auto completedAt = evidence.value(QStringLiteral("completedAtUtc")).toString();
    const auto startedDateTime =
        QDateTime::fromString(startedAt, Qt::ISODateWithMs);
    const auto completedDateTime =
        QDateTime::fromString(completedAt, Qt::ISODateWithMs);
    require(startedAt.endsWith(QLatin1Char('Z'))
            && completedAt.endsWith(QLatin1Char('Z'))
            && startedDateTime.isValid()
            && completedDateTime.isValid()
            && completedDateTime >= startedDateTime,
        "M23 evidence timestamp is not an ISO-8601 UTC value");

    const auto caseValue = evidence.value(QStringLiteral("case"));
    require(caseValue.isObject(), "M23 evidence canonical case is missing");
    const auto caseObjectValue = caseValue.toObject();
    require(caseObjectValue.size() == 11,
        "M23 evidence canonical case has missing or unknown fields");
    const auto caseId = caseObjectValue.value(QStringLiteral("caseId")).toString();
    const auto caseMatch = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& calibrationCase) {
            return runtimeCalibrationCaseId(calibrationCase) == caseId.toStdString();
        });
    require(caseMatch != inventory.cases.end(),
        "M23 evidence canonical case is not in the live registry");
    require(caseObjectValue.value(QStringLiteral("profileId")).toString()
                == qString(cryptobench::core::toStableProfileId(caseMatch->profileId))
            && caseObjectValue.value(QStringLiteral("operation")).toString()
                == qString(cryptobench::application::toStableOperationString(
                    caseMatch->operation))
            && caseObjectValue.value(QStringLiteral("inputKind")).toString()
                == qString(cryptobench::application::toStableString(
                    caseMatch->inputKind)),
        "M23 evidence typed case fields conflict with its canonical case ID");

    const auto role = caseObjectValue.value(QStringLiteral("role")).toString();
    require(role == QStringLiteral("reference") || role == QStringLiteral("holdout"),
        "M23 evidence role is invalid");
    const auto iterations = requiredUnsignedString(
        caseObjectValue, "iterationsPerRun", false);
    const auto runsExpected = requiredSmallInteger(caseObjectValue, "runs");
    const auto samplingInterval =
        requiredSmallInteger(caseObjectValue, "samplingIntervalMilliseconds");
    const auto repetition = requiredSmallInteger(caseObjectValue, "repetition");
    const auto order = requiredSmallInteger(caseObjectValue, "order");
    require(runsExpected > 0 && samplingInterval > 0 && repetition > 0 && order > 0,
        "M23 evidence plan coordinates are not positive");
    require(cryptobench::core::isValidMeasurementSettings(
            {static_cast<std::uint32_t>(samplingInterval)}),
        "M23 evidence sampling interval is invalid");
    static_cast<void>(iterations);

    const auto inputValue = caseObjectValue.value(QStringLiteral("inputBytes"));
    std::optional<std::uint64_t> inputBytes;
    if (caseMatch->hasVariableInputSize) {
        require(inputValue.isString(),
            "M23 variable-size evidence is missing input bytes");
        const auto bytes = parseCanonicalUnsigned(
            inputValue.toString().toStdString());
        const auto minimum = caseMatch->inputKind == RuntimeCalibrationInputKind::HashXof
            ? 0ULL
            : 1ULL;
        require(bytes.has_value() && *bytes >= minimum
                && *bytes <= cryptobench::core::kMaxWorkloadBytes,
            "M23 evidence input size is outside the canonical legal range");
        inputBytes = *bytes;
    } else {
        require(inputValue.isNull(),
            "M23 fixed-input evidence unexpectedly contains an input size");
    }
    const auto request = M23ObservationRequest{
        *caseMatch,
        role == QStringLiteral("reference")
            ? M23ObservationRole::Reference
            : M23ObservationRole::Holdout,
        inputBytes,
        iterations,
        static_cast<std::uint32_t>(runsExpected),
        static_cast<std::uint32_t>(samplingInterval),
        static_cast<std::uint32_t>(repetition),
        static_cast<std::uint32_t>(order)};
    require(evidence.value(QStringLiteral("observationId")).toString().toStdString()
            == m23ObservationIdentity(
                request,
                evidence.value(QStringLiteral("applicationSha256"))
                    .toString().toStdString(),
                evidence.value(QStringLiteral("workerSha256"))
                    .toString().toStdString(),
                environmentHash),
        "M23 observation identity does not match its typed evidence");
    if (kind == QStringLiteral("realObservation")) {
        validateRequest(request);
    } else {
        const auto config = makeConfig(request);
        cryptobench::core::ValidationResult validation;
        require(cryptobench::core::ConfigValidator{}.validateAndCreate(
                    config, validation).has_value(),
            "synthetic M23 evidence config is not canonically valid");
    }

    const auto runValues = evidence.value(QStringLiteral("runObservations"));
    require(runValues.isArray(), "M23 evidence run observations are missing");
    const auto runArray = runValues.toArray();
    require(runArray.size() == runsExpected,
        "M23 evidence does not contain exactly M complete worker observations");
    std::set<std::string> workerIdentities;
    std::uint64_t totalRunElapsed = 0;
    for (qsizetype index = 0; index < runArray.size(); ++index) {
        require(runArray[index].isObject(),
            "M23 worker observation is not an object");
        const auto run = runArray[index].toObject();
        require(run.size() == 5,
            "M23 worker observation has missing or unknown fields");
        const auto runIndex = requiredSmallInteger(run, "runIndex");
        require(runIndex == index, "M23 worker observations are not in canonical run order");
        const auto pid = requiredUnsignedString(run, "workerPid", false);
        require(pid <= std::numeric_limits<std::uint32_t>::max(),
            "M23 worker PID exceeds its supported integer range");
        const auto creation = requiredUnsignedString(
            run, "workerCreationTime100ns", false);
        const auto elapsed = requiredUnsignedString(
            run, "controllerElapsedNanoseconds", false);
        const auto measured = requiredUnsignedString(
            run, "measuredBlockNanoseconds", true);
        require(elapsed >= measured,
            "M23 controller-observed worker time is smaller than the measured block");
        require(workerIdentities.emplace(
                std::to_string(pid) + "/" + std::to_string(creation)).second,
            "M23 worker process identity was reused");
        totalRunElapsed = checkedSum(
            totalRunElapsed, elapsed, "M23 worker elapsed sum overflowed");
    }

    const auto entryElapsed = requiredUnsignedString(
        evidence, "entryElapsedNanoseconds", false);
    const auto entryOutside = requiredUnsignedString(
        evidence, "entryOutsideRunNanoseconds", true);
    const auto entryStartOffset = requiredUnsignedString(
        evidence, "entryStartOffsetNanoseconds", true);
    const auto entryEndOffset = requiredUnsignedString(
        evidence, "entryEndOffsetNanoseconds", false);
    const auto batchElapsed = requiredUnsignedString(
        evidence, "batchElapsedNanoseconds", false);
    const auto batchResidual = requiredUnsignedString(
        evidence, "batchOnlyResidualNanoseconds", true);
    const auto batchBeforeEntry = requiredUnsignedString(
        evidence, "batchBeforeEntryNanoseconds", true);
    const auto batchAfterEntry = requiredUnsignedString(
        evidence, "batchAfterEntryNanoseconds", true);
    require(entryElapsed >= totalRunElapsed
            && entryOutside == entryElapsed - totalRunElapsed,
        "M23 entry/run timing boundaries do not reconcile");
    require(entryEndOffset > entryStartOffset
            && entryElapsed == entryEndOffset - entryStartOffset
            && batchBeforeEntry == entryStartOffset
            && batchElapsed >= entryEndOffset
            && batchAfterEntry == batchElapsed - entryEndOffset,
        "M23 entry boundary offsets do not reconcile with the Batch clock");
    const auto nonEntryIntervals = checkedSum(
        batchBeforeEntry, batchAfterEntry,
        "M23 Batch-only interval sum overflowed");
    const auto conservedBatchElapsed = checkedSum(
        nonEntryIntervals, entryElapsed,
        "M23 Batch conservation sum overflowed");
    require(batchResidual == nonEntryIntervals
            && batchElapsed == conservedBatchElapsed,
        "M23 Batch/run/entry conservation identity does not hold");

    const auto checkpointValue =
        evidence.value(QStringLiteral("checkpointIntervals"));
    require(checkpointValue.isArray(),
        "M23 evidence checkpoint timing observations are missing");
    const auto checkpoints = checkpointValue.toArray();
    require(checkpoints.size() == 2,
        "single-entry M23 evidence requires initial and final checkpoint intervals");
    std::array<std::uint64_t, 2> checkpointDurations{};
    std::array<std::uint64_t, 2> checkpointStarts{};
    std::array<std::uint64_t, 2> checkpointEnds{};
    constexpr std::array<std::string_view, 2> checkpointKinds{"initial", "final"};
    std::uint64_t checkpointWriteTotal = 0;
    for (qsizetype index = 0; index < checkpoints.size(); ++index) {
        require(checkpoints[index].isObject(),
            "M23 checkpoint timing interval is not an object");
        const auto checkpoint = checkpoints[index].toObject();
        require(checkpoint.size() == 3
                && checkpoint.value(QStringLiteral("kind"))
                    == qString(checkpointKinds[static_cast<std::size_t>(index)]),
            "M23 checkpoint timing interval has an invalid kind or shape");
        const auto start = requiredUnsignedString(
            checkpoint, "startOffsetNanoseconds", true);
        const auto end = requiredUnsignedString(
            checkpoint, "endOffsetNanoseconds", true);
        require(end >= start && end <= batchElapsed,
            "M23 checkpoint timing interval is outside the Batch clock");
        checkpointStarts[static_cast<std::size_t>(index)] = start;
        checkpointEnds[static_cast<std::size_t>(index)] = end;
        const auto duration = end - start;
        checkpointDurations[static_cast<std::size_t>(index)] = duration;
        checkpointWriteTotal = checkedSum(
            checkpointWriteTotal, duration,
            "M23 checkpoint timing sum overflowed");
    }
    require(checkpointEnds[0] <= entryStartOffset
            && checkpointStarts[1] >= entryEndOffset,
        "initial/final checkpoint work overlaps the measured entry interval");
    require(checkpointWriteTotal <= batchResidual
            && checkpointDurations[0] <= batchBeforeEntry
            && checkpointDurations[1] <= batchAfterEntry,
        "checkpoint writes exceed their containing Batch-only intervals");
}

int executeM23Observation(
    const M23ObservationRequest& request,
    const QString& outputDirectory)
{
    validateRequest(request);
    require(QString::fromStdString(
            std::string(cryptobench::application::build_info::buildType))
            == QStringLiteral("Release"),
        "M23 observations require a Release build");
    require(QFileInfo(outputDirectory).isAbsolute(),
        "M23 output directory must be absolute");
    require(!QFileInfo::exists(outputDirectory),
        "M23 output directory already exists");

    const auto workerExecutable = workerPath();
    const auto applicationExecutable = applicationPath();
    const auto workerHash = fileSha256(workerExecutable);
    const auto applicationHash = fileSha256(applicationExecutable);
    const auto repositoryRoot = findRepositoryRoot();
    const auto gitCommit = gitOutput(repositoryRoot, {QStringLiteral("rev-parse"),
        QStringLiteral("HEAD")});
    const auto gitStatus = gitOutput(repositoryRoot, {
        QStringLiteral("status"), QStringLiteral("--porcelain")});
    require(gitStatus.isEmpty(), "M23 observations require a clean Git worktree");
    const auto relativeOutputPath = QDir(repositoryRoot).relativeFilePath(
        QFileInfo(outputDirectory).absoluteFilePath());
    require(relativeOutputPath == QStringLiteral("..")
            || relativeOutputPath.startsWith(QStringLiteral("../"))
            || relativeOutputPath.startsWith(QStringLiteral("..\\"))
            || QDir::isAbsolutePath(relativeOutputPath),
        "M23 observation output directory must be outside the repository");
    const auto environment = captureEnvironment();
    const auto inventory =
        cryptobench::application::enumerateRuntimeCalibrationInventory();
    const auto inventoryHash =
        cryptobench::application::runtimeCalibrationInventorySha256(inventory);

    require(QDir().mkpath(outputDirectory),
        "M23 output directory could not be created");
    const auto manifestPath =
        QDir(outputDirectory).filePath(QStringLiteral("manifest.json"));
    const auto evidencePath =
        QDir(outputDirectory).filePath(QStringLiteral("observation.json"));
    const auto batchResultPath =
        QDir(outputDirectory).filePath(QStringLiteral("batch-result.json"));
    const auto markerPath =
        QDir(outputDirectory).filePath(QStringLiteral("success.marker"));

    const auto planHash = m23CalibrationPlanSha256();
    const auto environmentJson = environmentObject(
        environment, gitCommit.toStdString(), false);
    const auto environmentHash = sha256(
        QJsonDocument(environmentJson).toJson(QJsonDocument::Compact));
    const auto observationId = m23ObservationIdentity(
        request, applicationHash, workerHash, environmentHash);
    QJsonObject manifest{
        {"applicationExecutable", applicationExecutable},
        {"applicationSha256", qString(applicationHash)},
        {"case", caseObject(request)},
        {"environment", environmentJson},
        {"format", QStringLiteral("cryptobenchmark-m23-observation-manifest")},
        {"inventorySha256", QString::fromLatin1(inventoryHash)},
        {"measurementAuthorization",
            QStringLiteral("Explicit M23.2 GO acknowledgment supplied by operator")},
        {"measurementAuthorized", true},
        {"observationId", qString(observationId)},
        {"planSha256", QString::fromLatin1(planHash)},
        {"sourceGitCommit", gitCommit},
        {"status", QStringLiteral("started")},
        {"workerExecutable", workerExecutable},
        {"workerSha256", qString(workerHash)},
        {"schemaVersion", 1}};
    writeJsonAtomically(manifestPath, QJsonDocument(manifest));

    const auto config = makeConfig(request);
    const auto definition = oneEntryDefinition(config);
    const auto target = batchResultPath;
    const auto settings = cryptobench::core::MeasurementSettings{
        request.samplingIntervalMilliseconds};

    std::vector<CapturedRun> capturedRuns;
    std::map<cryptobench::application::WorkerRunSession*, RunStart> activeRuns;
    std::vector<CheckpointObservation> checkpointIntervals;
    std::optional<std::uint64_t> entryStartOffset;
    std::optional<std::uint64_t> entryEndOffset;
    std::optional<std::uint64_t> batchElapsedAtTerminal;
    std::optional<cryptobench::core::BenchmarkStatus> executorStatus;
    std::optional<cryptobench::application::BatchStatus> batchStatus;
    QString callbackError;
    cryptobench::application::WorkerRunSession* activeSession = nullptr;
    QElapsedTimer batchTimer;

    cryptobench::application::BatchController* batchPointer = nullptr;
    const auto executorFactory =
        [&](const cryptobench::core::MeasurementSettings& factorySettings) {
            cryptobench::application::WorkerRunSessionTestHooks hooks;
            hooks.sessionCreated =
                [&](cryptobench::application::WorkerRunSession* session) {
                    activeSession = session;
                    RunStart runStart;
                    runStart.timer.start();
                    activeRuns.emplace(session, std::move(runStart));
                    QObject::connect(
                        session,
                        &cryptobench::application::WorkerRunSession::completed,
                        batchPointer,
                        [&, session](
                            const cryptobench::application::WorkerRunSessionResult& result) {
                            const auto found = activeRuns.find(session);
                            if (found == activeRuns.end()) {
                                callbackError = QStringLiteral(
                                    "M23 completed worker has no start boundary");
                                return;
                            }
                            const auto& start = found->second;
                            capturedRuns.push_back({
                                result.logicalRunIndex,
                                static_cast<std::uint64_t>(
                                    std::max<qint64>(0, start.timer.nsecsElapsed())),
                                result.workerMeasurement.elapsedNanoseconds,
                                start.workerPid,
                                start.workerCreationTime100ns});
                            activeRuns.erase(found);
                            activeSession = nullptr;
                        });
                    QObject::connect(
                        session,
                        &cryptobench::application::WorkerRunSession::failed,
                        batchPointer,
                        [&, session](const cryptobench::core::ErrorInfo& error) {
                            callbackError = QString::fromStdString(error.technicalMessage);
                            activeRuns.erase(session);
                            activeSession = nullptr;
                        });
                    QObject::connect(
                        session,
                        &cryptobench::application::WorkerRunSession::cancelled,
                        batchPointer,
                        [&, session] {
                            callbackError = QStringLiteral(
                                "M23 worker session was cancelled");
                            activeRuns.erase(session);
                            activeSession = nullptr;
                        });
                };
            hooks.workerStarted = [&](qint64 pid) {
                if (activeSession == nullptr || pid <= 0) {
                    callbackError = QStringLiteral(
                        "M23 worker start did not match a live session");
                    return;
                }
                const auto found = activeRuns.find(activeSession);
                if (found == activeRuns.end()) {
                    callbackError = QStringLiteral(
                        "M23 worker start has no session timing boundary");
                    return;
                }
                try {
                    found->second.workerPid = static_cast<std::uint32_t>(pid);
                    found->second.workerCreationTime100ns =
                        processCreationTime100ns(found->second.workerPid);
                } catch (const std::exception& error) {
                    callbackError = QString::fromUtf8(error.what());
                }
            };

            auto executor = std::make_unique<
                cryptobench::application::BenchmarkController>(
                    nullptr, workerExecutable, std::move(hooks), factorySettings);
            QObject::connect(
                executor.get(),
                &cryptobench::application::BenchmarkSessionExecutor::benchmarkFinished,
                batchPointer,
                [&](const cryptobench::core::BenchmarkResult& result) {
                    executorStatus = result.status;
                });
            return executor;
        };
    const auto persister =
        [&](const QString& path, const QByteArray& bytes) {
            const auto startOffset = static_cast<std::uint64_t>(
                std::max<qint64>(0, batchTimer.nsecsElapsed()));
            const auto result =
                cryptobench::application::AtomicFileWriter{}.writeAtomically(path, bytes);
            const auto endOffset = static_cast<std::uint64_t>(
                std::max<qint64>(0, batchTimer.nsecsElapsed()));
            const auto kind = checkpointIntervals.empty()
                ? std::string{"initial"}
                : checkpointIntervals.size() == 1
                    ? std::string{"final"}
                    : std::string{"unexpected"};
            checkpointIntervals.push_back({kind, startOffset, endOffset});
            return result;
        };

    cryptobench::application::BatchController batch(
        executorFactory, persister, {}, {}, nullptr);
    batchPointer = &batch;
    QEventLoop eventLoop;
    QObject::connect(
        &batch,
        &cryptobench::application::BatchController::batchFinished,
        &eventLoop,
        [&](const cryptobench::application::BatchExecutionState& state) {
            batchStatus = state.status;
            batchElapsedAtTerminal = static_cast<std::uint64_t>(
                std::max<qint64>(0, batchTimer.nsecsElapsed()));
            eventLoop.quit();
        });
    QObject::connect(
        &batch,
        &cryptobench::application::BatchController::progressChanged,
        &eventLoop,
        [&](const cryptobench::application::BatchProgress& progress) {
            if (progress.currentEntryIndex != std::optional<std::uint32_t>{1}) {
                return;
            }
            const auto offset = static_cast<std::uint64_t>(
                std::max<qint64>(0, batchTimer.nsecsElapsed()));
            if (!progress.persistenceInProgress && !entryStartOffset.has_value()) {
                entryStartOffset = offset;
            } else if (progress.persistenceInProgress
                && entryStartOffset.has_value()
                && !entryEndOffset.has_value()) {
                entryEndOffset = offset;
            }
        });
    const auto startedAtUtc =
        QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    manifest.insert("startedAtUtc", startedAtUtc);
    writeJsonAtomically(manifestPath, QJsonDocument(manifest));
    batchTimer.start();
    batch.start(definition, target, settings);
    if (!batchStatus.has_value()) {
        eventLoop.exec();
    }
    const auto batchElapsed = batchElapsedAtTerminal.value_or(0);
    const auto validEntryOffsets = entryStartOffset.has_value()
        && entryEndOffset.has_value()
        && *entryEndOffset > *entryStartOffset
        && *entryEndOffset <= batchElapsed;
    const auto entryElapsed = validEntryOffsets
        ? *entryEndOffset - *entryStartOffset
        : 0;
    const auto batchBeforeEntry = validEntryOffsets ? *entryStartOffset : 0;
    const auto batchAfterEntry = validEntryOffsets
        ? batchElapsed - *entryEndOffset
        : 0;
    const auto batchOnlyResidual = checkedSum(
        batchBeforeEntry,
        batchAfterEntry,
        "M23 Batch-only timing sum overflowed");

    QJsonArray runValues;
    std::uint64_t totalRunElapsed = 0;
    std::set<std::string> workerIdentities;
    std::sort(capturedRuns.begin(), capturedRuns.end(),
        [](const CapturedRun& left, const CapturedRun& right) {
            return left.runIndex < right.runIndex;
        });
    for (const auto& run : capturedRuns) {
        require(run.workerPid != 0 && run.workerCreationTime100ns != 0,
            "M23 worker identity was not fully observed");
        require(run.controllerElapsedNanoseconds >= run.measuredBlockNanoseconds,
            "M23 controller time was smaller than the measured worker block");
        const auto identity = std::to_string(run.workerPid)
            + "/" + std::to_string(run.workerCreationTime100ns);
        require(workerIdentities.emplace(identity).second,
            "M23 worker process identity was reused");
        totalRunElapsed = checkedSum(
            totalRunElapsed,
            run.controllerElapsedNanoseconds,
            "M23 run timing sum overflowed");
        runValues.append(QJsonObject{
            {"controllerElapsedNanoseconds",
                QString::number(run.controllerElapsedNanoseconds)},
            {"measuredBlockNanoseconds",
                QString::number(run.measuredBlockNanoseconds)},
            {"runIndex", static_cast<qint64>(run.runIndex)},
            {"workerCreationTime100ns",
                QString::number(run.workerCreationTime100ns)},
            {"workerPid", QString::number(run.workerPid)}});
    }

    const bool completed =
        batchStatus == cryptobench::application::BatchStatus::Completed
        && executorStatus == cryptobench::core::BenchmarkStatus::Completed
        && capturedRuns.size() == request.runs
        && activeRuns.empty()
        && callbackError.isEmpty()
        && validEntryOffsets
        && entryElapsed >= totalRunElapsed
        && batchElapsedAtTerminal.has_value()
        && checkpointIntervals.size() == 2;
    const auto entryOutsideRuns = entryElapsed >= totalRunElapsed
        ? entryElapsed - totalRunElapsed
        : 0;
    QJsonArray checkpointValues;
    for (const auto& interval : checkpointIntervals) {
        checkpointValues.append(QJsonObject{
            {"endOffsetNanoseconds", QString::number(interval.endOffsetNanoseconds)},
            {"kind", qString(interval.kind)},
            {"startOffsetNanoseconds", QString::number(interval.startOffsetNanoseconds)}});
    }
    QJsonObject evidence{
        {"applicationSha256", qString(applicationHash)},
        {"batchAfterEntryNanoseconds", QString::number(batchAfterEntry)},
        {"batchBeforeEntryNanoseconds", QString::number(batchBeforeEntry)},
        {"batchElapsedNanoseconds", QString::number(batchElapsed)},
        {"batchOnlyResidualNanoseconds", QString::number(batchOnlyResidual)},
        {"case", caseObject(request)},
        {"checkpointIntervals", checkpointValues},
        {"completedAtUtc",
            QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"environment", environmentJson},
        {"environmentSha256", qString(environmentHash)},
        {"evidenceKind", QStringLiteral("realObservation")},
        {"entryElapsedNanoseconds",
            QString::number(entryElapsed)},
        {"entryEndOffsetNanoseconds",
            QString::number(entryEndOffset.value_or(0))},
        {"entryOutsideRunNanoseconds", QString::number(entryOutsideRuns)},
        {"entryStartOffsetNanoseconds",
            QString::number(entryStartOffset.value_or(0))},
        {"format", QStringLiteral("cryptobenchmark-m23-observation-evidence")},
        {"inventorySha256", QString::fromLatin1(inventoryHash)},
        {"observationId", qString(observationId)},
        {"planSha256", QString::fromLatin1(planHash)},
        {"runObservations", runValues},
        {"schemaVersion", 1},
        {"startedAtUtc", startedAtUtc},
        {"status", completed ? QStringLiteral("completed")
                             : QStringLiteral("incomplete")},
        {"workerSha256", qString(workerHash)}};

    if (!callbackError.isEmpty()) {
        evidence.insert("failureDiagnostic", callbackError);
    }
    writeJsonAtomically(evidencePath, QJsonDocument(evidence));
    if (!completed) {
        manifest.insert("status", QStringLiteral("incomplete"));
        manifest.insert("failureDiagnostic", callbackError.isEmpty()
            ? QStringLiteral("Batch or worker observation did not complete")
            : callbackError);
        writeJsonAtomically(manifestPath, QJsonDocument(manifest));
        throw std::runtime_error(
            "M23 observation is incomplete; no success marker was written");
    }

    validateM23ObservationEvidence(evidence);
    manifest.insert("status", QStringLiteral("completed"));
    manifest.insert("evidenceSha256", qString(fileHash(evidencePath)));
    manifest.insert("batchResultSha256", qString(fileHash(batchResultPath)));
    manifest.insert("completedAtUtc",
        QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
    writeJsonAtomically(manifestPath, QJsonDocument(manifest));
    writeJsonAtomically(markerPath, QJsonDocument(QJsonObject{
        {"complete", true},
        {"evidenceSha256", qString(fileHash(evidencePath))},
        {"format", QStringLiteral("cryptobenchmark-m23-observation-success")},
        {"manifestSha256", qString(fileHash(manifestPath))},
        {"schemaVersion", 1}}));
    return 0;
}

} // namespace cryptobench::tests
