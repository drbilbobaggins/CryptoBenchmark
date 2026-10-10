#include <cryptobench/ipc/JsonCodec.h>

#include <charconv>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#include <QJsonDocument>
#include <QJsonObject>

#include <cryptobench/core/AlgorithmProfileId.h>

namespace cryptobench::ipc {
namespace {

using core::BenchmarkConfig;
using core::BenchmarkOperation;
using core::BenchmarkPhase;

[[noreturn]] void fail(const char* message) { throw std::invalid_argument(message); }

QJsonObject object(const QByteArray& payload)
{
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(payload, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) fail("invalid IPC JSON object");
    return document.object();
}

void strictKeys(const QJsonObject& value, std::initializer_list<const char*> keys)
{
    for (const auto& key : value.keys()) {
        bool known = false;
        for (const auto expected : keys) if (key == expected) known = true;
        if (!known) fail("unknown IPC JSON field");
    }
}

QJsonValue required(const QJsonObject& value, const char* key)
{
    if (!value.contains(key)) fail("missing IPC JSON field");
    return value.value(key);
}

std::uint64_t uint64String(const QJsonValue& value)
{
    if (!value.isString()) fail("uint64 IPC field must be a decimal string");
    const auto text = value.toString().toStdString();
    if (text.empty()) fail("empty uint64 IPC field");
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) fail("invalid uint64 IPC field");
    return result;
}

std::uint32_t uint32Number(const QJsonValue& value)
{
    if (!value.isDouble() || value.toDouble() < 0 || value.toDouble() > std::numeric_limits<std::uint32_t>::max() || value.toDouble() != static_cast<double>(static_cast<std::uint32_t>(value.toDouble()))) fail("invalid uint32 IPC field");
    return static_cast<std::uint32_t>(value.toDouble());
}

QString profileId(core::AlgorithmProfileId id) { const auto value = core::toStableProfileId(id); return QString::fromUtf8(value.data(), static_cast<int>(value.size())); }
core::AlgorithmProfileId profileId(const QJsonValue& value)
{
    if (!value.isString()) fail("profileId must be a string");
    const auto parsed = core::parseStableProfileId(value.toString().toUtf8().toStdString());
    if (!parsed) fail("unknown profileId");
    return *parsed;
}

QString operation(BenchmarkOperation value)
{
    switch (value) {
        case BenchmarkOperation::KeyGen: return "keyGen";
        case BenchmarkOperation::Sign: return "sign";
        case BenchmarkOperation::Verify: return "verify";
        case BenchmarkOperation::Derive: return "derive";
        case BenchmarkOperation::Encapsulate: return "encapsulate";
        case BenchmarkOperation::Decapsulate: return "decapsulate";
        case BenchmarkOperation::Encrypt: return "encrypt";
        case BenchmarkOperation::Decrypt: return "decrypt";
        case BenchmarkOperation::Hash: return "hash";
        case BenchmarkOperation::Xof: return "xof";
    }
    fail("unsupported operation");
}
BenchmarkOperation operation(const QJsonValue& value)
{
    if (!value.isString()) fail("operation must be a string");
    static const std::pair<const char*, BenchmarkOperation> values[] = {{"keyGen", BenchmarkOperation::KeyGen}, {"sign", BenchmarkOperation::Sign}, {"verify", BenchmarkOperation::Verify}, {"derive", BenchmarkOperation::Derive}, {"encapsulate", BenchmarkOperation::Encapsulate}, {"decapsulate", BenchmarkOperation::Decapsulate}, {"encrypt", BenchmarkOperation::Encrypt}, {"decrypt", BenchmarkOperation::Decrypt}, {"hash", BenchmarkOperation::Hash}, {"xof", BenchmarkOperation::Xof}};
    for (const auto& [name, result] : values) if (value.toString() == name) return result;
    fail("unknown operation");
}

QString errorCode(core::ErrorCode value)
{
    switch (value) {
        case core::ErrorCode::InvalidConfiguration: return "invalidConfiguration";
        case core::ErrorCode::UnknownExecutionStrategy: return "unknownExecutionStrategy";
        case core::ErrorCode::CryptoInitializationFailed: return "cryptoInitializationFailed";
        case core::ErrorCode::CryptoOperationFailed: return "cryptoOperationFailed";
        case core::ErrorCode::MemoryMeasurementFailed: return "memoryMeasurementFailed";
        case core::ErrorCode::WorkerStartupFailed: return "workerStartupFailed";
        case core::ErrorCode::WorkerCommunicationFailed: return "workerCommunicationFailed";
        case core::ErrorCode::InternalError: return "internalError";
    }
    fail("unsupported error code");
}

core::ErrorCode errorCode(const QJsonValue& value)
{
    if (!value.isString()) fail("error code must be a string");
    static const std::pair<const char*, core::ErrorCode> values[] = {{"invalidConfiguration", core::ErrorCode::InvalidConfiguration}, {"unknownExecutionStrategy", core::ErrorCode::UnknownExecutionStrategy}, {"cryptoInitializationFailed", core::ErrorCode::CryptoInitializationFailed}, {"cryptoOperationFailed", core::ErrorCode::CryptoOperationFailed}, {"memoryMeasurementFailed", core::ErrorCode::MemoryMeasurementFailed}, {"workerStartupFailed", core::ErrorCode::WorkerStartupFailed}, {"workerCommunicationFailed", core::ErrorCode::WorkerCommunicationFailed}, {"internalError", core::ErrorCode::InternalError}};
    for (const auto& [name, result] : values) if (value.toString() == name) return result;
    fail("unknown error code");
}

QString failureStage(core::FailureStage value)
{
    switch (value) {
        case core::FailureStage::WorkerStartup: return "workerStartup";
        case core::FailureStage::ConfigDeserialization: return "configDeserialization";
        case core::FailureStage::ConfigValidation: return "configValidation";
        case core::FailureStage::TaskCreation: return "taskCreation";
        case core::FailureStage::SeriesPreparation: return "seriesPreparation";
        case core::FailureStage::RunPreparation: return "runPreparation";
        case core::FailureStage::Warmup: return "warmup";
        case core::FailureStage::Measurement: return "measurement";
        case core::FailureStage::MemoryMeasurement: return "memoryMeasurement";
        case core::FailureStage::WorkerCommunication: return "workerCommunication";
        case core::FailureStage::ResultAssembly: return "resultAssembly";
    }
    fail("unsupported failure stage");
}

core::FailureStage failureStage(const QJsonValue& value)
{
    if (!value.isString()) fail("failure stage must be a string");
    static const std::pair<const char*, core::FailureStage> values[] = {{"workerStartup", core::FailureStage::WorkerStartup}, {"configDeserialization", core::FailureStage::ConfigDeserialization}, {"configValidation", core::FailureStage::ConfigValidation}, {"taskCreation", core::FailureStage::TaskCreation}, {"seriesPreparation", core::FailureStage::SeriesPreparation}, {"runPreparation", core::FailureStage::RunPreparation}, {"warmup", core::FailureStage::Warmup}, {"measurement", core::FailureStage::Measurement}, {"memoryMeasurement", core::FailureStage::MemoryMeasurement}, {"workerCommunication", core::FailureStage::WorkerCommunication}, {"resultAssembly", core::FailureStage::ResultAssembly}};
    for (const auto& [name, result] : values) if (value.toString() == name) return result;
    fail("unknown failure stage");
}

QJsonObject configObject(const BenchmarkConfig& config)
{
    QJsonObject result{{"profileId", profileId(config.profile)}, {"operation", operation(config.operation)}, {"iterationsPerRun", QString::number(config.iterationsPerRun)}, {"runs", static_cast<qint64>(config.runs)}};
    QJsonObject parameters;
    std::visit([&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, core::HashConfig>) { parameters["type"] = "hash"; parameters["inputSize"] = QString::number(value.inputSize); }
        else if constexpr (std::is_same_v<T, core::AeadConfig>) { parameters["type"] = "aead"; parameters["plaintextSize"] = QString::number(value.plaintextSize); }
        else if constexpr (std::is_same_v<T, core::KeyEstablishmentConfig>) { parameters["type"] = "keyEstablishment"; }
        else if constexpr (std::is_same_v<T, core::SignatureConfig>) { parameters["type"] = "signature"; std::visit([&](const auto& input) { using I = std::decay_t<decltype(input)>; if constexpr (std::is_same_v<I, core::NoSignatureInput>) parameters["input"] = "none"; else if constexpr (std::is_same_v<I, core::PrehashedInput>) parameters["input"] = "prehashed"; else { parameters["input"] = "message"; parameters["messageSize"] = QString::number(input.messageSize); } }, value.input); }
    }, config.parameters);
    result["parameters"] = parameters;
    return result;
}

BenchmarkConfig config(const QJsonObject& value)
{
    strictKeys(value, {"profileId", "operation", "iterationsPerRun", "runs", "parameters"});
    const auto parameters = required(value, "parameters");
    if (!parameters.isObject()) fail("parameters must be an object");
    const auto p = parameters.toObject();
    if (!p.contains("type") || !p.value("type").isString()) fail("parameter type missing");
    const auto type = p.value("type").toString();
    BenchmarkConfig result{profileId(required(value, "profileId")), operation(required(value, "operation")), uint64String(required(value, "iterationsPerRun")), uint32Number(required(value, "runs")), core::KeyEstablishmentConfig{}};
    if (type == "hash") { strictKeys(p, {"type", "inputSize"}); result.parameters = core::HashConfig{uint64String(required(p, "inputSize"))}; }
    else if (type == "aead") { strictKeys(p, {"type", "plaintextSize"}); result.parameters = core::AeadConfig{uint64String(required(p, "plaintextSize"))}; }
    else if (type == "keyEstablishment") { strictKeys(p, {"type"}); }
    else if (type == "signature") { if (!p.contains("input") || !p.value("input").isString()) fail("signature input missing"); const auto input = p.value("input").toString(); if (input == "none" || input == "prehashed") { strictKeys(p, {"type", "input"}); result.parameters = input == "none" ? core::SignatureConfig{core::NoSignatureInput{}} : core::SignatureConfig{core::PrehashedInput{}}; } else if (input == "message") { strictKeys(p, {"type", "input", "messageSize"}); result.parameters = core::SignatureConfig{core::MessageInput{uint64String(required(p, "messageSize"))}}; } else fail("unknown signature input"); }
    else fail("unknown parameter type");
    return result;
}

void validateLogicalRunIndex(std::uint32_t logicalRunIndex, const BenchmarkConfig& config)
{
    if (config.runs == 0 || logicalRunIndex >= config.runs) fail("logicalRunIndex is outside config.runs");
}

QByteArray compact(const QJsonObject& value) { return QJsonDocument(value).toJson(QJsonDocument::Compact); }

} // namespace

QByteArray encodeWorkerReady(const WorkerReady& value) { return compact({{"protocolVersion", static_cast<qint64>(value.protocolVersion)}}); }
WorkerReady decodeWorkerReady(const QByteArray& payload) { const auto v = object(payload); strictKeys(v, {"protocolVersion"}); return {uint32Number(required(v, "protocolVersion"))}; }
QByteArray encodeBenchmarkRequest(const BenchmarkRequest& value) { return compact(configObject(value.config)); }
BenchmarkRequest decodeBenchmarkRequest(const QByteArray& payload) { return {config(object(payload))}; }
QByteArray encodeBenchmarkRunRequest(const BenchmarkRunRequest& value)
{
    validateLogicalRunIndex(value.logicalRunIndex, value.config);
    return compact({{"logicalRunIndex", static_cast<qint64>(value.logicalRunIndex)}, {"config", configObject(value.config)}});
}
BenchmarkRunRequest decodeBenchmarkRunRequest(const QByteArray& payload)
{
    const auto value = object(payload);
    strictKeys(value, {"logicalRunIndex", "config"});
    const auto configValue = required(value, "config");
    if (!configValue.isObject()) fail("config must be an object");
    const auto result = BenchmarkRunRequest{uint32Number(required(value, "logicalRunIndex")), config(configValue.toObject())};
    validateLogicalRunIndex(result.logicalRunIndex, result.config);
    return result;
}
QByteArray encodeProgress(const Progress& value) { if (value.phase == BenchmarkPhase::Warmup && !value.runIndex) fail("warmup progress requires runIndex"); if (value.phase != BenchmarkPhase::Warmup && value.runIndex) fail("non-warmup progress cannot contain runIndex"); QString phase; switch (value.phase) { case BenchmarkPhase::Preparing: phase = "preparing"; break; case BenchmarkPhase::Warmup: phase = "warmup"; break; case BenchmarkPhase::Finalizing: phase = "finalizing"; break; case BenchmarkPhase::Measuring: fail("measuring progress is not a wire phase"); default: fail("unsupported progress phase"); } QJsonObject v{{"phase", phase}, {"totalRuns", static_cast<qint64>(value.totalRuns)}}; if (value.runIndex) v["runIndex"] = static_cast<qint64>(*value.runIndex); return compact(v); }
Progress decodeProgress(const QByteArray& payload) { const auto v = object(payload); strictKeys(v, {"phase", "runIndex", "totalRuns"}); const auto phase = required(v, "phase").toString(); BenchmarkPhase p; if (phase == "preparing") p = BenchmarkPhase::Preparing; else if (phase == "warmup") p = BenchmarkPhase::Warmup; else if (phase == "finalizing") p = BenchmarkPhase::Finalizing; else fail("unknown progress phase"); std::optional<std::uint32_t> index; if (v.contains("runIndex")) index = uint32Number(v.value("runIndex")); if (p == BenchmarkPhase::Warmup && !index) fail("warmup progress requires runIndex"); if (p != BenchmarkPhase::Warmup && index) fail("non-warmup progress cannot contain runIndex"); return {p, index, uint32Number(required(v, "totalRuns"))}; }
QByteArray encodeWorkerRunMeasurement(const WorkerRunMeasurement& value) { return compact({{"runIndex", static_cast<qint64>(value.runIndex)}, {"elapsedNanoseconds", QString::number(value.elapsedNanoseconds)}, {"processCpuNanoseconds", QString::number(value.processCpuNanoseconds)}}); }
WorkerRunMeasurement decodeWorkerRunMeasurement(const QByteArray& payload) { const auto v = object(payload); strictKeys(v, {"runIndex", "elapsedNanoseconds", "processCpuNanoseconds"}); return {uint32Number(required(v, "runIndex")), uint64String(required(v, "elapsedNanoseconds")), uint64String(required(v, "processCpuNanoseconds"))}; }

QByteArray encodeWorkerOutcome(const WorkerOutcome& value) { QString status; switch (value.status) { case WorkerOutcomeStatus::Completed: if (value.error) fail("completed outcome cannot contain error"); status = "completed"; break; case WorkerOutcomeStatus::Failed: if (!value.error) fail("failed outcome requires error"); status = "failed"; break; default: fail("unsupported worker outcome status"); } QJsonObject v{{"status", status}}; if (value.error) { const auto& e = *value.error; QJsonObject error{{"code", errorCode(e.code)}, {"stage", failureStage(e.stage)}, {"technicalMessage", QString::fromStdString(e.technicalMessage)}}; if (e.runIndex) error["runIndex"] = static_cast<qint64>(*e.runIndex); if (e.libraryDetails) error["libraryDetails"] = QString::fromStdString(*e.libraryDetails); v["error"] = error; } return compact(v); }
WorkerOutcome decodeWorkerOutcome(const QByteArray& payload) { const auto v = object(payload); strictKeys(v, {"status", "error"}); const auto status = v.value("status").toString(); if (status == "completed") { if (v.contains("error")) fail("completed outcome cannot contain error"); return {WorkerOutcomeStatus::Completed, std::nullopt}; } if (status != "failed" || !v.value("error").isObject()) fail("failed outcome requires error"); const auto e = v.value("error").toObject(); strictKeys(e, {"code", "stage", "runIndex", "technicalMessage", "libraryDetails"}); core::ErrorInfo info{errorCode(required(e, "code")), failureStage(required(e, "stage")), std::nullopt, required(e, "technicalMessage").toString().toStdString(), std::nullopt}; if (!required(e, "technicalMessage").isString()) fail("technical message must be a string"); if (e.contains("runIndex")) info.runIndex = uint32Number(e.value("runIndex")); if (e.contains("libraryDetails")) { if (!e.value("libraryDetails").isString()) fail("library details must be a string"); info.libraryDetails = e.value("libraryDetails").toString().toStdString(); } return {WorkerOutcomeStatus::Failed, info}; }

} // namespace cryptobench::ipc
