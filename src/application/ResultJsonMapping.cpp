#include <cryptobench/application/ResultJsonMapping.h>

#include <cmath>
#include <stdexcept>
#include <type_traits>

#include <QDateTime>
#include <QTimeZone>

namespace cryptobench::application {
namespace {

template <typename>
inline constexpr bool dependentFalse = false;

QString stableString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QJsonObject signatureSizeToJson(const core::SignatureSizeReference& signatureSize)
{
    return {
        {"bytes", static_cast<qint64>(signatureSize.bytes)},
        {"kind", stableString(toStableString(signatureSize.kind))}
    };
}

void addOptional(QJsonObject& object, const char* key, const std::optional<core::ByteCount>& value)
{
    if (value.has_value()) {
        object[key] = static_cast<qint64>(*value);
    }
}

QJsonObject statisticToJson(const core::Statistics<double>& statistic)
{
    const auto requireFinite = [](double value) {
        if (!std::isfinite(value)) {
            throw std::invalid_argument("benchmark statistics must be finite");
        }
        return value;
    };

    return {
        {"mean", requireFinite(statistic.mean)},
        {"median", requireFinite(statistic.median)},
        {"min", requireFinite(statistic.min)},
        {"max", requireFinite(statistic.max)},
        {"stddev", requireFinite(statistic.stddev)}
    };
}

QString measuredAtToJson(const std::chrono::system_clock::time_point& measuredAt)
{
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        measuredAt.time_since_epoch()).count();
    return QDateTime::fromMSecsSinceEpoch(milliseconds, QTimeZone::UTC).toString(Qt::ISODateWithMs);
}

} // namespace

std::string_view toStableString(core::SignatureSizeReferenceKind kind)
{
    switch (kind) {
    case core::SignatureSizeReferenceKind::Fixed:
        return "fixed";
    case core::SignatureSizeReferenceKind::MaximumDerEncoded:
        return "maximumDerEncoded";
    }
    throw std::invalid_argument("unsupported signature size reference kind");
}

std::string_view toStableString(core::ErrorCode code)
{
    switch (code) {
    case core::ErrorCode::InvalidConfiguration:
        return "invalidConfiguration";
    case core::ErrorCode::UnknownExecutionStrategy:
        return "unknownExecutionStrategy";
    case core::ErrorCode::CryptoInitializationFailed:
        return "cryptoInitializationFailed";
    case core::ErrorCode::CryptoOperationFailed:
        return "cryptoOperationFailed";
    case core::ErrorCode::MemoryMeasurementFailed:
        return "memoryMeasurementFailed";
    case core::ErrorCode::WorkerStartupFailed:
        return "workerStartupFailed";
    case core::ErrorCode::WorkerCommunicationFailed:
        return "workerCommunicationFailed";
    case core::ErrorCode::InternalError:
        return "internalError";
    }
    throw std::invalid_argument("unsupported error code");
}

std::string_view toStableString(core::FailureStage stage)
{
    switch (stage) {
    case core::FailureStage::WorkerStartup:
        return "workerStartup";
    case core::FailureStage::ConfigDeserialization:
        return "configDeserialization";
    case core::FailureStage::ConfigValidation:
        return "configValidation";
    case core::FailureStage::TaskCreation:
        return "taskCreation";
    case core::FailureStage::SeriesPreparation:
        return "seriesPreparation";
    case core::FailureStage::RunPreparation:
        return "runPreparation";
    case core::FailureStage::Warmup:
        return "warmup";
    case core::FailureStage::Measurement:
        return "measurement";
    case core::FailureStage::MemoryMeasurement:
        return "memoryMeasurement";
    case core::FailureStage::WorkerCommunication:
        return "workerCommunication";
    case core::FailureStage::ResultAssembly:
        return "resultAssembly";
    }
    throw std::invalid_argument("unsupported failure stage");
}

QJsonObject structuralCharacteristicsToJson(const core::StructuralCharacteristics& characteristics)
{
    return std::visit([](const auto& value) {
        using Value = std::decay_t<decltype(value)>;
        QJsonObject result;

        if constexpr (std::is_same_v<Value, core::SignatureCharacteristics>) {
            result["type"] = "signature";
            addOptional(result, "publicKeyBytes", value.publicKeyBytes);
            addOptional(result, "privateKeyBytes", value.privateKeyBytes);
            if (value.signatureSize.has_value()) {
                result["signatureSize"] = signatureSizeToJson(*value.signatureSize);
            }
        } else if constexpr (std::is_same_v<Value, core::KeyEstablishmentCharacteristics>) {
            result["type"] = "keyEstablishment";
            result["sharedSecretBytes"] = static_cast<qint64>(value.sharedSecretBytes);
            addOptional(result, "publicKeyBytes", value.publicKeyBytes);
            addOptional(result, "privateKeyBytes", value.privateKeyBytes);
            addOptional(result, "ciphertextBytes", value.ciphertextBytes);
        } else if constexpr (std::is_same_v<Value, core::AeadCharacteristics>) {
            result["type"] = "aead";
            result["keyBytes"] = static_cast<qint64>(value.keyBytes);
            result["nonceBytes"] = static_cast<qint64>(value.nonceBytes);
            result["aadBytes"] = static_cast<qint64>(value.aadBytes);
            result["tagBytes"] = static_cast<qint64>(value.tagBytes);
        } else if constexpr (std::is_same_v<Value, core::HashCharacteristics>) {
            result["type"] = "hashXof";
            result["outputBytes"] = static_cast<qint64>(value.outputBytes);
        } else {
            static_assert(dependentFalse<Value>, "unsupported structural characteristics alternative");
        }

        return result;
    }, characteristics);
}

QJsonObject environmentInfoToJson(const core::EnvironmentInfo& environment)
{
    return {
        {"applicationVersion", QString::fromStdString(environment.applicationVersion)},
        {"gitCommit", QString::fromStdString(environment.gitCommit)},
        {"opensslVersion", QString::fromStdString(environment.opensslVersion)},
        {"operatingSystem", QString::fromStdString(environment.operatingSystem)},
        {"architecture", QString::fromStdString(environment.architecture)},
        {"buildType", QString::fromStdString(environment.buildType)},
        {"measuredAt", measuredAtToJson(environment.measuredAt)}
    };
}

QJsonObject resultMeasurementMetadataToJson(const core::MeasurementSettings& settings)
{
    if (!core::isValidMeasurementSettings(settings)) {
        throw std::invalid_argument("result measurement settings are invalid");
    }
    return {
        {"memorySamplingIntervalMilliseconds",
         static_cast<qint64>(settings.memorySamplingIntervalMilliseconds)},
        {"memoryModel", "memoryV2"},
        {"workerLifecycle", "freshWorkerPerLogicalRun"}
    };
}

QJsonObject benchmarkStatisticsToJson(const core::BenchmarkStatistics& statistics)
{
    const auto* memory = std::get_if<core::MemoryV2Statistics>(&statistics.memory);
    if (memory == nullptr) {
        throw std::invalid_argument("Memory v2 statistics require result schema v2");
    }
    const auto memoryStatisticsToJson = [](const core::Statistics<double>& value) {
        return statisticToJson(value);
    };
    return {
        {"wallClockNanosecondsPerOperation", statisticToJson(statistics.elapsedNanosecondsPerOperation)},
        {"processCpuNanosecondsPerOperation", statisticToJson(statistics.cpuNanosecondsPerOperation)},
        {"memory", QJsonObject{
            {"unit", "bytes"},
            {"readyStateDelta", memoryStatisticsToJson(memory->readyStatePrivateUsageDeltaBytes)},
            {"preparationPeakDelta", memoryStatisticsToJson(memory->preparationPeakPrivateUsageDeltaBytes)},
            {"executionPeakDelta", memoryStatisticsToJson(memory->executionPeakPrivateUsageDeltaBytes)},
            {"operationalPeakDelta", memoryStatisticsToJson(memory->operationalPeakPrivateUsageDeltaBytes)}
        }}
    };
}

QJsonObject errorInfoToJson(const core::ErrorInfo& error)
{
    QJsonObject result{
        {"code", stableString(toStableString(error.code))},
        {"stage", stableString(toStableString(error.stage))},
        {"technicalMessage", QString::fromStdString(error.technicalMessage)}
    };
    if (error.runIndex.has_value()) {
        result["runIndex"] = static_cast<qint64>(*error.runIndex);
    }
    if (error.libraryDetails.has_value()) {
        result["libraryDetails"] = QString::fromStdString(*error.libraryDetails);
    }
    return result;
}

} // namespace cryptobench::application