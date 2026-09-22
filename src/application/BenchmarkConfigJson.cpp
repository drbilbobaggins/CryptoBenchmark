#include <cryptobench/application/BenchmarkConfigJson.h>

#include <stdexcept>
#include <type_traits>
#include <utility>

#include <QString>

#include <cryptobench/core/AlgorithmProfileId.h>

namespace cryptobench::application {
namespace {

template <typename>
inline constexpr bool dependentFalse = false;

QString stableProfileId(core::AlgorithmProfileId profile)
{
    const auto value = core::toStableProfileId(profile);
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QString stableOperation(core::BenchmarkOperation operation)
{
    const auto value = toStableOperationString(operation);
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QJsonObject parametersToJson(const core::PrimitiveConfig& parameters)
{
    QJsonObject result;
    std::visit([&result](const auto& value) {
        using Value = std::decay_t<decltype(value)>;

        if constexpr (std::is_same_v<Value, core::SignatureConfig>) {
            std::visit([&result](const auto& input) {
                using Input = std::decay_t<decltype(input)>;

                if constexpr (std::is_same_v<Input, core::NoSignatureInput>) {
                    static_cast<void>(input);
                } else if constexpr (std::is_same_v<Input, core::PrehashedInput>) {
                    result["inputMode"] = "prehashed";
                } else if constexpr (std::is_same_v<Input, core::MessageInput>) {
                    result["inputMode"] = "message";
                    result["messageSizeBytes"] = static_cast<qint64>(input.messageSize);
                } else {
                    static_assert(dependentFalse<Input>, "unsupported signature input alternative");
                }
            }, value.input);
        } else if constexpr (std::is_same_v<Value, core::KeyEstablishmentConfig>) {
            static_cast<void>(value);
        } else if constexpr (std::is_same_v<Value, core::AeadConfig>) {
            result["plaintextSizeBytes"] = static_cast<qint64>(value.plaintextSize);
        } else if constexpr (std::is_same_v<Value, core::HashConfig>) {
            result["inputSizeBytes"] = static_cast<qint64>(value.inputSize);
        } else {
            static_assert(dependentFalse<Value>, "unsupported primitive configuration alternative");
        }
    }, parameters);
    return result;
}

} // namespace

std::string_view toStableOperationString(core::BenchmarkOperation operation)
{
    switch (operation) {
    case core::BenchmarkOperation::KeyGen:
        return "keyGen";
    case core::BenchmarkOperation::Sign:
        return "sign";
    case core::BenchmarkOperation::Verify:
        return "verify";
    case core::BenchmarkOperation::Derive:
        return "derive";
    case core::BenchmarkOperation::Encapsulate:
        return "encapsulate";
    case core::BenchmarkOperation::Decapsulate:
        return "decapsulate";
    case core::BenchmarkOperation::Encrypt:
        return "encrypt";
    case core::BenchmarkOperation::Decrypt:
        return "decrypt";
    case core::BenchmarkOperation::Hash:
        return "hash";
    case core::BenchmarkOperation::Xof:
        return "xof";
    }
    throw std::invalid_argument("unsupported benchmark operation");
}

QJsonObject benchmarkConfigToJson(const core::BenchmarkConfig& config)
{
    return {
        {"profileId", stableProfileId(config.profile)},
        {"operation", stableOperation(config.operation)},
        {"iterationsPerRun", static_cast<qint64>(config.iterationsPerRun)},
        {"runs", static_cast<qint64>(config.runs)},
        {"parameters", parametersToJson(config.parameters)}
    };
}

} // namespace cryptobench::application