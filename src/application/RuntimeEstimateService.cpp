#include <cryptobench/application/RuntimeEstimateService.h>

#include <limits>
#include <type_traits>
#include <utility>

namespace cryptobench::application {
namespace {

constexpr auto kShortRunThreshold = RuntimeDuration{1'000'000'000};

RuntimeDurationComponent unavailable(RuntimeEstimateUnavailableReason reason)
{
    return reason;
}

bool isAvailable(const RuntimeDurationComponent& component)
{
    return std::holds_alternative<RuntimeDuration>(component);
}

bool isValidDuration(RuntimeDuration duration)
{
    return duration.count() >= 0;
}

RuntimeDurationComponent checkedAdd(
    const RuntimeDurationComponent& left,
    const RuntimeDurationComponent& right)
{
    if (!isAvailable(left)) {
        return std::get<RuntimeEstimateUnavailableReason>(left);
    }
    if (!isAvailable(right)) {
        return std::get<RuntimeEstimateUnavailableReason>(right);
    }

    const auto leftDuration = std::get<RuntimeDuration>(left);
    const auto rightDuration = std::get<RuntimeDuration>(right);
    if (!isValidDuration(leftDuration) || !isValidDuration(rightDuration)) {
        return unavailable(RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    }

    const auto sum = static_cast<unsigned __int128>(leftDuration.count())
        + static_cast<unsigned __int128>(rightDuration.count());
    if (sum > static_cast<unsigned __int128>(std::numeric_limits<std::int64_t>::max())) {
        return unavailable(RuntimeEstimateUnavailableReason::ArithmeticOverflow);
    }
    return RuntimeDuration{static_cast<std::int64_t>(sum)};
}

RuntimeDurationComponent checkedMultiply(
    const RuntimeDurationComponent& value,
    std::uint64_t multiplier)
{
    if (!isAvailable(value)) {
        return std::get<RuntimeEstimateUnavailableReason>(value);
    }

    const auto duration = std::get<RuntimeDuration>(value);
    if (!isValidDuration(duration)) {
        return unavailable(RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    }

    const auto product = static_cast<unsigned __int128>(duration.count()) * multiplier;
    if (product > static_cast<unsigned __int128>(std::numeric_limits<std::int64_t>::max())) {
        return unavailable(RuntimeEstimateUnavailableReason::ArithmeticOverflow);
    }
    return RuntimeDuration{static_cast<std::int64_t>(product)};
}

RuntimeDurationComponent validateComponent(const RuntimeDurationComponent& component)
{
    if (!isAvailable(component)) {
        return std::get<RuntimeEstimateUnavailableReason>(component);
    }
    if (!isValidDuration(std::get<RuntimeDuration>(component))) {
        return unavailable(RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    }
    return component;
}

RuntimeCalibrationInputIdentity makeInputIdentity(const core::BenchmarkConfig& config)
{
    return std::visit([](const auto& parameters) -> RuntimeCalibrationInputIdentity {
        using Parameters = std::decay_t<decltype(parameters)>;
        if constexpr (std::is_same_v<Parameters, core::SignatureConfig>) {
            return std::visit([](const auto& input) -> RuntimeCalibrationInputIdentity {
                using Input = std::decay_t<decltype(input)>;
                if constexpr (std::is_same_v<Input, core::NoSignatureInput>) {
                    return NoSignatureInput{};
                } else if constexpr (std::is_same_v<Input, core::PrehashedInput>) {
                    return PrehashedInput{};
                } else {
                    return MessageInput{input.messageSize};
                }
            }, parameters.input);
        } else if constexpr (std::is_same_v<Parameters, core::KeyEstablishmentConfig>) {
            return KeyEstablishmentInput{};
        } else if constexpr (std::is_same_v<Parameters, core::AeadConfig>) {
            return AeadInput{parameters.plaintextSize};
        } else {
            return HashXofInput{parameters.inputSize};
        }
    }, config.parameters);
}

} // namespace

RuntimeCalibrationKey makeRuntimeCalibrationKey(
    const core::BenchmarkConfig& config,
    const core::MeasurementSettings& settings)
{
    return RuntimeCalibrationKey{
        config.profile,
        config.operation,
        makeInputIdentity(config),
        settings};
}

bool operator==(
    const RuntimeCalibrationInputIdentity& left,
    const RuntimeCalibrationInputIdentity& right) noexcept
{
    if (left.index() != right.index()) {
        return false;
    }
    return std::visit([](const auto& leftValue, const auto& rightValue) {
        using Left = std::decay_t<decltype(leftValue)>;
        using Right = std::decay_t<decltype(rightValue)>;
        if constexpr (!std::is_same_v<Left, Right>) {
            return false;
        } else if constexpr (std::is_same_v<Left, MessageInput>) {
            return leftValue.messageSize == rightValue.messageSize;
        } else if constexpr (std::is_same_v<Left, AeadInput>) {
            return leftValue.plaintextSize == rightValue.plaintextSize;
        } else if constexpr (std::is_same_v<Left, HashXofInput>) {
            return leftValue.inputSize == rightValue.inputSize;
        } else {
            return true;
        }
    }, left, right);
}

bool operator==(
    const RuntimeCalibrationKey& left,
    const RuntimeCalibrationKey& right) noexcept
{
    return left.profileId == right.profileId
        && left.operation == right.operation
        && left.inputIdentity == right.inputIdentity
        && left.measurementSettings.memorySamplingIntervalMilliseconds
            == right.measurementSettings.memorySamplingIntervalMilliseconds;
}

CalibrationLookupResult NoDataRuntimeCalibrationProvider::estimateEntry(
    RuntimeCalibrationRequest) const
{
    return {
        unavailable(RuntimeEstimateUnavailableReason::CalibrationPointMissing),
        unavailable(RuntimeEstimateUnavailableReason::CalibrationPointMissing),
        unavailable(RuntimeEstimateUnavailableReason::CalibrationPointMissing)};
}

RuntimeDurationComponent NoDataRuntimeCalibrationProvider::estimateBatchOverhead(
    const BatchDefinition&,
    core::MeasurementSettings) const
{
    return unavailable(RuntimeEstimateUnavailableReason::BatchOverheadUnavailable);
}

RuntimeEstimate RuntimeEstimateService::estimate(
    const BatchDefinition& definition,
    const core::MeasurementSettings& settings,
    const RuntimeCalibrationProvider& provider) const
{
    RuntimeEstimate result{
        {},
        unavailable(RuntimeEstimateUnavailableReason::BatchOverheadUnavailable),
        RuntimeEstimateAvailability::Unavailable,
        0,
        0,
        {}};
    result.perEntry.reserve(definition.entries().size());

    bool hasUsablePerEntryEstimate = false;
    RuntimeDurationComponent entrySum =
        RuntimeDuration{0};

    for (const auto& entry : definition.entries()) {
        const auto lookup = provider.estimateEntry(RuntimeCalibrationRequest{
            makeRuntimeCalibrationKey(entry.config, settings),
            entry.config.iterationsPerRun,
            entry.config.runs});
        const auto measured = validateComponent(
            lookup.estimatedMeasuredBlockDurationPerRun);
        const auto nonMeasured = validateComponent(
            lookup.estimatedNonMeasuredDurationPerRun);
        const auto fixed = validateComponent(lookup.estimatedFixedEntryOverhead);

        if (isAvailable(measured) && std::get<RuntimeDuration>(measured) < kShortRunThreshold) {
            result.shortRunEntryIndices.push_back(entry.entryIndex);
        }
        if (!isAvailable(measured)) {
            ++result.missingMeasuredBlockEntryCount;
        } else {
            hasUsablePerEntryEstimate = true;
        }

        const auto perRun = checkedAdd(measured, nonMeasured);
        const auto repeated = checkedMultiply(
            perRun,
            static_cast<std::uint64_t>(entry.config.runs));
        const auto total = checkedAdd(repeated, fixed);
        if (!isAvailable(total)) {
            ++result.missingTotalEntryCount;
        } else {
            hasUsablePerEntryEstimate = true;
        }
        entrySum = checkedAdd(entrySum, total);

        result.perEntry.push_back({
            entry.entryIndex,
            measured,
            total});
    }

    const auto batchOverhead = validateComponent(
        provider.estimateBatchOverhead(definition, settings));
    result.estimatedTotalBatchDuration = checkedAdd(entrySum, batchOverhead);
    if (isAvailable(result.estimatedTotalBatchDuration)
        && result.missingTotalEntryCount == 0) {
        result.availability = RuntimeEstimateAvailability::Available;
    } else if (hasUsablePerEntryEstimate) {
        result.availability = RuntimeEstimateAvailability::Partial;
    }
    return result;
}

} // namespace cryptobench::application
