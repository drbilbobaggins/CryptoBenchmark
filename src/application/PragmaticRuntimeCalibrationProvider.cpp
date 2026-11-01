#include <cryptobench/application/PragmaticRuntimeCalibrationProvider.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <cryptobench/application/RuntimeCalibrationInventory.h>
#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::application {
namespace {

using WideUnsigned = unsigned __int128;

constexpr std::uint32_t kMeasuredSamplingIntervalMilliseconds = 5;

RuntimeDurationComponent unavailable(RuntimeEstimateUnavailableReason reason)
{
    return reason;
}

CalibrationLookupResult unavailableEntry(RuntimeEstimateUnavailableReason reason)
{
    return {reason, reason, reason};
}

class UnavailableProvider final : public RuntimeCalibrationProvider {
public:
    UnavailableProvider(
        RuntimeEstimateUnavailableReason entryReason,
        RuntimeEstimateUnavailableReason batchReason)
        : entryReason_(entryReason)
        , batchReason_(batchReason)
    {
    }

    CalibrationLookupResult estimateEntry(RuntimeCalibrationRequest) const override
    {
        return unavailableEntry(entryReason_);
    }

    RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition&,
        core::MeasurementSettings) const override
    {
        return unavailable(batchReason_);
    }

private:
    RuntimeEstimateUnavailableReason entryReason_;
    RuntimeEstimateUnavailableReason batchReason_;
};

std::unique_ptr<RuntimeCalibrationProvider> noDataProvider()
{
    return std::make_unique<NoDataRuntimeCalibrationProvider>();
}

std::unique_ptr<RuntimeCalibrationProvider> unavailableProvider(
    RuntimeEstimateUnavailableReason reason)
{
    return std::make_unique<UnavailableProvider>(reason, reason);
}

bool matchesCase(
    const RuntimeCalibrationCase& left,
    const RuntimeCalibrationCase& right)
{
    return left.profileId == right.profileId
        && left.operation == right.operation
        && left.inputKind == right.inputKind
        && left.hasVariableInputSize == right.hasVariableInputSize;
}

bool isValidPragmaticResource(const RuntimeCalibrationResource& resource)
{
    if (resource.dialect != RuntimeCalibrationResourceDialect::M23Pragmatic
        || resource.qualificationStatus != "reducedScopeApproximate"
        || !resource.approximationPolicy.has_value()
        || !resource.pragmaticProvenance.has_value()
        || resource.pragmaticProvenance->calibrationProtocolId
            != "memory-v2-calibration-v1") {
        return false;
    }

    const auto& policy = *resource.approximationPolicy;
    if (policy.warmupOperationsPerLogicalRun != 1
        || policy.fixedEntryOverhead.nanoseconds != 0
        || policy.fixedEntryOverhead.tag
            != RuntimeCalibrationAssumptionTag::AssumedUnmeasured
        || policy.batchOverhead.nanoseconds != 0
        || policy.batchOverhead.tag
            != RuntimeCalibrationAssumptionTag::AssumedUnmeasured
        || policy.samplingAssumptions.size() != 4) {
        return false;
    }
    for (std::size_t index = 0; index < policy.samplingAssumptions.size(); ++index) {
        const auto& assumption = policy.samplingAssumptions[index];
        if (assumption.requestedIntervalMilliseconds != index + 1
            || assumption.sourceMeasuredIntervalMilliseconds
                != kMeasuredSamplingIntervalMilliseconds
            || assumption.tag != RuntimeCalibrationAssumptionTag::AssumedFrom5ms) {
            return false;
        }
    }

    const auto inventory = enumerateRuntimeCalibrationInventory();
    if (inventory.cases.size() != 175
        || inventory.fixedInputCaseCount != 78
        || inventory.variableInputCaseCount != 97
        || resource.records.size() != inventory.cases.size()) {
        return false;
    }

    std::vector<bool> seen(inventory.cases.size(), false);
    for (const auto& record : resource.records) {
        if (record.samplingIntervalMilliseconds
            != kMeasuredSamplingIntervalMilliseconds) {
            return false;
        }

        const auto inventoryCase = std::ranges::find_if(
            inventory.cases,
            [&](const RuntimeCalibrationCase& candidate) {
                return matchesCase(candidate, record.calibrationCase);
            });
        if (inventoryCase == inventory.cases.end()) {
            return false;
        }
        const auto inventoryIndex = static_cast<std::size_t>(
            std::distance(inventory.cases.begin(), inventoryCase));
        if (seen[inventoryIndex]) {
            return false;
        }
        seen[inventoryIndex] = true;

        if (record.calibrationCase.hasVariableInputSize) {
            const auto minimum = record.calibrationCase.inputKind
                    == RuntimeCalibrationInputKind::HashXof
                ? std::uint64_t{0}
                : std::uint64_t{1};
            if (record.modelKind
                    != RuntimeCalibrationMeasuredModelKind::AnchoredAffinePerOperation
                || record.evidenceStatus
                    != RuntimeCalibrationRecordEvidenceStatus::
                        PerOperationReferenceFitSizeHoldoutOnly
                || record.minimumInputBytes != minimum
                || record.maximumInputBytes != core::kMaxWorkloadBytes) {
                return false;
            }
            if (!record.pragmaticModel.has_value()) {
                return false;
            }
            const auto* model = std::get_if<
                RuntimeCalibrationAnchoredAffinePerOperationModel>(
                    &*record.pragmaticModel);
            if (model == nullptr
                || model->anchorInputBytes != minimum
                || model->anchorPicosecondsPerOperation == 0) {
                return false;
            }
            const auto sizeGrowth =
                static_cast<WideUnsigned>(model->slopePicosecondsPerBytePerOperation)
                * (core::kMaxWorkloadBytes - minimum);
            if (static_cast<WideUnsigned>(model->anchorPicosecondsPerOperation)
                    + sizeGrowth
                > std::numeric_limits<std::uint64_t>::max()) {
                return false;
            }
        } else {
            if (record.modelKind
                    != RuntimeCalibrationMeasuredModelKind::ConstantPerOperation
                || record.evidenceStatus
                    != RuntimeCalibrationRecordEvidenceStatus::
                        PerOperationReferenceFitOnly
                || record.minimumInputBytes.has_value()
                || record.maximumInputBytes.has_value()
                || !record.pragmaticModel.has_value()) {
                return false;
            }
            const auto* model = std::get_if<
                RuntimeCalibrationConstantPerOperationModel>(
                    &*record.pragmaticModel);
            if (model == nullptr || model->picosecondsPerOperation == 0) {
                return false;
            }
        }
    }
    return std::ranges::all_of(seen, [](bool value) { return value; });
}

RuntimeCalibrationInputKind inputKindFor(
    const RuntimeCalibrationInputIdentity& inputIdentity)
{
    return std::visit([](const auto& input) {
        using Input = std::decay_t<decltype(input)>;
        if constexpr (std::is_same_v<Input, NoSignatureInput>) {
            return RuntimeCalibrationInputKind::NoSignature;
        } else if constexpr (std::is_same_v<Input, PrehashedInput>) {
            return RuntimeCalibrationInputKind::Prehashed;
        } else if constexpr (std::is_same_v<Input, MessageInput>) {
            return RuntimeCalibrationInputKind::Message;
        } else if constexpr (std::is_same_v<Input, KeyEstablishmentInput>) {
            return RuntimeCalibrationInputKind::KeyEstablishment;
        } else if constexpr (std::is_same_v<Input, AeadInput>) {
            return RuntimeCalibrationInputKind::Aead;
        } else {
            return RuntimeCalibrationInputKind::HashXof;
        }
    }, inputIdentity);
}

std::optional<std::uint64_t> inputSizeFor(
    const RuntimeCalibrationInputIdentity& inputIdentity)
{
    return std::visit([](const auto& input) -> std::optional<std::uint64_t> {
        using Input = std::decay_t<decltype(input)>;
        if constexpr (std::is_same_v<Input, MessageInput>) {
            return input.messageSize;
        } else if constexpr (std::is_same_v<Input, AeadInput>) {
            return input.plaintextSize;
        } else if constexpr (std::is_same_v<Input, HashXofInput>) {
            return input.inputSize;
        } else {
            return std::nullopt;
        }
    }, inputIdentity);
}

RuntimeDurationComponent durationFromPicoseconds(
    std::uint64_t picosecondsPerOperation,
    std::uint64_t operations)
{
    constexpr WideUnsigned kPicosecondsPerNanosecond = 1000;
    constexpr WideUnsigned kHalfNanosecond = 500;
    const auto totalPicoseconds =
        static_cast<WideUnsigned>(picosecondsPerOperation) * operations;
    auto roundedNanoseconds = totalPicoseconds / kPicosecondsPerNanosecond;
    if (totalPicoseconds % kPicosecondsPerNanosecond >= kHalfNanosecond) {
        ++roundedNanoseconds;
    }
    if (roundedNanoseconds
        > static_cast<WideUnsigned>(
            std::numeric_limits<RuntimeDuration::rep>::max())) {
        return unavailable(RuntimeEstimateUnavailableReason::ArithmeticOverflow);
    }
    return RuntimeDuration{
        static_cast<RuntimeDuration::rep>(roundedNanoseconds)};
}

class PragmaticProvider final : public RuntimeCalibrationProvider {
public:
    explicit PragmaticProvider(RuntimeCalibrationResource resource)
        : resource_(std::move(resource))
    {
    }

    CalibrationLookupResult estimateEntry(
        RuntimeCalibrationRequest request) const override
    {
        const auto requestedInterval =
            request.key.measurementSettings.memorySamplingIntervalMilliseconds;
        if (!supportsSamplingInterval(requestedInterval)) {
            return unavailableEntry(
                RuntimeEstimateUnavailableReason::MeasurementContextUnsupported);
        }
        if (request.iterationsPerRun < core::kMinIterationsPerRun
            || request.iterationsPerRun > core::kMaxIterationsPerRun) {
            return unavailableEntry(
                RuntimeEstimateUnavailableReason::InvalidCalibrationData);
        }

        const auto inputKind = inputKindFor(request.key.inputIdentity);
        const auto inputSize = inputSizeFor(request.key.inputIdentity);
        const auto record = std::ranges::find_if(
            resource_.records,
            [&](const RuntimeCalibrationResourceRecord& candidate) {
                return candidate.calibrationCase.profileId == request.key.profileId
                    && candidate.calibrationCase.operation == request.key.operation
                    && candidate.calibrationCase.inputKind == inputKind;
            });
        if (record == resource_.records.end()) {
            return unavailableEntry(
                RuntimeEstimateUnavailableReason::CalibrationPointMissing);
        }

        std::uint64_t picosecondsPerOperation = 0;
        const auto modelReason = resolvePicosecondsPerOperation(
            *record, inputSize, picosecondsPerOperation);
        if (modelReason.has_value()) {
            return unavailableEntry(*modelReason);
        }

        const auto measured = durationFromPicoseconds(
            picosecondsPerOperation, request.iterationsPerRun);
        const auto nonMeasured = durationFromPicoseconds(
            picosecondsPerOperation,
            resource_.approximationPolicy->warmupOperationsPerLogicalRun);
        const auto fixed = RuntimeDuration{
            static_cast<RuntimeDuration::rep>(
                resource_.approximationPolicy->fixedEntryOverhead.nanoseconds)};
        return {measured, nonMeasured, fixed};
    }

    RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition&,
        core::MeasurementSettings settings) const override
    {
        if (!supportsSamplingInterval(settings.memorySamplingIntervalMilliseconds)) {
            return unavailable(
                RuntimeEstimateUnavailableReason::MeasurementContextUnsupported);
        }
        return RuntimeDuration{static_cast<RuntimeDuration::rep>(
            resource_.approximationPolicy->batchOverhead.nanoseconds)};
    }

private:
    bool supportsSamplingInterval(std::uint32_t requestedInterval) const
    {
        if (requestedInterval == kMeasuredSamplingIntervalMilliseconds) {
            return true;
        }
        return std::ranges::any_of(
            resource_.approximationPolicy->samplingAssumptions,
            [&](const RuntimeCalibrationSamplingAssumption& assumption) {
                return assumption.requestedIntervalMilliseconds == requestedInterval
                    && assumption.sourceMeasuredIntervalMilliseconds
                        == kMeasuredSamplingIntervalMilliseconds
                    && assumption.tag
                        == RuntimeCalibrationAssumptionTag::AssumedFrom5ms;
            });
    }

    std::optional<RuntimeEstimateUnavailableReason>
    resolvePicosecondsPerOperation(
        const RuntimeCalibrationResourceRecord& record,
        std::optional<std::uint64_t> inputSize,
        std::uint64_t& result) const
    {
        if (record.calibrationCase.hasVariableInputSize != inputSize.has_value()
            || !record.pragmaticModel.has_value()) {
            return RuntimeEstimateUnavailableReason::InvalidCalibrationData;
        }

        if (record.modelKind
            == RuntimeCalibrationMeasuredModelKind::ConstantPerOperation) {
            const auto* model = std::get_if<
                RuntimeCalibrationConstantPerOperationModel>(
                    &*record.pragmaticModel);
            if (record.calibrationCase.hasVariableInputSize
                || model == nullptr
                || model->picosecondsPerOperation == 0) {
                return RuntimeEstimateUnavailableReason::InvalidCalibrationData;
            }
            result = model->picosecondsPerOperation;
            return std::nullopt;
        }

        if (record.modelKind
            != RuntimeCalibrationMeasuredModelKind::AnchoredAffinePerOperation) {
            return RuntimeEstimateUnavailableReason::InvalidCalibrationData;
        }
        const auto* model = std::get_if<
            RuntimeCalibrationAnchoredAffinePerOperationModel>(
                &*record.pragmaticModel);
        if (model == nullptr
            || !record.minimumInputBytes.has_value()
            || !record.maximumInputBytes.has_value()
            || model->anchorInputBytes != *record.minimumInputBytes
            || !inputSize.has_value()) {
            return RuntimeEstimateUnavailableReason::InvalidCalibrationData;
        }
        if (*inputSize < *record.minimumInputBytes
            || *inputSize > *record.maximumInputBytes) {
            return RuntimeEstimateUnavailableReason::CalibrationPointMissing;
        }

        const auto sizeGrowth =
            static_cast<WideUnsigned>(model->slopePicosecondsPerBytePerOperation)
            * (*inputSize - model->anchorInputBytes);
        const auto modeledPicoseconds =
            static_cast<WideUnsigned>(model->anchorPicosecondsPerOperation)
            + sizeGrowth;
        if (modeledPicoseconds > std::numeric_limits<std::uint64_t>::max()) {
            return RuntimeEstimateUnavailableReason::ArithmeticOverflow;
        }
        result = static_cast<std::uint64_t>(modeledPicoseconds);
        return std::nullopt;
    }

    RuntimeCalibrationResource resource_;
};

} // namespace

std::unique_ptr<RuntimeCalibrationProvider> makePragmaticRuntimeCalibrationProvider(
    RuntimeCalibrationResourceLoadResult loadResult)
{
    switch (loadResult.status) {
    case RuntimeCalibrationResourceStatus::Missing:
        return noDataProvider();
    case RuntimeCalibrationResourceStatus::Corrupt:
        return unavailableProvider(
            RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    case RuntimeCalibrationResourceStatus::Inapplicable:
        return unavailableProvider(
            RuntimeEstimateUnavailableReason::MeasurementContextUnsupported);
    case RuntimeCalibrationResourceStatus::Loaded:
        break;
    }

    if (!loadResult.resource.has_value()) {
        return unavailableProvider(
            RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    }
    auto resource = std::move(*loadResult.resource);
    if (resource.dialect != RuntimeCalibrationResourceDialect::M23Pragmatic) {
        return noDataProvider();
    }
    if (!isValidPragmaticResource(resource)) {
        return unavailableProvider(
            RuntimeEstimateUnavailableReason::InvalidCalibrationData);
    }
    return std::make_unique<PragmaticProvider>(std::move(resource));
}

} // namespace cryptobench::application
