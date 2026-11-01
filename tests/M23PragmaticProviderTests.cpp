#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/PragmaticRuntimeCalibrationProvider.h>
#include <cryptobench/application/RuntimeCalibrationInventory.h>
#include <cryptobench/application/RuntimeEstimateService.h>
#include <cryptobench/core/ConfigValidation.h>

#include <QByteArray>
#include <QCoreApplication>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

namespace application = cryptobench::application;
namespace core = cryptobench::core;

using application::RuntimeCalibrationCase;
using application::RuntimeCalibrationInputKind;
using application::RuntimeCalibrationInputIdentity;
using application::RuntimeCalibrationResource;
using application::RuntimeCalibrationResourceRecord;
using application::RuntimeDuration;
using application::RuntimeDurationComponent;
using application::RuntimeEstimateUnavailableReason;

using WideUnsigned = unsigned __int128;

constexpr std::uint32_t kMeasuredSamplingIntervalMilliseconds = 5;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireDuration(
    const RuntimeDurationComponent& component,
    std::int64_t expected,
    std::string_view message)
{
    require(std::holds_alternative<RuntimeDuration>(component), message);
    require(std::get<RuntimeDuration>(component).count() == expected, message);
}

void requireReason(
    const RuntimeDurationComponent& component,
    RuntimeEstimateUnavailableReason expected,
    std::string_view message)
{
    require(
        std::holds_alternative<RuntimeEstimateUnavailableReason>(component),
        message);
    require(
        std::get<RuntimeEstimateUnavailableReason>(component) == expected,
        message);
}

std::uint64_t modeledPicoseconds(
    const RuntimeCalibrationResourceRecord& record,
    std::optional<std::uint64_t> inputSize)
{
    require(record.pragmaticModel.has_value(), "synthetic model is absent");
    if (const auto* constant = std::get_if<
            application::RuntimeCalibrationConstantPerOperationModel>(
                &*record.pragmaticModel)) {
        return constant->picosecondsPerOperation;
    }
    const auto* affine = std::get_if<
        application::RuntimeCalibrationAnchoredAffinePerOperationModel>(
            &*record.pragmaticModel);
    require(affine != nullptr && inputSize.has_value(),
        "synthetic affine model or size is absent");
    return affine->anchorPicosecondsPerOperation
        + affine->slopePicosecondsPerBytePerOperation
            * (*inputSize - affine->anchorInputBytes);
}

std::int64_t roundedNanoseconds(
    std::uint64_t picosecondsPerOperation,
    std::uint64_t operations)
{
    const auto total = static_cast<WideUnsigned>(picosecondsPerOperation) * operations;
    auto rounded = total / 1000;
    if (total % 1000 >= 500) {
        ++rounded;
    }
    require(
        rounded <= static_cast<WideUnsigned>(
            std::numeric_limits<RuntimeDuration::rep>::max()),
        "test expected value does not fit RuntimeDuration");
    return static_cast<std::int64_t>(rounded);
}

std::uint64_t minimumSize(const RuntimeCalibrationCase& calibrationCase)
{
    return calibrationCase.inputKind == RuntimeCalibrationInputKind::HashXof
        ? 0
        : 1;
}

RuntimeCalibrationInputIdentity inputIdentity(
    const RuntimeCalibrationCase& calibrationCase,
    std::uint64_t size)
{
    switch (calibrationCase.inputKind) {
    case RuntimeCalibrationInputKind::NoSignature:
        return application::NoSignatureInput{};
    case RuntimeCalibrationInputKind::Prehashed:
        return application::PrehashedInput{};
    case RuntimeCalibrationInputKind::Message:
        return application::MessageInput{size};
    case RuntimeCalibrationInputKind::KeyEstablishment:
        return application::KeyEstablishmentInput{};
    case RuntimeCalibrationInputKind::Aead:
        return application::AeadInput{size};
    case RuntimeCalibrationInputKind::HashXof:
        return application::HashXofInput{size};
    }
    throw std::runtime_error("unknown canonical input kind");
}

application::RuntimeCalibrationRequest requestFor(
    const RuntimeCalibrationCase& calibrationCase,
    std::uint64_t size,
    std::uint32_t samplingInterval = kMeasuredSamplingIntervalMilliseconds,
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return {
        {
            calibrationCase.profileId,
            calibrationCase.operation,
            inputIdentity(calibrationCase, size),
            core::MeasurementSettings{samplingInterval}},
        iterations,
        runs};
}

RuntimeCalibrationResource makeSyntheticResource()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    require(inventory.cases.size() == 175, "inventory case count changed");
    require(
        inventory.fixedInputCaseCount == 78
            && inventory.variableInputCaseCount == 97,
        "inventory model shape counts changed");

    RuntimeCalibrationResource resource;
    resource.datasetId = "synthetic-pragmatic-provider-fixture";
    resource.datasetVersion = "1.0.0-test";
    resource.qualificationStatus = "reducedScopeApproximate";
    resource.dialect = application::RuntimeCalibrationResourceDialect::M23Pragmatic;

    application::RuntimeCalibrationPragmaticProvenance provenance;
    provenance.calibrationProtocolId = "memory-v2-calibration-v1";
    resource.pragmaticProvenance = std::move(provenance);

    application::RuntimeCalibrationApproximationPolicy policy;
    policy.warmupOperationsPerLogicalRun = 1;
    policy.fixedEntryOverhead = {
        0, application::RuntimeCalibrationAssumptionTag::AssumedUnmeasured};
    policy.batchOverhead = {
        0, application::RuntimeCalibrationAssumptionTag::AssumedUnmeasured};
    for (std::uint32_t interval = 1; interval <= 4; ++interval) {
        policy.samplingAssumptions.push_back({
            interval,
            kMeasuredSamplingIntervalMilliseconds,
            application::RuntimeCalibrationAssumptionTag::AssumedFrom5ms});
    }
    resource.approximationPolicy = std::move(policy);

    resource.records.reserve(inventory.cases.size());
    for (std::size_t index = 0; index < inventory.cases.size(); ++index) {
        const auto& calibrationCase = inventory.cases[index];
        RuntimeCalibrationResourceRecord record{};
        record.calibrationCase = calibrationCase;
        record.samplingIntervalMilliseconds =
            kMeasuredSamplingIntervalMilliseconds;
        if (calibrationCase.hasVariableInputSize) {
            const auto minimum = minimumSize(calibrationCase);
            record.modelKind =
                application::RuntimeCalibrationMeasuredModelKind::
                    AnchoredAffinePerOperation;
            record.minimumInputBytes = minimum;
            record.maximumInputBytes = core::kMaxWorkloadBytes;
            record.pragmaticModel =
                application::RuntimeCalibrationAnchoredAffinePerOperationModel{
                    minimum,
                    1500 + static_cast<std::uint64_t>(index),
                    3 + static_cast<std::uint64_t>(index)};
            record.evidenceStatus =
                application::RuntimeCalibrationRecordEvidenceStatus::
                    PerOperationReferenceFitSizeHoldoutOnly;
        } else {
            record.modelKind =
                application::RuntimeCalibrationMeasuredModelKind::
                    ConstantPerOperation;
            record.pragmaticModel =
                application::RuntimeCalibrationConstantPerOperationModel{
                    1500 + static_cast<std::uint64_t>(index)};
            record.evidenceStatus =
                application::RuntimeCalibrationRecordEvidenceStatus::
                    PerOperationReferenceFitOnly;
        }
        resource.records.push_back(std::move(record));
    }
    return resource;
}

RuntimeCalibrationResourceRecord& findRecord(
    RuntimeCalibrationResource& resource,
    const RuntimeCalibrationCase& calibrationCase)
{
    const auto record = std::ranges::find_if(
        resource.records,
        [&](const RuntimeCalibrationResourceRecord& candidate) {
            return candidate.calibrationCase.profileId == calibrationCase.profileId
                && candidate.calibrationCase.operation == calibrationCase.operation
                && candidate.calibrationCase.inputKind == calibrationCase.inputKind;
        });
    require(record != resource.records.end(), "synthetic record was not found");
    return *record;
}

RuntimeCalibrationCase findCase(RuntimeCalibrationInputKind inputKind)
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& candidate) {
            return candidate.inputKind == inputKind;
        });
    require(calibrationCase != inventory.cases.end(), "inventory input kind is absent");
    return *calibrationCase;
}

application::BatchDefinition parseBatch(std::string_view entries)
{
    const auto entryBytes = QByteArray{
        entries.data(), static_cast<qsizetype>(entries.size())};
    const auto input = QByteArray{
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"}
        + entryBytes + "]}";
    const auto parsed = application::BatchInputParser{}.parseData(input);
    require(parsed.issues.empty(), "synthetic provider Batch input was rejected");
    require(parsed.definition.has_value(), "synthetic provider Batch has no definition");
    return *parsed.definition;
}

std::unique_ptr<application::RuntimeCalibrationProvider> providerFor(
    RuntimeCalibrationResource resource)
{
    return application::makePragmaticRuntimeCalibrationProvider({
        application::RuntimeCalibrationResourceStatus::Loaded,
        "synthetic typed test resource",
        std::move(resource)});
}

void testAllCanonicalRecordsAreReachable()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    auto provider = providerFor(makeSyntheticResource());
    require(inventory.profileIds.size() == 72, "profile inventory count changed");
    require(inventory.profileOperationCount == 139, "profile-operation count changed");
    require(inventory.cases.size() == 175, "typed case count changed");
    require(
        inventory.fixedInputCaseCount == 78
            && inventory.variableInputCaseCount == 97,
        "fixed/variable case counts changed");

    for (const auto& calibrationCase : inventory.cases) {
        const auto size = minimumSize(calibrationCase);
        const auto lookup = provider->estimateEntry(
            requestFor(calibrationCase, size, 5, 1, 1));
        require(
            std::holds_alternative<RuntimeDuration>(
                lookup.estimatedMeasuredBlockDurationPerRun),
            "canonical case did not resolve a measured model");
        require(
            std::holds_alternative<RuntimeDuration>(
                lookup.estimatedNonMeasuredDurationPerRun),
            "canonical case did not resolve its one-operation warm-up");
        requireDuration(
            lookup.estimatedFixedEntryOverhead,
            0,
            "canonical case did not preserve assumed zero fixed overhead");
    }
}

void testVariableSizesSamplingAndTypedIdentity()
{
    auto resource = makeSyntheticResource();
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const RuntimeCalibrationCase* prehashedCase = nullptr;
    const RuntimeCalibrationCase* pairedMessageCase = nullptr;
    const RuntimeCalibrationCase* encryptCase = nullptr;
    const RuntimeCalibrationCase* pairedDecryptCase = nullptr;
    for (const auto& candidate : inventory.cases) {
        if (candidate.inputKind == RuntimeCalibrationInputKind::Prehashed) {
            const auto message = std::ranges::find_if(
                inventory.cases,
                [&](const RuntimeCalibrationCase& other) {
                    return other.profileId == candidate.profileId
                        && other.operation == candidate.operation
                        && other.inputKind == RuntimeCalibrationInputKind::Message;
                });
            if (message != inventory.cases.end()) {
                prehashedCase = &candidate;
                pairedMessageCase = &*message;
                break;
            }
        }
    }
    for (const auto& candidate : inventory.cases) {
        if (candidate.inputKind == RuntimeCalibrationInputKind::Aead
            && candidate.operation == core::BenchmarkOperation::Encrypt) {
            const auto decrypt = std::ranges::find_if(
                inventory.cases,
                [&](const RuntimeCalibrationCase& other) {
                    return other.profileId == candidate.profileId
                        && other.operation == core::BenchmarkOperation::Decrypt
                        && other.inputKind == RuntimeCalibrationInputKind::Aead;
                });
            if (decrypt != inventory.cases.end()) {
                encryptCase = &candidate;
                pairedDecryptCase = &*decrypt;
                break;
            }
        }
    }
    require(prehashedCase != nullptr && pairedMessageCase != nullptr,
        "same-profile Message and Prehashed identities are not in the inventory");
    require(encryptCase != nullptr && pairedDecryptCase != nullptr,
        "same-profile AEAD Encrypt and Decrypt identities are not in the inventory");

    findRecord(resource, *prehashedCase).pragmaticModel =
        application::RuntimeCalibrationConstantPerOperationModel{1000};
    findRecord(resource, *pairedMessageCase).pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{1, 10'000, 0};
    findRecord(resource, *encryptCase).pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{1, 2000, 0};
    findRecord(resource, *pairedDecryptCase).pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{1, 30'000, 0};
    auto provider = providerFor(resource);

    requireDuration(
        provider->estimateEntry(requestFor(*prehashedCase, 0))
            .estimatedMeasuredBlockDurationPerRun,
        1,
        "Prehashed signature resolved to the Message model");
    requireDuration(
        provider->estimateEntry(requestFor(*pairedMessageCase, 1))
            .estimatedMeasuredBlockDurationPerRun,
        10,
        "Message signature resolved to the Prehashed model");
    requireDuration(
        provider->estimateEntry(requestFor(*encryptCase, 1))
            .estimatedMeasuredBlockDurationPerRun,
        2,
        "AEAD Encrypt resolved to the Decrypt model");
    requireDuration(
        provider->estimateEntry(requestFor(*pairedDecryptCase, 1))
            .estimatedMeasuredBlockDurationPerRun,
        30,
        "AEAD Decrypt resolved to the Encrypt model");

    constexpr std::uint64_t kSizes[]{
        0, 1, 64, 4096, 65'536, 16'777'216, core::kMaxWorkloadBytes};

    for (const auto inputKind : {
             RuntimeCalibrationInputKind::Message,
             RuntimeCalibrationInputKind::Aead,
             RuntimeCalibrationInputKind::HashXof}) {
        const auto calibrationCase = std::ranges::find_if(
            inventory.cases,
            [&](const RuntimeCalibrationCase& candidate) {
                return candidate.inputKind == inputKind;
            });
        require(calibrationCase != inventory.cases.end(), "variable case is missing");
        const auto& record = *std::ranges::find_if(
            resource.records,
            [&](const RuntimeCalibrationResourceRecord& candidate) {
                return candidate.calibrationCase.profileId == calibrationCase->profileId
                    && candidate.calibrationCase.operation == calibrationCase->operation
                    && candidate.calibrationCase.inputKind == calibrationCase->inputKind;
            });
        for (const auto size : kSizes) {
            if (size < *record.minimumInputBytes
                || size > *record.maximumInputBytes) {
                continue;
            }
            const auto lookup = provider->estimateEntry(
                requestFor(*calibrationCase, size));
            const auto picoseconds = modeledPicoseconds(record, size);
            requireDuration(
                lookup.estimatedMeasuredBlockDurationPerRun,
                roundedNanoseconds(picoseconds, 1),
                "variable-size affine computation or rounding was incorrect");
        }
    }

    const auto messageCase = std::ranges::find_if(
        inventory.cases,
        [](const RuntimeCalibrationCase& candidate) {
            return candidate.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(messageCase != inventory.cases.end(), "Message case is absent");
    const auto ps = modeledPicoseconds(
        *std::ranges::find_if(
            resource.records,
            [&](const RuntimeCalibrationResourceRecord& candidate) {
                return candidate.calibrationCase.profileId == messageCase->profileId
                    && candidate.calibrationCase.operation == messageCase->operation
                    && candidate.calibrationCase.inputKind == messageCase->inputKind;
            }),
        1);
    for (std::uint32_t interval = 1; interval <= 5; ++interval) {
        const auto lookup = provider->estimateEntry(
            requestFor(*messageCase, 1, interval, 2, interval == 1 ? 1 : 1000));
        const auto expected = roundedNanoseconds(ps, 2);
        requireDuration(
            lookup.estimatedMeasuredBlockDurationPerRun,
            expected,
            "explicit 1-5 ms context mapping changed the per-run model");
    }
    requireReason(
        provider->estimateEntry(requestFor(*messageCase, 1, 6))
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported,
        "unsupported sampling interval did not retain its typed reason");

    const auto hashCase = std::ranges::find_if(
        inventory.cases,
        [](const RuntimeCalibrationCase& candidate) {
            return candidate.inputKind == RuntimeCalibrationInputKind::HashXof;
        });
    require(hashCase != inventory.cases.end(), "Hash/XOF case is absent");
    requireDuration(
        provider->estimateEntry(requestFor(*hashCase, 0))
            .estimatedMeasuredBlockDurationPerRun,
        roundedNanoseconds(
            modeledPicoseconds(
                findRecord(resource, *hashCase), std::uint64_t{0}),
            1),
        "legal zero-byte Hash/XOF request was unavailable");

    auto illegalMessageSize = requestFor(*messageCase, 0);
    requireReason(
        provider->estimateEntry(illegalMessageSize)
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "zero-byte Message request was not rejected");

    auto wrongVariant = requestFor(*hashCase, 1);
    wrongVariant.key.inputIdentity = application::MessageInput{1};
    requireReason(
        provider->estimateEntry(wrongVariant)
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "mismatched typed input identity resolved to another record");

    auto badIterations = requestFor(*messageCase, 1, 5, 0);
    requireReason(
        provider->estimateEntry(badIterations)
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "zero N produced a numeric estimate");
}

void testRoundingMIndependenceAndServiceComposition()
{
    const auto definition = parseBatch(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":2,"runs":3,"parameters":{"inputMode":"message","messageSizeBytes":1}})");
    auto resource = makeSyntheticResource();
    const auto requestKey = application::makeRuntimeCalibrationKey(
        definition.entries()[0].config, core::MeasurementSettings{5});
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto calibrationCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& candidate) {
            return candidate.profileId == requestKey.profileId
                && candidate.operation == requestKey.operation
                && candidate.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(calibrationCase != inventory.cases.end(), "service case is absent");
    auto& record = findRecord(resource, *calibrationCase);
    record.pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{
            1, 1500, 0};
    auto provider = providerFor(resource);

    const auto request = application::RuntimeCalibrationRequest{
        requestKey, 2, 3};
    const auto mIndependent = application::RuntimeCalibrationRequest{
        requestKey, 2, 1000};
    const auto first = provider->estimateEntry(request);
    const auto second = provider->estimateEntry(mIndependent);
    requireDuration(
        first.estimatedMeasuredBlockDurationPerRun,
        3,
        "N was not applied before picosecond-to-nanosecond rounding");
    requireDuration(
        first.estimatedMeasuredBlockDurationPerRun,
        std::get<RuntimeDuration>(second.estimatedMeasuredBlockDurationPerRun).count(),
        "M changed measured-block duration per run");
    requireDuration(
        first.estimatedNonMeasuredDurationPerRun,
        2,
        "one warm-up operation did not use half-up rounding");

    const auto estimate = application::RuntimeEstimateService{}.estimate(
        definition, core::MeasurementSettings{5}, *provider);
    require(
        estimate.availability == application::RuntimeEstimateAvailability::Available,
        "M22 service did not aggregate the pragmatic provider");
    requireDuration(
        estimate.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        3,
        "service changed the measured per-run block");
    requireDuration(
        estimate.perEntry[0].estimatedTotalEntryDuration,
        15,
        "M22 service did not apply M to measured plus warm-up components");
    requireDuration(
        estimate.estimatedTotalBatchDuration,
        15,
        "M22 service did not include the explicit assumed-zero Batch overhead");

    auto highRuns = parseBatch(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":2,"runs":1000,"parameters":{"inputMode":"message","messageSizeBytes":1}})");
    const auto highRunsEstimate = application::RuntimeEstimateService{}.estimate(
        highRuns, core::MeasurementSettings{5}, *provider);
    requireDuration(
        highRunsEstimate.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        3,
        "legal maximum M changed measured-block duration");
    requireDuration(
        highRunsEstimate.perEntry[0].estimatedTotalEntryDuration,
        5000,
        "M22 service did not own M aggregation");
}

void testSafeFallbackAndMalformedTypedResources()
{
    const auto calibrationCase = findCase(RuntimeCalibrationInputKind::Message);
    const auto request = requestFor(calibrationCase, 1);
    const auto definition = parseBatch(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}})");

    const auto missing = application::makePragmaticRuntimeCalibrationProvider({
        application::RuntimeCalibrationResourceStatus::Missing,
        "missing",
        std::nullopt});
    const auto missingResult = missing->estimateEntry(request);
    requireReason(
        missingResult.estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "missing resource did not use the safe no-data provider");
    requireReason(
        missing->estimateBatchOverhead(definition, core::MeasurementSettings{5}),
        RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
        "missing resource fabricated Batch overhead");

    const auto corrupt = application::makePragmaticRuntimeCalibrationProvider({
        application::RuntimeCalibrationResourceStatus::Corrupt,
        "corrupt",
        std::nullopt});
    requireReason(
        corrupt->estimateEntry(request).estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "corrupt resource did not retain an invalid-data reason");

    const auto inapplicable = application::makePragmaticRuntimeCalibrationProvider({
        application::RuntimeCalibrationResourceStatus::Inapplicable,
        "inapplicable",
        std::nullopt});
    requireReason(
        inapplicable->estimateEntry(request).estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported,
        "inapplicable resource did not retain a context reason");

    RuntimeCalibrationResource provisional;
    provisional.qualificationStatus = "unqualified";
    const auto provisionalProvider = providerFor(std::move(provisional));
    requireReason(
        provisionalProvider->estimateEntry(request)
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "provisional dialect did not fall back to no-data behavior");

    auto malformed = makeSyntheticResource();
    malformed.records.pop_back();
    const auto malformedProvider = providerFor(std::move(malformed));
    requireReason(
        malformedProvider->estimateEntry(request)
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "incomplete trusted-resource construction returned a numeric estimate");
}

void testZeroDurationOverflowAndPartialServiceResult()
{
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto fixedCase = std::ranges::find_if(
        inventory.cases,
        [](const RuntimeCalibrationCase& candidate) {
            return !candidate.hasVariableInputSize;
        });
    require(fixedCase != inventory.cases.end(), "fixed case is absent");

    auto zeroResource = makeSyntheticResource();
    auto& zeroRecord = findRecord(zeroResource, *fixedCase);
    zeroRecord.pragmaticModel =
        application::RuntimeCalibrationConstantPerOperationModel{1};
    auto zeroProvider = providerFor(std::move(zeroResource));
    const auto zeroLookup = zeroProvider->estimateEntry(
        requestFor(*fixedCase, 0, 5, 1, 1000));
    requireDuration(
        zeroLookup.estimatedMeasuredBlockDurationPerRun,
        0,
        "rounded available zero was confused with missing data");
    requireDuration(
        zeroLookup.estimatedNonMeasuredDurationPerRun,
        0,
        "sub-nanosecond warm-up did not round to available zero");
    requireDuration(
        zeroLookup.estimatedFixedEntryOverhead,
        0,
        "assumed-unmeasured fixed overhead was not available zero");

    const auto definition = parseBatch(
        R"({"profileId":"rsa-pss-2048-sha256","operation":"sign","iterationsPerRun":1000000000,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}})");
    auto overflowResource = makeSyntheticResource();
    const auto rsaKey = application::makeRuntimeCalibrationKey(
        definition.entries()[0].config, core::MeasurementSettings{5});
    const auto overflowCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& candidate) {
            return candidate.profileId == rsaKey.profileId
                && candidate.operation == rsaKey.operation
                && candidate.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(overflowCase != inventory.cases.end(), "overflow case is absent");
    auto& overflowRecord = findRecord(overflowResource, *overflowCase);
    overflowRecord.pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{
            1,
            std::numeric_limits<std::uint64_t>::max(),
            0};
    auto overflowProvider = providerFor(overflowResource);
    const auto overflowRequest = application::RuntimeCalibrationRequest{
        rsaKey, core::kMaxIterationsPerRun, 1};
    const auto overflowLookup = overflowProvider->estimateEntry(overflowRequest);
    requireReason(
        overflowLookup.estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "N-scaled picosecond overflow did not retain its typed reason");
    require(
        std::holds_alternative<RuntimeDuration>(
            overflowLookup.estimatedNonMeasuredDurationPerRun),
        "measured-block overflow suppressed the available warm-up component");
    requireDuration(
        overflowLookup.estimatedFixedEntryOverhead,
        0,
        "measured-block overflow suppressed assumed fixed zero");

    const auto partial = application::RuntimeEstimateService{}.estimate(
        definition, core::MeasurementSettings{5}, *overflowProvider);
    require(
        partial.availability == application::RuntimeEstimateAvailability::Partial,
        "one overflowing entry suppressed another usable entry");
    require(partial.missingMeasuredBlockEntryCount == 1
            && partial.missingTotalEntryCount == 1,
        "partial overflow counts were incorrect");
    requireReason(
        partial.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "service replaced the overflow reason");
    require(
        std::holds_alternative<RuntimeDuration>(
            partial.perEntry[1].estimatedMeasuredBlockDurationPerRun),
        "service discarded a separate available measured block");
    requireReason(
        partial.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "overflowing Batch exposed a numeric total");

    auto invalidEndpointResource = makeSyntheticResource();
    const auto variableCase = std::ranges::find_if(
        inventory.cases,
        [](const RuntimeCalibrationCase& candidate) {
            return candidate.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(variableCase != inventory.cases.end(), "variable case is absent");

    auto zeroAnchorResource = makeSyntheticResource();
    auto& zeroAnchorRecord = findRecord(zeroAnchorResource, *variableCase);
    zeroAnchorRecord.pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{
            1, 0, 0};
    const auto zeroAnchorProvider = providerFor(std::move(zeroAnchorResource));
    requireReason(
        zeroAnchorProvider->estimateEntry(requestFor(*variableCase, 1))
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "factory accepted a zero anchored-affine per-operation reference");

    auto& invalidEndpoint = findRecord(invalidEndpointResource, *variableCase);
    invalidEndpoint.pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{
            1, 1, std::numeric_limits<std::uint64_t>::max()};
    const auto invalidProvider = providerFor(std::move(invalidEndpointResource));
    requireReason(
        invalidProvider->estimateEntry(requestFor(*variableCase, 1))
            .estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "invalid uint64 affine endpoint was accepted");
}

void testShortRunWarningIntegration()
{
    const auto definition = parseBatch(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":2,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":3,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1000000000,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":268435456}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":10,"parameters":{"inputMode":"message","messageSizeBytes":1}})");
    const auto settings = core::MeasurementSettings{5};
    auto resource = makeSyntheticResource();
    const auto firstKey = application::makeRuntimeCalibrationKey(
        definition.entries()[0].config, settings);
    const auto inventory = application::enumerateRuntimeCalibrationInventory();
    const auto messageCase = std::ranges::find_if(
        inventory.cases,
        [&](const RuntimeCalibrationCase& candidate) {
            return candidate.profileId == firstKey.profileId
                && candidate.operation == firstKey.operation
                && candidate.inputKind == RuntimeCalibrationInputKind::Message;
        });
    require(messageCase != inventory.cases.end(),
        "short-run integration Message case is absent");

    constexpr std::uint64_t kHalfSecondPicoseconds = 500'000'000'000ULL;
    const auto slope =
        (std::numeric_limits<std::uint64_t>::max() - kHalfSecondPicoseconds)
        / (core::kMaxWorkloadBytes - 1);
    auto& record = findRecord(resource, *messageCase);
    record.pragmaticModel =
        application::RuntimeCalibrationAnchoredAffinePerOperationModel{
            1, kHalfSecondPicoseconds, slope};
    const auto provider = providerFor(std::move(resource));

    constexpr std::int64_t kHalfSecondNanoseconds = 500'000'000;
    constexpr std::int64_t kOneSecondNanoseconds = 1'000'000'000;
    constexpr std::int64_t kOneAndHalfSecondsNanoseconds = 1'500'000'000;
    const std::int64_t expectedMeasured[]{
        kHalfSecondNanoseconds,
        kOneSecondNanoseconds,
        kOneAndHalfSecondsNanoseconds,
        0,
        kHalfSecondNanoseconds};
    for (std::size_t index = 0; index < definition.entries().size(); ++index) {
        const auto& entry = definition.entries()[index];
        const auto lookup = provider->estimateEntry({
            application::makeRuntimeCalibrationKey(entry.config, settings),
            entry.config.iterationsPerRun,
            entry.config.runs});
        if (index == 3) {
            requireReason(
                lookup.estimatedMeasuredBlockDurationPerRun,
                RuntimeEstimateUnavailableReason::ArithmeticOverflow,
                "overflowing measured block unexpectedly remained available");
        } else {
            requireDuration(
                lookup.estimatedMeasuredBlockDurationPerRun,
                expectedMeasured[index],
                "direct provider measured block did not match the short-run boundary case");
        }
    }

    const auto estimate = application::RuntimeEstimateService{}.estimate(
        definition, settings, *provider);
    require(
        estimate.shortRunEntryIndices == std::vector<std::uint32_t>{1, 5},
        "service short-run indices did not preserve strict threshold/order/M independence");
    require(
        estimate.availability == application::RuntimeEstimateAvailability::Partial
            && estimate.missingMeasuredBlockEntryCount == 1,
        "unavailable measured block did not remain partial");
    requireReason(
        estimate.perEntry[3].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "service did not preserve the unavailable measured-block reason");
}

void verifyPrivateCandidate(const QStringList& arguments)
{
    require(arguments.size() == 11,
        "expected --candidate <file> --sha256 <hex> --os <name> "
        "--architecture <name> --openssl <version>");
    require(arguments[1] == QStringLiteral("--candidate")
            && arguments[3] == QStringLiteral("--sha256")
            && arguments[5] == QStringLiteral("--os")
            && arguments[7] == QStringLiteral("--architecture")
            && arguments[9] == QStringLiteral("--openssl"),
        "private candidate options must use the exact named order");
    const auto path = arguments[2];
    const auto hash = arguments[4].toStdString();
    const application::RuntimeCalibrationEnvironment environment{
        "memory-v2-calibration-v1",
        arguments[6].toStdString(),
        arguments[8].toStdString(),
        "Release",
        arguments[10].toStdString()};
    auto loaded = application::loadRuntimeCalibrationResource(path, hash, environment);
    require(
        loaded.status == application::RuntimeCalibrationResourceStatus::Loaded
            && loaded.resource.has_value()
            && loaded.resource->dialect
                == application::RuntimeCalibrationResourceDialect::M23Pragmatic
            && loaded.resource->records.size() == 175,
        "approved private candidate failed strict typed loading");
    const auto records = loaded.resource->records;
    auto provider = application::makePragmaticRuntimeCalibrationProvider(
        std::move(loaded));
    constexpr std::uint64_t kSizes[]{
        0, 1, 64, 4096, 65'536, 1'048'576, 16'777'216,
        core::kMaxWorkloadBytes};
    constexpr std::uint64_t kIterations[]{1, 1000};
    std::size_t checkedRequests = 0;
    for (const auto& record : records) {
        const auto minimum = record.minimumInputBytes.value_or(0);
        for (const auto size : kSizes) {
            if (record.calibrationCase.hasVariableInputSize
                && (size < *record.minimumInputBytes
                    || size > *record.maximumInputBytes)) {
                continue;
            }
            if (!record.calibrationCase.hasVariableInputSize && size != minimum) {
                continue;
            }
            for (const auto iterations : kIterations) {
                const auto lookup = provider->estimateEntry(requestFor(
                    record.calibrationCase,
                    size,
                    kMeasuredSamplingIntervalMilliseconds,
                    iterations,
                    1000));
                const auto picoseconds = modeledPicoseconds(
                    record,
                    record.calibrationCase.hasVariableInputSize
                        ? std::optional<std::uint64_t>{size}
                        : std::nullopt);
                requireDuration(
                    lookup.estimatedMeasuredBlockDurationPerRun,
                    roundedNanoseconds(picoseconds, iterations),
                    "private candidate measured value differed from direct arithmetic");
                requireDuration(
                    lookup.estimatedNonMeasuredDurationPerRun,
                    roundedNanoseconds(picoseconds, 1),
                    "private candidate warm-up differed from direct arithmetic");
                requireDuration(
                    lookup.estimatedFixedEntryOverhead,
                    0,
                    "private candidate fixed overhead was not assumed zero");
                ++checkedRequests;
            }
        }
    }
    require(checkedRequests > 1000, "private candidate integration covered too few values");
    std::cout << "PASS private candidate integration: 175 records, "
              << checkedRequests << " direct arithmetic requests; no benchmark executed\n";
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        testAllCanonicalRecordsAreReachable();
        testVariableSizesSamplingAndTypedIdentity();
        testRoundingMIndependenceAndServiceComposition();
        testSafeFallbackAndMalformedTypedResources();
        testZeroDurationOverflowAndPartialServiceResult();
        testShortRunWarningIntegration();
        if (argc > 1) {
            verifyPrivateCandidate(application.arguments());
        } else {
            std::cout << "PASS synthetic pragmatic provider tests; no benchmark executed\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL pragmatic provider tests: " << error.what() << '\n';
        return 1;
    }
}
