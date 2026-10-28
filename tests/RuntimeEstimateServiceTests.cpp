#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/RuntimeEstimateService.h>

#include <QByteArray>

#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

using namespace cryptobench::application;
using cryptobench::core::MeasurementSettings;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

cryptobench::application::BatchDefinition parse(const QByteArray& entries)
{
    const auto result = BatchInputParser{}.parseData(
        QByteArray{R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"}
        + entries + "]}");
    if (!result.issues.empty()) {
        const auto& issue = result.issues.front();
        throw std::runtime_error(
            "batch fixture was rejected: " + issue.path + " " + issue.technicalMessage);
    }
    if (!result.definition.has_value()) {
        throw std::runtime_error("batch fixture produced no definition and no issues");
    }
    return std::move(*result.definition);
}

cryptobench::application::BatchDefinition singleEntry(
    std::string_view profile = "ed25519",
    std::string_view operation = "sign",
    std::string_view parameters =
        R"({"inputMode":"message","messageSizeBytes":1})",
    std::uint64_t iterations = 1,
    std::uint32_t runs = 1)
{
    return parse(
        QByteArray{"{\"profileId\":\""} + profile.data() + "\",\"operation\":\""
        + operation.data() + "\",\"iterationsPerRun\":"
        + QByteArray::number(iterations) + ",\"runs\":"
        + QByteArray::number(runs) + ",\"parameters\":" + parameters.data() + "}");
}

struct FakeProvider final : RuntimeCalibrationProvider {
    std::vector<std::pair<RuntimeCalibrationKey, CalibrationLookupResult>> records;
    RuntimeDurationComponent batchOverhead{RuntimeDuration{0}};

    CalibrationLookupResult estimateEntry(RuntimeCalibrationRequest request) const override
    {
        for (const auto& record : records) {
            if (record.first == request.key) {
                return record.second;
            }
        }
        return {
            RuntimeEstimateUnavailableReason::CalibrationPointMissing,
            RuntimeEstimateUnavailableReason::CalibrationPointMissing,
            RuntimeEstimateUnavailableReason::CalibrationPointMissing};
    }

    RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition&,
        MeasurementSettings) const override
    {
        return batchOverhead;
    }
};

struct ScalingProvider final : RuntimeCalibrationProvider {
    std::optional<RuntimeCalibrationKey> exactKey;
    std::uint64_t referenceIterations = 2;
    std::int64_t referenceMeasuredDuration = 3;
    RuntimeDurationComponent nonMeasured{RuntimeDuration{0}};
    RuntimeDurationComponent fixed{RuntimeDuration{0}};
    RuntimeDurationComponent batchOverhead{RuntimeDuration{0}};
    mutable std::uint64_t lastIterations = 0;
    mutable std::uint32_t lastRuns = 0;

    CalibrationLookupResult estimateEntry(RuntimeCalibrationRequest request) const override
    {
        if (!exactKey.has_value() || !(request.key == *exactKey)) {
            return {
                RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                RuntimeEstimateUnavailableReason::CalibrationPointMissing};
        }
        lastIterations = request.iterationsPerRun;
        lastRuns = request.runs;
        if (referenceIterations == 0 || referenceMeasuredDuration < 0) {
            return {
                RuntimeEstimateUnavailableReason::InvalidCalibrationData,
                nonMeasured,
                fixed};
        }

        const auto numerator = static_cast<unsigned __int128>(referenceMeasuredDuration)
            * request.iterationsPerRun;
        const auto quotient = numerator / referenceIterations;
        const auto remainder = numerator % referenceIterations;
        const auto rounded = quotient
            + (remainder * 2 >= referenceIterations ? 1 : 0);
        if (rounded > static_cast<unsigned __int128>(
                std::numeric_limits<std::int64_t>::max())) {
            return {
                RuntimeEstimateUnavailableReason::ArithmeticOverflow,
                nonMeasured,
                fixed};
        }
        return {
            RuntimeDuration{static_cast<std::int64_t>(rounded)},
            nonMeasured,
            fixed};
    }

    RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition&,
        MeasurementSettings) const override
    {
        return batchOverhead;
    }
};

CalibrationLookupResult available(
    std::int64_t measured,
    std::int64_t nonMeasured = 0,
    std::int64_t fixed = 0)
{
    return {RuntimeDuration{measured}, RuntimeDuration{nonMeasured}, RuntimeDuration{fixed}};
}

void addRecord(
    FakeProvider& provider,
    const cryptobench::core::BenchmarkConfig& config,
    MeasurementSettings settings,
    CalibrationLookupResult lookup)
{
    provider.records.emplace_back(
        makeRuntimeCalibrationKey(config, settings), std::move(lookup));
}

void requireReason(
    const RuntimeDurationComponent& component,
    RuntimeEstimateUnavailableReason reason,
    std::string_view message)
{
    require(std::holds_alternative<RuntimeEstimateUnavailableReason>(component), message);
    require(std::get<RuntimeEstimateUnavailableReason>(component) == reason, message);
}

void requireOverflow(const RuntimeEstimate& estimate, std::string_view message)
{
    requireReason(
        estimate.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        message);
    require(estimate.availability != RuntimeEstimateAvailability::Available, message);
}

void testExactCompositionOrderAndBatchAggregation()
{
    const auto definition = parse(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":3,"parameters":{"inputMode":"message","messageSizeBytes":32}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":3,"parameters":{"inputMode":"message","messageSizeBytes":32}})");
    const auto settings = MeasurementSettings{3};
    FakeProvider provider;
    addRecord(provider, definition.entries()[0].config, settings, available(100, 20, 7));
    provider.batchOverhead = RuntimeDuration{11};

    const auto estimate = RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(estimate.availability == RuntimeEstimateAvailability::Available, "estimate was not available");
    require(estimate.perEntry[0].entryIndex == 1 && estimate.perEntry[1].entryIndex == 2,
        "original entry order was not retained");
    require(std::get<RuntimeDuration>(estimate.perEntry[0].estimatedTotalEntryDuration).count() == 367,
        "entry composition mismatch");
    require(std::get<RuntimeDuration>(estimate.estimatedTotalBatchDuration).count() == 745,
        "batch aggregation mismatch");
}

void testIdentityDimensionsAndMissingLookups()
{
    const auto definition = parse(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":32}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":64}},)"
        R"({"profileId":"aes-256-gcm","operation":"encrypt","iterationsPerRun":1,"runs":1,"parameters":{"plaintextSizeBytes":32}},)"
        R"({"profileId":"aes-256-gcm","operation":"encrypt","iterationsPerRun":1,"runs":1,"parameters":{"plaintextSizeBytes":64}},)"
        R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":32}},)"
        R"({"profileId":"shake128-28bytes","operation":"xof","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":32}},)"
        R"({"profileId":"x25519","operation":"derive","iterationsPerRun":1,"runs":1,"parameters":{}},)"
        R"({"profileId":"rsa-pss-2048-sha256","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"prehashed"}},)"
        R"({"profileId":"rsa-2048-keygen","operation":"keyGen","iterationsPerRun":1,"runs":1,"parameters":{}})");
    const auto settings = MeasurementSettings{2};
    FakeProvider provider;
    addRecord(provider, definition.entries()[0].config, settings, available(2));
    const auto missing = RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(missing.missingMeasuredBlockEntryCount == definition.entries().size() - 1,
        "distinct canonical keys did not produce missing lookups");
    requireReason(
        missing.perEntry[1].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "message-size identity was not distinct");

    for (const auto& entry : definition.entries()) {
        addRecord(provider, entry.config, settings, available(2));
    }
    const auto complete = RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(complete.missingMeasuredBlockEntryCount == 0, "identity dimensions collided");

    const auto otherSettings = RuntimeEstimateService{}.estimate(
        definition, MeasurementSettings{3}, provider);
    require(otherSettings.missingMeasuredBlockEntryCount == definition.entries().size(),
        "measurement settings were treated as interchangeable");
}

void testIndependentRsaAndProfileKeyDimensions()
{
    const auto rsaMessage = singleEntry("rsa-pss-2048-sha256", "sign",
        R"({"inputMode":"message","messageSizeBytes":32})");
    const auto rsaPrehashed = singleEntry("rsa-pss-2048-sha256", "sign",
        R"({"inputMode":"prehashed"})");
    const auto rsaVerify = singleEntry("rsa-pss-2048-sha256", "verify",
        R"({"inputMode":"message","messageSizeBytes":32})");
    const auto otherProfile = singleEntry("rsa-pss-2048-sha384", "sign",
        R"({"inputMode":"message","messageSizeBytes":32})");
    const auto settings = MeasurementSettings{3};
    const auto messageKey = makeRuntimeCalibrationKey(
        rsaMessage.entries()[0].config, settings);
    const auto prehashedKey = makeRuntimeCalibrationKey(
        rsaPrehashed.entries()[0].config, settings);
    const auto verifyKey = makeRuntimeCalibrationKey(
        rsaVerify.entries()[0].config, settings);
    const auto profileKey = makeRuntimeCalibrationKey(
        otherProfile.entries()[0].config, settings);

    require(!(messageKey == prehashedKey), "message and prehashed keys collided");
    require(!(messageKey == verifyKey), "sign and verify keys collided");
    require(!(messageKey == profileKey), "profile keys collided");

    FakeProvider provider;
    addRecord(provider, rsaMessage.entries()[0].config, settings, available(10));
    for (const auto& definition : {rsaPrehashed, rsaVerify, otherProfile}) {
        const auto request = RuntimeCalibrationRequest{
            makeRuntimeCalibrationKey(definition.entries()[0].config, settings),
            1,
            1};
        const auto lookup = provider.estimateEntry(request);
        requireReason(
            lookup.estimatedMeasuredBlockDurationPerRun,
            RuntimeEstimateUnavailableReason::CalibrationPointMissing,
            "exact-key provider returned another key's calibration");
    }
}

void testExactScalingAndMIndependence()
{
    const auto definition = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":1})", 1, 3);
    const auto settings = MeasurementSettings{4};
    ScalingProvider provider;
    provider.exactKey = makeRuntimeCalibrationKey(definition.entries()[0].config, settings);
    provider.nonMeasured = RuntimeDuration{4};
    provider.fixed = RuntimeDuration{5};
    provider.batchOverhead = RuntimeDuration{6};

    const auto estimate = RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(std::get<RuntimeDuration>(
        estimate.perEntry[0].estimatedMeasuredBlockDurationPerRun).count() == 2,
        "exact reference-N scaling or rounding failed");
    require(std::get<RuntimeDuration>(
        estimate.perEntry[0].estimatedTotalEntryDuration).count() == 23,
        "M entry aggregation mismatch");
    require(std::get<RuntimeDuration>(estimate.estimatedTotalBatchDuration).count() == 29,
        "exact batch total mismatch");

    const auto differentIdentity = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":2})");
    const auto missing = RuntimeEstimateService{}.estimate(
        differentIdentity, settings, provider);
    requireReason(
        missing.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "scaling provider extrapolated across workload identity");

    provider.referenceIterations = 0;
    const auto zeroReference = RuntimeEstimateService{}.estimate(
        definition, settings, provider);
    requireReason(zeroReference.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "zero reference N was not rejected");
    provider.referenceIterations = 2;
    provider.referenceMeasuredDuration = -1;
    const auto negativeReference = RuntimeEstimateService{}.estimate(
        definition, settings, provider);
    requireReason(negativeReference.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "negative reference duration was not rejected");
}

void testHighValidNAndM()
{
    const auto settings = MeasurementSettings{5};
    const auto highN = singleEntry(
        "ed25519", "sign", R"({"inputMode":"message","messageSizeBytes":1})",
        1'000'000'000, 1);
    ScalingProvider nProvider;
    nProvider.exactKey = makeRuntimeCalibrationKey(highN.entries()[0].config, settings);
    const auto nEstimate = RuntimeEstimateService{}.estimate(highN, settings, nProvider);
    require(nProvider.lastIterations == 1'000'000'000 && nProvider.lastRuns == 1,
        "high N/M request was not preserved");
    require(std::get<RuntimeDuration>(
        nEstimate.perEntry[0].estimatedMeasuredBlockDurationPerRun).count() == 1'500'000'000,
        "high N scaling mismatch");
    require(std::get<RuntimeDuration>(
        nEstimate.estimatedTotalBatchDuration).count() == 1'500'000'000,
        "high N total mismatch");
    require(nEstimate.availability == RuntimeEstimateAvailability::Available,
        "high N estimate was not available");

    const auto highM = singleEntry(
        "ed25519", "sign", R"({"inputMode":"message","messageSizeBytes":1})",
        1'000'000, 1000);
    ScalingProvider mProvider;
    mProvider.exactKey = makeRuntimeCalibrationKey(highM.entries()[0].config, settings);
    const auto mEstimate = RuntimeEstimateService{}.estimate(highM, settings, mProvider);
    require(mProvider.lastIterations == 1'000'000 && mProvider.lastRuns == 1000,
        "high M request was not preserved");
    require(std::get<RuntimeDuration>(
        mEstimate.perEntry[0].estimatedMeasuredBlockDurationPerRun).count() == 1'500'000,
        "high M measured duration mismatch");
    require(std::get<RuntimeDuration>(
        mEstimate.estimatedTotalBatchDuration).count() == 1'500'000'000,
        "high M aggregation mismatch");
    require(mEstimate.availability == RuntimeEstimateAvailability::Available,
        "high M estimate was not available");
}

void testPartialMissingAndNoDataReasons()
{
    const auto definition = parse(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":32}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":64}})");
    const auto settings = MeasurementSettings{5};
    FakeProvider partialProvider;
    addRecord(partialProvider, definition.entries()[0].config, settings, {
        RuntimeDuration{999'999'999},
        RuntimeEstimateUnavailableReason::NonMeasuredOverheadUnavailable,
        RuntimeEstimateUnavailableReason::EntryOverheadUnavailable});
    partialProvider.batchOverhead = RuntimeEstimateUnavailableReason::BatchOverheadUnavailable;
    const auto partial = RuntimeEstimateService{}.estimate(
        definition, settings, partialProvider);
    require(partial.availability == RuntimeEstimateAvailability::Partial, "partial state missing");
    require(partial.missingMeasuredBlockEntryCount == 1 && partial.missingTotalEntryCount == 2,
        "partial missing counts mismatch");
    require(partial.shortRunEntryIndices == std::vector<std::uint32_t>{1},
        "known short measured block was lost");
    require(std::holds_alternative<RuntimeEstimateUnavailableReason>(
        partial.estimatedTotalBatchDuration), "partial batch total was numeric");

    FakeProvider overheadMissing;
    addRecord(overheadMissing, definition.entries()[0].config, settings, available(10, 2, 3));
    addRecord(overheadMissing, definition.entries()[1].config, settings, available(10, 2, 3));
    overheadMissing.batchOverhead = RuntimeEstimateUnavailableReason::BatchOverheadUnavailable;
    const auto batchPartial = RuntimeEstimateService{}.estimate(
        definition, settings, overheadMissing);
    require(batchPartial.availability == RuntimeEstimateAvailability::Partial,
        "missing batch overhead was not partial");
    require(batchPartial.missingTotalEntryCount == 0,
        "known entry totals were counted as missing");
    requireReason(
        batchPartial.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
        "batch-overhead-only reason mismatch");

    const NoDataRuntimeCalibrationProvider noData;
    const auto request = RuntimeCalibrationRequest{
        makeRuntimeCalibrationKey(definition.entries()[0].config, settings),
        1,
        1};
    const auto lookup = noData.estimateEntry(request);
    requireReason(lookup.estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "no-data measured reason mismatch");
    requireReason(lookup.estimatedNonMeasuredDurationPerRun,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "no-data non-measured reason mismatch");
    requireReason(lookup.estimatedFixedEntryOverhead,
        RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        "no-data fixed reason mismatch");
    requireReason(noData.estimateBatchOverhead(definition, settings),
        RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
        "no-data batch reason mismatch");

    const auto unavailable = RuntimeEstimateService{}.estimate(definition, settings, noData);
    require(unavailable.availability == RuntimeEstimateAvailability::Unavailable,
        "no-data service result was not unavailable");
    require(!std::holds_alternative<RuntimeDuration>(
        unavailable.estimatedTotalBatchDuration),
        "no-data provider exposed numeric Batch ETA");
    require(unavailable.missingMeasuredBlockEntryCount == definition.entries().size()
        && unavailable.missingTotalEntryCount == definition.entries().size(),
        "no-data missing-entry counts mismatch");
    require(unavailable.shortRunEntryIndices.empty(),
        "no-data service classified entries as short");
}

void testUnsupportedSamplingContext()
{
    const auto definition = singleEntry();
    const auto settings = MeasurementSettings{2};
    FakeProvider provider;
    addRecord(provider, definition.entries()[0].config, settings, {
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported,
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported,
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported});
    const auto estimate = RuntimeEstimateService{}.estimate(definition, settings, provider);
    requireReason(
        estimate.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::MeasurementContextUnsupported,
        "unsupported sampling reason was not retained");
    require(!std::holds_alternative<RuntimeDuration>(
        estimate.estimatedTotalBatchDuration),
        "unsupported sampling fabricated a numeric estimate");
}

void testShortThresholdMeasuredVersusTotal()
{
    const auto shortDefinition = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":1})", 1, 1);
    const auto longDefinition = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":2})", 1, 1);
    const auto settings = MeasurementSettings{1};
    FakeProvider provider;
    addRecord(provider, shortDefinition.entries()[0].config, settings,
        available(700'000'000, 4'000'000'000, 300'000'000));
    addRecord(provider, longDefinition.entries()[0].config, settings,
        available(1'200'000'000, 18'000'000'000, 800'000'000));
    provider.batchOverhead = RuntimeDuration{0};

    const auto shortEstimate = RuntimeEstimateService{}.estimate(
        shortDefinition, settings, provider);
    const auto longEstimate = RuntimeEstimateService{}.estimate(
        longDefinition, settings, provider);
    require(std::get<RuntimeDuration>(
        shortEstimate.perEntry[0].estimatedTotalEntryDuration).count() == 5'000'000'000,
        "0.7-second measured / 5-second total mismatch");
    require(shortEstimate.shortRunEntryIndices == std::vector<std::uint32_t>{1},
        "0.7-second measured block was not short");
    require(std::get<RuntimeDuration>(
        longEstimate.perEntry[0].estimatedTotalEntryDuration).count() == 20'000'000'000,
        "1.2-second measured / 20-second total mismatch");
    require(longEstimate.shortRunEntryIndices.empty(),
        "1.2-second measured block was incorrectly short");

    const auto mDefinition = parse(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":3}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":10,"parameters":{"inputMode":"message","messageSizeBytes":3}})");
    addRecord(provider, mDefinition.entries()[0].config, settings,
        available(700'000'000, 0, 0));
    const auto mEstimate = RuntimeEstimateService{}.estimate(mDefinition, settings, provider);
    require(mEstimate.shortRunEntryIndices == std::vector<std::uint32_t>{1, 2},
        "M changed measured-block short classification");
}

void testExactShortRunBoundaries()
{
    const auto definition = parse(
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":2}},)"
        R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":3}})");
    const auto settings = MeasurementSettings{1};
    FakeProvider provider;
    addRecord(provider, definition.entries()[0].config, settings,
        available(999'999'999));
    addRecord(provider, definition.entries()[1].config, settings,
        available(1'000'000'000));
    addRecord(provider, definition.entries()[2].config, settings,
        available(1'000'000'001));
    const auto estimate = RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(estimate.shortRunEntryIndices == std::vector<std::uint32_t>{1},
        "short-run boundary classification was not exact");
}

void testInvalidAndZeroComponents()
{
    const auto definition = singleEntry();
    const auto settings = MeasurementSettings{2};
    const auto run = [&](
        RuntimeDurationComponent measured,
        RuntimeDurationComponent nonMeasured,
        RuntimeDurationComponent fixed,
        RuntimeDurationComponent batch) {
        FakeProvider provider;
        provider.records.emplace_back(
            makeRuntimeCalibrationKey(definition.entries()[0].config, settings),
            CalibrationLookupResult{measured, nonMeasured, fixed});
        provider.batchOverhead = batch;
        return RuntimeEstimateService{}.estimate(definition, settings, provider);
    };

    const auto zero = run(RuntimeDuration{0}, RuntimeDuration{0}, RuntimeDuration{0},
        RuntimeDuration{0});
    require(zero.availability == RuntimeEstimateAvailability::Available,
        "valid zero durations were treated as missing");
    require(std::get<RuntimeDuration>(zero.estimatedTotalBatchDuration).count() == 0,
        "valid zero total was not preserved");

    const auto missing = run(RuntimeEstimateUnavailableReason::MeasuredBlockUnavailable,
        RuntimeDuration{0}, RuntimeDuration{0}, RuntimeDuration{0});
    requireReason(missing.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::MeasuredBlockUnavailable,
        "missing measured reason mismatch");
    require(missing.availability == RuntimeEstimateAvailability::Unavailable,
        "missing measured data was available");

    const auto negativeMeasured = run(RuntimeDuration{-1}, RuntimeDuration{0},
        RuntimeDuration{0}, RuntimeDuration{0});
    requireReason(negativeMeasured.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "negative measured duration was accepted");
    const auto negativeNonMeasured = run(RuntimeDuration{0}, RuntimeDuration{-1},
        RuntimeDuration{0}, RuntimeDuration{0});
    requireReason(negativeNonMeasured.perEntry[0].estimatedTotalEntryDuration,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "negative non-measured duration was accepted");
    const auto negativeFixed = run(RuntimeDuration{0}, RuntimeDuration{0},
        RuntimeDuration{-1}, RuntimeDuration{0});
    requireReason(negativeFixed.perEntry[0].estimatedTotalEntryDuration,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "negative fixed duration was accepted");
    const auto negativeBatch = run(RuntimeDuration{0}, RuntimeDuration{0},
        RuntimeDuration{0}, RuntimeDuration{-1});
    requireReason(negativeBatch.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::InvalidCalibrationData,
        "negative batch duration was accepted");
}

void testIndependentOverflowPaths()
{
    const auto settings = MeasurementSettings{1};
    const auto max = std::numeric_limits<std::int64_t>::max();

    const auto scalingDefinition = singleEntry(
        "ed25519", "sign", R"({"inputMode":"message","messageSizeBytes":1})", 100, 1);
    ScalingProvider scaling;
    scaling.exactKey = makeRuntimeCalibrationKey(
        scalingDefinition.entries()[0].config, settings);
    scaling.referenceMeasuredDuration = max;
    scaling.referenceIterations = 1;
    const auto scalingOverflow = RuntimeEstimateService{}.estimate(
        scalingDefinition, settings, scaling);
    requireReason(scalingOverflow.perEntry[0].estimatedMeasuredBlockDurationPerRun,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "reference-N overflow reason mismatch");

    const auto additionDefinition = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":2})");
    const auto runWith = [&](std::int64_t measured, std::int64_t nonMeasured,
        std::int64_t fixed, std::uint32_t runs, std::size_t entries,
        RuntimeDurationComponent batch) {
        QByteArray input;
        for (std::size_t index = 0; index < entries; ++index) {
            if (index != 0) {
                input.append(',');
            }
            input.append(
                R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":)"
                + QByteArray::number(runs)
                + R"(,"parameters":{"inputMode":"message","messageSizeBytes":2}})");
        }
        const auto definition = parse(input);
        FakeProvider provider;
        addRecord(provider, definition.entries()[0].config, settings,
            available(measured, nonMeasured, fixed));
        provider.batchOverhead = std::move(batch);
        const auto estimate = RuntimeEstimateService{}.estimate(
            definition, settings, provider);
        requireOverflow(estimate, "overflow did not propagate to batch total");
        return estimate;
    };

    const auto perRunOverflow = runWith(max, 1, 0, 1, 1, RuntimeDuration{0});
    requireReason(perRunOverflow.perEntry[0].estimatedTotalEntryDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "per-run addition overflow reason mismatch");
    const auto multiplicationOverflow = runWith(max, 0, 0, 2, 1, RuntimeDuration{0});
    requireReason(multiplicationOverflow.perEntry[0].estimatedTotalEntryDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "M multiplication overflow reason mismatch");
    const auto fixedOverflow = runWith(max, 0, 1, 1, 1, RuntimeDuration{0});
    requireReason(fixedOverflow.perEntry[0].estimatedTotalEntryDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "fixed-entry addition overflow reason mismatch");
    const auto accumulationOverflow = runWith(max, 0, 0, 1, 2, RuntimeDuration{0});
    requireReason(accumulationOverflow.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "entry accumulation overflow reason mismatch");
    const auto batchOverflow = runWith(max, 0, 0, 1, 1, RuntimeDuration{1});
    requireReason(batchOverflow.estimatedTotalBatchDuration,
        RuntimeEstimateUnavailableReason::ArithmeticOverflow,
        "batch overhead addition overflow reason mismatch");
}

void testShortEntryCardinalityAndImmutability()
{
    const auto makeEntries = [](std::size_t count) {
        QByteArray entries;
        for (std::size_t index = 0; index < count; ++index) {
            if (index != 0) {
                entries.append(',');
            }
            entries.append(
                R"({"profileId":"ed25519","operation":"sign","iterationsPerRun":1,"runs":1,"parameters":{"inputMode":"message","messageSizeBytes":1}})");
        }
        return parse(entries);
    };
    const auto checkShort = [&](std::size_t count, std::int64_t duration) {
        const auto definition = makeEntries(count);
        FakeProvider provider;
        const auto settings = MeasurementSettings{4};
        addRecord(provider, definition.entries().front().config, settings, available(duration));
        const auto estimate = RuntimeEstimateService{}.estimate(definition, settings, provider);
        require(estimate.shortRunEntryIndices.size() == count, "short-entry count mismatch");
        for (std::size_t index = 0; index < count; ++index) {
            require(estimate.shortRunEntryIndices[index] == index + 1,
                "short-entry original index/order mismatch");
        }
    };
    checkShort(1, 700'000'000);
    checkShort(10, 700'000'000);
    checkShort(11, 700'000'000);
    checkShort(1000, 700'000'000);
    const auto exactDefinition = makeEntries(1);
    FakeProvider exactProvider;
    const auto exactSettings = MeasurementSettings{4};
    addRecord(exactProvider, exactDefinition.entries().front().config, exactSettings,
        available(1'000'000'000));
    const auto exactEstimate = RuntimeEstimateService{}.estimate(
        exactDefinition, exactSettings, exactProvider);
    require(exactEstimate.shortRunEntryIndices.empty(),
        "exactly one second was incorrectly classified as short");

    const auto definition = singleEntry("ed25519", "sign",
        R"({"inputMode":"message","messageSizeBytes":64})", 10, 3);
    const auto settings = MeasurementSettings{2};
    std::vector<RuntimeCalibrationKey> beforeKeys;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> beforeCounts;
    for (const auto& entry : definition.entries()) {
        beforeKeys.push_back(makeRuntimeCalibrationKey(entry.config, settings));
        beforeCounts.emplace_back(entry.config.iterationsPerRun, entry.config.runs);
    }
    FakeProvider provider;
    addRecord(provider, definition.entries()[0].config, settings, available(1));
    (void)RuntimeEstimateService{}.estimate(definition, settings, provider);
    require(settings.memorySamplingIntervalMilliseconds == 2,
        "measurement settings were mutated");
    for (std::size_t index = 0; index < definition.entries().size(); ++index) {
        const auto& entry = definition.entries()[index];
        require(makeRuntimeCalibrationKey(entry.config, settings) == beforeKeys[index],
            "BatchDefinition/config/input parameters were mutated");
        require(entry.config.iterationsPerRun == beforeCounts[index].first
            && entry.config.runs == beforeCounts[index].second,
            "N/M were mutated");
    }
}

} // namespace

int main()
{
    try {
        testExactCompositionOrderAndBatchAggregation();
        testIdentityDimensionsAndMissingLookups();
        testIndependentRsaAndProfileKeyDimensions();
        testExactScalingAndMIndependence();
        testHighValidNAndM();
        testPartialMissingAndNoDataReasons();
        testUnsupportedSamplingContext();
        testShortThresholdMeasuredVersusTotal();
        testExactShortRunBoundaries();
        testInvalidAndZeroComponents();
        testIndependentOverflowPaths();
        testShortEntryCardinalityAndImmutability();
        return 0;
    } catch (const std::exception& error) {
        return std::fprintf(stderr, "Runtime estimate tests failed: %s\n", error.what()) == 0 ? 1 : 1;
    }
}
