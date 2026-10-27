#pragma once

#include <chrono>
#include <cstdint>
#include <variant>

#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/MeasurementSettings.h>

namespace cryptobench::application {

struct NoSignatureInput {};
struct PrehashedInput {};
struct MessageInput {
    core::WorkloadBytes messageSize;
};
struct KeyEstablishmentInput {};
struct AeadInput {
    core::WorkloadBytes plaintextSize;
};
struct HashXofInput {
    core::WorkloadBytes inputSize;
};

using RuntimeCalibrationInputIdentity = std::variant<
    NoSignatureInput,
    PrehashedInput,
    MessageInput,
    KeyEstablishmentInput,
    AeadInput,
    HashXofInput>;

struct RuntimeCalibrationKey {
    core::AlgorithmProfileId profileId;
    core::BenchmarkOperation operation;
    RuntimeCalibrationInputIdentity inputIdentity;
    core::MeasurementSettings measurementSettings;
};

struct RuntimeCalibrationRequest {
    RuntimeCalibrationKey key;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
};

using RuntimeDuration = std::chrono::nanoseconds;

enum class RuntimeEstimateUnavailableReason {
    CalibrationPointMissing,
    MeasurementContextUnsupported,
    MeasuredBlockUnavailable,
    NonMeasuredOverheadUnavailable,
    EntryOverheadUnavailable,
    BatchOverheadUnavailable,
    InvalidCalibrationData,
    ArithmeticOverflow
};

using RuntimeDurationComponent =
    std::variant<RuntimeDuration, RuntimeEstimateUnavailableReason>;

struct CalibrationLookupResult {
    RuntimeDurationComponent estimatedMeasuredBlockDurationPerRun;
    RuntimeDurationComponent estimatedNonMeasuredDurationPerRun;
    RuntimeDurationComponent estimatedFixedEntryOverhead;
};

RuntimeCalibrationKey makeRuntimeCalibrationKey(
    const core::BenchmarkConfig& config,
    const core::MeasurementSettings& settings);

class RuntimeCalibrationProvider {
public:
    virtual ~RuntimeCalibrationProvider() = default;

    virtual CalibrationLookupResult estimateEntry(
        RuntimeCalibrationRequest request) const = 0;
    virtual RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition& definition,
        core::MeasurementSettings settings) const = 0;
};

class NoDataRuntimeCalibrationProvider final : public RuntimeCalibrationProvider {
public:
    CalibrationLookupResult estimateEntry(
        RuntimeCalibrationRequest request) const override;
    RuntimeDurationComponent estimateBatchOverhead(
        const BatchDefinition& definition,
        core::MeasurementSettings settings) const override;
};

bool operator==(
    const RuntimeCalibrationInputIdentity& left,
    const RuntimeCalibrationInputIdentity& right) noexcept;
bool operator==(
    const RuntimeCalibrationKey& left,
    const RuntimeCalibrationKey& right) noexcept;

} // namespace cryptobench::application
