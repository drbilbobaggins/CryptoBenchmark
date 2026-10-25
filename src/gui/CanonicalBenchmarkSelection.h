#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <cryptobench/core/AlgorithmProfile.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidation.h>

namespace cryptobench::gui {

enum class SignatureInputMode {
    Prehashed,
    Message
};

enum class WorkloadInputKind {
    MessageSize,
    PlaintextSize,
    HashInputSize
};

struct CategoryChoice {
    core::PrimitiveCategory category;
    std::string_view label;
};

struct WorkloadInputControl {
    WorkloadInputKind kind;
    std::string_view label;
    core::WorkloadBytes minimum;
};

struct SelectionControls {
    std::vector<SignatureInputMode> signatureInputModes;
    std::optional<WorkloadInputControl> workload;
};

struct BenchmarkSelection {
    core::PrimitiveCategory category = core::PrimitiveCategory::Signature;
    std::optional<core::AlgorithmProfileId> profile;
    std::optional<core::BenchmarkOperation> operation;
    std::optional<SignatureInputMode> signatureInputMode;
    core::WorkloadBytes workloadSizeBytes = 1024;
    std::uint64_t iterationsPerRun = 1000;
    std::uint32_t runs = 3;
};

std::span<const CategoryChoice> canonicalCategories() noexcept;
std::vector<const core::AlgorithmProfile*> profilesForCategory(
    core::PrimitiveCategory category);
std::vector<core::BenchmarkOperation> operationsForProfile(
    core::AlgorithmProfileId profile);
SelectionControls selectionControlsFor(
    core::AlgorithmProfileId profile,
    core::BenchmarkOperation operation,
    std::optional<SignatureInputMode> signatureInputMode);
std::optional<core::BenchmarkConfig> benchmarkConfigFromSelection(
    const BenchmarkSelection& selection);

std::string_view operationDisplayName(core::BenchmarkOperation operation) noexcept;
std::string_view signatureInputModeDisplayName(SignatureInputMode mode) noexcept;

} // namespace cryptobench::gui
