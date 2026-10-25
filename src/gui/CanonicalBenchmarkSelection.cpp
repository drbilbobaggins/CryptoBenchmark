#include "CanonicalBenchmarkSelection.h"

#include <array>
#include <type_traits>
#include <utility>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/InputCapability.h>

namespace cryptobench::gui {
namespace {

constexpr std::array<CategoryChoice, 4> kCategories{{
    {core::PrimitiveCategory::Signature, "Digital signatures"},
    {core::PrimitiveCategory::KeyEstablishment, "Key establishment / KEM"},
    {core::PrimitiveCategory::Aead, "AEAD"},
    {core::PrimitiveCategory::HashXof, "Hash / XOF"}
}};

constexpr std::array<core::BenchmarkOperation, 10> kOperations{
    core::BenchmarkOperation::KeyGen,
    core::BenchmarkOperation::Sign,
    core::BenchmarkOperation::Verify,
    core::BenchmarkOperation::Derive,
    core::BenchmarkOperation::Encapsulate,
    core::BenchmarkOperation::Decapsulate,
    core::BenchmarkOperation::Encrypt,
    core::BenchmarkOperation::Decrypt,
    core::BenchmarkOperation::Hash,
    core::BenchmarkOperation::Xof
};

const core::AlgorithmProfile* coherentProfile(
    core::PrimitiveCategory category,
    core::AlgorithmProfileId profileId,
    core::BenchmarkOperation operation)
{
    const auto* profile = core::AlgorithmRegistry::find(profileId);
    if (profile == nullptr || profile->category != category
        || !profile->operations.contains(operation)) {
        return nullptr;
    }
    return profile;
}

} // namespace

std::span<const CategoryChoice> canonicalCategories() noexcept
{
    return kCategories;
}

std::vector<const core::AlgorithmProfile*> profilesForCategory(
    core::PrimitiveCategory category)
{
    std::vector<const core::AlgorithmProfile*> profiles;
    for (const auto& profile : core::AlgorithmRegistry::all()) {
        if (profile.category == category) {
            profiles.push_back(&profile);
        }
    }
    return profiles;
}

std::vector<core::BenchmarkOperation> operationsForProfile(
    core::AlgorithmProfileId profileId)
{
    const auto* profile = core::AlgorithmRegistry::find(profileId);
    if (profile == nullptr) {
        return {};
    }

    std::vector<core::BenchmarkOperation> operations;
    for (const auto operation : kOperations) {
        if (profile->operations.contains(operation)) {
            operations.push_back(operation);
        }
    }
    return operations;
}

SelectionControls selectionControlsFor(
    core::AlgorithmProfileId profileId,
    core::BenchmarkOperation operation,
    std::optional<SignatureInputMode> signatureInputMode)
{
    SelectionControls controls;
    const auto* profile = core::AlgorithmRegistry::find(profileId);
    if (profile == nullptr || !profile->operations.contains(operation)) {
        return controls;
    }

    if (profile->category == core::PrimitiveCategory::Signature) {
        if (operation == core::BenchmarkOperation::KeyGen) {
            return controls;
        }
        if (operation != core::BenchmarkOperation::Sign
            && operation != core::BenchmarkOperation::Verify) {
            return controls;
        }

        const auto* capability =
            std::get_if<core::SignatureInputCapability>(&profile->inputCapability);
        if (capability == nullptr) {
            return controls;
        }
        if (capability->support == core::SignatureInputSupport::PrehashedAndMessage) {
            controls.signatureInputModes.push_back(SignatureInputMode::Prehashed);
        }
        controls.signatureInputModes.push_back(SignatureInputMode::Message);
        if (signatureInputMode == SignatureInputMode::Message) {
            controls.workload = WorkloadInputControl{
                WorkloadInputKind::MessageSize, "Message size:", 1};
        }
        return controls;
    }

    if (std::holds_alternative<core::PlaintextSizeInput>(profile->inputCapability)
        && profile->category == core::PrimitiveCategory::Aead
        && (operation == core::BenchmarkOperation::Encrypt
            || operation == core::BenchmarkOperation::Decrypt)) {
        controls.workload = WorkloadInputControl{
            WorkloadInputKind::PlaintextSize, "Plaintext size:", 1};
    } else if (std::holds_alternative<core::HashInputSizeInput>(profile->inputCapability)
        && profile->category == core::PrimitiveCategory::HashXof
        && (operation == core::BenchmarkOperation::Hash
            || operation == core::BenchmarkOperation::Xof)) {
        controls.workload = WorkloadInputControl{
            WorkloadInputKind::HashInputSize, "Input size:", 0};
    }
    return controls;
}

std::optional<core::BenchmarkConfig> benchmarkConfigFromSelection(
    const BenchmarkSelection& selection)
{
    if (!selection.profile.has_value() || !selection.operation.has_value()) {
        return std::nullopt;
    }

    const auto* profile = coherentProfile(
        selection.category, *selection.profile, *selection.operation);
    if (profile == nullptr) {
        return std::nullopt;
    }

    core::PrimitiveConfig parameters;
    if (profile->category == core::PrimitiveCategory::Signature) {
        if (*selection.operation == core::BenchmarkOperation::KeyGen) {
            parameters = core::SignatureConfig{core::NoSignatureInput{}};
        } else {
            const auto controls = selectionControlsFor(
                profile->id, *selection.operation, selection.signatureInputMode);
            if (!selection.signatureInputMode.has_value()) {
                return std::nullopt;
            }
            if (*selection.signatureInputMode == SignatureInputMode::Prehashed
                && std::ranges::find(controls.signatureInputModes,
                                     SignatureInputMode::Prehashed)
                    == controls.signatureInputModes.end()) {
                return std::nullopt;
            }
            if (*selection.signatureInputMode == SignatureInputMode::Message
                && std::ranges::find(controls.signatureInputModes,
                                     SignatureInputMode::Message)
                    == controls.signatureInputModes.end()) {
                return std::nullopt;
            }
            if (*selection.signatureInputMode == SignatureInputMode::Prehashed) {
                parameters = core::SignatureConfig{core::PrehashedInput{}};
            } else if (*selection.signatureInputMode == SignatureInputMode::Message) {
                parameters = core::SignatureConfig{
                    core::MessageInput{selection.workloadSizeBytes}};
            } else {
                return std::nullopt;
            }
        }
    } else if (profile->category == core::PrimitiveCategory::KeyEstablishment
        && std::holds_alternative<core::NoWorkloadInput>(profile->inputCapability)) {
        parameters = core::KeyEstablishmentConfig{};
    } else if (profile->category == core::PrimitiveCategory::Aead
        && std::holds_alternative<core::PlaintextSizeInput>(profile->inputCapability)
        && (*selection.operation == core::BenchmarkOperation::Encrypt
            || *selection.operation == core::BenchmarkOperation::Decrypt)) {
        parameters = core::AeadConfig{selection.workloadSizeBytes};
    } else if (profile->category == core::PrimitiveCategory::HashXof
        && std::holds_alternative<core::HashInputSizeInput>(profile->inputCapability)
        && (*selection.operation == core::BenchmarkOperation::Hash
            || *selection.operation == core::BenchmarkOperation::Xof)) {
        parameters = core::HashConfig{selection.workloadSizeBytes};
    } else {
        return std::nullopt;
    }

    return core::BenchmarkConfig{
        *selection.profile,
        *selection.operation,
        selection.iterationsPerRun,
        selection.runs,
        std::move(parameters)};
}

std::string_view operationDisplayName(core::BenchmarkOperation operation) noexcept
{
    switch (operation) {
    case core::BenchmarkOperation::KeyGen: return "Key generation";
    case core::BenchmarkOperation::Sign: return "Sign";
    case core::BenchmarkOperation::Verify: return "Verify";
    case core::BenchmarkOperation::Derive: return "Derive";
    case core::BenchmarkOperation::Encapsulate: return "Encapsulate";
    case core::BenchmarkOperation::Decapsulate: return "Decapsulate";
    case core::BenchmarkOperation::Encrypt: return "Encrypt";
    case core::BenchmarkOperation::Decrypt: return "Decrypt";
    case core::BenchmarkOperation::Hash: return "Hash";
    case core::BenchmarkOperation::Xof: return "XOF";
    }
    return {};
}

std::string_view signatureInputModeDisplayName(SignatureInputMode mode) noexcept
{
    switch (mode) {
    case SignatureInputMode::Prehashed: return "Prehashed";
    case SignatureInputMode::Message: return "Message";
    }
    return {};
}

} // namespace cryptobench::gui
