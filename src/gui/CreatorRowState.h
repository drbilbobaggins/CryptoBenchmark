#pragma once

#include <cstdint>
#include <optional>

#include "CanonicalBenchmarkSelection.h"

namespace cryptobench::gui {

struct CreatorRowState {
    core::PrimitiveCategory category = core::PrimitiveCategory::Signature;
    core::AlgorithmProfileId profile = core::AlgorithmProfileId::Rsa2048KeyGen;
    core::BenchmarkOperation operation = core::BenchmarkOperation::KeyGen;
    std::optional<SignatureInputMode> signatureInputMode;
    core::WorkloadBytes workloadSizeBytes = 1024;
    std::uint64_t iterationsPerRun = 1000;
    std::uint32_t runs = 3;

    BenchmarkSelection selection() const;
};

CreatorRowState defaultCreatorRowState();

} // namespace cryptobench::gui
