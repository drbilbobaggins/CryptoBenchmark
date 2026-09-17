#include <cryptobench/crypto/AdapterFactory.h>

#include <stdexcept>
#include <variant>

#include "adapters/DigestAdapter.h"

namespace cryptobench::crypto {

std::unique_ptr<core::AlgorithmAdapter> AdapterFactory::create(
    const core::AlgorithmProfile& profile,
    core::BenchmarkOperation operation,
    const core::ValidatedBenchmarkConfig& config) const
{
    const auto& validatedConfig = config.value();
    if (profile.id != validatedConfig.profile) {
        throw std::logic_error("AdapterFactory profile does not match validated configuration");
    }
    if (operation != validatedConfig.operation) {
        throw std::logic_error("AdapterFactory operation does not match validated configuration");
    }

    switch (profile.executionStrategy) {
    case core::ExecutionStrategyId::Digest: {
        const auto* digestParameters = std::get_if<core::DigestParameters>(&profile.parameters);
        if (digestParameters == nullptr) {
            throw std::logic_error("Digest strategy requires DigestParameters");
        }

        const auto* hashConfig = std::get_if<core::HashConfig>(&validatedConfig.parameters);
        if (hashConfig == nullptr) {
            throw std::logic_error("Digest strategy requires HashConfig");
        }

        return std::make_unique<DigestAdapter>(*digestParameters, hashConfig->inputSize);
    }
    case core::ExecutionStrategyId::RsaPssSignature:
    case core::ExecutionStrategyId::EcdsaSignature:
    case core::ExecutionStrategyId::EdDsaSignature:
    case core::ExecutionStrategyId::MlDsaSignature:
    case core::ExecutionStrategyId::SlhDsaSignature:
    case core::ExecutionStrategyId::Ecdh:
    case core::ExecutionStrategyId::Xdh:
    case core::ExecutionStrategyId::MlKem:
    case core::ExecutionStrategyId::Aead:
    case core::ExecutionStrategyId::Xof:
        throw std::invalid_argument("AdapterFactory execution strategy is unsupported");
    }

    throw std::logic_error("AdapterFactory encountered an unknown execution strategy");
}

} // namespace cryptobench::crypto
