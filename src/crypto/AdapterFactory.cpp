#include <cryptobench/crypto/AdapterFactory.h>

#include <stdexcept>
#include <variant>

#include "adapters/AeadAdapter.h"
#include "adapters/DigestAdapter.h"
#include "adapters/XofAdapter.h"

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
    case core::ExecutionStrategyId::Xof: {
        const auto* xofParameters = std::get_if<core::XofParameters>(&profile.parameters);
        if (xofParameters == nullptr) {
            throw std::logic_error("Xof strategy requires XofParameters");
        }

        const auto* hashConfig = std::get_if<core::HashConfig>(&validatedConfig.parameters);
        if (hashConfig == nullptr) {
            throw std::logic_error("Xof strategy requires HashConfig");
        }

        return std::make_unique<XofAdapter>(*xofParameters, hashConfig->inputSize);
    }
    case core::ExecutionStrategyId::RsaPssSignature:
    case core::ExecutionStrategyId::EcdsaSignature:
    case core::ExecutionStrategyId::EdDsaSignature:
    case core::ExecutionStrategyId::MlDsaSignature:
    case core::ExecutionStrategyId::SlhDsaSignature:
    case core::ExecutionStrategyId::Ecdh:
    case core::ExecutionStrategyId::Xdh:
    case core::ExecutionStrategyId::MlKem:
        throw std::invalid_argument("AdapterFactory execution strategy is unsupported");
    case core::ExecutionStrategyId::Aead: {
        const auto* aeadConfig = std::get_if<core::AeadConfig>(&validatedConfig.parameters);
        if (aeadConfig == nullptr) {
            throw std::logic_error("Aead strategy requires AeadConfig");
        }

        if (profile.family == core::AlgorithmFamily::AesGcm) {
            const auto* aesParameters = std::get_if<core::AesGcmParameters>(&profile.parameters);
            if (aesParameters == nullptr) {
                throw std::logic_error("AES-GCM profile requires AesGcmParameters");
            }
            return std::make_unique<AeadAdapter>(*aesParameters, operation, aeadConfig->plaintextSize);
        }
        if (profile.family == core::AlgorithmFamily::ChaCha20Poly1305) {
            const auto* chachaParameters = std::get_if<core::ChaCha20Poly1305Parameters>(&profile.parameters);
            if (chachaParameters == nullptr) {
                throw std::logic_error("ChaCha20-Poly1305 profile requires ChaCha20Poly1305Parameters");
            }
            return std::make_unique<AeadAdapter>(*chachaParameters, operation, aeadConfig->plaintextSize);
        }
        throw std::logic_error("Aead strategy requires AEAD parameters");
    }
    }

    throw std::logic_error("AdapterFactory encountered an unknown execution strategy");
}

} // namespace cryptobench::crypto
