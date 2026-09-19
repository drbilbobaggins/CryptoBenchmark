#include <cryptobench/crypto/AdapterFactory.h>

#include <stdexcept>
#include <variant>

#include "adapters/AeadAdapter.h"
#include "adapters/DigestAdapter.h"
#include "adapters/EcdhAdapter.h"
#include "adapters/MlKemAdapter.h"
#include "adapters/RsaPssAdapter.h"
#include "adapters/XofAdapter.h"
#include "adapters/XdhAdapter.h"

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
    case core::ExecutionStrategyId::Ecdh: {
        const auto* ecdhParameters = std::get_if<core::EcdhParameters>(&profile.parameters);
        if (ecdhParameters == nullptr) {
            throw std::logic_error("Ecdh strategy requires EcdhParameters");
        }
        const auto* keyEstablishmentConfig =
            std::get_if<core::KeyEstablishmentConfig>(&validatedConfig.parameters);
        if (keyEstablishmentConfig == nullptr) {
            throw std::logic_error("Ecdh strategy requires KeyEstablishmentConfig");
        }
        const auto& characteristics = std::get<core::KeyEstablishmentCharacteristics>(profile.characteristics);
        return std::make_unique<EcdhAdapter>(
            *ecdhParameters, operation, characteristics.sharedSecretBytes);
    }
    case core::ExecutionStrategyId::Xdh: {
        const auto* xdhParameters = std::get_if<core::XdhParameters>(&profile.parameters);
        if (xdhParameters == nullptr) {
            throw std::logic_error("Xdh strategy requires XdhParameters");
        }
        const auto* keyEstablishmentConfig =
            std::get_if<core::KeyEstablishmentConfig>(&validatedConfig.parameters);
        if (keyEstablishmentConfig == nullptr) {
            throw std::logic_error("Xdh strategy requires KeyEstablishmentConfig");
        }
        const auto& characteristics = std::get<core::KeyEstablishmentCharacteristics>(profile.characteristics);
        return std::make_unique<XdhAdapter>(
            *xdhParameters, operation, characteristics.sharedSecretBytes);
    }
    case core::ExecutionStrategyId::MlKem: {
        const auto* mlKemParameters = std::get_if<core::MlKemParameters>(&profile.parameters);
        if (mlKemParameters == nullptr) {
            throw std::logic_error("MlKem strategy requires MlKemParameters");
        }
        const auto* keyEstablishmentConfig =
            std::get_if<core::KeyEstablishmentConfig>(&validatedConfig.parameters);
        if (keyEstablishmentConfig == nullptr) {
            throw std::logic_error("MlKem strategy requires KeyEstablishmentConfig");
        }
        const auto& characteristics = std::get<core::KeyEstablishmentCharacteristics>(profile.characteristics);
        return std::make_unique<MlKemAdapter>(
            *mlKemParameters, operation, characteristics.ciphertextBytes.value(),
            characteristics.sharedSecretBytes);
    }
    case core::ExecutionStrategyId::RsaPssSignature: {
        const auto* signatureConfig = std::get_if<core::SignatureConfig>(&validatedConfig.parameters);
        if (signatureConfig == nullptr) {
            throw std::logic_error("RSA-PSS strategy requires SignatureConfig");
        }
        const auto& characteristics = std::get<core::SignatureCharacteristics>(profile.characteristics);
        if (!characteristics.signatureSize) {
            throw std::logic_error("RSA-PSS profile requires signature-size characteristics");
        }

        if (const auto* keyGenParameters = std::get_if<core::RsaKeyGenParameters>(&profile.parameters)) {
            if (operation != core::BenchmarkOperation::KeyGen ||
                !std::holds_alternative<core::NoSignatureInput>(signatureConfig->input)) {
                throw std::logic_error("RSA KeyGen requires KeyGen and NoSignatureInput");
            }
            return std::make_unique<RsaPssAdapter>(
                *keyGenParameters, operation, characteristics.signatureSize->bytes);
        }

        const auto* pssParameters = std::get_if<core::RsaPssParameters>(&profile.parameters);
        if (pssParameters == nullptr) {
            throw std::logic_error("RSA-PSS strategy requires RSA parameters");
        }
        if (operation != core::BenchmarkOperation::Sign && operation != core::BenchmarkOperation::Verify) {
            throw std::logic_error("RSA-PSS parameters require Sign or Verify");
        }
        if (std::holds_alternative<core::MessageInput>(signatureConfig->input)) {
            throw std::invalid_argument("RSA-PSS Message input is not implemented until M07.6");
        }
        if (!std::holds_alternative<core::PrehashedInput>(signatureConfig->input)) {
            throw std::logic_error("RSA-PSS Sign and Verify require PrehashedInput in M07.5");
        }
        return std::make_unique<RsaPssAdapter>(
            *pssParameters, operation, RsaPssAdapter::InputMode::Prehashed,
            characteristics.signatureSize->bytes);
    }
    case core::ExecutionStrategyId::EcdsaSignature:
    case core::ExecutionStrategyId::EdDsaSignature:
    case core::ExecutionStrategyId::MlDsaSignature:
    case core::ExecutionStrategyId::SlhDsaSignature:
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
