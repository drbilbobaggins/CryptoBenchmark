#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class EcdhAdapter final : public core::AlgorithmAdapter {
public:
    EcdhAdapter(core::EcdhParameters parameters, core::BenchmarkOperation operation, core::ByteCount sharedSecretBytes);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> sharedSecret() const noexcept;
    EVP_PKEY* currentKeyForTesting() const noexcept;
    EVP_PKEY* ownKeyForTesting() const noexcept;
    void setPeerKeyForTesting(EVP_PKEY* peerKey) noexcept;

private:
    void prepareKeyGeneration();
    void prepareDerive();
    void executeKeyGeneration();
    void executeDerive();

    core::EcdhParameters parameters_;
    core::BenchmarkOperation operation_;
    core::ByteCount sharedSecretBytes_;
    openssl::EvpPkeyCtxPtr context_{nullptr, &EVP_PKEY_CTX_free};
    openssl::EvpPkeyPtr currentKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr ownKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr peerKey_{nullptr, &EVP_PKEY_free};
    EVP_PKEY* peerKeyForDerive_ = nullptr;
    std::vector<unsigned char> sharedSecret_;
};

} // namespace cryptobench::crypto
