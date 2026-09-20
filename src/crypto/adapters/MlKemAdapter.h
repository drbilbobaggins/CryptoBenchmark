#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class MlKemAdapter final : public core::AlgorithmAdapter {
public:
    MlKemAdapter(core::MlKemParameters parameters, core::BenchmarkOperation operation,
                 core::ByteCount ciphertextBytes, core::ByteCount sharedSecretBytes);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> ciphertext() const noexcept;
    std::span<const unsigned char> sharedSecret() const noexcept;
    std::span<const unsigned char> prerequisiteSharedSecretForTesting() const noexcept;
    EVP_PKEY* currentKeyForTesting() const noexcept;
    EVP_PKEY* recipientKeyForTesting() const noexcept;

private:
    void prepareKeyGeneration();
    void prepareEncapsulate();
    void prepareDecapsulate();
    void generateRecipientKey();
    void createPrerequisiteEncapsulation();
    void executeKeyGeneration();
    void executeEncapsulate();
    void executeDecapsulate();

    core::MlKemParameters parameters_;
    core::BenchmarkOperation operation_;
    core::ByteCount ciphertextBytes_;
    core::ByteCount sharedSecretBytes_;
    openssl::EvpPkeyCtxPtr context_{nullptr, &EVP_PKEY_CTX_free};
    openssl::EvpPkeyPtr currentKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr recipientKey_{nullptr, &EVP_PKEY_free};
    std::vector<unsigned char> ciphertext_;
    std::vector<unsigned char> sharedSecret_;
    std::vector<unsigned char> prerequisiteSharedSecret_;
};

} // namespace cryptobench::crypto
