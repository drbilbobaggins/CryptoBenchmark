#pragma once

#include <cstddef>
#include <span>
#include <variant>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class AeadAdapter final : public core::AlgorithmAdapter {
public:
    using Parameters = std::variant<core::AesGcmParameters, core::ChaCha20Poly1305Parameters>;

    AeadAdapter(core::AesGcmParameters parameters, core::BenchmarkOperation operation, core::WorkloadBytes plaintextSize);
    AeadAdapter(core::ChaCha20Poly1305Parameters parameters, core::BenchmarkOperation operation, core::WorkloadBytes plaintextSize);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> plaintext() const noexcept;
    std::span<const unsigned char> ciphertext() const noexcept;
    std::span<unsigned char> mutableCiphertext() noexcept;
    std::span<const unsigned char> decryptedPlaintext() const noexcept;
    std::span<const unsigned char> tag() const noexcept;
    std::span<unsigned char> mutableTag() noexcept;

private:
    void prepareSeriesImpl();
    void encryptPrerequisite();
    void executeEncrypt();
    void executeDecrypt();

    Parameters parameters_;
    core::BenchmarkOperation operation_;
    core::WorkloadBytes plaintextSize_;
    openssl::EvpCipherPtr cipher_{nullptr, &EVP_CIPHER_free};
    openssl::EvpCipherCtxPtr context_{nullptr, &EVP_CIPHER_CTX_free};
    std::vector<unsigned char> key_;
    std::vector<unsigned char> nonce_;
    std::vector<unsigned char> aad_;
    std::vector<unsigned char> plaintext_;
    std::vector<unsigned char> ciphertext_;
    std::vector<unsigned char> decryptedPlaintext_;
    std::vector<unsigned char> tag_;
    std::size_t ciphertextSize_ = 0;
};

} // namespace cryptobench::crypto
