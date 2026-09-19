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

class EdDsaAdapter final : public core::AlgorithmAdapter {
public:
    enum class InputMode {
        NoInput,
        Message
    };

    EdDsaAdapter(
        core::EdDsaParameters parameters,
        core::BenchmarkOperation operation,
        InputMode inputMode,
        core::ByteCount signatureBytes,
        core::WorkloadBytes messageSize = 0);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> messageForTesting() const noexcept;
    std::span<const unsigned char> signatureForTesting() const noexcept;
    EVP_PKEY* currentKeyForTesting() const noexcept;
    EVP_PKEY* signingKeyForTesting() const noexcept;

private:
    void prepareKeyGeneration();
    void prepareSignature();
    void createPrerequisiteSignature();
    void executeKeyGeneration();
    void executeSign();
    void executeVerify();

    core::EdDsaParameters parameters_;
    core::BenchmarkOperation operation_;
    InputMode inputMode_;
    core::ByteCount signatureBytes_;
    core::WorkloadBytes messageSize_ = 0;
    openssl::EvpSignaturePtr signatureAlgorithm_{nullptr, &EVP_SIGNATURE_free};
    openssl::EvpPkeyCtxPtr context_{nullptr, &EVP_PKEY_CTX_free};
    openssl::EvpPkeyPtr currentKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr signingKey_{nullptr, &EVP_PKEY_free};
    std::vector<unsigned char> message_;
    std::vector<unsigned char> signature_;
};

} // namespace cryptobench::crypto
