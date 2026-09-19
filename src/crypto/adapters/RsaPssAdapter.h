#pragma once

#include <span>
#include <variant>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class RsaPssAdapter final : public core::AlgorithmAdapter {
public:
    enum class InputMode {
        NoInput,
        Prehashed
    };

    RsaPssAdapter(core::RsaKeyGenParameters parameters, core::BenchmarkOperation operation,
                  core::ByteCount signatureBytes);
    RsaPssAdapter(core::RsaPssParameters parameters, core::BenchmarkOperation operation,
                  InputMode inputMode, core::ByteCount signatureBytes);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> digestForTesting() const noexcept;
    std::span<const unsigned char> signatureForTesting() const noexcept;
    EVP_PKEY* currentKeyForTesting() const noexcept;
    EVP_PKEY* signingKeyForTesting() const noexcept;

private:
    using Parameters = std::variant<core::RsaKeyGenParameters, core::RsaPssParameters>;

    void prepareKeyGeneration();
    void prepareSignature();
    void generateSignatureKey();
    void createPrerequisiteSignature();
    void executeKeyGeneration();
    void executeSign();
    void executeVerify();
    void configurePss(EVP_PKEY_CTX* context) const;

    Parameters parameters_;
    core::BenchmarkOperation operation_;
    InputMode inputMode_;
    core::ByteCount signatureBytes_;
    openssl::EvpMdPtr digest_{nullptr, &EVP_MD_free};
    openssl::EvpPkeyCtxPtr context_{nullptr, &EVP_PKEY_CTX_free};
    openssl::EvpPkeyPtr currentKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr signingKey_{nullptr, &EVP_PKEY_free};
    std::vector<unsigned char> digestBytes_;
    std::vector<unsigned char> signature_;
};

} // namespace cryptobench::crypto
