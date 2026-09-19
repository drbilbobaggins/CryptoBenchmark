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

class EcdsaAdapter final : public core::AlgorithmAdapter {
public:
    enum class InputMode { NoInput, Prehashed, Message };

    EcdsaAdapter(core::EcKeyGenParameters parameters, core::BenchmarkOperation operation);
    EcdsaAdapter(core::EcdsaParameters parameters, core::BenchmarkOperation operation, InputMode inputMode,
                 core::ByteCount signatureBytes);

    void prepareSeries() override;
    void prepareRun() override;
    void executeIteration() override;

    std::span<const unsigned char> digestForTesting() const noexcept;
    std::span<const unsigned char> signatureForTesting() const noexcept;
    EVP_PKEY* currentKeyForTesting() const noexcept;
    EVP_PKEY* signingKeyForTesting() const noexcept;

private:
    using Parameters = std::variant<core::EcKeyGenParameters, core::EcdsaParameters>;

    void prepareKeyGeneration();
    void prepareSignature();
    void createPrerequisiteSignature();
    void executeKeyGeneration();
    void executeSign();
    void executeVerify();

    Parameters parameters_;
    core::BenchmarkOperation operation_;
    InputMode inputMode_;
    core::ByteCount signatureBytes_ = 0;
    openssl::EvpMdPtr digest_{nullptr, &EVP_MD_free};
    openssl::EvpPkeyCtxPtr context_{nullptr, &EVP_PKEY_CTX_free};
    openssl::EvpPkeyPtr currentKey_{nullptr, &EVP_PKEY_free};
    openssl::EvpPkeyPtr signingKey_{nullptr, &EVP_PKEY_free};
    std::vector<unsigned char> digestBytes_;
    std::vector<unsigned char> signature_;
    std::size_t actualSignatureLength_ = 0;
};

} // namespace cryptobench::crypto
