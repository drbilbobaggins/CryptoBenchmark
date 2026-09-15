#include "DigestAdapter.h"

#include <array>
#include <stdexcept>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {

DigestAdapter::DigestAdapter(core::DigestParameters parameters, core::WorkloadBytes inputSize)
    : parameters_(parameters),
      inputSize_(inputSize)
{
    if (parameters_.algorithm != core::DigestAlgorithm::Sha256) {
        throw std::invalid_argument("DigestAdapter supports SHA-256 only");
    }
}

void DigestAdapter::prepareSeries()
{
    digest_ = openssl::EvpMdPtr(EVP_MD_fetch(nullptr, "SHA256", nullptr), &EVP_MD_free);
    if (!digest_) {
        openssl::throwOpenSslError("EVP_MD_fetch(SHA256)");
    }

    context_ = openssl::EvpMdCtxPtr(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_MD_CTX_new");
    }

    input_.resize(static_cast<std::size_t>(inputSize_));
    constexpr std::array pattern{'a', 'b', 'c'};
    for (std::size_t index = 0; index < input_.size(); ++index) {
        input_[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
    }
    output_.resize(32);
}

void DigestAdapter::executeIteration()
{
    if (!digest_ || !context_ || output_.size() != 32) {
        throw std::logic_error("DigestAdapter is not prepared");
    }

    openssl::checkOpenSslReturn(EVP_MD_CTX_reset(context_.get()), "EVP_MD_CTX_reset");
    openssl::checkOpenSslReturn(EVP_DigestInit_ex2(context_.get(), digest_.get(), nullptr), "EVP_DigestInit_ex2");
    if (!input_.empty()) {
        openssl::checkOpenSslReturn(
            EVP_DigestUpdate(context_.get(), input_.data(), input_.size()),
            "EVP_DigestUpdate");
    }

    unsigned int outputLength = 0;
    openssl::checkOpenSslReturn(
        EVP_DigestFinal_ex(context_.get(), output_.data(), &outputLength),
        "EVP_DigestFinal_ex");
    if (outputLength != output_.size()) {
        throw std::runtime_error("SHA-256 digest length mismatch");
    }
}

std::span<const unsigned char> DigestAdapter::output() const noexcept
{
    return output_;
}

} // namespace cryptobench::crypto
