#include "DigestAdapter.h"

#include <array>
#include <stdexcept>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {

namespace {

std::string_view digestName(core::DigestAlgorithm algorithm)
{
    switch (algorithm) {
    case core::DigestAlgorithm::Sha224: return "SHA-224";
    case core::DigestAlgorithm::Sha256: return "SHA-256";
    case core::DigestAlgorithm::Sha384: return "SHA-384";
    case core::DigestAlgorithm::Sha512: return "SHA-512";
    case core::DigestAlgorithm::Sha3_224: return "SHA3-224";
    case core::DigestAlgorithm::Sha3_256: return "SHA3-256";
    case core::DigestAlgorithm::Sha3_384: return "SHA3-384";
    case core::DigestAlgorithm::Sha3_512: return "SHA3-512";
    }

    throw std::invalid_argument("DigestAdapter received an unknown digest algorithm");
}

std::size_t digestOutputSize(core::DigestAlgorithm algorithm)
{
    switch (algorithm) {
    case core::DigestAlgorithm::Sha224:
    case core::DigestAlgorithm::Sha3_224: return 28;
    case core::DigestAlgorithm::Sha256:
    case core::DigestAlgorithm::Sha3_256: return 32;
    case core::DigestAlgorithm::Sha384:
    case core::DigestAlgorithm::Sha3_384: return 48;
    case core::DigestAlgorithm::Sha512:
    case core::DigestAlgorithm::Sha3_512: return 64;
    }

    throw std::invalid_argument("DigestAdapter received an unknown digest algorithm");
}

} // namespace

DigestAdapter::DigestAdapter(core::DigestParameters parameters, core::WorkloadBytes inputSize)
    : parameters_(parameters),
      inputSize_(inputSize)
{
    static_cast<void>(digestName(parameters_.algorithm));
}

void DigestAdapter::prepareSeries()
{
    const auto name = digestName(parameters_.algorithm);
    digest_ = openssl::EvpMdPtr(EVP_MD_fetch(nullptr, name.data(), nullptr), &EVP_MD_free);
    if (!digest_) {
        openssl::throwOpenSslError(std::string("EVP_MD_fetch(") + std::string(name) + ")");
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
    output_.resize(digestOutputSize(parameters_.algorithm));
}

void DigestAdapter::executeIteration()
{
    if (!digest_ || !context_ || output_.size() != digestOutputSize(parameters_.algorithm)) {
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
        throw std::runtime_error("Digest output length mismatch");
    }
}

std::span<const unsigned char> DigestAdapter::output() const noexcept
{
    return output_;
}

} // namespace cryptobench::crypto
