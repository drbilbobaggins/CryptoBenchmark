#include "XofAdapter.h"

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {

namespace {

std::string_view xofName(core::XofAlgorithm algorithm)
{
    switch (algorithm) {
    case core::XofAlgorithm::Shake128: return "SHAKE-128";
    case core::XofAlgorithm::Shake256: return "SHAKE-256";
    }

    throw std::invalid_argument("XofAdapter received an unknown XOF algorithm");
}

} // namespace

XofAdapter::XofAdapter(core::XofParameters parameters, core::WorkloadBytes inputSize)
    : parameters_(parameters),
      inputSize_(inputSize)
{
    static_cast<void>(xofName(parameters_.algorithm));
    if (parameters_.outputBytes == 0) {
        throw std::invalid_argument("XofAdapter output size must be non-zero");
    }
}

XofAdapter::XofAdapter(core::XofParameters parameters, core::CommonWorkload&& workload)
    : parameters_(parameters),
      inputSize_(static_cast<core::WorkloadBytes>(workload.size())),
      commonWorkload_(std::move(workload))
{
    static_cast<void>(xofName(parameters_.algorithm));
    if (parameters_.outputBytes == 0) {
        throw std::invalid_argument("XofAdapter output size must be non-zero");
    }
}

void XofAdapter::prepareSeries()
{
    const auto name = xofName(parameters_.algorithm);
    digest_ = openssl::EvpMdPtr(EVP_MD_fetch(nullptr, name.data(), nullptr), &EVP_MD_free);
    if (!digest_) {
        openssl::throwOpenSslError(std::string("EVP_MD_fetch(") + std::string(name) + ")");
    }

    context_ = openssl::EvpMdCtxPtr(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_MD_CTX_new");
    }

    if (!commonWorkload_) {
        input_.resize(static_cast<std::size_t>(inputSize_));
        constexpr std::array pattern{'a', 'b', 'c'};
        for (std::size_t index = 0; index < input_.size(); ++index) {
            input_[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
        }
    }
    output_.resize(static_cast<std::size_t>(parameters_.outputBytes));
}

void XofAdapter::executeIteration()
{
    if (!digest_ || !context_ || output_.size() != parameters_.outputBytes) {
        throw std::logic_error("XofAdapter is not prepared");
    }

    openssl::checkOpenSslReturn(EVP_MD_CTX_reset(context_.get()), "EVP_MD_CTX_reset");
    openssl::checkOpenSslReturn(EVP_DigestInit_ex2(context_.get(), digest_.get(), nullptr), "EVP_DigestInit_ex2");
    const auto input = inputBytes();
    if (!input.empty()) {
        openssl::checkOpenSslReturn(
            EVP_DigestUpdate(context_.get(), input.data(), input.size()),
            "EVP_DigestUpdate");
    }

    openssl::checkOpenSslReturn(
        EVP_DigestFinalXOF(context_.get(), output_.data(), output_.size()),
        "EVP_DigestFinalXOF");
}

std::span<const unsigned char> XofAdapter::output() const noexcept
{
    return output_;
}

std::span<const unsigned char> XofAdapter::input() const noexcept
{
    return inputBytes();
}

std::span<const unsigned char> XofAdapter::inputBytes() const noexcept
{
    if (commonWorkload_) return commonWorkload_->bytes();
    return input_;
}

} // namespace cryptobench::crypto
