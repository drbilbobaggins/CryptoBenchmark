#include "MlDsaAdapter.h"

#include <array>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view algorithmName(core::MlDsaLevel level)
{
    switch (level) {
    case core::MlDsaLevel::MlDsa44: return "ML-DSA-44";
    case core::MlDsaLevel::MlDsa65: return "ML-DSA-65";
    case core::MlDsaLevel::MlDsa87: return "ML-DSA-87";
    }
    throw std::invalid_argument("MlDsaAdapter received an unknown level");
}

} // namespace

MlDsaAdapter::MlDsaAdapter(
    core::MlDsaParameters parameters,
    core::BenchmarkOperation operation,
    InputMode inputMode,
    core::ByteCount signatureBytes,
    core::WorkloadBytes messageSize)
    : parameters_(parameters),
      operation_(operation),
      inputMode_(inputMode),
      signatureBytes_(signatureBytes),
      messageSize_(messageSize)
{
    static_cast<void>(algorithmName(parameters_.level));
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("MlDsaAdapter signature size must be non-zero");
    }
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        if (inputMode_ != InputMode::NoInput) {
            throw std::invalid_argument("MlDsaAdapter KeyGen requires NoInput");
        }
    } else {
        if (operation_ != core::BenchmarkOperation::Sign && operation_ != core::BenchmarkOperation::Verify) {
            throw std::invalid_argument("MlDsaAdapter supports only KeyGen, Sign, and Verify");
        }
        if (inputMode_ != InputMode::Message || messageSize_ == 0) {
            throw std::invalid_argument("MlDsaAdapter Sign and Verify require a non-zero Message input");
        }
    }
}

MlDsaAdapter::MlDsaAdapter(
    core::MlDsaParameters parameters,
    core::BenchmarkOperation operation,
    InputMode inputMode,
    core::ByteCount signatureBytes,
    core::CommonWorkload&& workload)
    : MlDsaAdapter(parameters, operation, inputMode, signatureBytes,
                   static_cast<core::WorkloadBytes>(workload.size()))
{
    commonWorkload_.emplace(std::move(workload));
}

void MlDsaAdapter::prepareSeries()
{
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        prepareKeyGeneration();
    } else {
        prepareSignature();
    }
}

void MlDsaAdapter::prepareRun()
{
}

void MlDsaAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_.level).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(ML-DSA)");
    }
}

void MlDsaAdapter::prepareSignature()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_.level).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(ML-DSA signature)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init(ML-DSA signature)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &generatedKey), "EVP_PKEY_generate(ML-DSA signature)");
    signingKey_.reset(generatedKey);

    signatureAlgorithm_ = openssl::EvpSignaturePtr(
        EVP_SIGNATURE_fetch(nullptr, algorithmName(parameters_.level).data(), nullptr),
        &EVP_SIGNATURE_free);
    if (!signatureAlgorithm_) {
        openssl::throwOpenSslError("EVP_SIGNATURE_fetch(ML-DSA)");
    }
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ML-DSA)");
    }

    if (!commonWorkload_) {
        message_.resize(static_cast<std::size_t>(messageSize_));
        constexpr std::array pattern{'a', 'b', 'c'};
        for (std::size_t index = 0; index < message_.size(); ++index) {
            message_[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
        }
    }
    signature_.resize(static_cast<std::size_t>(signatureBytes_));
    if (operation_ == core::BenchmarkOperation::Verify) {
        createPrerequisiteSignature();
    }
}

void MlDsaAdapter::createPrerequisiteSignature()
{
    openssl::EvpPkeyCtxPtr prerequisiteContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!prerequisiteContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ML-DSA prerequisite)");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(prerequisiteContext.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(ML-DSA prerequisite)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            prerequisiteContext.get(), signature_.data(), &signatureLength,
            messageInput().data(), messageInput().size()),
        "EVP_PKEY_sign(ML-DSA prerequisite)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("ML-DSA prerequisite signature length mismatch");
    }
}

void MlDsaAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("MlDsaAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen: executeKeyGeneration(); break;
    case core::BenchmarkOperation::Sign: executeSign(); break;
    case core::BenchmarkOperation::Verify: executeVerify(); break;
    default: throw std::logic_error("MlDsaAdapter received an unsupported operation");
    }
}

void MlDsaAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init(ML-DSA)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate(ML-DSA)");
    currentKey_.reset(generatedKey);
}

void MlDsaAdapter::executeSign()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(ML-DSA)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(context_.get(), signature_.data(), &signatureLength, messageInput().data(), messageInput().size()),
        "EVP_PKEY_sign(ML-DSA)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("ML-DSA signature length mismatch");
    }
}

void MlDsaAdapter::executeVerify()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_verify_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_verify_message_init(ML-DSA)");
    const int result = EVP_PKEY_verify(
        context_.get(), signature_.data(), signature_.size(), messageInput().data(), messageInput().size());
    if (result == 1) {
        return;
    }
    if (result == 0) {
        throw std::runtime_error("ML-DSA verification failed for a valid prerequisite signature");
    }
    openssl::throwOpenSslError("EVP_PKEY_verify(ML-DSA)");
}

std::span<const unsigned char> MlDsaAdapter::messageForTesting() const noexcept
{
    return messageInput();
}

std::span<const unsigned char> MlDsaAdapter::messageInput() const noexcept
{
    if (commonWorkload_) return commonWorkload_->bytes();
    return message_;
}

std::span<const unsigned char> MlDsaAdapter::signatureForTesting() const noexcept
{
    return signature_;
}

EVP_PKEY* MlDsaAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* MlDsaAdapter::signingKeyForTesting() const noexcept
{
    return signingKey_.get();
}

} // namespace cryptobench::crypto
