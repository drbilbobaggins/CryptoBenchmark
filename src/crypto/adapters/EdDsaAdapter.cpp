#include "EdDsaAdapter.h"

#include <array>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view algorithmName(core::EdDsaVariant variant)
{
    switch (variant) {
    case core::EdDsaVariant::Ed25519: return "ED25519";
    case core::EdDsaVariant::Ed448: return "ED448";
    }
    throw std::invalid_argument("EdDsaAdapter received an unknown variant");
}

} // namespace

EdDsaAdapter::EdDsaAdapter(
    core::EdDsaParameters parameters,
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
    static_cast<void>(algorithmName(parameters_.variant));
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("EdDsaAdapter signature size must be non-zero");
    }
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        if (inputMode_ != InputMode::NoInput) {
            throw std::invalid_argument("EdDsaAdapter KeyGen requires NoInput");
        }
    } else {
        if (operation_ != core::BenchmarkOperation::Sign && operation_ != core::BenchmarkOperation::Verify) {
            throw std::invalid_argument("EdDsaAdapter supports only KeyGen, Sign, and Verify");
        }
        if (inputMode_ != InputMode::Message || messageSize_ == 0) {
            throw std::invalid_argument("EdDsaAdapter Sign and Verify require a non-zero Message input");
        }
    }
}

EdDsaAdapter::EdDsaAdapter(
    core::EdDsaParameters parameters,
    core::BenchmarkOperation operation,
    InputMode inputMode,
    core::ByteCount signatureBytes,
    core::CommonWorkload&& workload)
    : EdDsaAdapter(parameters, operation, inputMode, signatureBytes,
                   static_cast<core::WorkloadBytes>(workload.size()))
{
    commonWorkload_.emplace(std::move(workload));
}

void EdDsaAdapter::prepareSeries()
{
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        prepareKeyGeneration();
    } else {
        prepareSignature();
    }
}

void EdDsaAdapter::prepareRun()
{
}

void EdDsaAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_.variant).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(EdDSA)");
    }
}

void EdDsaAdapter::prepareSignature()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_.variant).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(EdDSA signature)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init(EdDSA)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &generatedKey), "EVP_PKEY_generate(EdDSA)");
    signingKey_.reset(generatedKey);

    signatureAlgorithm_ = openssl::EvpSignaturePtr(
        EVP_SIGNATURE_fetch(nullptr, algorithmName(parameters_.variant).data(), nullptr),
        &EVP_SIGNATURE_free);
    if (!signatureAlgorithm_) {
        openssl::throwOpenSslError("EVP_SIGNATURE_fetch(EdDSA)");
    }
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(EdDSA)");
    }

    if (!commonWorkload_) {
        message_.resize(static_cast<std::size_t>(messageSize_));
        constexpr std::array pattern{'a', 'b', 'c'};
        for (std::size_t index = 0; index < message_.size(); ++index) {
            message_[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
        }
    }
    signature_.resize(signatureBytes_);
    if (operation_ == core::BenchmarkOperation::Verify) {
        createPrerequisiteSignature();
    }
}

void EdDsaAdapter::createPrerequisiteSignature()
{
    openssl::EvpPkeyCtxPtr prerequisiteContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!prerequisiteContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(EdDSA prerequisite)");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(prerequisiteContext.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(EdDSA prerequisite)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            prerequisiteContext.get(), signature_.data(), &signatureLength,
            messageInput().data(), messageInput().size()),
        "EVP_PKEY_sign(EdDSA prerequisite)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("EdDSA prerequisite signature length mismatch");
    }
}

void EdDsaAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("EdDsaAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen: executeKeyGeneration(); break;
    case core::BenchmarkOperation::Sign: executeSign(); break;
    case core::BenchmarkOperation::Verify: executeVerify(); break;
    default: throw std::logic_error("EdDsaAdapter received an unsupported operation");
    }
}

void EdDsaAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init(EdDSA)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate(EdDSA)");
    currentKey_.reset(generatedKey);
}

void EdDsaAdapter::executeSign()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(EdDSA)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(context_.get(), signature_.data(), &signatureLength, messageInput().data(), messageInput().size()),
        "EVP_PKEY_sign(EdDSA)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("EdDSA signature length mismatch");
    }
}

void EdDsaAdapter::executeVerify()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_verify_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_verify_message_init(EdDSA)");
    const int result = EVP_PKEY_verify(
        context_.get(), signature_.data(), signature_.size(), messageInput().data(), messageInput().size());
    if (result == 1) {
        return;
    }
    if (result == 0) {
        throw std::runtime_error("EdDSA verification failed for a valid prerequisite signature");
    }
    openssl::throwOpenSslError("EVP_PKEY_verify(EdDSA)");
}

std::span<const unsigned char> EdDsaAdapter::messageForTesting() const noexcept
{
    return messageInput();
}

std::span<const unsigned char> EdDsaAdapter::messageInput() const noexcept
{
    if (commonWorkload_) return commonWorkload_->bytes();
    return message_;
}

std::span<const unsigned char> EdDsaAdapter::signatureForTesting() const noexcept
{
    return signature_;
}

EVP_PKEY* EdDsaAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* EdDsaAdapter::signingKeyForTesting() const noexcept
{
    return signingKey_.get();
}

} // namespace cryptobench::crypto
