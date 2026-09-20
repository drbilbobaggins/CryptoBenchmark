#include "SlhDsaAdapter.h"

#include <array>
#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view algorithmName(core::SlhDsaParameters parameters)
{
    const auto suffix = [parameters] {
        switch (parameters.variant) {
        case core::SlhVariant::Small: return 's';
        case core::SlhVariant::Fast: return 'f';
        }
        throw std::invalid_argument("SlhDsaAdapter received an unknown variant");
    }();

    switch (parameters.hashFamily) {
    case core::SlhHashFamily::Sha2:
        switch (parameters.securityLevel) {
        case core::SlhSecurityLevel::Bits128: return suffix == 's' ? "SLH-DSA-SHA2-128s" : "SLH-DSA-SHA2-128f";
        case core::SlhSecurityLevel::Bits192: return suffix == 's' ? "SLH-DSA-SHA2-192s" : "SLH-DSA-SHA2-192f";
        case core::SlhSecurityLevel::Bits256: return suffix == 's' ? "SLH-DSA-SHA2-256s" : "SLH-DSA-SHA2-256f";
        }
        break;
    case core::SlhHashFamily::Shake:
        switch (parameters.securityLevel) {
        case core::SlhSecurityLevel::Bits128: return suffix == 's' ? "SLH-DSA-SHAKE-128s" : "SLH-DSA-SHAKE-128f";
        case core::SlhSecurityLevel::Bits192: return suffix == 's' ? "SLH-DSA-SHAKE-192s" : "SLH-DSA-SHAKE-192f";
        case core::SlhSecurityLevel::Bits256: return suffix == 's' ? "SLH-DSA-SHAKE-256s" : "SLH-DSA-SHAKE-256f";
        }
        break;
    }
    throw std::invalid_argument("SlhDsaAdapter received unknown parameters");
}

} // namespace

SlhDsaAdapter::SlhDsaAdapter(
    core::SlhDsaParameters parameters,
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
    static_cast<void>(algorithmName(parameters_));
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("SlhDsaAdapter signature size must be non-zero");
    }
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        if (inputMode_ != InputMode::NoInput) {
            throw std::invalid_argument("SlhDsaAdapter KeyGen requires NoInput");
        }
    } else {
        if (operation_ != core::BenchmarkOperation::Sign && operation_ != core::BenchmarkOperation::Verify) {
            throw std::invalid_argument("SlhDsaAdapter supports only KeyGen, Sign, and Verify");
        }
        if (inputMode_ != InputMode::Message || messageSize_ == 0) {
            throw std::invalid_argument("SlhDsaAdapter Sign and Verify require a non-zero Message input");
        }
    }
}

void SlhDsaAdapter::prepareSeries()
{
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        prepareKeyGeneration();
    } else {
        prepareSignature();
    }
}

void SlhDsaAdapter::prepareRun()
{
}

void SlhDsaAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(SLH-DSA)");
    }
}

void SlhDsaAdapter::prepareSignature()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithmName(parameters_).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(SLH-DSA signature)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init(SLH-DSA signature)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &generatedKey), "EVP_PKEY_generate(SLH-DSA signature)");
    signingKey_.reset(generatedKey);

    signatureAlgorithm_ = openssl::EvpSignaturePtr(
        EVP_SIGNATURE_fetch(nullptr, algorithmName(parameters_).data(), nullptr),
        &EVP_SIGNATURE_free);
    if (!signatureAlgorithm_) {
        openssl::throwOpenSslError("EVP_SIGNATURE_fetch(SLH-DSA)");
    }
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(SLH-DSA)");
    }

    message_.resize(static_cast<std::size_t>(messageSize_));
    constexpr std::array pattern{'a', 'b', 'c'};
    for (std::size_t index = 0; index < message_.size(); ++index) {
        message_[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
    }
    signature_.resize(static_cast<std::size_t>(signatureBytes_));
    if (operation_ == core::BenchmarkOperation::Verify) {
        createPrerequisiteSignature();
    }
}

void SlhDsaAdapter::createPrerequisiteSignature()
{
    openssl::EvpPkeyCtxPtr prerequisiteContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!prerequisiteContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(SLH-DSA prerequisite)");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(prerequisiteContext.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(SLH-DSA prerequisite)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            prerequisiteContext.get(), signature_.data(), &signatureLength,
            message_.data(), message_.size()),
        "EVP_PKEY_sign(SLH-DSA prerequisite)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("SLH-DSA prerequisite signature length mismatch");
    }
}

void SlhDsaAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("SlhDsaAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen: executeKeyGeneration(); break;
    case core::BenchmarkOperation::Sign: executeSign(); break;
    case core::BenchmarkOperation::Verify: executeVerify(); break;
    default: throw std::logic_error("SlhDsaAdapter received an unsupported operation");
    }
}

void SlhDsaAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init(SLH-DSA)");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate(SLH-DSA)");
    currentKey_.reset(generatedKey);
}

void SlhDsaAdapter::executeSign()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_sign_message_init(SLH-DSA)");
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(context_.get(), signature_.data(), &signatureLength, message_.data(), message_.size()),
        "EVP_PKEY_sign(SLH-DSA)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("SLH-DSA signature length mismatch");
    }
}

void SlhDsaAdapter::executeVerify()
{
    openssl::checkOpenSslReturn(
        EVP_PKEY_verify_message_init(context_.get(), signatureAlgorithm_.get(), nullptr),
        "EVP_PKEY_verify_message_init(SLH-DSA)");
    const int result = EVP_PKEY_verify(
        context_.get(), signature_.data(), signature_.size(), message_.data(), message_.size());
    if (result == 1) {
        return;
    }
    if (result == 0) {
        throw std::runtime_error("SLH-DSA verification failed for a valid prerequisite signature");
    }
    openssl::throwOpenSslError("EVP_PKEY_verify(SLH-DSA)");
}

std::span<const unsigned char> SlhDsaAdapter::messageForTesting() const noexcept
{
    return message_;
}

std::span<const unsigned char> SlhDsaAdapter::signatureForTesting() const noexcept
{
    return signature_;
}

EVP_PKEY* SlhDsaAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* SlhDsaAdapter::signingKeyForTesting() const noexcept
{
    return signingKey_.get();
}

} // namespace cryptobench::crypto
