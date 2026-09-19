#include "RsaPssAdapter.h"

#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

int modulusBits(core::RsaModulusBits bits)
{
    return static_cast<int>(bits);
}

std::string_view digestName(core::SignatureDigest digest)
{
    switch (digest) {
    case core::SignatureDigest::Sha256: return "SHA256";
    case core::SignatureDigest::Sha384: return "SHA384";
    case core::SignatureDigest::Sha512: return "SHA512";
    }
    throw std::invalid_argument("RsaPssAdapter received an unknown digest");
}

std::size_t digestBytes(core::SignatureDigest digest)
{
    switch (digest) {
    case core::SignatureDigest::Sha256: return 32;
    case core::SignatureDigest::Sha384: return 48;
    case core::SignatureDigest::Sha512: return 64;
    }
    throw std::invalid_argument("RsaPssAdapter received an unknown digest");
}

} // namespace

RsaPssAdapter::RsaPssAdapter(
    core::RsaKeyGenParameters parameters,
    core::BenchmarkOperation operation,
    core::ByteCount signatureBytes)
    : parameters_(parameters),
      operation_(operation),
      inputMode_(InputMode::NoInput),
      signatureBytes_(signatureBytes)
{
    if (operation_ != core::BenchmarkOperation::KeyGen) {
        throw std::invalid_argument("RsaPssAdapter KeyGen requires the KeyGen operation");
    }
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("RsaPssAdapter signature size must be non-zero");
    }
}

RsaPssAdapter::RsaPssAdapter(
    core::RsaPssParameters parameters,
    core::BenchmarkOperation operation,
    InputMode inputMode,
    core::ByteCount signatureBytes)
    : parameters_(parameters),
      operation_(operation),
      inputMode_(inputMode),
      signatureBytes_(signatureBytes)
{
    static_cast<void>(digestName(parameters.digest));
    if (operation_ != core::BenchmarkOperation::Sign && operation_ != core::BenchmarkOperation::Verify) {
        throw std::invalid_argument("RsaPssAdapter PSS parameters require Sign or Verify");
    }
    if (inputMode_ != InputMode::Prehashed) {
        throw std::invalid_argument("RsaPssAdapter supports only Prehashed input in M07.5");
    }
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("RsaPssAdapter signature size must be non-zero");
    }
}

void RsaPssAdapter::prepareSeries()
{
    if (std::holds_alternative<core::RsaKeyGenParameters>(parameters_)) {
        prepareKeyGeneration();
    } else {
        prepareSignature();
    }
}

void RsaPssAdapter::prepareRun()
{
}

void RsaPssAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(RSA)");
    }
}

void RsaPssAdapter::prepareSignature()
{
    generateSignatureKey();

    const auto& parameters = std::get<core::RsaPssParameters>(parameters_);
    digest_ = openssl::EvpMdPtr(
        EVP_MD_fetch(nullptr, digestName(parameters.digest).data(), nullptr), &EVP_MD_free);
    if (!digest_) {
        openssl::throwOpenSslError("EVP_MD_fetch(RSA-PSS digest)");
    }
    digestBytes_.assign(digestBytes(parameters.digest), 0xA5U);
    signature_.resize(signatureBytes_);

    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(RSA-PSS)");
    }
    if (operation_ == core::BenchmarkOperation::Verify) {
        createPrerequisiteSignature();
    }
}

void RsaPssAdapter::generateSignatureKey()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(RSA)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
    const auto& parameters = std::get<core::RsaPssParameters>(parameters_);
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_rsa_keygen_bits(keygenContext.get(), modulusBits(parameters.modulusBits)),
        "EVP_PKEY_CTX_set_rsa_keygen_bits");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &generatedKey), "EVP_PKEY_generate");
    signingKey_.reset(generatedKey);
}

void RsaPssAdapter::createPrerequisiteSignature()
{
    openssl::EvpPkeyCtxPtr prerequisiteContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!prerequisiteContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(RSA-PSS prerequisite)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_sign_init(prerequisiteContext.get()), "EVP_PKEY_sign_init");
    configurePss(prerequisiteContext.get());
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            prerequisiteContext.get(), signature_.data(), &signatureLength,
            digestBytes_.data(), digestBytes_.size()),
        "EVP_PKEY_sign(RSA-PSS prerequisite)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("RSA-PSS prerequisite signature length mismatch");
    }
}

void RsaPssAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("RsaPssAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen:
        executeKeyGeneration();
        break;
    case core::BenchmarkOperation::Sign:
        executeSign();
        break;
    case core::BenchmarkOperation::Verify:
        executeVerify();
        break;
    default:
        throw std::logic_error("RsaPssAdapter received an unsupported operation");
    }
}

void RsaPssAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    const auto& parameters = std::get<core::RsaKeyGenParameters>(parameters_);
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_rsa_keygen_bits(context_.get(), modulusBits(parameters.modulusBits)),
        "EVP_PKEY_CTX_set_rsa_keygen_bits");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate");
    currentKey_.reset(generatedKey);
}

void RsaPssAdapter::executeSign()
{
    std::size_t signatureLength = signature_.size();
    openssl::checkOpenSslReturn(EVP_PKEY_sign_init(context_.get()), "EVP_PKEY_sign_init");
    configurePss(context_.get());
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            context_.get(), signature_.data(), &signatureLength,
            digestBytes_.data(), digestBytes_.size()),
        "EVP_PKEY_sign(RSA-PSS)");
    if (signatureLength != signature_.size()) {
        throw std::runtime_error("RSA-PSS signature length mismatch");
    }
}

void RsaPssAdapter::executeVerify()
{
    openssl::checkOpenSslReturn(EVP_PKEY_verify_init(context_.get()), "EVP_PKEY_verify_init");
    configurePss(context_.get());
    const int result = EVP_PKEY_verify(
        context_.get(), signature_.data(), signature_.size(),
        digestBytes_.data(), digestBytes_.size());
    if (result == 1) {
        return;
    }
    if (result == 0) {
        throw std::runtime_error("RSA-PSS verification failed for a valid prerequisite signature");
    }
    openssl::throwOpenSslError("EVP_PKEY_verify(RSA-PSS)");
}

void RsaPssAdapter::configurePss(EVP_PKEY_CTX* context) const
{
    const auto& parameters = std::get<core::RsaPssParameters>(parameters_);
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING),
        "EVP_PKEY_CTX_set_rsa_padding");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_signature_md(context, digest_.get()),
        "EVP_PKEY_CTX_set_signature_md");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, digest_.get()),
        "EVP_PKEY_CTX_set_rsa_mgf1_md");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_rsa_pss_saltlen(context, RSA_PSS_SALTLEN_DIGEST),
        "EVP_PKEY_CTX_set_rsa_pss_saltlen");
    static_cast<void>(parameters);
}

std::span<const unsigned char> RsaPssAdapter::digestForTesting() const noexcept
{
    return digestBytes_;
}

std::span<const unsigned char> RsaPssAdapter::signatureForTesting() const noexcept
{
    return signature_;
}

EVP_PKEY* RsaPssAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* RsaPssAdapter::signingKeyForTesting() const noexcept
{
    return signingKey_.get();
}

} // namespace cryptobench::crypto
