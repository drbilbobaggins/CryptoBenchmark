#include "EcdsaAdapter.h"

#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include "../EcKeyGen.h"
#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view digestName(core::SignatureDigest digest)
{
    switch (digest) {
    case core::SignatureDigest::Sha256: return "SHA256";
    case core::SignatureDigest::Sha384: return "SHA384";
    case core::SignatureDigest::Sha512: return "SHA512";
    }
    throw std::invalid_argument("EcdsaAdapter received an unknown digest");
}

std::size_t digestBytes(core::SignatureDigest digest)
{
    switch (digest) {
    case core::SignatureDigest::Sha256: return 32;
    case core::SignatureDigest::Sha384: return 48;
    case core::SignatureDigest::Sha512: return 64;
    }
    throw std::invalid_argument("EcdsaAdapter received an unknown digest");
}

} // namespace

EcdsaAdapter::EcdsaAdapter(core::EcKeyGenParameters parameters, core::BenchmarkOperation operation)
    : parameters_(parameters), operation_(operation), inputMode_(InputMode::NoInput)
{
    static_cast<void>(ecCurveGroupName(parameters.curve));
    if (operation_ != core::BenchmarkOperation::KeyGen) {
        throw std::invalid_argument("EcdsaAdapter EC KeyGen requires the KeyGen operation");
    }
}

EcdsaAdapter::EcdsaAdapter(
    core::EcdsaParameters parameters,
    core::BenchmarkOperation operation,
    InputMode inputMode,
    core::ByteCount signatureBytes)
    : parameters_(parameters), operation_(operation), inputMode_(inputMode), signatureBytes_(signatureBytes)
{
    static_cast<void>(ecCurveGroupName(parameters.curve));
    static_cast<void>(digestName(parameters.digest));
    if (operation_ != core::BenchmarkOperation::Sign && operation_ != core::BenchmarkOperation::Verify) {
        throw std::invalid_argument("EcdsaAdapter ECDSA parameters require Sign or Verify");
    }
    if (inputMode_ != InputMode::Prehashed) {
        throw std::invalid_argument("EcdsaAdapter Message input is not implemented until M07.8");
    }
    if (signatureBytes_ == 0) {
        throw std::invalid_argument("EcdsaAdapter signature size must be non-zero");
    }
}

void EcdsaAdapter::prepareSeries()
{
    if (std::holds_alternative<core::EcKeyGenParameters>(parameters_)) {
        prepareKeyGeneration();
    } else {
        prepareSignature();
    }
}

void EcdsaAdapter::prepareRun()
{
}

void EcdsaAdapter::prepareKeyGeneration()
{
    context_ = createEcKeyGenerationContext();
}

void EcdsaAdapter::prepareSignature()
{
    const auto& parameters = std::get<core::EcdsaParameters>(parameters_);
    auto keygenContext = createEcKeyGenerationContext();
    signingKey_ = generateEcKey(keygenContext.get(), parameters.curve);
    digest_ = openssl::EvpMdPtr(
        EVP_MD_fetch(nullptr, digestName(parameters.digest).data(), nullptr), &EVP_MD_free);
    if (!digest_) {
        openssl::throwOpenSslError("EVP_MD_fetch(ECDSA digest)");
    }
    digestBytes_.assign(digestBytes(parameters.digest), 0xA5U);
    signature_.resize(signatureBytes_);
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ECDSA)");
    }
    if (operation_ == core::BenchmarkOperation::Verify) {
        createPrerequisiteSignature();
    }
}

void EcdsaAdapter::createPrerequisiteSignature()
{
    openssl::EvpPkeyCtxPtr prerequisiteContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, signingKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!prerequisiteContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ECDSA prerequisite)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_sign_init(prerequisiteContext.get()), "EVP_PKEY_sign_init(ECDSA prerequisite)");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_signature_md(prerequisiteContext.get(), digest_.get()),
        "EVP_PKEY_CTX_set_signature_md(ECDSA prerequisite)");
    actualSignatureLength_ = signature_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            prerequisiteContext.get(), signature_.data(), &actualSignatureLength_,
            digestBytes_.data(), digestBytes_.size()),
        "EVP_PKEY_sign(ECDSA prerequisite)");
    if (actualSignatureLength_ == 0 || actualSignatureLength_ > signature_.size()) {
        throw std::runtime_error("ECDSA prerequisite signature length is invalid");
    }
}

void EcdsaAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("EcdsaAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen: executeKeyGeneration(); break;
    case core::BenchmarkOperation::Sign: executeSign(); break;
    case core::BenchmarkOperation::Verify: executeVerify(); break;
    default: throw std::logic_error("EcdsaAdapter received an unsupported operation");
    }
}

void EcdsaAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    const auto& parameters = std::get<core::EcKeyGenParameters>(parameters_);
    currentKey_ = generateEcKey(context_.get(), parameters.curve);
}

void EcdsaAdapter::executeSign()
{
    actualSignatureLength_ = signature_.size();
    openssl::checkOpenSslReturn(EVP_PKEY_sign_init(context_.get()), "EVP_PKEY_sign_init(ECDSA)");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_signature_md(context_.get(), digest_.get()),
        "EVP_PKEY_CTX_set_signature_md(ECDSA)");
    openssl::checkOpenSslReturn(
        EVP_PKEY_sign(
            context_.get(), signature_.data(), &actualSignatureLength_,
            digestBytes_.data(), digestBytes_.size()),
        "EVP_PKEY_sign(ECDSA)");
    if (actualSignatureLength_ == 0 || actualSignatureLength_ > signature_.size()) {
        throw std::runtime_error("ECDSA signature length is invalid");
    }
}

void EcdsaAdapter::executeVerify()
{
    openssl::checkOpenSslReturn(EVP_PKEY_verify_init(context_.get()), "EVP_PKEY_verify_init(ECDSA)");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_signature_md(context_.get(), digest_.get()),
        "EVP_PKEY_CTX_set_signature_md(ECDSA)");
    const int result = EVP_PKEY_verify(
        context_.get(), signature_.data(), actualSignatureLength_, digestBytes_.data(), digestBytes_.size());
    if (result == 1) {
        return;
    }
    if (result == 0) {
        throw std::runtime_error("ECDSA verification failed for a valid prerequisite signature");
    }
    openssl::throwOpenSslError("EVP_PKEY_verify(ECDSA)");
}

std::span<const unsigned char> EcdsaAdapter::digestForTesting() const noexcept
{
    return digestBytes_;
}

std::span<const unsigned char> EcdsaAdapter::signatureForTesting() const noexcept
{
    return std::span<const unsigned char>(signature_.data(), actualSignatureLength_);
}

EVP_PKEY* EcdsaAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* EcdsaAdapter::signingKeyForTesting() const noexcept
{
    return signingKey_.get();
}

} // namespace cryptobench::crypto
