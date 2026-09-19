#include "EcdhAdapter.h"

#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view curveName(core::EcCurve curve)
{
    switch (curve) {
    case core::EcCurve::P256: return "prime256v1";
    case core::EcCurve::P384: return "secp384r1";
    case core::EcCurve::P521: return "secp521r1";
    }
    throw std::invalid_argument("EcdhAdapter received an unknown curve");
}

} // namespace

EcdhAdapter::EcdhAdapter(
    core::EcdhParameters parameters,
    core::BenchmarkOperation operation,
    core::ByteCount sharedSecretBytes)
    : parameters_(parameters), operation_(operation), sharedSecretBytes_(sharedSecretBytes)
{
    static_cast<void>(curveName(parameters_.curve));
    if (operation_ != core::BenchmarkOperation::KeyGen && operation_ != core::BenchmarkOperation::Derive) {
        throw std::invalid_argument("EcdhAdapter supports only KeyGen and Derive");
    }
    if (sharedSecretBytes_ == 0) {
        throw std::invalid_argument("EcdhAdapter shared-secret size must be non-zero");
    }
}

void EcdhAdapter::prepareSeries()
{
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        prepareKeyGeneration();
    } else {
        prepareDerive();
    }
}

void EcdhAdapter::prepareRun()
{
}

void EcdhAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(EC)");
    }
}

void EcdhAdapter::prepareDerive()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(EC)");
    }

    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_group_name(keygenContext.get(), curveName(parameters_.curve).data()),
        "EVP_PKEY_CTX_set_group_name");
    EVP_PKEY* ownKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &ownKey), "EVP_PKEY_generate");
    ownKey_.reset(ownKey);

    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_group_name(keygenContext.get(), curveName(parameters_.curve).data()),
        "EVP_PKEY_CTX_set_group_name");
    EVP_PKEY* peerKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &peerKey), "EVP_PKEY_generate");
    peerKey_.reset(peerKey);
    peerKeyForDerive_ = peerKey_.get();

    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, ownKey_.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey");
    }
    sharedSecret_.resize(sharedSecretBytes_);
}

void EcdhAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("EcdhAdapter is not prepared");
    }
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        executeKeyGeneration();
    } else {
        executeDerive();
    }
}

void EcdhAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_group_name(context_.get(), curveName(parameters_.curve).data()),
        "EVP_PKEY_CTX_set_group_name");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate");
    currentKey_.reset(generatedKey);
}

void EcdhAdapter::executeDerive()
{
    if (!ownKey_ || peerKeyForDerive_ == nullptr || sharedSecret_.size() != sharedSecretBytes_) {
        throw std::logic_error("EcdhAdapter derive state is not prepared");
    }

    openssl::checkOpenSslReturn(EVP_PKEY_derive_init(context_.get()), "EVP_PKEY_derive_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_derive_set_peer(context_.get(), peerKeyForDerive_), "EVP_PKEY_derive_set_peer");
    std::size_t secretLength = sharedSecret_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_derive(context_.get(), sharedSecret_.data(), &secretLength), "EVP_PKEY_derive");
    if (secretLength != sharedSecret_.size()) {
        throw std::runtime_error("ECDH shared-secret length mismatch");
    }
}

std::span<const unsigned char> EcdhAdapter::sharedSecret() const noexcept
{
    return sharedSecret_;
}

EVP_PKEY* EcdhAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* EcdhAdapter::ownKeyForTesting() const noexcept
{
    return ownKey_.get();
}

void EcdhAdapter::setPeerKeyForTesting(EVP_PKEY* peerKey) noexcept
{
    peerKeyForDerive_ = peerKey;
}

} // namespace cryptobench::crypto
