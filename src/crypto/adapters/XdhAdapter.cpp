#include "XdhAdapter.h"

#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view keyType(core::XdhVariant variant)
{
    switch (variant) {
    case core::XdhVariant::X25519: return "X25519";
    case core::XdhVariant::X448: return "X448";
    }
    throw std::invalid_argument("XdhAdapter received an unknown variant");
}

} // namespace

XdhAdapter::XdhAdapter(
    core::XdhParameters parameters,
    core::BenchmarkOperation operation,
    core::ByteCount sharedSecretBytes)
    : parameters_(parameters), operation_(operation), sharedSecretBytes_(sharedSecretBytes)
{
    static_cast<void>(keyType(parameters_.variant));
    if (operation_ != core::BenchmarkOperation::KeyGen && operation_ != core::BenchmarkOperation::Derive) {
        throw std::invalid_argument("XdhAdapter supports only KeyGen and Derive");
    }
    if (sharedSecretBytes_ == 0) {
        throw std::invalid_argument("XdhAdapter shared-secret size must be non-zero");
    }
}

void XdhAdapter::prepareSeries()
{
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        prepareKeyGeneration();
    } else {
        prepareDerive();
    }
}

void XdhAdapter::prepareRun()
{
}

void XdhAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, keyType(parameters_.variant).data(), nullptr), &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(XDH)");
    }
}

void XdhAdapter::prepareDerive()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, keyType(parameters_.variant).data(), nullptr), &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(XDH)");
    }

    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
    EVP_PKEY* ownKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &ownKey), "EVP_PKEY_generate");
    ownKey_.reset(ownKey);

    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
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

void XdhAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("XdhAdapter is not prepared");
    }
    if (operation_ == core::BenchmarkOperation::KeyGen) {
        executeKeyGeneration();
    } else {
        executeDerive();
    }
}

void XdhAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate");
    currentKey_.reset(generatedKey);
}

void XdhAdapter::executeDerive()
{
    if (!ownKey_ || peerKeyForDerive_ == nullptr || sharedSecret_.size() != sharedSecretBytes_) {
        throw std::logic_error("XdhAdapter derive state is not prepared");
    }

    openssl::checkOpenSslReturn(EVP_PKEY_derive_init(context_.get()), "EVP_PKEY_derive_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_derive_set_peer(context_.get(), peerKeyForDerive_), "EVP_PKEY_derive_set_peer");
    std::size_t secretLength = sharedSecret_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_derive(context_.get(), sharedSecret_.data(), &secretLength), "EVP_PKEY_derive");
    if (secretLength != sharedSecret_.size()) {
        throw std::runtime_error("XDH shared-secret length mismatch");
    }
}

std::span<const unsigned char> XdhAdapter::sharedSecret() const noexcept
{
    return sharedSecret_;
}

EVP_PKEY* XdhAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* XdhAdapter::ownKeyForTesting() const noexcept
{
    return ownKey_.get();
}

void XdhAdapter::setPeerKeyForTesting(EVP_PKEY* peerKey) noexcept
{
    peerKeyForDerive_ = peerKey;
}

} // namespace cryptobench::crypto
