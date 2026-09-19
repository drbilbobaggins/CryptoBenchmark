#include "MlKemAdapter.h"

#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {
namespace {

std::string_view keyType(core::MlKemLevel level)
{
    switch (level) {
    case core::MlKemLevel::MlKem512: return "ML-KEM-512";
    case core::MlKemLevel::MlKem768: return "ML-KEM-768";
    case core::MlKemLevel::MlKem1024: return "ML-KEM-1024";
    }
    throw std::invalid_argument("MlKemAdapter received an unknown ML-KEM level");
}

} // namespace

MlKemAdapter::MlKemAdapter(
    core::MlKemParameters parameters,
    core::BenchmarkOperation operation,
    core::ByteCount ciphertextBytes,
    core::ByteCount sharedSecretBytes)
    : parameters_(parameters),
      operation_(operation),
      ciphertextBytes_(ciphertextBytes),
      sharedSecretBytes_(sharedSecretBytes)
{
    static_cast<void>(keyType(parameters_.level));
    if (operation_ != core::BenchmarkOperation::KeyGen &&
        operation_ != core::BenchmarkOperation::Encapsulate &&
        operation_ != core::BenchmarkOperation::Decapsulate) {
        throw std::invalid_argument("MlKemAdapter supports only KeyGen, Encapsulate, and Decapsulate");
    }
    if (ciphertextBytes_ == 0 || sharedSecretBytes_ == 0) {
        throw std::invalid_argument("MlKemAdapter output sizes must be non-zero");
    }
}

void MlKemAdapter::prepareSeries()
{
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen:
        prepareKeyGeneration();
        break;
    case core::BenchmarkOperation::Encapsulate:
        prepareEncapsulate();
        break;
    case core::BenchmarkOperation::Decapsulate:
        prepareDecapsulate();
        break;
    default:
        throw std::logic_error("MlKemAdapter received an unsupported operation");
    }
}

void MlKemAdapter::prepareRun()
{
}

void MlKemAdapter::prepareKeyGeneration()
{
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_name(nullptr, keyType(parameters_.level).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(ML-KEM)");
    }
}

void MlKemAdapter::prepareEncapsulate()
{
    generateRecipientKey();
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, recipientKey_.get(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ML-KEM encapsulate)");
    }
    ciphertext_.resize(ciphertextBytes_);
    sharedSecret_.resize(sharedSecretBytes_);
}

void MlKemAdapter::prepareDecapsulate()
{
    generateRecipientKey();
    context_ = openssl::EvpPkeyCtxPtr(
        EVP_PKEY_CTX_new_from_pkey(nullptr, recipientKey_.get(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ML-KEM decapsulate)");
    }
    ciphertext_.resize(ciphertextBytes_);
    sharedSecret_.resize(sharedSecretBytes_);
    prerequisiteSharedSecret_.resize(sharedSecretBytes_);
    createPrerequisiteEncapsulation();
}

void MlKemAdapter::generateRecipientKey()
{
    openssl::EvpPkeyCtxPtr keygenContext(
        EVP_PKEY_CTX_new_from_name(nullptr, keyType(parameters_.level).data(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!keygenContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(ML-KEM)");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(keygenContext.get()), "EVP_PKEY_keygen_init");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(keygenContext.get(), &generatedKey), "EVP_PKEY_generate");
    recipientKey_.reset(generatedKey);
}

void MlKemAdapter::createPrerequisiteEncapsulation()
{
    openssl::EvpPkeyCtxPtr encapsulationContext(
        EVP_PKEY_CTX_new_from_pkey(nullptr, recipientKey_.get(), nullptr),
        &EVP_PKEY_CTX_free);
    if (!encapsulationContext) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_pkey(ML-KEM prerequisite)");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_encapsulate_init(encapsulationContext.get(), nullptr),
        "EVP_PKEY_encapsulate_init");
    std::size_t ciphertextLength = ciphertext_.size();
    std::size_t secretLength = prerequisiteSharedSecret_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_encapsulate(
            encapsulationContext.get(), ciphertext_.data(), &ciphertextLength,
            prerequisiteSharedSecret_.data(), &secretLength),
        "EVP_PKEY_encapsulate");
    if (ciphertextLength != ciphertext_.size() || secretLength != prerequisiteSharedSecret_.size()) {
        throw std::runtime_error("ML-KEM prerequisite output length mismatch");
    }
}

void MlKemAdapter::executeIteration()
{
    if (!context_) {
        throw std::logic_error("MlKemAdapter is not prepared");
    }
    switch (operation_) {
    case core::BenchmarkOperation::KeyGen:
        executeKeyGeneration();
        break;
    case core::BenchmarkOperation::Encapsulate:
        executeEncapsulate();
        break;
    case core::BenchmarkOperation::Decapsulate:
        executeDecapsulate();
        break;
    default:
        throw std::logic_error("MlKemAdapter received an unsupported operation");
    }
}

void MlKemAdapter::executeKeyGeneration()
{
    currentKey_.reset();
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context_.get()), "EVP_PKEY_keygen_init");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context_.get(), &generatedKey), "EVP_PKEY_generate");
    currentKey_.reset(generatedKey);
}

void MlKemAdapter::executeEncapsulate()
{
    if (ciphertext_.size() != ciphertextBytes_ || sharedSecret_.size() != sharedSecretBytes_) {
        throw std::logic_error("MlKemAdapter encapsulation state is not prepared");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_encapsulate_init(context_.get(), nullptr), "EVP_PKEY_encapsulate_init");
    std::size_t ciphertextLength = ciphertext_.size();
    std::size_t secretLength = sharedSecret_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_encapsulate(
            context_.get(), ciphertext_.data(), &ciphertextLength,
            sharedSecret_.data(), &secretLength),
        "EVP_PKEY_encapsulate");
    if (ciphertextLength != ciphertext_.size() || secretLength != sharedSecret_.size()) {
        throw std::runtime_error("ML-KEM encapsulation output length mismatch");
    }
}

void MlKemAdapter::executeDecapsulate()
{
    if (ciphertext_.size() != ciphertextBytes_ || sharedSecret_.size() != sharedSecretBytes_) {
        throw std::logic_error("MlKemAdapter decapsulation state is not prepared");
    }
    openssl::checkOpenSslReturn(
        EVP_PKEY_decapsulate_init(context_.get(), nullptr), "EVP_PKEY_decapsulate_init");
    std::size_t secretLength = sharedSecret_.size();
    openssl::checkOpenSslReturn(
        EVP_PKEY_decapsulate(
            context_.get(), sharedSecret_.data(), &secretLength,
            ciphertext_.data(), ciphertext_.size()),
        "EVP_PKEY_decapsulate");
    if (secretLength != sharedSecret_.size()) {
        throw std::runtime_error("ML-KEM decapsulation output length mismatch");
    }
}

std::span<const unsigned char> MlKemAdapter::ciphertext() const noexcept
{
    return ciphertext_;
}

std::span<const unsigned char> MlKemAdapter::sharedSecret() const noexcept
{
    return sharedSecret_;
}

std::span<const unsigned char> MlKemAdapter::prerequisiteSharedSecretForTesting() const noexcept
{
    return prerequisiteSharedSecret_;
}

EVP_PKEY* MlKemAdapter::currentKeyForTesting() const noexcept
{
    return currentKey_.get();
}

EVP_PKEY* MlKemAdapter::recipientKeyForTesting() const noexcept
{
    return recipientKey_.get();
}

} // namespace cryptobench::crypto
