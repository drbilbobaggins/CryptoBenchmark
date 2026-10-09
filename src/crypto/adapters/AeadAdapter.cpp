#include "AeadAdapter.h"

#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

#include <openssl/evp.h>

#include "../openssl/OpenSslError.h"

namespace cryptobench::crypto {

namespace {

constexpr std::size_t nonceSize = 12;
constexpr std::size_t aadSize = 32;
constexpr std::size_t tagSize = 16;

std::string_view cipherName(const AeadAdapter::Parameters& parameters)
{
    return std::visit([](const auto& value) -> std::string_view {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, core::AesGcmParameters>) {
            switch (value.keyBits) {
            case core::AesKeyBits::Bits128: return "AES-128-GCM";
            case core::AesKeyBits::Bits192: return "AES-192-GCM";
            case core::AesKeyBits::Bits256: return "AES-256-GCM";
            }
        } else {
            return "CHACHA20-POLY1305";
        }
        throw std::invalid_argument("AeadAdapter received unknown AES-GCM parameters");
    }, parameters);
}

std::size_t keySize(const AeadAdapter::Parameters& parameters)
{
    return std::visit([](const auto& value) -> std::size_t {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, core::AesGcmParameters>) {
            switch (value.keyBits) {
            case core::AesKeyBits::Bits128: return 16;
            case core::AesKeyBits::Bits192: return 24;
            case core::AesKeyBits::Bits256: return 32;
            }
        } else {
            return 32;
        }
        throw std::invalid_argument("AeadAdapter received unknown AES-GCM parameters");
    }, parameters);
}

int checkedLength(std::size_t size, std::string_view name)
{
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument(std::string(name) + " is too large for OpenSSL EVP");
    }
    return static_cast<int>(size);
}

void requireLength(int actual, std::size_t expected, std::string_view name)
{
    if (actual != checkedLength(expected, name)) {
        throw std::runtime_error(std::string(name) + " length mismatch");
    }
}

} // namespace

AeadAdapter::AeadAdapter(core::AesGcmParameters parameters, core::BenchmarkOperation operation, core::WorkloadBytes plaintextSize)
    : parameters_(parameters), operation_(operation), plaintextSize_(plaintextSize)
{
    static_cast<void>(cipherName(parameters_));
    if (operation_ != core::BenchmarkOperation::Encrypt && operation_ != core::BenchmarkOperation::Decrypt) {
        throw std::invalid_argument("AeadAdapter supports only Encrypt and Decrypt");
    }
}

AeadAdapter::AeadAdapter(core::ChaCha20Poly1305Parameters parameters, core::BenchmarkOperation operation, core::WorkloadBytes plaintextSize)
    : parameters_(parameters), operation_(operation), plaintextSize_(plaintextSize)
{
    static_cast<void>(cipherName(parameters_));
    if (operation_ != core::BenchmarkOperation::Encrypt && operation_ != core::BenchmarkOperation::Decrypt) {
        throw std::invalid_argument("AeadAdapter supports only Encrypt and Decrypt");
    }
}

AeadAdapter::AeadAdapter(core::AesGcmParameters parameters, core::BenchmarkOperation operation, core::CommonWorkload&& workload)
    : parameters_(parameters),
      operation_(operation),
      plaintextSize_(static_cast<core::WorkloadBytes>(workload.size())),
      commonWorkload_(std::move(workload))
{
    static_cast<void>(cipherName(parameters_));
    if (operation_ != core::BenchmarkOperation::Encrypt && operation_ != core::BenchmarkOperation::Decrypt) {
        throw std::invalid_argument("AeadAdapter supports only Encrypt and Decrypt");
    }
}

AeadAdapter::AeadAdapter(core::ChaCha20Poly1305Parameters parameters, core::BenchmarkOperation operation, core::CommonWorkload&& workload)
    : parameters_(parameters),
      operation_(operation),
      plaintextSize_(static_cast<core::WorkloadBytes>(workload.size())),
      commonWorkload_(std::move(workload))
{
    static_cast<void>(cipherName(parameters_));
    if (operation_ != core::BenchmarkOperation::Encrypt && operation_ != core::BenchmarkOperation::Decrypt) {
        throw std::invalid_argument("AeadAdapter supports only Encrypt and Decrypt");
    }
}

void AeadAdapter::prepareSeries()
{
    prepareSeriesImpl();
    if (operation_ == core::BenchmarkOperation::Decrypt) {
        encryptPrerequisite();
    }
}

void AeadAdapter::prepareSeriesImpl()
{
    const auto name = cipherName(parameters_);
    cipher_ = openssl::EvpCipherPtr(EVP_CIPHER_fetch(nullptr, name.data(), nullptr), &EVP_CIPHER_free);
    if (!cipher_) {
        openssl::throwOpenSslError(std::string("EVP_CIPHER_fetch(") + std::string(name) + ")");
    }

    context_ = openssl::EvpCipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!context_) {
        openssl::throwOpenSslError("EVP_CIPHER_CTX_new");
    }

    key_.resize(keySize(parameters_));
    nonce_.resize(nonceSize);
    aad_.resize(aadSize);
    if (!commonWorkload_) {
        plaintext_.resize(static_cast<std::size_t>(plaintextSize_));
        constexpr auto pattern = [](std::size_t index) {
            return static_cast<unsigned char>(index & 0xffU);
        };
        for (std::size_t index = 0; index < plaintext_.size(); ++index) {
            plaintext_[index] = pattern(index);
        }
    }
    const auto plaintext = plaintextInput();
    ciphertext_.resize(plaintext.size());
    decryptedPlaintext_.resize(plaintext.size());
    tag_.resize(tagSize);

    for (std::size_t index = 0; index < key_.size(); ++index) {
        key_[index] = static_cast<unsigned char>(0x10U + index);
    }
    for (std::size_t index = 0; index < nonce_.size(); ++index) {
        nonce_[index] = static_cast<unsigned char>(0x20U + index);
    }
    for (std::size_t index = 0; index < aad_.size(); ++index) {
        aad_[index] = static_cast<unsigned char>(0x30U + index);
    }
}

std::span<const unsigned char> AeadAdapter::plaintextInput() const noexcept
{
    if (commonWorkload_) return commonWorkload_->bytes();
    return plaintext_;
}

void AeadAdapter::encryptPrerequisite()
{
    executeEncrypt();
}

void AeadAdapter::prepareRun()
{
}

void AeadAdapter::executeIteration()
{
    if (!cipher_ || !context_ || key_.empty() || nonce_.size() != nonceSize || aad_.size() != aadSize ||
        tag_.size() != tagSize || plaintextInput().size() != static_cast<std::size_t>(plaintextSize_)) {
        throw std::logic_error("AeadAdapter is not prepared");
    }

    if (operation_ == core::BenchmarkOperation::Encrypt) {
        executeEncrypt();
    } else {
        executeDecrypt();
    }
}

void AeadAdapter::executeEncrypt()
{
    const auto plaintext = plaintextInput();
    openssl::checkOpenSslReturn(EVP_CIPHER_CTX_reset(context_.get()), "EVP_CIPHER_CTX_reset");
    openssl::checkOpenSslReturn(
        EVP_EncryptInit_ex(context_.get(), cipher_.get(), nullptr, nullptr, nullptr),
        "EVP_EncryptInit_ex");
    openssl::checkOpenSslReturn(
        EVP_EncryptInit_ex(context_.get(), nullptr, nullptr, key_.data(), nonce_.data()),
        "EVP_EncryptInit_ex key and nonce");

    int aadLength = 0;
    openssl::checkOpenSslReturn(
        EVP_EncryptUpdate(context_.get(), nullptr, &aadLength, aad_.data(), checkedLength(aad_.size(), "AAD")),
        "EVP_EncryptUpdate AAD");
    requireLength(aadLength, aad_.size(), "AAD");

    int payloadLength = 0;
    openssl::checkOpenSslReturn(
        EVP_EncryptUpdate(context_.get(), ciphertext_.data(), &payloadLength, plaintext.data(), checkedLength(plaintext.size(), "plaintext")),
        "EVP_EncryptUpdate plaintext");
    int finalLength = 0;
    openssl::checkOpenSslReturn(
        EVP_EncryptFinal_ex(context_.get(), ciphertext_.data() + payloadLength, &finalLength),
        "EVP_EncryptFinal_ex");
    ciphertextSize_ = static_cast<std::size_t>(payloadLength + finalLength);
    requireLength(payloadLength + finalLength, plaintext.size(), "ciphertext");

    openssl::checkOpenSslReturn(
        EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_AEAD_GET_TAG, checkedLength(tag_.size(), "tag"), tag_.data()),
        "EVP_CIPHER_CTX_ctrl GET_TAG");
}

void AeadAdapter::executeDecrypt()
{
    if (ciphertextSize_ != plaintextInput().size() || ciphertext_.size() < ciphertextSize_) {
        throw std::logic_error("AeadAdapter decrypt prerequisite is not prepared");
    }

    openssl::checkOpenSslReturn(EVP_CIPHER_CTX_reset(context_.get()), "EVP_CIPHER_CTX_reset");
    openssl::checkOpenSslReturn(
        EVP_DecryptInit_ex(context_.get(), cipher_.get(), nullptr, nullptr, nullptr),
        "EVP_DecryptInit_ex");
    openssl::checkOpenSslReturn(
        EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_AEAD_SET_TAG, checkedLength(tag_.size(), "tag"), tag_.data()),
        "EVP_CIPHER_CTX_ctrl SET_TAG");
    openssl::checkOpenSslReturn(
        EVP_DecryptInit_ex(context_.get(), nullptr, nullptr, key_.data(), nonce_.data()),
        "EVP_DecryptInit_ex key and nonce");

    int aadLength = 0;
    openssl::checkOpenSslReturn(
        EVP_DecryptUpdate(context_.get(), nullptr, &aadLength, aad_.data(), checkedLength(aad_.size(), "AAD")),
        "EVP_DecryptUpdate AAD");
    requireLength(aadLength, aad_.size(), "AAD");

    int payloadLength = 0;
    openssl::checkOpenSslReturn(
        EVP_DecryptUpdate(context_.get(), decryptedPlaintext_.data(), &payloadLength, ciphertext_.data(), checkedLength(ciphertextSize_, "ciphertext")),
        "EVP_DecryptUpdate ciphertext");
    int finalLength = 0;
    const int finalResult = EVP_DecryptFinal_ex(
        context_.get(), decryptedPlaintext_.data() + payloadLength, &finalLength);
    if (finalResult != 1) {
        throw std::runtime_error("AeadAdapter authentication failed");
    }
    requireLength(payloadLength + finalLength, plaintextInput().size(), "decrypted plaintext");
}

std::span<const unsigned char> AeadAdapter::plaintext() const noexcept { return plaintextInput(); }
std::span<const unsigned char> AeadAdapter::ciphertext() const noexcept { return {ciphertext_.data(), ciphertextSize_}; }
std::span<unsigned char> AeadAdapter::mutableCiphertext() noexcept { return {ciphertext_.data(), ciphertextSize_}; }
std::span<const unsigned char> AeadAdapter::decryptedPlaintext() const noexcept { return decryptedPlaintext_; }
std::span<const unsigned char> AeadAdapter::tag() const noexcept { return tag_; }
std::span<unsigned char> AeadAdapter::mutableTag() noexcept { return tag_; }

} // namespace cryptobench::crypto
