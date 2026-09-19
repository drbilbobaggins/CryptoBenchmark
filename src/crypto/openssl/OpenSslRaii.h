#pragma once

#include <memory>

#include <openssl/evp.h>

namespace cryptobench::crypto::openssl {

using EvpMdPtr = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpCipherPtr = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

} // namespace cryptobench::crypto::openssl
