#include "EcKeyGen.h"

#include <stdexcept>

#include <openssl/evp.h>

#include "openssl/OpenSslError.h"

namespace cryptobench::crypto {

std::string_view ecCurveGroupName(core::EcCurve curve)
{
    switch (curve) {
    case core::EcCurve::P256: return "prime256v1";
    case core::EcCurve::P384: return "secp384r1";
    case core::EcCurve::P521: return "secp521r1";
    }
    throw std::invalid_argument("unknown EC curve");
}

openssl::EvpPkeyCtxPtr createEcKeyGenerationContext()
{
    openssl::EvpPkeyCtxPtr context(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free);
    if (!context) {
        openssl::throwOpenSslError("EVP_PKEY_CTX_new_from_name(EC)");
    }
    return context;
}

openssl::EvpPkeyPtr generateEcKey(EVP_PKEY_CTX* context, core::EcCurve curve)
{
    if (context == nullptr) {
        throw std::invalid_argument("EC key generation context is null");
    }
    openssl::checkOpenSslReturn(EVP_PKEY_keygen_init(context), "EVP_PKEY_keygen_init");
    openssl::checkOpenSslReturn(
        EVP_PKEY_CTX_set_group_name(context, ecCurveGroupName(curve).data()),
        "EVP_PKEY_CTX_set_group_name");
    EVP_PKEY* generatedKey = nullptr;
    openssl::checkOpenSslReturn(EVP_PKEY_generate(context, &generatedKey), "EVP_PKEY_generate");
    return openssl::EvpPkeyPtr(generatedKey, &EVP_PKEY_free);
}

} // namespace cryptobench::crypto
