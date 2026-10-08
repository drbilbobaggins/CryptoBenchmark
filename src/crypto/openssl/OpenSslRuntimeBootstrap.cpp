#include <cryptobench/crypto/OpenSslRuntimeBootstrap.h>

#include "OpenSslError.h"

#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <mutex>

namespace cryptobench::crypto {
namespace {

std::once_flag defaultProviderOnce;

} // namespace

void initializeGenericOpenSslRuntime()
{
    if (OPENSSL_init_crypto(0, nullptr) != 1) {
        openssl::throwOpenSslError("OPENSSL_init_crypto");
    }

    std::call_once(defaultProviderOnce, [] {
        if (OSSL_PROVIDER_load(nullptr, "default") == nullptr) {
            openssl::throwOpenSslError("OSSL_PROVIDER_load(default)");
        }
    });
}

} // namespace cryptobench::crypto
