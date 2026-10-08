#include <cryptobench/crypto/OpenSslRuntimeBootstrap.h>

#include <openssl/provider.h>

#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

void testBootstrapIsRepeatable()
{
    cryptobench::crypto::initializeGenericOpenSslRuntime();
    require(OSSL_PROVIDER_available(nullptr, "default") == 1,
            "default provider is not available after bootstrap");
    cryptobench::crypto::initializeGenericOpenSslRuntime();
    require(OSSL_PROVIDER_available(nullptr, "default") == 1,
            "default provider is not available after repeated bootstrap");
}

} // namespace

int main()
{
    try {
        testBootstrapIsRepeatable();
        std::cout << "OpenSslRuntimeBootstrapTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "OpenSslRuntimeBootstrapTests failed: " << error.what() << '\n';
        return 1;
    }
}
