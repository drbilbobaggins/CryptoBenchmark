add_library(cryptobench_crypto STATIC
    adapters/DigestAdapter.cpp
    openssl/OpenSslError.cpp
)

target_link_libraries(cryptobench_crypto
    PUBLIC
        cryptobench_core
    PRIVATE
        OpenSSL::Crypto
)
