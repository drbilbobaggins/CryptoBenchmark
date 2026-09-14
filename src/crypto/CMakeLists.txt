add_library(cryptobench_crypto STATIC
    crypto.cpp
)

target_link_libraries(cryptobench_crypto
    PUBLIC
        cryptobench_core
    PRIVATE
        OpenSSL::Crypto
)
