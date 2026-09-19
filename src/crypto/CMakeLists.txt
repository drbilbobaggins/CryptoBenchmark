add_library(cryptobench_crypto STATIC
    AdapterFactory.cpp
    adapters/AeadAdapter.cpp
    adapters/DigestAdapter.cpp
    adapters/XofAdapter.cpp
    openssl/OpenSslError.cpp
)

target_include_directories(cryptobench_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cryptobench_crypto
    PUBLIC
        cryptobench_core
    PRIVATE
        OpenSSL::Crypto
)
