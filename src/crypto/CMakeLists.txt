add_library(cryptobench_crypto STATIC
    AdapterFactory.cpp
    EcKeyGen.cpp
    openssl/OpenSslRuntimeBootstrap.cpp
    adapters/AeadAdapter.cpp
    adapters/DigestAdapter.cpp
    adapters/EdDsaAdapter.cpp
    adapters/MlDsaAdapter.cpp
    adapters/EcdhAdapter.cpp
    adapters/EcdsaAdapter.cpp
    adapters/MlKemAdapter.cpp
    adapters/RsaPssAdapter.cpp
    adapters/SlhDsaAdapter.cpp
    adapters/XofAdapter.cpp
    adapters/XdhAdapter.cpp
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
