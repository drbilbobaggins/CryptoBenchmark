#include <cryptobench/core/AlgorithmProfileId.h>

#include <array>
#include <string_view>
#include <utility>

namespace cryptobench::core {

std::string_view toStableProfileId(AlgorithmProfileId id)
{
    switch (id) {
        case AlgorithmProfileId::Rsa2048KeyGen: return "rsa-2048-keygen";
        case AlgorithmProfileId::Rsa3072KeyGen: return "rsa-3072-keygen";
        case AlgorithmProfileId::Rsa4096KeyGen: return "rsa-4096-keygen";
        case AlgorithmProfileId::RsaPss2048Sha256: return "rsa-pss-2048-sha256";
        case AlgorithmProfileId::RsaPss2048Sha384: return "rsa-pss-2048-sha384";
        case AlgorithmProfileId::RsaPss2048Sha512: return "rsa-pss-2048-sha512";
        case AlgorithmProfileId::RsaPss3072Sha256: return "rsa-pss-3072-sha256";
        case AlgorithmProfileId::RsaPss3072Sha384: return "rsa-pss-3072-sha384";
        case AlgorithmProfileId::RsaPss3072Sha512: return "rsa-pss-3072-sha512";
        case AlgorithmProfileId::RsaPss4096Sha256: return "rsa-pss-4096-sha256";
        case AlgorithmProfileId::RsaPss4096Sha384: return "rsa-pss-4096-sha384";
        case AlgorithmProfileId::RsaPss4096Sha512: return "rsa-pss-4096-sha512";
        case AlgorithmProfileId::EcdsaP256KeyGen: return "ecdsa-p256-keygen";
        case AlgorithmProfileId::EcdsaP384KeyGen: return "ecdsa-p384-keygen";
        case AlgorithmProfileId::EcdsaP521KeyGen: return "ecdsa-p521-keygen";
        case AlgorithmProfileId::EcdsaP256Sha256: return "ecdsa-p256-sha256";
        case AlgorithmProfileId::EcdsaP256Sha384: return "ecdsa-p256-sha384";
        case AlgorithmProfileId::EcdsaP256Sha512: return "ecdsa-p256-sha512";
        case AlgorithmProfileId::EcdsaP384Sha256: return "ecdsa-p384-sha256";
        case AlgorithmProfileId::EcdsaP384Sha384: return "ecdsa-p384-sha384";
        case AlgorithmProfileId::EcdsaP384Sha512: return "ecdsa-p384-sha512";
        case AlgorithmProfileId::EcdsaP521Sha256: return "ecdsa-p521-sha256";
        case AlgorithmProfileId::EcdsaP521Sha384: return "ecdsa-p521-sha384";
        case AlgorithmProfileId::EcdsaP521Sha512: return "ecdsa-p521-sha512";
        case AlgorithmProfileId::Ed25519: return "ed25519";
        case AlgorithmProfileId::Ed448: return "ed448";
        case AlgorithmProfileId::MlDsa44: return "ml-dsa-44";
        case AlgorithmProfileId::MlDsa65: return "ml-dsa-65";
        case AlgorithmProfileId::MlDsa87: return "ml-dsa-87";
        case AlgorithmProfileId::SlhDsaSha2128S: return "slh-dsa-sha2-128s";
        case AlgorithmProfileId::SlhDsaSha2128F: return "slh-dsa-sha2-128f";
        case AlgorithmProfileId::SlhDsaSha2192S: return "slh-dsa-sha2-192s";
        case AlgorithmProfileId::SlhDsaSha2192F: return "slh-dsa-sha2-192f";
        case AlgorithmProfileId::SlhDsaSha2256S: return "slh-dsa-sha2-256s";
        case AlgorithmProfileId::SlhDsaSha2256F: return "slh-dsa-sha2-256f";
        case AlgorithmProfileId::SlhDsaShake128S: return "slh-dsa-shake-128s";
        case AlgorithmProfileId::SlhDsaShake128F: return "slh-dsa-shake-128f";
        case AlgorithmProfileId::SlhDsaShake192S: return "slh-dsa-shake-192s";
        case AlgorithmProfileId::SlhDsaShake192F: return "slh-dsa-shake-192f";
        case AlgorithmProfileId::SlhDsaShake256S: return "slh-dsa-shake-256s";
        case AlgorithmProfileId::SlhDsaShake256F: return "slh-dsa-shake-256f";
        case AlgorithmProfileId::EcdhP256: return "ecdh-p256";
        case AlgorithmProfileId::EcdhP384: return "ecdh-p384";
        case AlgorithmProfileId::EcdhP521: return "ecdh-p521";
        case AlgorithmProfileId::X25519: return "x25519";
        case AlgorithmProfileId::X448: return "x448";
        case AlgorithmProfileId::MlKem512: return "ml-kem-512";
        case AlgorithmProfileId::MlKem768: return "ml-kem-768";
        case AlgorithmProfileId::MlKem1024: return "ml-kem-1024";
        case AlgorithmProfileId::Aes128Gcm: return "aes-128-gcm";
        case AlgorithmProfileId::Aes192Gcm: return "aes-192-gcm";
        case AlgorithmProfileId::Aes256Gcm: return "aes-256-gcm";
        case AlgorithmProfileId::ChaCha20Poly1305: return "chacha20-poly1305";
        case AlgorithmProfileId::Sha224: return "sha224";
        case AlgorithmProfileId::Sha256: return "sha256";
        case AlgorithmProfileId::Sha384: return "sha384";
        case AlgorithmProfileId::Sha512: return "sha512";
        case AlgorithmProfileId::Sha3_224: return "sha3-224";
        case AlgorithmProfileId::Sha3_256: return "sha3-256";
        case AlgorithmProfileId::Sha3_384: return "sha3-384";
        case AlgorithmProfileId::Sha3_512: return "sha3-512";
        case AlgorithmProfileId::Shake128_28B: return "shake128-28bytes";
        case AlgorithmProfileId::Shake128_32B: return "shake128-32bytes";
        case AlgorithmProfileId::Shake128_48B: return "shake128-48bytes";
        case AlgorithmProfileId::Shake128_64B: return "shake128-64bytes";
        case AlgorithmProfileId::Shake128_128B: return "shake128-128bytes";
        case AlgorithmProfileId::Shake256_28B: return "shake256-28bytes";
        case AlgorithmProfileId::Shake256_32B: return "shake256-32bytes";
        case AlgorithmProfileId::Shake256_48B: return "shake256-48bytes";
        case AlgorithmProfileId::Shake256_64B: return "shake256-64bytes";
        case AlgorithmProfileId::Shake256_128B: return "shake256-128bytes";
        case AlgorithmProfileId::Shake256_256B: return "shake256-256bytes";
    }

    return {};
}

std::optional<AlgorithmProfileId> parseStableProfileId(std::string_view text)
{
    static constexpr std::array<std::pair<std::string_view, AlgorithmProfileId>, 72> kMappings = {{
        {"rsa-2048-keygen", AlgorithmProfileId::Rsa2048KeyGen},
        {"rsa-3072-keygen", AlgorithmProfileId::Rsa3072KeyGen},
        {"rsa-4096-keygen", AlgorithmProfileId::Rsa4096KeyGen},
        {"rsa-pss-2048-sha256", AlgorithmProfileId::RsaPss2048Sha256},
        {"rsa-pss-2048-sha384", AlgorithmProfileId::RsaPss2048Sha384},
        {"rsa-pss-2048-sha512", AlgorithmProfileId::RsaPss2048Sha512},
        {"rsa-pss-3072-sha256", AlgorithmProfileId::RsaPss3072Sha256},
        {"rsa-pss-3072-sha384", AlgorithmProfileId::RsaPss3072Sha384},
        {"rsa-pss-3072-sha512", AlgorithmProfileId::RsaPss3072Sha512},
        {"rsa-pss-4096-sha256", AlgorithmProfileId::RsaPss4096Sha256},
        {"rsa-pss-4096-sha384", AlgorithmProfileId::RsaPss4096Sha384},
        {"rsa-pss-4096-sha512", AlgorithmProfileId::RsaPss4096Sha512},
        {"ecdsa-p256-keygen", AlgorithmProfileId::EcdsaP256KeyGen},
        {"ecdsa-p384-keygen", AlgorithmProfileId::EcdsaP384KeyGen},
        {"ecdsa-p521-keygen", AlgorithmProfileId::EcdsaP521KeyGen},
        {"ecdsa-p256-sha256", AlgorithmProfileId::EcdsaP256Sha256},
        {"ecdsa-p256-sha384", AlgorithmProfileId::EcdsaP256Sha384},
        {"ecdsa-p256-sha512", AlgorithmProfileId::EcdsaP256Sha512},
        {"ecdsa-p384-sha256", AlgorithmProfileId::EcdsaP384Sha256},
        {"ecdsa-p384-sha384", AlgorithmProfileId::EcdsaP384Sha384},
        {"ecdsa-p384-sha512", AlgorithmProfileId::EcdsaP384Sha512},
        {"ecdsa-p521-sha256", AlgorithmProfileId::EcdsaP521Sha256},
        {"ecdsa-p521-sha384", AlgorithmProfileId::EcdsaP521Sha384},
        {"ecdsa-p521-sha512", AlgorithmProfileId::EcdsaP521Sha512},
        {"ed25519", AlgorithmProfileId::Ed25519},
        {"ed448", AlgorithmProfileId::Ed448},
        {"ml-dsa-44", AlgorithmProfileId::MlDsa44},
        {"ml-dsa-65", AlgorithmProfileId::MlDsa65},
        {"ml-dsa-87", AlgorithmProfileId::MlDsa87},
        {"slh-dsa-sha2-128s", AlgorithmProfileId::SlhDsaSha2128S},
        {"slh-dsa-sha2-128f", AlgorithmProfileId::SlhDsaSha2128F},
        {"slh-dsa-sha2-192s", AlgorithmProfileId::SlhDsaSha2192S},
        {"slh-dsa-sha2-192f", AlgorithmProfileId::SlhDsaSha2192F},
        {"slh-dsa-sha2-256s", AlgorithmProfileId::SlhDsaSha2256S},
        {"slh-dsa-sha2-256f", AlgorithmProfileId::SlhDsaSha2256F},
        {"slh-dsa-shake-128s", AlgorithmProfileId::SlhDsaShake128S},
        {"slh-dsa-shake-128f", AlgorithmProfileId::SlhDsaShake128F},
        {"slh-dsa-shake-192s", AlgorithmProfileId::SlhDsaShake192S},
        {"slh-dsa-shake-192f", AlgorithmProfileId::SlhDsaShake192F},
        {"slh-dsa-shake-256s", AlgorithmProfileId::SlhDsaShake256S},
        {"slh-dsa-shake-256f", AlgorithmProfileId::SlhDsaShake256F},
        {"ecdh-p256", AlgorithmProfileId::EcdhP256},
        {"ecdh-p384", AlgorithmProfileId::EcdhP384},
        {"ecdh-p521", AlgorithmProfileId::EcdhP521},
        {"x25519", AlgorithmProfileId::X25519},
        {"x448", AlgorithmProfileId::X448},
        {"ml-kem-512", AlgorithmProfileId::MlKem512},
        {"ml-kem-768", AlgorithmProfileId::MlKem768},
        {"ml-kem-1024", AlgorithmProfileId::MlKem1024},
        {"aes-128-gcm", AlgorithmProfileId::Aes128Gcm},
        {"aes-192-gcm", AlgorithmProfileId::Aes192Gcm},
        {"aes-256-gcm", AlgorithmProfileId::Aes256Gcm},
        {"chacha20-poly1305", AlgorithmProfileId::ChaCha20Poly1305},
        {"sha224", AlgorithmProfileId::Sha224},
        {"sha256", AlgorithmProfileId::Sha256},
        {"sha384", AlgorithmProfileId::Sha384},
        {"sha512", AlgorithmProfileId::Sha512},
        {"sha3-224", AlgorithmProfileId::Sha3_224},
        {"sha3-256", AlgorithmProfileId::Sha3_256},
        {"sha3-384", AlgorithmProfileId::Sha3_384},
        {"sha3-512", AlgorithmProfileId::Sha3_512},
        {"shake128-28bytes", AlgorithmProfileId::Shake128_28B},
        {"shake128-32bytes", AlgorithmProfileId::Shake128_32B},
        {"shake128-48bytes", AlgorithmProfileId::Shake128_48B},
        {"shake128-64bytes", AlgorithmProfileId::Shake128_64B},
        {"shake128-128bytes", AlgorithmProfileId::Shake128_128B},
        {"shake256-28bytes", AlgorithmProfileId::Shake256_28B},
        {"shake256-32bytes", AlgorithmProfileId::Shake256_32B},
        {"shake256-48bytes", AlgorithmProfileId::Shake256_48B},
        {"shake256-64bytes", AlgorithmProfileId::Shake256_64B},
        {"shake256-128bytes", AlgorithmProfileId::Shake256_128B},
        {"shake256-256bytes", AlgorithmProfileId::Shake256_256B},
    }};

    for (const auto& [key, value] : kMappings) {
        if (text == key) {
            return value;
        }
    }

    return std::nullopt;
}

} // namespace cryptobench::core
