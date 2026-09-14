#pragma once

#include <cstdint>
#include <variant>

#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::core {

enum class RsaModulusBits : std::uint16_t {
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096
};

enum class EcCurve {
    P256,
    P384,
    P521
};

enum class SignatureDigest {
    Sha256,
    Sha384,
    Sha512
};

enum class EdDsaVariant {
    Ed25519,
    Ed448
};

enum class MlDsaLevel {
    MlDsa44,
    MlDsa65,
    MlDsa87
};

enum class SlhHashFamily {
    Sha2,
    Shake
};

enum class SlhSecurityLevel {
    Bits128,
    Bits192,
    Bits256
};

enum class SlhVariant {
    Small,
    Fast
};

enum class XdhVariant {
    X25519,
    X448
};

enum class MlKemLevel {
    MlKem512,
    MlKem768,
    MlKem1024
};

enum class AesKeyBits : std::uint16_t {
    Bits128 = 128,
    Bits192 = 192,
    Bits256 = 256
};

enum class DigestAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512
};

enum class XofAlgorithm {
    Shake128,
    Shake256
};

struct RsaKeyGenParameters {
    RsaModulusBits modulusBits;
};

struct RsaPssParameters {
    RsaModulusBits modulusBits;
    SignatureDigest digest;
};

struct EcKeyGenParameters {
    EcCurve curve;
};

struct EcdsaParameters {
    EcCurve curve;
    SignatureDigest digest;
};

struct EdDsaParameters {
    EdDsaVariant variant;
};

struct MlDsaParameters {
    MlDsaLevel level;
};

struct SlhDsaParameters {
    SlhHashFamily hashFamily;
    SlhSecurityLevel securityLevel;
    SlhVariant variant;
};

struct EcdhParameters {
    EcCurve curve;
};

struct XdhParameters {
    XdhVariant variant;
};

struct MlKemParameters {
    MlKemLevel level;
};

struct AesGcmParameters {
    AesKeyBits keyBits;
};

struct ChaCha20Poly1305Parameters {};

struct DigestParameters {
    DigestAlgorithm algorithm;
};

struct XofParameters {
    XofAlgorithm algorithm;
    ByteCount outputBytes;
};

using ProfileParameters = std::variant<
    RsaKeyGenParameters,
    RsaPssParameters,
    EcKeyGenParameters,
    EcdsaParameters,
    EdDsaParameters,
    MlDsaParameters,
    SlhDsaParameters,
    EcdhParameters,
    XdhParameters,
    MlKemParameters,
    AesGcmParameters,
    ChaCha20Poly1305Parameters,
    DigestParameters,
    XofParameters
>;

} // namespace cryptobench::core
