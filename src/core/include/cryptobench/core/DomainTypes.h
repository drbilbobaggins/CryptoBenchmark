#pragma once

#include <cstdint>

namespace cryptobench::core {

using WorkloadBytes = std::uint64_t;
using ByteCount = std::uint32_t;

enum class PrimitiveCategory {
    Signature,
    KeyEstablishment,
    Aead,
    HashXof
};

enum class AlgorithmFamily {
    RsaPss,
    Ecdsa,
    EdDsa,
    MlDsa,
    SlhDsa,
    Ecdh,
    Xdh,
    MlKem,
    AesGcm,
    ChaCha20Poly1305,
    Sha2,
    Sha3,
    Shake
};

enum class BenchmarkOperation {
    KeyGen,
    Sign,
    Verify,
    Derive,
    Encapsulate,
    Decapsulate,
    Encrypt,
    Decrypt,
    Hash,
    Xof
};

enum class ExecutionStrategyId {
    RsaPssSignature,
    EcdsaSignature,
    EdDsaSignature,
    MlDsaSignature,
    SlhDsaSignature,
    Ecdh,
    Xdh,
    MlKem,
    Aead,
    Digest,
    Xof
};

} // namespace cryptobench::core
