#pragma once

#include <optional>
#include <variant>

#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::core {

enum class SignatureSizeReferenceKind {
    Fixed,
    MaximumDerEncoded
};

struct SignatureSizeReference {
    ByteCount bytes;
    SignatureSizeReferenceKind kind;
};

struct SignatureCharacteristics {
    std::optional<ByteCount> publicKeyBytes;
    std::optional<ByteCount> privateKeyBytes;
    std::optional<SignatureSizeReference> signatureSize;
};

struct KeyEstablishmentCharacteristics {
    ByteCount sharedSecretBytes;
    std::optional<ByteCount> publicKeyBytes;
    std::optional<ByteCount> privateKeyBytes;
    std::optional<ByteCount> ciphertextBytes;
};

struct AeadCharacteristics {
    ByteCount keyBytes;
    ByteCount nonceBytes;
    ByteCount aadBytes;
    ByteCount tagBytes;
};

struct HashCharacteristics {
    ByteCount outputBytes;
};

using StructuralCharacteristics = std::variant<
    SignatureCharacteristics,
    KeyEstablishmentCharacteristics,
    AeadCharacteristics,
    HashCharacteristics
>;

} // namespace cryptobench::core
