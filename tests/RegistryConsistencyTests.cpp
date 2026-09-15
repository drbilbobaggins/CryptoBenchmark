#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/AlgorithmProfileId.h>

#include <array>
#include <initializer_list>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

namespace cryptobench::tests {
using namespace core;

int runValidatorTests();
int runCoreExecutionContractTests();

using Profiles = std::span<const AlgorithmProfile>;

constexpr std::array canonicalIds{
    AlgorithmProfileId::Rsa2048KeyGen,
    AlgorithmProfileId::Rsa3072KeyGen,
    AlgorithmProfileId::Rsa4096KeyGen,
    AlgorithmProfileId::RsaPss2048Sha256,
    AlgorithmProfileId::RsaPss2048Sha384,
    AlgorithmProfileId::RsaPss2048Sha512,
    AlgorithmProfileId::RsaPss3072Sha256,
    AlgorithmProfileId::RsaPss3072Sha384,
    AlgorithmProfileId::RsaPss3072Sha512,
    AlgorithmProfileId::RsaPss4096Sha256,
    AlgorithmProfileId::RsaPss4096Sha384,
    AlgorithmProfileId::RsaPss4096Sha512,
    AlgorithmProfileId::EcdsaP256KeyGen,
    AlgorithmProfileId::EcdsaP384KeyGen,
    AlgorithmProfileId::EcdsaP521KeyGen,
    AlgorithmProfileId::EcdsaP256Sha256,
    AlgorithmProfileId::EcdsaP256Sha384,
    AlgorithmProfileId::EcdsaP256Sha512,
    AlgorithmProfileId::EcdsaP384Sha256,
    AlgorithmProfileId::EcdsaP384Sha384,
    AlgorithmProfileId::EcdsaP384Sha512,
    AlgorithmProfileId::EcdsaP521Sha256,
    AlgorithmProfileId::EcdsaP521Sha384,
    AlgorithmProfileId::EcdsaP521Sha512,
    AlgorithmProfileId::Ed25519,
    AlgorithmProfileId::Ed448,
    AlgorithmProfileId::MlDsa44,
    AlgorithmProfileId::MlDsa65,
    AlgorithmProfileId::MlDsa87,
    AlgorithmProfileId::SlhDsaSha2128S,
    AlgorithmProfileId::SlhDsaSha2128F,
    AlgorithmProfileId::SlhDsaSha2192S,
    AlgorithmProfileId::SlhDsaSha2192F,
    AlgorithmProfileId::SlhDsaSha2256S,
    AlgorithmProfileId::SlhDsaSha2256F,
    AlgorithmProfileId::SlhDsaShake128S,
    AlgorithmProfileId::SlhDsaShake128F,
    AlgorithmProfileId::SlhDsaShake192S,
    AlgorithmProfileId::SlhDsaShake192F,
    AlgorithmProfileId::SlhDsaShake256S,
    AlgorithmProfileId::SlhDsaShake256F,
    AlgorithmProfileId::EcdhP256,
    AlgorithmProfileId::EcdhP384,
    AlgorithmProfileId::EcdhP521,
    AlgorithmProfileId::X25519,
    AlgorithmProfileId::X448,
    AlgorithmProfileId::MlKem512,
    AlgorithmProfileId::MlKem768,
    AlgorithmProfileId::MlKem1024,
    AlgorithmProfileId::Aes128Gcm,
    AlgorithmProfileId::Aes192Gcm,
    AlgorithmProfileId::Aes256Gcm,
    AlgorithmProfileId::ChaCha20Poly1305,
    AlgorithmProfileId::Sha224,
    AlgorithmProfileId::Sha256,
    AlgorithmProfileId::Sha384,
    AlgorithmProfileId::Sha512,
    AlgorithmProfileId::Sha3_224,
    AlgorithmProfileId::Sha3_256,
    AlgorithmProfileId::Sha3_384,
    AlgorithmProfileId::Sha3_512,
    AlgorithmProfileId::Shake128_28B,
    AlgorithmProfileId::Shake128_32B,
    AlgorithmProfileId::Shake128_48B,
    AlgorithmProfileId::Shake128_64B,
    AlgorithmProfileId::Shake128_128B,
    AlgorithmProfileId::Shake256_28B,
    AlgorithmProfileId::Shake256_32B,
    AlgorithmProfileId::Shake256_48B,
    AlgorithmProfileId::Shake256_64B,
    AlgorithmProfileId::Shake256_128B,
    AlgorithmProfileId::Shake256_256B
};

constexpr std::array allOperations{
    BenchmarkOperation::KeyGen,
    BenchmarkOperation::Sign,
    BenchmarkOperation::Verify,
    BenchmarkOperation::Derive,
    BenchmarkOperation::Encapsulate,
    BenchmarkOperation::Decapsulate,
    BenchmarkOperation::Encrypt,
    BenchmarkOperation::Decrypt,
    BenchmarkOperation::Hash,
    BenchmarkOperation::Xof
};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

bool isOneOf(AlgorithmProfileId id, std::initializer_list<AlgorithmProfileId> ids)
{
    for (const auto candidate : ids) {
        if (candidate == id) return true;
    }
    return false;
}

bool isRsaKeyGen(AlgorithmProfileId id)
{
    return isOneOf(id, {AlgorithmProfileId::Rsa2048KeyGen, AlgorithmProfileId::Rsa3072KeyGen,
                        AlgorithmProfileId::Rsa4096KeyGen});
}

bool isEcdsaKeyGen(AlgorithmProfileId id)
{
    return isOneOf(id, {AlgorithmProfileId::EcdsaP256KeyGen, AlgorithmProfileId::EcdsaP384KeyGen,
                        AlgorithmProfileId::EcdsaP521KeyGen});
}

bool isRsaDigest(AlgorithmProfileId id)
{
    return isOneOf(id, {AlgorithmProfileId::RsaPss2048Sha256, AlgorithmProfileId::RsaPss2048Sha384,
                        AlgorithmProfileId::RsaPss2048Sha512, AlgorithmProfileId::RsaPss3072Sha256,
                        AlgorithmProfileId::RsaPss3072Sha384, AlgorithmProfileId::RsaPss3072Sha512,
                        AlgorithmProfileId::RsaPss4096Sha256, AlgorithmProfileId::RsaPss4096Sha384,
                        AlgorithmProfileId::RsaPss4096Sha512});
}

bool isEcdsaDigest(AlgorithmProfileId id)
{
    return isOneOf(id, {AlgorithmProfileId::EcdsaP256Sha256, AlgorithmProfileId::EcdsaP256Sha384,
                        AlgorithmProfileId::EcdsaP256Sha512, AlgorithmProfileId::EcdsaP384Sha256,
                        AlgorithmProfileId::EcdsaP384Sha384, AlgorithmProfileId::EcdsaP384Sha512,
                        AlgorithmProfileId::EcdsaP521Sha256, AlgorithmProfileId::EcdsaP521Sha384,
                        AlgorithmProfileId::EcdsaP521Sha512});
}

void requireOperations(const AlgorithmProfile& profile, std::initializer_list<BenchmarkOperation> expected)
{
    for (const auto operation : allOperations) {
        bool shouldContain = false;
        for (const auto expectedOperation : expected) {
            if (operation == expectedOperation) shouldContain = true;
        }
        require(profile.operations.contains(operation) == shouldContain,
                "operation set mismatch");
    }
}

void testCanonicalSet(Profiles profiles)
{
    require(profiles.size() == 72, "registry size is not 72");
    std::set<AlgorithmProfileId> actual;
    for (const auto& profile : profiles) actual.insert(profile.id);
    require(actual.size() == canonicalIds.size(), "profile IDs are not unique");
    for (const auto id : canonicalIds) require(actual.contains(id), "canonical profile ID is missing");
}

void testStableIds(Profiles profiles)
{
    std::set<std::string_view> stableIds;
    for (const auto id : canonicalIds) {
        const auto stable = toStableProfileId(id);
        require(!stable.empty(), "stable ID is empty");
        require(stableIds.insert(stable).second, "stable IDs are not unique");
        require(parseStableProfileId(stable).has_value() && *parseStableProfileId(stable) == id,
                "stable ID roundtrip failed");
    }
    static_cast<void>(profiles);
    for (const auto text : {std::string_view{}, std::string_view{"unknown-profile"}, std::string_view{"rsa-2048"},
                            std::string_view{"RSA-2048-KEYGEN"}, std::string_view{"rsa-2048-keygen-extra"},
                            std::string_view{"RSA 2048 KeyGen"}}) {
        require(!parseStableProfileId(text).has_value(), "non-canonical stable ID was accepted");
    }
}

void testDisplayNamesAndFind(Profiles profiles)
{
    std::set<std::string_view> names;
    for (const auto& profile : profiles) {
        require(!profile.displayName.empty(), "display name is empty");
        require(names.insert(profile.displayName).second, "display names are not unique");
        require(AlgorithmRegistry::find(profile.id) == &profile, "find returned a different object");
    }
    require(AlgorithmRegistry::find(static_cast<AlgorithmProfileId>(9999)) == nullptr,
            "invalid profile ID resolved");
}

void testCompatibility(Profiles profiles)
{
    for (const auto& profile : profiles) {
        switch (profile.family) {
            case AlgorithmFamily::RsaPss:
                require(profile.category == PrimitiveCategory::Signature && profile.executionStrategy == ExecutionStrategyId::RsaPssSignature, "RSA compatibility mismatch"); break;
            case AlgorithmFamily::Ecdsa:
                require(profile.category == PrimitiveCategory::Signature && profile.executionStrategy == ExecutionStrategyId::EcdsaSignature, "ECDSA compatibility mismatch"); break;
            case AlgorithmFamily::EdDsa:
                require(profile.category == PrimitiveCategory::Signature && profile.executionStrategy == ExecutionStrategyId::EdDsaSignature, "EdDSA compatibility mismatch"); break;
            case AlgorithmFamily::MlDsa:
                require(profile.category == PrimitiveCategory::Signature && profile.executionStrategy == ExecutionStrategyId::MlDsaSignature, "ML-DSA compatibility mismatch"); break;
            case AlgorithmFamily::SlhDsa:
                require(profile.category == PrimitiveCategory::Signature && profile.executionStrategy == ExecutionStrategyId::SlhDsaSignature, "SLH-DSA compatibility mismatch"); break;
            case AlgorithmFamily::Ecdh:
                require(profile.category == PrimitiveCategory::KeyEstablishment && profile.executionStrategy == ExecutionStrategyId::Ecdh, "ECDH compatibility mismatch"); break;
            case AlgorithmFamily::Xdh:
                require(profile.category == PrimitiveCategory::KeyEstablishment && profile.executionStrategy == ExecutionStrategyId::Xdh, "XDH compatibility mismatch"); break;
            case AlgorithmFamily::MlKem:
                require(profile.category == PrimitiveCategory::KeyEstablishment && profile.executionStrategy == ExecutionStrategyId::MlKem, "ML-KEM compatibility mismatch"); break;
            case AlgorithmFamily::AesGcm:
                require(profile.category == PrimitiveCategory::Aead && profile.executionStrategy == ExecutionStrategyId::Aead, "AES compatibility mismatch"); break;
            case AlgorithmFamily::ChaCha20Poly1305:
                require(profile.category == PrimitiveCategory::Aead && profile.executionStrategy == ExecutionStrategyId::Aead, "ChaCha compatibility mismatch"); break;
            case AlgorithmFamily::Sha2:
            case AlgorithmFamily::Sha3:
                require(profile.category == PrimitiveCategory::HashXof && profile.executionStrategy == ExecutionStrategyId::Digest, "digest compatibility mismatch"); break;
            case AlgorithmFamily::Shake:
                require(profile.category == PrimitiveCategory::HashXof && profile.executionStrategy == ExecutionStrategyId::Xof, "XOF compatibility mismatch"); break;
        }
    }
}

void testParameterVariants(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (profile.family == AlgorithmFamily::RsaPss) {
            require((isRsaKeyGen(profile.id) && std::holds_alternative<RsaKeyGenParameters>(profile.parameters)) ||
                    (isRsaDigest(profile.id) && std::holds_alternative<RsaPssParameters>(profile.parameters)), "RSA parameter variant mismatch");
        } else if (profile.family == AlgorithmFamily::Ecdsa) {
            require((isEcdsaKeyGen(profile.id) && std::holds_alternative<EcKeyGenParameters>(profile.parameters)) ||
                    (isEcdsaDigest(profile.id) && std::holds_alternative<EcdsaParameters>(profile.parameters)), "ECDSA parameter variant mismatch");
        } else {
            const bool correct =
                (profile.family == AlgorithmFamily::EdDsa && std::holds_alternative<EdDsaParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::MlDsa && std::holds_alternative<MlDsaParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::SlhDsa && std::holds_alternative<SlhDsaParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::Ecdh && std::holds_alternative<EcdhParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::Xdh && std::holds_alternative<XdhParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::MlKem && std::holds_alternative<MlKemParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::AesGcm && std::holds_alternative<AesGcmParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::ChaCha20Poly1305 && std::holds_alternative<ChaCha20Poly1305Parameters>(profile.parameters)) ||
                ((profile.family == AlgorithmFamily::Sha2 || profile.family == AlgorithmFamily::Sha3) && std::holds_alternative<DigestParameters>(profile.parameters)) ||
                (profile.family == AlgorithmFamily::Shake && std::holds_alternative<XofParameters>(profile.parameters));
            require(correct, "parameter variant mismatch");
        }
    }
}

void testStructuralVariantsAndOperations(Profiles profiles)
{
    std::array<std::size_t, 11> counts{};
    for (const auto& profile : profiles) {
        require(!profile.operations.empty(), "operation set is empty");
        if (profile.category == PrimitiveCategory::Signature) {
            require(std::holds_alternative<SignatureCharacteristics>(profile.characteristics), "signature structural variant mismatch");
        } else if (profile.category == PrimitiveCategory::KeyEstablishment) {
            require(std::holds_alternative<KeyEstablishmentCharacteristics>(profile.characteristics), "key-establishment structural variant mismatch");
        } else if (profile.category == PrimitiveCategory::Aead) {
            require(std::holds_alternative<AeadCharacteristics>(profile.characteristics), "AEAD structural variant mismatch");
        } else {
            require(std::holds_alternative<HashCharacteristics>(profile.characteristics), "hash structural variant mismatch");
        }
        switch (profile.family) {
            case AlgorithmFamily::RsaPss: ++counts[0]; requireOperations(profile, isRsaKeyGen(profile.id) ? std::initializer_list<BenchmarkOperation>{BenchmarkOperation::KeyGen} : std::initializer_list<BenchmarkOperation>{BenchmarkOperation::Sign, BenchmarkOperation::Verify}); break;
            case AlgorithmFamily::Ecdsa: ++counts[1]; requireOperations(profile, isEcdsaKeyGen(profile.id) ? std::initializer_list<BenchmarkOperation>{BenchmarkOperation::KeyGen} : std::initializer_list<BenchmarkOperation>{BenchmarkOperation::Sign, BenchmarkOperation::Verify}); break;
            case AlgorithmFamily::EdDsa: ++counts[2]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Sign, BenchmarkOperation::Verify}); break;
            case AlgorithmFamily::MlDsa: ++counts[3]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Sign, BenchmarkOperation::Verify}); break;
            case AlgorithmFamily::SlhDsa: ++counts[4]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Sign, BenchmarkOperation::Verify}); break;
            case AlgorithmFamily::Ecdh: ++counts[5]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Derive}); break;
            case AlgorithmFamily::Xdh: ++counts[6]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Derive}); break;
            case AlgorithmFamily::MlKem: ++counts[7]; requireOperations(profile, {BenchmarkOperation::KeyGen, BenchmarkOperation::Encapsulate, BenchmarkOperation::Decapsulate}); break;
            case AlgorithmFamily::AesGcm:
            case AlgorithmFamily::ChaCha20Poly1305: ++counts[8]; requireOperations(profile, {BenchmarkOperation::Encrypt, BenchmarkOperation::Decrypt}); break;
            case AlgorithmFamily::Sha2:
            case AlgorithmFamily::Sha3: ++counts[9]; requireOperations(profile, {BenchmarkOperation::Hash}); break;
            case AlgorithmFamily::Shake: ++counts[10]; requireOperations(profile, {BenchmarkOperation::Xof}); break;
        }
    }
    require(counts == std::array<std::size_t, 11>{12, 12, 2, 3, 12, 3, 2, 3, 4, 8, 11}, "canonical group counts mismatch");
}

void testCapabilities(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (profile.family == AlgorithmFamily::RsaPss || profile.family == AlgorithmFamily::Ecdsa) {
            if ((profile.family == AlgorithmFamily::RsaPss && isRsaKeyGen(profile.id)) || (profile.family == AlgorithmFamily::Ecdsa && isEcdsaKeyGen(profile.id))) {
                require(std::holds_alternative<NoWorkloadInput>(profile.inputCapability), "classical KeyGen capability mismatch");
            } else {
                require(std::holds_alternative<SignatureInputCapability>(profile.inputCapability), "classical signature capability type mismatch");
                require(std::get<SignatureInputCapability>(profile.inputCapability).support == SignatureInputSupport::PrehashedAndMessage, "classical signature capability value mismatch");
            }
        } else if (profile.category == PrimitiveCategory::Signature) {
            require(std::holds_alternative<SignatureInputCapability>(profile.inputCapability), "message-only signature capability variant missing");
            require(std::get<SignatureInputCapability>(profile.inputCapability).support == SignatureInputSupport::MessageOnly, "message-only capability mismatch");
        } else if (profile.category == PrimitiveCategory::KeyEstablishment) {
            require(std::holds_alternative<NoWorkloadInput>(profile.inputCapability), "key-establishment capability mismatch");
        } else if (profile.category == PrimitiveCategory::Aead) {
            require(std::holds_alternative<PlaintextSizeInput>(profile.inputCapability), "AEAD capability mismatch");
        } else if (profile.family == AlgorithmFamily::Sha2 || profile.family == AlgorithmFamily::Sha3 || profile.family == AlgorithmFamily::Shake) {
            require(std::holds_alternative<HashInputSizeInput>(profile.inputCapability), "hash capability mismatch");
        }
    }
}

void testSignatureCapabilities(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (isRsaDigest(profile.id) || isEcdsaDigest(profile.id)) {
            require(std::holds_alternative<SignatureInputCapability>(profile.inputCapability), "RSA/ECDSA signature capability variant missing");
            require(std::get<SignatureInputCapability>(profile.inputCapability).support == SignatureInputSupport::PrehashedAndMessage, "RSA/ECDSA input support mismatch");
        }
        if (profile.family == AlgorithmFamily::EdDsa || profile.family == AlgorithmFamily::MlDsa || profile.family == AlgorithmFamily::SlhDsa) {
            require(std::holds_alternative<SignatureInputCapability>(profile.inputCapability), "PQ signature capability variant missing");
            require(std::get<SignatureInputCapability>(profile.inputCapability).support == SignatureInputSupport::MessageOnly, "PQ signature input support mismatch");
        }
    }
}

void testAeadDigestXof(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (profile.category == PrimitiveCategory::Aead) {
            const auto& characteristics = std::get<AeadCharacteristics>(profile.characteristics);
            require(profile.executionStrategy == ExecutionStrategyId::Aead, "AEAD strategy mismatch");
            require(characteristics.nonceBytes == 12 && characteristics.aadBytes == 32 && characteristics.tagBytes == 16, "AEAD static fields mismatch");
        } else if (profile.family == AlgorithmFamily::Sha2 || profile.family == AlgorithmFamily::Sha3) {
            require(profile.executionStrategy == ExecutionStrategyId::Digest && std::holds_alternative<DigestParameters>(profile.parameters), "digest semantics mismatch");
        } else if (profile.family == AlgorithmFamily::Shake) {
            require(profile.executionStrategy == ExecutionStrategyId::Xof && std::holds_alternative<XofParameters>(profile.parameters), "XOF semantics mismatch");
            const auto output = std::get<XofParameters>(profile.parameters).outputBytes;
            require(output == std::get<HashCharacteristics>(profile.characteristics).outputBytes, "SHAKE output mismatch");
        }
    }
}

void testAesReferences(Profiles profiles)
{
    const std::array expected{std::pair{AlgorithmProfileId::Aes128Gcm, AesKeyBits::Bits128}, std::pair{AlgorithmProfileId::Aes192Gcm, AesKeyBits::Bits192}, std::pair{AlgorithmProfileId::Aes256Gcm, AesKeyBits::Bits256}};
    for (const auto [id, keyBits] : expected) {
        const auto* profile = AlgorithmRegistry::find(id);
        require(profile != nullptr, "AES profile missing");
        require(std::get<AesGcmParameters>(profile->parameters).keyBits == keyBits, "AES key bits mismatch");
        const auto& characteristics = std::get<AeadCharacteristics>(profile->characteristics);
        const auto expectedBytes = keyBits == AesKeyBits::Bits128 ? 16u : keyBits == AesKeyBits::Bits192 ? 24u : 32u;
        require(characteristics.keyBytes == expectedBytes && characteristics.nonceBytes == 12 && characteristics.aadBytes == 32 && characteristics.tagBytes == 16, "AES structural values mismatch");
    }
    static_cast<void>(profiles);
}

void testRsaReferences(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (profile.family != AlgorithmFamily::RsaPss) continue;
        RsaModulusBits modulus;
        if (isRsaKeyGen(profile.id)) modulus = std::get<RsaKeyGenParameters>(profile.parameters).modulusBits;
        else modulus = std::get<RsaPssParameters>(profile.parameters).modulusBits;
        const auto expectedBytes = modulus == RsaModulusBits::Bits2048 ? 256u : modulus == RsaModulusBits::Bits3072 ? 384u : 512u;
        const auto& characteristics = std::get<SignatureCharacteristics>(profile.characteristics);
        require(characteristics.publicKeyBytes == std::nullopt && characteristics.privateKeyBytes == std::nullopt, "RSA serialized key sizes were populated");
        require(characteristics.signatureSize.has_value(), "RSA signature size reference is missing");
        require(characteristics.signatureSize->bytes == expectedBytes && characteristics.signatureSize->kind == SignatureSizeReferenceKind::Fixed, "RSA signature reference mismatch");
    }
}

void testPostQuantumReferences(Profiles profiles)
{
    for (const auto& profile : profiles) {
        if (profile.family == AlgorithmFamily::MlKem) {
            const auto& p = std::get<MlKemParameters>(profile.parameters);
            const auto& c = std::get<KeyEstablishmentCharacteristics>(profile.characteristics);
            const auto expected = p.level == MlKemLevel::MlKem512 ? std::array{800u, 1632u, 768u, 32u} : p.level == MlKemLevel::MlKem768 ? std::array{1184u, 2400u, 1088u, 32u} : std::array{1568u, 3168u, 1568u, 32u};
            require(c.publicKeyBytes == expected[0] && c.privateKeyBytes == expected[1] && c.ciphertextBytes == expected[2] && c.sharedSecretBytes == expected[3], "ML-KEM reference mismatch");
        } else if (profile.family == AlgorithmFamily::MlDsa) {
            const auto& p = std::get<MlDsaParameters>(profile.parameters);
            const auto& c = std::get<SignatureCharacteristics>(profile.characteristics);
            const auto expected = p.level == MlDsaLevel::MlDsa44 ? std::array{1312u, 2560u, 2420u} : p.level == MlDsaLevel::MlDsa65 ? std::array{1952u, 4032u, 3309u} : std::array{2592u, 4896u, 4627u};
            require(c.signatureSize.has_value(), "ML-DSA signature size reference is missing");
            require(c.publicKeyBytes == expected[0] && c.privateKeyBytes == expected[1] && c.signatureSize->bytes == expected[2] && c.signatureSize->kind == SignatureSizeReferenceKind::Fixed, "ML-DSA reference mismatch");
        } else if (profile.family == AlgorithmFamily::SlhDsa) {
            const auto& p = std::get<SlhDsaParameters>(profile.parameters);
            const auto& c = std::get<SignatureCharacteristics>(profile.characteristics);
            const auto publicBytes = p.securityLevel == SlhSecurityLevel::Bits128 ? 32u : p.securityLevel == SlhSecurityLevel::Bits192 ? 48u : 64u;
            const auto privateBytes = p.securityLevel == SlhSecurityLevel::Bits128 ? 64u : p.securityLevel == SlhSecurityLevel::Bits192 ? 96u : 128u;
            const auto signatureBytes = p.securityLevel == SlhSecurityLevel::Bits128 ? (p.variant == SlhVariant::Small ? 7856u : 17088u) : p.securityLevel == SlhSecurityLevel::Bits192 ? (p.variant == SlhVariant::Small ? 16224u : 35664u) : (p.variant == SlhVariant::Small ? 29792u : 49856u);
            require(c.signatureSize.has_value(), "SLH-DSA signature size reference is missing");
            require(c.publicKeyBytes == publicBytes && c.privateKeyBytes == privateBytes && c.signatureSize->bytes == signatureBytes && c.signatureSize->kind == SignatureSizeReferenceKind::Fixed, "SLH-DSA reference mismatch");
        }
    }
}

void runTest(std::string_view name, void (*test)(Profiles), Profiles profiles, int& passed)
{
    test(profiles);
    ++passed;
    std::cout << "PASS " << name << '\n';
}

} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto profiles = AlgorithmRegistry::all();
        int passed = 0;
        runTest("canonical set and count", testCanonicalSet, profiles, passed);
        runTest("stable IDs and parsing", testStableIds, profiles, passed);
        runTest("display names and find", testDisplayNamesAndFind, profiles, passed);
        runTest("category family strategy", testCompatibility, profiles, passed);
        runTest("parameter variants", testParameterVariants, profiles, passed);
        runTest("structural variants and operations", testStructuralVariantsAndOperations, profiles, passed);
        runTest("input capabilities", testCapabilities, profiles, passed);
        runTest("signature capabilities", testSignatureCapabilities, profiles, passed);
        runTest("AEAD digest XOF semantics", testAeadDigestXof, profiles, passed);
        runTest("AES references", testAesReferences, profiles, passed);
        runTest("RSA references", testRsaReferences, profiles, passed);
        runTest("post-quantum references", testPostQuantumReferences, profiles, passed);
        passed += runValidatorTests();
        passed += runCoreExecutionContractTests();
        std::cout << "PASS total=" << passed << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
