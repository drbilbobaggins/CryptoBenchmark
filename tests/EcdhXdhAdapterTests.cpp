#include "adapters/EcdhAdapter.h"
#include "adapters/XdhAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::AdapterFactory;
using crypto::EcdhAdapter;
using crypto::XdhAdapter;
using core::AlgorithmProfileId;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::ConfigValidator;
using core::EcCurve;
using core::EcdhParameters;
using core::KeyEstablishmentConfig;
using core::ValidationResult;
using core::XdhParameters;
using core::XdhVariant;

struct EcdhCase {
    AlgorithmProfileId profile;
    EcCurve curve;
    std::size_t sharedSecretBytes;
};

struct XdhCase {
    AlgorithmProfileId profile;
    XdhVariant variant;
    std::size_t sharedSecretBytes;
};

constexpr std::array ecdhCases{
    EcdhCase{AlgorithmProfileId::EcdhP256, EcCurve::P256, 32},
    EcdhCase{AlgorithmProfileId::EcdhP384, EcCurve::P384, 48},
    EcdhCase{AlgorithmProfileId::EcdhP521, EcCurve::P521, 66}};

constexpr std::array xdhCases{
    XdhCase{AlgorithmProfileId::X25519, XdhVariant::X25519, 32},
    XdhCase{AlgorithmProfileId::X448, XdhVariant::X448, 56}};

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

const core::AlgorithmProfile& profileFor(AlgorithmProfileId profileId)
{
    const auto* profile = AlgorithmRegistry::find(profileId);
    require(profile != nullptr, "canonical key-establishment profile was not found");
    return *profile;
}

core::ValidatedBenchmarkConfig validateConfig(AlgorithmProfileId profile, BenchmarkOperation operation)
{
    const core::BenchmarkConfig config{profile, operation, 1, 1, KeyEstablishmentConfig{}};
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "key-establishment config validation failed");
    return std::move(*validated);
}

std::unique_ptr<core::AlgorithmAdapter> createAdapter(
    AlgorithmProfileId profile,
    BenchmarkOperation operation)
{
    auto validated = validateConfig(profile, operation);
    return AdapterFactory{}.create(profileFor(profile), operation, validated);
}

std::vector<unsigned char> deriveWithKeys(EVP_PKEY* ownKey, EVP_PKEY* peerKey, std::size_t expectedLength)
{
    require(ownKey != nullptr && peerKey != nullptr, "KeyGen did not produce usable key pointers");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_pkey(nullptr, ownKey, nullptr), &EVP_PKEY_CTX_free);
    require(context != nullptr, "could not create direct derive context");
    require(EVP_PKEY_derive_init(context.get()) == 1, "direct derive init failed");
    require(EVP_PKEY_derive_set_peer(context.get(), peerKey) == 1, "direct derive peer setup failed");

    std::vector<unsigned char> secret(expectedLength);
    std::size_t secretLength = secret.size();
    require(EVP_PKEY_derive(context.get(), secret.data(), &secretLength) == 1, "direct derive failed");
    require(secretLength == expectedLength, "direct derive length mismatch");
    return secret;
}

void testEcdhAgreementAndLengths()
{
    for (const auto& testCase : ecdhCases) {
        auto alice = std::make_unique<EcdhAdapter>(
            EcdhParameters{testCase.curve}, BenchmarkOperation::Derive,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        auto bob = std::make_unique<EcdhAdapter>(
            EcdhParameters{testCase.curve}, BenchmarkOperation::Derive,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        alice->prepareSeries();
        bob->prepareSeries();
        alice->setPeerKeyForTesting(bob->ownKeyForTesting());
        bob->setPeerKeyForTesting(alice->ownKeyForTesting());

        alice->executeIteration();
        bob->executeIteration();
        require(alice->sharedSecret().size() == testCase.sharedSecretBytes, "ECDH Alice length mismatch");
        require(bob->sharedSecret().size() == testCase.sharedSecretBytes, "ECDH Bob length mismatch");
        require(
            std::vector<unsigned char>(alice->sharedSecret().begin(), alice->sharedSecret().end()) ==
                std::vector<unsigned char>(bob->sharedSecret().begin(), bob->sharedSecret().end()),
            "ECDH Alice/Bob shared secrets differ");
    }
}

void testXdhAgreementAndLengths()
{
    for (const auto& testCase : xdhCases) {
        auto alice = std::make_unique<XdhAdapter>(
            XdhParameters{testCase.variant}, BenchmarkOperation::Derive,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        auto bob = std::make_unique<XdhAdapter>(
            XdhParameters{testCase.variant}, BenchmarkOperation::Derive,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        alice->prepareSeries();
        bob->prepareSeries();
        alice->setPeerKeyForTesting(bob->ownKeyForTesting());
        bob->setPeerKeyForTesting(alice->ownKeyForTesting());

        alice->executeIteration();
        bob->executeIteration();
        require(alice->sharedSecret().size() == testCase.sharedSecretBytes, "XDH Alice length mismatch");
        require(bob->sharedSecret().size() == testCase.sharedSecretBytes, "XDH Bob length mismatch");
        require(
            std::vector<unsigned char>(alice->sharedSecret().begin(), alice->sharedSecret().end()) ==
                std::vector<unsigned char>(bob->sharedSecret().begin(), bob->sharedSecret().end()),
            "XDH Alice/Bob shared secrets differ");
    }
}

void testKeyGenUsability()
{
    for (const auto& testCase : ecdhCases) {
        auto alice = std::make_unique<EcdhAdapter>(
            EcdhParameters{testCase.curve}, BenchmarkOperation::KeyGen,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        auto bob = std::make_unique<EcdhAdapter>(
            EcdhParameters{testCase.curve}, BenchmarkOperation::KeyGen,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        alice->prepareSeries();
        bob->prepareSeries();
        alice->executeIteration();
        bob->executeIteration();
        require(
            deriveWithKeys(alice->currentKeyForTesting(), bob->currentKeyForTesting(), testCase.sharedSecretBytes).size() ==
                testCase.sharedSecretBytes,
            "ECDH KeyGen output was not usable");
        EVP_PKEY* firstKey = alice->currentKeyForTesting();
        require(firstKey != nullptr, "first ECDH KeyGen key was null");
        require(EVP_PKEY_up_ref(firstKey) == 1, "could not retain first ECDH key");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstKeyReference(firstKey, &EVP_PKEY_free);
        alice->executeIteration();
        EVP_PKEY* secondKey = alice->currentKeyForTesting();
        require(secondKey != nullptr, "second ECDH KeyGen key was null");
        require(EVP_PKEY_eq(firstKeyReference.get(), secondKey) == 0, "repeated ECDH KeyGen reused the key");
        require(
            deriveWithKeys(secondKey, bob->currentKeyForTesting(), testCase.sharedSecretBytes).size() ==
                testCase.sharedSecretBytes,
            "second ECDH KeyGen output was not usable");
    }

    for (const auto& testCase : xdhCases) {
        auto alice = std::make_unique<XdhAdapter>(
            XdhParameters{testCase.variant}, BenchmarkOperation::KeyGen,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        auto bob = std::make_unique<XdhAdapter>(
            XdhParameters{testCase.variant}, BenchmarkOperation::KeyGen,
            static_cast<core::ByteCount>(testCase.sharedSecretBytes));
        alice->prepareSeries();
        bob->prepareSeries();
        alice->executeIteration();
        bob->executeIteration();
        require(
            deriveWithKeys(alice->currentKeyForTesting(), bob->currentKeyForTesting(), testCase.sharedSecretBytes).size() ==
                testCase.sharedSecretBytes,
            "XDH KeyGen output was not usable");
        EVP_PKEY* firstKey = alice->currentKeyForTesting();
        require(firstKey != nullptr, "first XDH KeyGen key was null");
        require(EVP_PKEY_up_ref(firstKey) == 1, "could not retain first XDH key");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> firstKeyReference(firstKey, &EVP_PKEY_free);
        alice->executeIteration();
        EVP_PKEY* secondKey = alice->currentKeyForTesting();
        require(secondKey != nullptr, "second XDH KeyGen key was null");
        require(EVP_PKEY_eq(firstKeyReference.get(), secondKey) == 0, "repeated XDH KeyGen reused the key");
        require(
            deriveWithKeys(secondKey, bob->currentKeyForTesting(), testCase.sharedSecretBytes).size() ==
                testCase.sharedSecretBytes,
            "second XDH KeyGen output was not usable");
    }
}

void testRepeatedDerive()
{
    auto ecdh = std::make_unique<EcdhAdapter>(EcdhParameters{EcCurve::P256}, BenchmarkOperation::Derive, 32);
    ecdh->prepareSeries();
    ecdh->executeIteration();
    const auto firstEcdh = std::vector<unsigned char>(ecdh->sharedSecret().begin(), ecdh->sharedSecret().end());
    ecdh->executeIteration();
    require(
        std::vector<unsigned char>(ecdh->sharedSecret().begin(), ecdh->sharedSecret().end()) == firstEcdh,
        "repeated ECDH Derive changed the prepared-key result");

    auto xdh = std::make_unique<XdhAdapter>(XdhParameters{XdhVariant::X25519}, BenchmarkOperation::Derive, 32);
    xdh->prepareSeries();
    xdh->executeIteration();
    const auto firstXdh = std::vector<unsigned char>(xdh->sharedSecret().begin(), xdh->sharedSecret().end());
    xdh->executeIteration();
    require(
        std::vector<unsigned char>(xdh->sharedSecret().begin(), xdh->sharedSecret().end()) == firstXdh,
        "repeated XDH Derive changed the prepared-key result");
}

void testFactoryCreatesAllCanonicalPairs()
{
    for (const auto& testCase : ecdhCases) {
        for (const auto operation : {BenchmarkOperation::KeyGen, BenchmarkOperation::Derive}) {
            auto adapter = createAdapter(testCase.profile, operation);
            require(adapter != nullptr, "factory did not create ECDH adapter");
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
    for (const auto& testCase : xdhCases) {
        for (const auto operation : {BenchmarkOperation::KeyGen, BenchmarkOperation::Derive}) {
            auto adapter = createAdapter(testCase.profile, operation);
            require(adapter != nullptr, "factory did not create XDH adapter");
            adapter->prepareSeries();
            adapter->executeIteration();
        }
    }
}

void testFactoryRejectsIncorrectParameterVariant()
{
    auto validated = validateConfig(AlgorithmProfileId::EcdhP256, BenchmarkOperation::KeyGen);
    auto mismatchedProfile = profileFor(AlgorithmProfileId::EcdhP256);
    mismatchedProfile.parameters = XdhParameters{XdhVariant::X25519};

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::KeyGen, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory accepted an incorrect ECDH parameter variant");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"ECDH agreement and lengths", &testEcdhAgreementAndLengths},
            std::pair{"XDH agreement and lengths", &testXdhAgreementAndLengths},
            std::pair{"KeyGen usability", &testKeyGenUsability},
            std::pair{"repeated Derive", &testRepeatedDerive},
            std::pair{"factory creates all ECDH/XDH pairs", &testFactoryCreatesAllCanonicalPairs},
            std::pair{"factory rejects incorrect parameter variant", &testFactoryRejectsIncorrectParameterVariant}};
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS ECDH/XDH adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
