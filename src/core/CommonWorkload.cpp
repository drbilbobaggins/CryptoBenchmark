#include <cryptobench/core/CommonWorkload.h>

#include <array>
#include <limits>
#include <stdexcept>
#include <variant>

namespace cryptobench::core {
namespace {

std::size_t checkedSize(WorkloadBytes bytes)
{
    if (bytes > static_cast<WorkloadBytes>(std::numeric_limits<std::size_t>::max())) {
        throw std::length_error("common workload does not fit in size_t");
    }
    return static_cast<std::size_t>(bytes);
}

CommonWorkload patternedWorkload(WorkloadBytes size)
{
    const auto count = checkedSize(size);
    std::vector<unsigned char> bytes(count);
    constexpr std::array pattern{'a', 'b', 'c'};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<unsigned char>(pattern[index % pattern.size()]);
    }
    return CommonWorkload(std::move(bytes));
}

CommonWorkload plaintextWorkload(WorkloadBytes size)
{
    const auto count = checkedSize(size);
    std::vector<unsigned char> bytes(count);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<unsigned char>(index & 0xffU);
    }
    return CommonWorkload(std::move(bytes));
}

std::size_t digestSize(SignatureDigest digest)
{
    switch (digest) {
    case SignatureDigest::Sha256: return 32;
    case SignatureDigest::Sha384: return 48;
    case SignatureDigest::Sha512: return 64;
    }
    throw std::logic_error("unknown signature digest");
}

SignatureDigest prehashedDigest(const AlgorithmProfile& profile)
{
    if (const auto* parameters = std::get_if<RsaPssParameters>(&profile.parameters)) {
        return parameters->digest;
    }
    if (const auto* parameters = std::get_if<EcdsaParameters>(&profile.parameters)) {
        return parameters->digest;
    }
    throw std::logic_error("prehashed workload requires RSA-PSS or ECDSA parameters");
}

} // namespace

CommonWorkload buildCommonWorkload(
    const ValidatedBenchmarkConfig& config,
    const AlgorithmProfile& profile)
{
    const auto& validated = config.value();
    if (profile.id != validated.profile) {
        throw std::logic_error("common workload profile does not match validated configuration");
    }

    switch (profile.category) {
    case PrimitiveCategory::Signature: {
        const auto* signature = std::get_if<SignatureConfig>(&validated.parameters);
        if (signature == nullptr) {
            throw std::logic_error("signature workload requires SignatureConfig");
        }
        if (validated.operation == BenchmarkOperation::KeyGen ||
            std::holds_alternative<NoSignatureInput>(signature->input)) {
            return {};
        }
        if (const auto* message = std::get_if<MessageInput>(&signature->input)) {
            return patternedWorkload(message->messageSize);
        }
        if (std::holds_alternative<PrehashedInput>(signature->input)) {
            return CommonWorkload(std::vector<unsigned char>(digestSize(prehashedDigest(profile)), 0xA5U));
        }
        throw std::logic_error("unknown signature input mode");
    }
    case PrimitiveCategory::KeyEstablishment:
        if (!std::holds_alternative<KeyEstablishmentConfig>(validated.parameters)) {
            throw std::logic_error("key-establishment workload requires KeyEstablishmentConfig");
        }
        return {};
    case PrimitiveCategory::Aead: {
        const auto* aead = std::get_if<AeadConfig>(&validated.parameters);
        if (aead == nullptr) {
            throw std::logic_error("AEAD workload requires AeadConfig");
        }
        return plaintextWorkload(aead->plaintextSize);
    }
    case PrimitiveCategory::HashXof: {
        const auto* hash = std::get_if<HashConfig>(&validated.parameters);
        if (hash == nullptr) {
            throw std::logic_error("hash/XOF workload requires HashConfig");
        }
        return patternedWorkload(hash->inputSize);
    }
    }
    throw std::logic_error("unknown primitive category");
}

} // namespace cryptobench::core
