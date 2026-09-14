#pragma once

#include <cstdint>
#include <variant>

#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::core {

struct NoSignatureInput {};
struct PrehashedInput {};

struct MessageInput {
    WorkloadBytes messageSize;
};

struct SignatureConfig {
    std::variant<
        NoSignatureInput,
        PrehashedInput,
        MessageInput
    > input;
};

struct KeyEstablishmentConfig {};

struct AeadConfig {
    WorkloadBytes plaintextSize;
};

struct HashConfig {
    WorkloadBytes inputSize;
};

using PrimitiveConfig = std::variant<
    SignatureConfig,
    KeyEstablishmentConfig,
    AeadConfig,
    HashConfig
>;

struct BenchmarkConfig {
    AlgorithmProfileId profile;
    BenchmarkOperation operation;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    PrimitiveConfig parameters;
};

} // namespace cryptobench::core
