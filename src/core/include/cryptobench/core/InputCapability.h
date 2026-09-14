#pragma once

#include <variant>

namespace cryptobench::core {

struct NoWorkloadInput {};

enum class SignatureInputSupport {
    PrehashedAndMessage,
    MessageOnly
};

struct SignatureInputCapability {
    SignatureInputSupport support;
};

struct PlaintextSizeInput {};
struct HashInputSizeInput {};

using InputCapability = std::variant<
    NoWorkloadInput,
    SignatureInputCapability,
    PlaintextSizeInput,
    HashInputSizeInput
>;

} // namespace cryptobench::core
