#pragma once

#include <string_view>

#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/InputCapability.h>
#include <cryptobench/core/ProfileParameters.h>
#include <cryptobench/core/StructuralCharacteristics.h>
#include <cryptobench/core/SupportedOperations.h>

namespace cryptobench::core {

struct AlgorithmProfile {
    AlgorithmProfileId id;
    PrimitiveCategory category;
    AlgorithmFamily family;
    std::string_view displayName;
    SupportedOperations operations;
    ExecutionStrategyId executionStrategy;
    ProfileParameters parameters;
    InputCapability inputCapability;
    StructuralCharacteristics characteristics;
};

} // namespace cryptobench::core
