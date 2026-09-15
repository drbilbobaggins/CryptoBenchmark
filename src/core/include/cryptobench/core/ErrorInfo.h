#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace cryptobench::core {

enum class ErrorCode {
    InvalidConfiguration,
    UnknownExecutionStrategy,
    CryptoInitializationFailed,
    CryptoOperationFailed,
    MemoryMeasurementFailed,
    WorkerStartupFailed,
    WorkerCommunicationFailed,
    InternalError
};

enum class FailureStage {
    WorkerStartup,
    ConfigDeserialization,
    ConfigValidation,
    TaskCreation,
    SeriesPreparation,
    RunPreparation,
    Warmup,
    Measurement,
    MemoryMeasurement,
    WorkerCommunication,
    ResultAssembly
};

struct ErrorInfo {
    ErrorCode code;
    FailureStage stage;
    std::optional<std::uint32_t> runIndex;
    std::string technicalMessage;
    std::optional<std::string> libraryDetails;
};

} // namespace cryptobench::core
