#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <QByteArray>

#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::application {

enum class RuntimeCalibrationInputKind {
    NoSignature,
    Prehashed,
    Message,
    KeyEstablishment,
    Aead,
    HashXof
};

struct RuntimeCalibrationCase {
    core::AlgorithmProfileId profileId;
    core::BenchmarkOperation operation;
    RuntimeCalibrationInputKind inputKind;
    bool hasVariableInputSize;
};

struct RuntimeCalibrationInventory {
    std::vector<std::string> profileIds;
    std::vector<RuntimeCalibrationCase> cases;
    std::size_t profileOperationCount = 0;
    std::size_t fixedInputCaseCount = 0;
    std::size_t variableInputCaseCount = 0;
};

RuntimeCalibrationInventory enumerateRuntimeCalibrationInventory();
std::string_view toStableString(RuntimeCalibrationInputKind inputKind);
std::string runtimeCalibrationCaseId(const RuntimeCalibrationCase& calibrationCase);
QByteArray runtimeCalibrationInventoryManifest(
    const RuntimeCalibrationInventory& inventory);
QByteArray runtimeCalibrationInventorySha256(
    const RuntimeCalibrationInventory& inventory);

} // namespace cryptobench::application
