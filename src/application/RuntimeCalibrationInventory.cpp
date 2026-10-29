#include <cryptobench/application/RuntimeCalibrationInventory.h>

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <tuple>

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/AlgorithmProfile.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/InputCapability.h>

namespace cryptobench::application {
namespace {

constexpr std::array kOperations{
    core::BenchmarkOperation::KeyGen,
    core::BenchmarkOperation::Sign,
    core::BenchmarkOperation::Verify,
    core::BenchmarkOperation::Derive,
    core::BenchmarkOperation::Encapsulate,
    core::BenchmarkOperation::Decapsulate,
    core::BenchmarkOperation::Encrypt,
    core::BenchmarkOperation::Decrypt,
    core::BenchmarkOperation::Hash,
    core::BenchmarkOperation::Xof
};

QString asQString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

bool caseLess(
    const RuntimeCalibrationCase& left,
    const RuntimeCalibrationCase& right)
{
    const auto leftKey = std::tuple{
        core::toStableProfileId(left.profileId),
        toStableOperationString(left.operation),
        toStableString(left.inputKind)};
    const auto rightKey = std::tuple{
        core::toStableProfileId(right.profileId),
        toStableOperationString(right.operation),
        toStableString(right.inputKind)};
    return leftKey < rightKey;
}

void addCase(
    RuntimeCalibrationInventory& inventory,
    const core::AlgorithmProfile& profile,
    core::BenchmarkOperation operation,
    RuntimeCalibrationInputKind inputKind,
    bool hasVariableInputSize)
{
    const auto duplicate = std::ranges::any_of(
        inventory.cases,
        [&](const RuntimeCalibrationCase& value) {
            return value.profileId == profile.id
                && value.operation == operation
                && value.inputKind == inputKind;
        });
    if (duplicate) {
        throw std::logic_error("AlgorithmRegistry produced a duplicate calibration identity");
    }

    inventory.cases.push_back(
        {profile.id, operation, inputKind, hasVariableInputSize});
}

void addLegalCases(
    RuntimeCalibrationInventory& inventory,
    const core::AlgorithmProfile& profile,
    core::BenchmarkOperation operation)
{
    switch (profile.category) {
    case core::PrimitiveCategory::Signature: {
        if (operation == core::BenchmarkOperation::KeyGen) {
            addCase(
                inventory,
                profile,
                operation,
                RuntimeCalibrationInputKind::NoSignature,
                false);
            return;
        }
        if (operation != core::BenchmarkOperation::Sign
            && operation != core::BenchmarkOperation::Verify) {
            throw std::logic_error("signature profile exposes an unsupported operation category");
        }
        const auto* capability =
            std::get_if<core::SignatureInputCapability>(&profile.inputCapability);
        if (capability == nullptr) {
            throw std::logic_error(
                "signature operation has a non-signature input capability");
        }
        if (capability->support == core::SignatureInputSupport::PrehashedAndMessage) {
            addCase(
                inventory,
                profile,
                operation,
                RuntimeCalibrationInputKind::Prehashed,
                false);
        }
        addCase(
            inventory,
            profile,
            operation,
            RuntimeCalibrationInputKind::Message,
            true);
        return;
    }
    case core::PrimitiveCategory::KeyEstablishment:
        if (!std::holds_alternative<core::NoWorkloadInput>(profile.inputCapability)) {
            throw std::logic_error("key-establishment profile has inconsistent registry metadata");
        }
        addCase(
            inventory,
            profile,
            operation,
            RuntimeCalibrationInputKind::KeyEstablishment,
            false);
        return;
    case core::PrimitiveCategory::Aead:
        if (!std::holds_alternative<core::PlaintextSizeInput>(profile.inputCapability)
            || (operation != core::BenchmarkOperation::Encrypt
                && operation != core::BenchmarkOperation::Decrypt)) {
            throw std::logic_error("AEAD profile has inconsistent registry metadata");
        }
        addCase(
            inventory,
            profile,
            operation,
            RuntimeCalibrationInputKind::Aead,
            true);
        return;
    case core::PrimitiveCategory::HashXof:
        if (!std::holds_alternative<core::HashInputSizeInput>(profile.inputCapability)
            || (operation != core::BenchmarkOperation::Hash
                && operation != core::BenchmarkOperation::Xof)) {
            throw std::logic_error("Hash/XOF profile has inconsistent registry metadata");
        }
        addCase(
            inventory,
            profile,
            operation,
            RuntimeCalibrationInputKind::HashXof,
            true);
        return;
    }

    throw std::logic_error("AlgorithmRegistry contains an unknown primitive category");
}

} // namespace

RuntimeCalibrationInventory enumerateRuntimeCalibrationInventory()
{
    RuntimeCalibrationInventory inventory;
    std::set<std::string> profileIds;

    for (const auto& profile : core::AlgorithmRegistry::all()) {
        const auto stableId = core::toStableProfileId(profile.id);
        if (stableId.empty() || !profileIds.emplace(stableId).second) {
            throw std::logic_error("AlgorithmRegistry contains an invalid or duplicate stable profile ID");
        }
        inventory.profileIds.emplace_back(stableId);

        bool hasOperation = false;
        for (const auto operation : kOperations) {
            if (!profile.operations.contains(operation)) {
                continue;
            }
            hasOperation = true;
            ++inventory.profileOperationCount;
            addLegalCases(inventory, profile, operation);
        }
        if (!hasOperation) {
            throw std::logic_error("AlgorithmRegistry profile has no supported operations");
        }
    }

    std::sort(inventory.profileIds.begin(), inventory.profileIds.end());
    std::sort(inventory.cases.begin(), inventory.cases.end(), caseLess);
    for (const auto& calibrationCase : inventory.cases) {
        if (calibrationCase.hasVariableInputSize) {
            ++inventory.variableInputCaseCount;
        } else {
            ++inventory.fixedInputCaseCount;
        }
    }
    return inventory;
}

std::string_view toStableString(RuntimeCalibrationInputKind inputKind)
{
    switch (inputKind) {
    case RuntimeCalibrationInputKind::NoSignature:
        return "noSignature";
    case RuntimeCalibrationInputKind::Prehashed:
        return "prehashed";
    case RuntimeCalibrationInputKind::Message:
        return "message";
    case RuntimeCalibrationInputKind::KeyEstablishment:
        return "keyEstablishment";
    case RuntimeCalibrationInputKind::Aead:
        return "aead";
    case RuntimeCalibrationInputKind::HashXof:
        return "hashXof";
    }
    throw std::invalid_argument("unknown runtime calibration input kind");
}

std::string runtimeCalibrationCaseId(const RuntimeCalibrationCase& calibrationCase)
{
    return std::string(core::toStableProfileId(calibrationCase.profileId))
        + "/" + std::string(toStableOperationString(calibrationCase.operation))
        + "/" + std::string(toStableString(calibrationCase.inputKind));
}

QByteArray runtimeCalibrationInventoryManifest(
    const RuntimeCalibrationInventory& inventory)
{
    QJsonArray profiles;
    for (const auto& profileId : inventory.profileIds) {
        const auto parsedId = core::parseStableProfileId(profileId);
        if (!parsedId) {
            throw std::invalid_argument("runtime calibration inventory contains an unknown profile ID");
        }
        const auto* profile = core::AlgorithmRegistry::find(*parsedId);
        if (profile == nullptr) {
            throw std::invalid_argument("runtime calibration inventory profile is absent from the registry");
        }
        QJsonArray operations;
        for (const auto operation : kOperations) {
            if (profile->operations.contains(operation)) {
                operations.append(asQString(toStableOperationString(operation)));
            }
        }
        profiles.append(QJsonObject{
            {"operations", operations},
            {"profileId", asQString(profileId)}});
    }

    QJsonArray cases;
    for (const auto& calibrationCase : inventory.cases) {
        cases.append(QJsonObject{
            {"hasVariableInputSize", calibrationCase.hasVariableInputSize},
            {"inputKind", asQString(toStableString(calibrationCase.inputKind))},
            {"operation", asQString(toStableOperationString(calibrationCase.operation))},
            {"profileId", asQString(core::toStableProfileId(calibrationCase.profileId))}});
    }

    const QJsonObject manifest{
        {"cases", cases},
        {"fixedInputCaseCount", static_cast<qint64>(inventory.fixedInputCaseCount)},
        {"format", QStringLiteral("cryptobenchmark-runtime-calibration-inventory")},
        {"profileOperationCount", static_cast<qint64>(inventory.profileOperationCount)},
        {"profiles", profiles},
        {"schemaVersion", 1},
        {"variableInputCaseCount", static_cast<qint64>(inventory.variableInputCaseCount)}};
    return QJsonDocument(manifest).toJson(QJsonDocument::Compact);
}

QByteArray runtimeCalibrationInventorySha256(
    const RuntimeCalibrationInventory& inventory)
{
    return QCryptographicHash::hash(
        runtimeCalibrationInventoryManifest(inventory),
        QCryptographicHash::Sha256).toHex();
}

} // namespace cryptobench::application
