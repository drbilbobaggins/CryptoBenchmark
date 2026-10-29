#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <QByteArray>
#include <QJsonObject>
#include <QString>

#include <cryptobench/application/RuntimeCalibrationInventory.h>

namespace cryptobench::tests {

enum class M23ObservationRole {
    Reference,
    Holdout
};

struct M23CalibrationPlanEntry {
    cryptobench::application::RuntimeCalibrationCase calibrationCase;
    M23ObservationRole role;
    std::optional<std::uint64_t> inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingIntervalMilliseconds;
    std::uint32_t repetition;
    std::uint32_t order;
};

struct M23ObservationRequest {
    cryptobench::application::RuntimeCalibrationCase calibrationCase;
    M23ObservationRole role;
    std::optional<std::uint64_t> inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingIntervalMilliseconds;
    std::uint32_t repetition;
    std::uint32_t order;
};

std::vector<M23CalibrationPlanEntry> m23CalibrationPlanEntries();
QByteArray m23CalibrationPlanManifest();
QByteArray m23CalibrationPlanSha256();
QJsonObject syntheticM23ObservationEvidence();
void validateM23ObservationEvidence(
    const QJsonObject& evidence,
    bool allowSyntheticTestFixture = false);
std::string m23ObservationIdentity(
    const M23ObservationRequest& request,
    std::string_view applicationSha256,
    std::string_view workerSha256,
    std::string_view environmentSha256);
int executeM23Observation(
    const M23ObservationRequest& request,
    const QString& outputDirectory);

} // namespace cryptobench::tests
