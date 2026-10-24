#pragma once

#include <QJsonDocument>
#include <QString>
#include <QByteArray>

#include <cstdint>

namespace cryptobench::tests {

QJsonDocument prepareM19_3ConfirmatoryPlan(
    std::uint64_t seed,
    std::uint32_t repetitions,
    std::uint64_t sha256Iterations,
    std::uint64_t aes256GcmIterations,
    const QString& sha256CalibrationSha256,
    const QString& aes256GcmCalibrationSha256,
    const QJsonDocument& sha256CalibrationArtifact,
    const QJsonDocument& aes256GcmCalibrationArtifact,
    const QByteArray& sha256CalibrationSourceBytes,
    const QByteArray& aes256GcmCalibrationSourceBytes,
    const QString& workerExecutablePath,
    const QString& workerExecutableSha256,
    const QString& gitHead,
    const QString& buildType);

void validateM19_3ConfirmatoryPlan(const QJsonDocument& document);
std::uint32_t m19_3ConfirmatoryInternalInterval(std::uint32_t plannedIntervalMilliseconds);
void validateM19_3ConfirmatoryProvenance(
    const QJsonDocument& document,
    const QString& workerExecutablePath,
    const QString& workerExecutableSha256,
    const QString& gitHead,
    const QString& buildType);
void validateM19_3CalibrationArtifact(
    const QString& path,
    const QString& workload,
    const QString& workerExecutableSha256,
    const QString& gitHead,
    const QString& buildType);
void validateM19_3ConfirmatoryOutput(const QString& outputDirectory);

int executeM19_3Confirmatory(
    const QString& planPath,
    const QString& outputDirectory);

} // namespace cryptobench::tests
