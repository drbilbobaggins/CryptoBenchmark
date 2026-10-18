#pragma once

#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/WorkerRunMeasurement.h>

#include <QJsonDocument>
#include <QString>

#include <cstdint>
#include <optional>
#include <vector>

namespace cryptobench::tests {

enum class SamplingOverheadMode {
    BoundaryOnlyControl,
    Periodic
};

struct SamplingOverheadRun {
    SamplingOverheadMode mode = SamplingOverheadMode::BoundaryOnlyControl;
    std::uint32_t intervalMilliseconds = 5;
    std::uint32_t logicalRunIndex = 0;
    std::uint32_t executionOrder = 0;
    std::uint32_t workerPid = 0;
    std::optional<std::uint64_t> workerCreationTime100ns;
    std::optional<std::uint64_t> parentSessionWallNanoseconds;
    std::optional<std::uint64_t> parentSessionCpuNanoseconds;
    core::WorkerRunMeasurement workerMeasurement{};
    core::MemoryV2RawObservations memory{};
    bool workerMeasurementObserved = false;
    bool memoryObserved = false;
    bool normalExit = false;
    QString status = QStringLiteral("failed");
    QString error;
    QString workerExecutablePath;
    QString workerExecutableSha256;
    QString gitHead;
    bool gitDirty = false;
    QString buildType;
    QString operatingSystem;
    QString architecture;
    QString algorithmProfile = QStringLiteral("sha256");
    QString operation = QStringLiteral("hash");
    std::uint64_t inputBytes = 8;
    std::uint64_t iterationsPerRun = 0;
    std::uint32_t runs = 1;
    QString measurementWindowDefinition = QStringLiteral(
        "parent session: worker process start through verified normal exit; "
        "worker timing: canonical CPU-before/wall-start through wall-stop/CPU-after around N executeIteration calls");
};

SamplingOverheadRun runRealSamplingOverheadSmoke(
    SamplingOverheadMode mode,
    std::uint32_t intervalMilliseconds,
    std::uint64_t iterationsPerRun,
    std::uint32_t executionOrder = 0);

QJsonDocument samplingOverheadBatchArtifact(const std::vector<SamplingOverheadRun>& runs);
void validateSamplingOverheadBatchArtifact(const QJsonDocument& document);
bool eventDrivenWatchdogSelfTest(std::uint32_t deadlineMilliseconds);

QJsonDocument samplingOverheadRunArtifact(const SamplingOverheadRun& run);
void validateSamplingOverheadRunArtifact(const QJsonDocument& document);
void writeSamplingOverheadArtifact(const QString& destination, const QJsonDocument& document);
QJsonDocument readSamplingOverheadArtifact(const QString& source);

} // namespace cryptobench::tests
