#pragma once

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/WorkerRunMeasurement.h>
#include "MemoryV2SyntheticScenario.h"

#include <QJsonDocument>
#include <QString>

#include <cstdint>
#include <optional>
#include <vector>

namespace cryptobench::tests {

enum class QualificationSamplingMode {
    Periodic,
    BoundaryOnlyControl
};

enum class ProcessTerminationStatus {
    Exited,
    Running,
    Indeterminate
};

struct QualificationIdentity {
    QString campaignId = QStringLiteral("m19.1-foundation-smoke");
    QString caseId = QStringLiteral("default");
    QString repetitionId = QStringLiteral("0");
    std::uint32_t executionOrder = 0;
};

struct QualificationRun {
    std::uint32_t logicalRunIndex = 0;
    std::uint32_t workerPid = 0;
    core::WorkerRunMeasurement workerMeasurement{};
    core::MemoryV2RawObservations raw{};
    std::optional<core::MemoryV2DerivedMetrics> derived;
    bool workerMeasurementObserved = false;
    QString status = QStringLiteral("failed");
    QString error;
    bool normalExit = false;
    bool workerStarted = false;
    bool processFinishedObserved = false;
    std::uint32_t startEventOrdinal = 0;
    std::uint32_t finishEventOrdinal = 0;
    std::uint64_t processCreationTime100ns = 0;
    bool processCreationTimeObserved = false;
    ProcessTerminationStatus terminationStatus = ProcessTerminationStatus::Indeterminate;
    std::optional<std::uint64_t> observedPreparationLifetimeNanoseconds;
    std::optional<std::uint64_t> observedExecutionLifetimeNanoseconds;
};

QString syntheticWorkerPath();
core::BenchmarkConfig qualificationConfig();
QualificationRun runQualification(QualificationSamplingMode mode,
                                  const SyntheticScenario& scenario,
                                  std::uint32_t intervalMilliseconds,
                        const QualificationIdentity& identity = {});
ProcessTerminationStatus workerProcessTerminationStatus(std::uint32_t processId);
QJsonDocument makeQualificationArtifact(const QualificationRun& run,
                                        QualificationSamplingMode mode,
                                        const SyntheticScenario& scenario,
                                        std::uint32_t intervalMilliseconds,
                            const QualificationIdentity& identity = {});
void requireQualificationArtifact(const QJsonDocument& document);
void writeQualificationArtifact(const QString& path, const QJsonDocument& document);

struct QualificationCampaignMode {
    QualificationSamplingMode mode;
    std::uint32_t intervalMilliseconds;
};

struct QualificationCampaignCase {
    QString caseId;
    SyntheticScenario scenario;
};

struct QualificationCampaignManifest {
    QString campaignId;
    QString phase;
    std::uint64_t seed = 0;
    std::uint32_t repetitions = 0;
    std::vector<QualificationCampaignMode> modes;
    std::vector<QualificationCampaignCase> cases;
};

QualificationCampaignManifest defaultExploratoryPilotManifest();
QualificationCampaignManifest parseQualificationCampaignManifest(const QJsonDocument& document);
QualificationCampaignManifest parseQualificationCampaignManifest(const QString& encoded);
QJsonDocument encodeQualificationCampaignManifest(const QualificationCampaignManifest& manifest);
QJsonDocument runQualificationCampaign(const QualificationCampaignManifest& manifest,
                                       const QString& outputDirectory);
void verifyQualificationCampaign(const QString& outputDirectory);

} // namespace cryptobench::tests
