#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <QString>

#include <cryptobench/application/RuntimeCalibrationInventory.h>

namespace cryptobench::application {

inline constexpr qsizetype kMaximumRuntimeCalibrationResourceBytes = 16 * 1024 * 1024;
inline constexpr std::string_view kRuntimeCalibrationResourceRelativePath =
    "calibration/runtime-calibration-v1.json";

enum class RuntimeCalibrationResourceStatus {
    Loaded,
    Missing,
    Corrupt,
    Inapplicable
};

struct RuntimeCalibrationEnvironment {
    std::string calibrationProtocolId;
    std::string operatingSystem;
    std::string architecture;
    std::string buildType;
    std::string opensslVersion;
};

enum class RuntimeCalibrationMeasuredModelKind {
    ExactReference,
    AffinePerIteration,
    ConstantPerOperation,
    AnchoredAffinePerOperation
};

enum class RuntimeCalibrationResourceDialect {
    M23_1Provisional,
    M23Pragmatic
};

enum class RuntimeCalibrationRecordEvidenceStatus {
    Unqualified,
    PerOperationReferenceFitOnly,
    PerOperationReferenceFitSizeHoldoutOnly
};

enum class RuntimeCalibrationAssumptionTag {
    AssumedUnmeasured,
    AssumedFrom5ms
};

struct RuntimeCalibrationConstantPerOperationModel {
    std::uint64_t picosecondsPerOperation;
};

struct RuntimeCalibrationAnchoredAffinePerOperationModel {
    std::uint64_t anchorInputBytes;
    std::uint64_t anchorPicosecondsPerOperation;
    std::uint64_t slopePicosecondsPerBytePerOperation;
};

using RuntimeCalibrationPragmaticMeasuredModel = std::variant<
    RuntimeCalibrationConstantPerOperationModel,
    RuntimeCalibrationAnchoredAffinePerOperationModel>;

struct RuntimeCalibrationOverheadAssumption {
    std::uint64_t nanoseconds;
    RuntimeCalibrationAssumptionTag tag;
};

struct RuntimeCalibrationSamplingAssumption {
    std::uint32_t requestedIntervalMilliseconds;
    std::uint32_t sourceMeasuredIntervalMilliseconds;
    RuntimeCalibrationAssumptionTag tag;
};

struct RuntimeCalibrationApproximationPolicy {
    std::uint32_t warmupOperationsPerLogicalRun;
    RuntimeCalibrationOverheadAssumption fixedEntryOverhead;
    RuntimeCalibrationOverheadAssumption batchOverhead;
    std::vector<RuntimeCalibrationSamplingAssumption> samplingAssumptions;
};

struct RuntimeCalibrationSourceEvidenceSha256 {
    std::string nightResult;
    std::string supplementalResult;
    std::string splitManifest;
};

enum class RuntimeCalibrationMissingProvenanceField {
    ReferenceWorkerSha256,
    ReferenceAppSha256,
    QtVersion,
    CompilerId,
    ReferenceCpu,
    ReferenceRamBytes,
    PowerPlan
};

enum class RuntimeCalibrationMissingProvenanceReason {
    NotRecordedInCampaignEvidence
};

struct RuntimeCalibrationMissingProvenance {
    RuntimeCalibrationMissingProvenanceField field;
    RuntimeCalibrationMissingProvenanceReason reason;
};

struct RuntimeCalibrationPragmaticProvenance {
    std::string generatedAtUtc;
    std::string calibrationProtocolId;
    std::string generatorVersion;
    std::string qualificationSummary;
    std::string sourceGitCommit;
    std::string referenceAppVersion;
    std::string referenceBuildType;
    std::optional<std::string> referenceWorkerSha256;
    std::optional<std::string> referenceAppSha256;
    std::string opensslVersion;
    std::optional<std::string> qtVersion;
    std::optional<std::string> compilerId;
    std::string operatingSystem;
    std::string architecture;
    std::optional<std::string> referenceCpu;
    std::optional<std::uint64_t> referenceRamBytes;
    std::optional<std::string> powerPlan;
    std::string registryInventorySha256;
    std::string campaignPlanSha256;
    std::string rawEvidenceManifestSha256;
    std::string holdoutReportSha256;
    RuntimeCalibrationSourceEvidenceSha256 sourceEvidenceSha256;
    std::vector<RuntimeCalibrationMissingProvenance> missingFields;
};

struct RuntimeCalibrationResourceRecord {
    RuntimeCalibrationCase calibrationCase;
    std::uint32_t samplingIntervalMilliseconds;
    RuntimeCalibrationMeasuredModelKind modelKind;
    std::uint64_t referenceIterations;
    std::uint64_t referenceMeasuredBlockNanoseconds;
    std::uint64_t interceptPicosecondsPerIteration;
    std::uint64_t slopePicosecondsPerBytePerIteration;
    std::optional<std::uint64_t> referenceInputBytes;
    std::optional<std::uint64_t> minimumInputBytes;
    std::optional<std::uint64_t> maximumInputBytes;
    std::optional<RuntimeCalibrationPragmaticMeasuredModel> pragmaticModel;
    RuntimeCalibrationRecordEvidenceStatus evidenceStatus =
        RuntimeCalibrationRecordEvidenceStatus::Unqualified;
};

struct RuntimeCalibrationResource {
    std::string datasetId;
    std::string datasetVersion;
    std::string qualificationStatus;
    std::vector<RuntimeCalibrationResourceRecord> records;
    RuntimeCalibrationResourceDialect dialect =
        RuntimeCalibrationResourceDialect::M23_1Provisional;
    std::optional<RuntimeCalibrationApproximationPolicy> approximationPolicy;
    std::optional<RuntimeCalibrationPragmaticProvenance> pragmaticProvenance;
};

struct RuntimeCalibrationResourceLoadResult {
    RuntimeCalibrationResourceStatus status;
    std::string diagnostic;
    std::optional<RuntimeCalibrationResource> resource;
};

QString runtimeCalibrationResourcePath(const QString& executablePath);
RuntimeCalibrationResourceLoadResult loadRuntimeCalibrationResource(
    const QString& resourcePath,
    std::string_view expectedSha256,
    const RuntimeCalibrationEnvironment& expectedEnvironment);

} // namespace cryptobench::application
