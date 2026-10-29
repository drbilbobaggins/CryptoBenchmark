#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <QByteArray>
#include <QJsonObject>

#include <cryptobench/application/RuntimeCalibrationInventory.h>

namespace cryptobench::tests {

inline constexpr std::uint32_t kM23PilotMaximumObservationSeconds = 900;
inline constexpr std::uint32_t kM23PilotMaximumBatchEntries = 3;
inline constexpr std::uint64_t kM23PilotMaximumN = 100;
inline constexpr std::uint32_t kM23PilotMaximumM = 10;
inline constexpr std::uint64_t kM23PilotMaximumInitialInputBytes = 1'048'576;
inline constexpr std::uint64_t kM23PilotMinimumFreeDiskBytes =
    512ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kM23PilotMinimumAvailableMemoryBytes =
    512ULL * 1024ULL * 1024ULL;

enum class M23PilotRole {
    Reference,
    Holdout,
    Sensitivity,
    BatchShape
};

enum class M23PilotProbeKind {
    WorkloadSize,
    IterationScaling,
    RunCountSensitivity,
    SamplingSensitivity,
    BatchEntryCount
};

enum class M23PilotRiskClass {
    Low,
    Moderate,
    High
};

enum class M23PilotPlanStatus {
    Candidate,
    Deferred
};

struct M23PilotPlanRow {
    std::string rowId;
    cryptobench::application::RuntimeCalibrationCase calibrationCase;
    M23PilotRole role;
    M23PilotProbeKind probeKind;
    M23PilotPlanStatus status;
    std::optional<std::uint64_t> inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingIntervalMilliseconds;
    std::uint32_t repetition;
    std::uint32_t order;
    M23PilotRiskClass risk;
    std::string hypothesis;
    std::string deferredReason;
};

struct M23PilotBatchShape {
    std::string batchId;
    std::vector<cryptobench::application::RuntimeCalibrationCase> entries;
    std::uint64_t inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingIntervalMilliseconds;
    M23PilotPlanStatus status;
    M23PilotRiskClass risk;
    std::string hypothesis;
    std::string deferredReason;
};

struct M23PilotExecutionEntry {
    std::string rowId;
    cryptobench::application::RuntimeCalibrationCase calibrationCase;
    M23PilotRole role;
    M23PilotProbeKind probeKind;
    std::optional<std::uint64_t> inputBytes;
    std::uint64_t iterationsPerRun;
    std::uint32_t runs;
    std::uint32_t samplingIntervalMilliseconds;
    std::uint32_t repetition;
    std::uint32_t order;
};

struct M23PilotExecutionGroup {
    std::string groupId;
    bool batchShape = false;
    M23PilotRiskClass risk;
    std::string hypothesis;
    std::vector<M23PilotExecutionEntry> entries;
};

struct M23PilotApprovedPlan {
    std::string approvalReference;
    std::string approvedAtUtc;
    QByteArray approvalSha256;
};

std::vector<M23PilotPlanRow> m23PilotPlanRows();
std::vector<M23PilotBatchShape> m23PilotBatchShapes();
std::vector<std::string> m23PilotDeferredProbeIds();
QByteArray m23PilotPlanManifest();
QByteArray m23PilotPlanSha256();
QByteArray m23PilotDryRunReport();
std::optional<M23PilotExecutionGroup> m23PilotExecutionGroup(
    std::string_view groupId);
std::optional<M23PilotApprovedPlan> validateApprovedM23PilotPlan(
    const QJsonObject& document,
    bool allowSyntheticTestApproval = false);
QJsonObject syntheticApprovedM23PilotPlanForTests();

std::string toStableString(M23PilotRole role);
std::string toStableString(M23PilotProbeKind probeKind);
std::string toStableString(M23PilotRiskClass risk);
std::string toStableString(M23PilotPlanStatus status);

} // namespace cryptobench::tests
