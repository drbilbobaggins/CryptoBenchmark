#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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
    AffinePerIteration
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
};

struct RuntimeCalibrationResource {
    std::string datasetId;
    std::string datasetVersion;
    std::string qualificationStatus;
    std::vector<RuntimeCalibrationResourceRecord> records;
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
