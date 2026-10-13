#pragma once

#include <string_view>

#include <QJsonObject>

#include <cryptobench/core/BenchmarkStatistics.h>
#include <cryptobench/core/EnvironmentInfo.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/StructuralCharacteristics.h>

namespace cryptobench::application {

std::string_view toStableString(core::SignatureSizeReferenceKind kind);
std::string_view toStableString(core::ErrorCode code);
std::string_view toStableString(core::FailureStage stage);

QJsonObject structuralCharacteristicsToJson(const core::StructuralCharacteristics& characteristics);
QJsonObject environmentInfoToJson(const core::EnvironmentInfo& environment);
QJsonObject resultMeasurementMetadataToJson(const core::MeasurementSettings& settings);
QJsonObject benchmarkStatisticsToJson(const core::BenchmarkStatistics& statistics);
QJsonObject errorInfoToJson(const core::ErrorInfo& error);

} // namespace cryptobench::application