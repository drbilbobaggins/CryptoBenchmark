#pragma once

#include <string_view>

#include <QJsonObject>

#include <cryptobench/core/BenchmarkConfig.h>

namespace cryptobench::application {

std::string_view toStableOperationString(core::BenchmarkOperation operation);
QJsonObject benchmarkConfigToJson(const core::BenchmarkConfig& config);

} // namespace cryptobench::application