#pragma once

#include <optional>
#include <string_view>

#include <QJsonObject>

#include <cryptobench/core/BenchmarkConfig.h>

namespace cryptobench::application {

std::string_view toStableOperationString(core::BenchmarkOperation operation);
std::optional<core::BenchmarkOperation> parseStableOperationString(std::string_view text);
QJsonObject benchmarkConfigToJson(const core::BenchmarkConfig& config);

} // namespace cryptobench::application