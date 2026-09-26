#pragma once

#include <string_view>
#include <variant>
#include <vector>

#include <QJsonObject>

#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/application/StrictJsonPreflight.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/DomainTypes.h>

namespace cryptobench::application {

using BatchPrimitiveParametersResult =
    std::variant<core::PrimitiveConfig, std::vector<BatchInputIssue>>;

BatchPrimitiveParametersResult decodeBatchPrimitiveParameters(
    core::PrimitiveCategory category,
    const QJsonObject& parameters,
    std::string_view parametersPath,
    const std::vector<JsonNumberToken>& numberTokens);

} // namespace cryptobench::application