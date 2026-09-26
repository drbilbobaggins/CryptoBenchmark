#pragma once

#include <variant>
#include <vector>

#include <QByteArray>
#include <QJsonObject>

#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/application/StrictJsonPreflight.h>

namespace cryptobench::application {

// Schema-checked JSON entries and original numeric tokens; this is not a validated BatchDefinition.
struct BatchInputSchema {
    std::vector<QJsonObject> entries;
    std::vector<JsonNumberToken> numberTokens;
};

using BatchInputSchemaResult = std::variant<BatchInputSchema, std::vector<BatchInputIssue>>;

BatchInputSchemaResult decodeBatchInputSchema(const QByteArray& utf8Bytes);

} // namespace cryptobench::application
