#pragma once

#include <optional>
#include <vector>

#include <QString>

#include <cryptobench/application/BatchTypes.h>

namespace cryptobench::application {

struct BatchParseResult {
    std::optional<BatchDefinition> definition;
    std::vector<BatchInputIssue> issues;
};

class BatchInputParser {
public:
    BatchParseResult parseFile(const QString& filePath) const;
};

} // namespace cryptobench::application
