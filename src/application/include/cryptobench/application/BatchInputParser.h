#pragma once

#include <optional>
#include <vector>

#include <QByteArray>
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
    BatchParseResult parseData(const QByteArray& bytes) const;

private:
    BatchParseResult parsePreparedData(const QByteArray& bytes) const;
};

} // namespace cryptobench::application
