#pragma once

#include <vector>

#include <QByteArray>

#include <cryptobench/core/BenchmarkConfig.h>

namespace cryptobench::application {

class BatchInputDocumentBuilder {
public:
    QByteArray build(const std::vector<core::BenchmarkConfig>& configs) const;
};

} // namespace cryptobench::application
