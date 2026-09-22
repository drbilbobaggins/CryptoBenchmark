#pragma once

#include <cryptobench/application/ResultDocument.h>
#include <cryptobench/core/BenchmarkResult.h>

namespace cryptobench::application {

class SingleResultDocumentService {
public:
    ResultDocument create(const core::BenchmarkResult& result) const;
};

} // namespace cryptobench::application
