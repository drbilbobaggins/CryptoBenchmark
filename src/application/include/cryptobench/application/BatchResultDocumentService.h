#pragma once

#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/application/ResultDocument.h>

namespace cryptobench::application {

class BatchResultDocumentService {
public:
    ResultDocument create(const BatchExecutionState& state) const;
};

} // namespace cryptobench::application