#pragma once

#include <cryptobench/core/ProgressInfo.h>

namespace cryptobench::core {

class ProgressSink {
public:
    virtual ~ProgressSink() = default;

    virtual void reportProgress(const ProgressInfo& info) = 0;
};

} // namespace cryptobench::core
