#pragma once

namespace cryptobench::core {

class AlgorithmAdapter {
public:
    virtual ~AlgorithmAdapter() = default;

    virtual void prepareSeries() = 0;
    virtual void prepareRun() {}
    virtual void executeIteration() = 0;
};

} // namespace cryptobench::core
