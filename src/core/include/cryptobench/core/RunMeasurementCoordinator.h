#pragma once

#include <cstdint>

#include <cryptobench/core/WorkerRunMeasurement.h>

namespace cryptobench::core {

class RunMeasurementCoordinator {
public:
    virtual ~RunMeasurementCoordinator() = default;

    virtual void beforeMeasurement(std::uint32_t runIndex) = 0;
    virtual void afterMeasurement(const WorkerRunMeasurement& measurement) = 0;
};

} // namespace cryptobench::core
