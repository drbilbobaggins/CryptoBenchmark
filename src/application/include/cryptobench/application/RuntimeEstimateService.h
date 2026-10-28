#pragma once

#include <cryptobench/application/RuntimeEstimate.h>

namespace cryptobench::application {

class RuntimeEstimateService {
public:
    RuntimeEstimate estimate(
        const BatchDefinition& definition,
        const core::MeasurementSettings& settings,
        const RuntimeCalibrationProvider& provider) const;
};

} // namespace cryptobench::application
