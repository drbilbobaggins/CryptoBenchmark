#pragma once

#include <memory>

#include <cryptobench/application/RuntimeCalibrationProvider.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>

namespace cryptobench::application {

// Pass the result of loadRuntimeCalibrationResource; unsupported load results
// produce a provider that reports typed unavailability instead of estimates.
std::unique_ptr<RuntimeCalibrationProvider> makePragmaticRuntimeCalibrationProvider(
    RuntimeCalibrationResourceLoadResult loadResult);

} // namespace cryptobench::application
