#pragma once

#include <QString>

#include <cryptobench/application/RuntimeEstimate.h>

namespace cryptobench::gui {

enum class BatchRuntimeEstimatePresentationMode {
    Standard,
    PragmaticReducedScope
};

QString formatRuntimeDuration(cryptobench::application::RuntimeDuration duration);
QString batchRuntimeEstimateConfirmationText(
    const cryptobench::application::RuntimeEstimate& estimate);
QString batchRuntimeEstimateConfirmationText(
    const cryptobench::application::RuntimeEstimate& estimate,
    BatchRuntimeEstimatePresentationMode mode);

} // namespace cryptobench::gui
