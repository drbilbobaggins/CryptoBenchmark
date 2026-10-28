#pragma once

#include <QString>

#include <cryptobench/application/RuntimeEstimate.h>

namespace cryptobench::gui {

QString formatRuntimeDuration(cryptobench::application::RuntimeDuration duration);
QString batchRuntimeEstimateConfirmationText(
    const cryptobench::application::RuntimeEstimate& estimate);

} // namespace cryptobench::gui
