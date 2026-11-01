#include "BatchRuntimeEstimatePresentation.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <variant>

#include <QStringList>

namespace cryptobench::gui {
namespace {

using cryptobench::application::RuntimeDuration;
using cryptobench::application::RuntimeDurationComponent;
using cryptobench::application::RuntimeEstimate;
using cryptobench::application::RuntimeEstimateUnavailableReason;

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000;
constexpr std::uint64_t kNanosecondsPerMinute = 60 * kNanosecondsPerSecond;
constexpr std::uint64_t kNanosecondsPerHour = 60 * kNanosecondsPerMinute;
constexpr std::uint64_t kNanosecondsPerDay = 24 * kNanosecondsPerHour;

QString pluralized(std::uint64_t count, const QString& singular, const QString& plural)
{
    return QStringLiteral("%1 %2").arg(static_cast<qulonglong>(count))
        .arg(count == 1 ? singular : plural);
}

std::uint64_t roundToNearest(std::uint64_t value, std::uint64_t unit)
{
    const auto quotient = value / unit;
    const auto remainder = value % unit;
    return quotient + (remainder >= unit / 2 ? 1 : 0);
}

bool hasReason(
    const RuntimeDurationComponent& component,
    RuntimeEstimateUnavailableReason reason)
{
    return std::holds_alternative<RuntimeEstimateUnavailableReason>(component)
        && std::get<RuntimeEstimateUnavailableReason>(component) == reason;
}

bool hasUnsafeComponent(const RuntimeEstimate& estimate)
{
    const auto isUnsafe = [](const RuntimeDurationComponent& component) {
        if (const auto* duration = std::get_if<RuntimeDuration>(&component)) {
            return duration->count() < 0;
        }
        const auto reason = std::get<RuntimeEstimateUnavailableReason>(component);
        return reason == RuntimeEstimateUnavailableReason::InvalidCalibrationData
            || reason == RuntimeEstimateUnavailableReason::ArithmeticOverflow;
    };

    if (isUnsafe(estimate.estimatedTotalBatchDuration)) {
        return true;
    }
    for (const auto& entry : estimate.perEntry) {
        if (isUnsafe(entry.estimatedMeasuredBlockDurationPerRun)
            || isUnsafe(entry.estimatedTotalEntryDuration)) {
            return true;
        }
    }
    return false;
}

bool allEntryCalibrationPointsMissing(const RuntimeEstimate& estimate)
{
    if (estimate.perEntry.empty()
        || estimate.missingTotalEntryCount != estimate.perEntry.size()
        || estimate.missingMeasuredBlockEntryCount != estimate.perEntry.size()) {
        return false;
    }
    for (const auto& entry : estimate.perEntry) {
        if (!hasReason(entry.estimatedMeasuredBlockDurationPerRun,
                       RuntimeEstimateUnavailableReason::CalibrationPointMissing)
            || !hasReason(entry.estimatedTotalEntryDuration,
                          RuntimeEstimateUnavailableReason::CalibrationPointMissing)) {
            return false;
        }
    }
    return true;
}

QString durationUnavailableText(const RuntimeEstimate& estimate)
{
    if (hasUnsafeComponent(estimate)) {
        return QStringLiteral(
            "Estimated total batch duration unavailable: the estimate cannot be calculated safely.");
    }

    if (const auto* reason = std::get_if<RuntimeEstimateUnavailableReason>(
            &estimate.estimatedTotalBatchDuration);
        reason != nullptr
        && *reason == RuntimeEstimateUnavailableReason::BatchOverheadUnavailable
        && estimate.missingTotalEntryCount == 0) {
        return QStringLiteral(
            "Estimated total batch duration unavailable: batch-level calibration overhead is missing.");
    }

    const auto missingCount = static_cast<qulonglong>(estimate.missingTotalEntryCount);
    const auto entryCount = static_cast<qulonglong>(estimate.perEntry.size());
    if (allEntryCalibrationPointsMissing(estimate)) {
        return QStringLiteral(
            "Estimated duration unavailable: calibration data is missing for %1 of %2 %3.")
            .arg(missingCount)
            .arg(entryCount)
            .arg(estimate.perEntry.size() == 1 ? QStringLiteral("entry") : QStringLiteral("entries"));
    }

    return QStringLiteral(
        "Estimated total batch duration unavailable: calibration data is incomplete for %1 of %2 %3.")
        .arg(missingCount)
        .arg(entryCount)
        .arg(estimate.perEntry.size() == 1 ? QStringLiteral("entry") : QStringLiteral("entries"));
}

QString shortRunWarning(const RuntimeEstimate& estimate)
{
    if (estimate.shortRunEntryIndices.empty()) {
        return {};
    }

    QStringList displayedIndices;
    constexpr std::size_t kDisplayedIndexLimit = 10;
    const auto displayedCount = std::min(
        estimate.shortRunEntryIndices.size(), kDisplayedIndexLimit);
    for (std::size_t index = 0; index < displayedCount; ++index) {
        displayedIndices.push_back(
            QString::number(static_cast<qulonglong>(estimate.shortRunEntryIndices[index])));
    }

    QString indices = displayedIndices.join(QStringLiteral(", "));
    if (estimate.shortRunEntryIndices.size() > kDisplayedIndexLimit) {
        const auto remaining = estimate.shortRunEntryIndices.size() - kDisplayedIndexLimit;
        indices += QStringLiteral(", plus %1 more").arg(static_cast<qulonglong>(remaining));
    }

    const auto itemWord = estimate.shortRunEntryIndices.size() == 1
        ? QStringLiteral("entry")
        : QStringLiteral("entries");
    return QStringLiteral(
        "The estimated measured cryptographic block duration per logical run is below 1 second for %1 %2.\n"
        "Shorter runs may be more sensitive to fixed overhead and system noise.")
        .arg(itemWord, indices);
}

} // namespace

QString formatRuntimeDuration(RuntimeDuration duration)
{
    if (duration.count() < 0) {
        throw std::invalid_argument("runtime duration must not be negative");
    }
    if (duration.count() == 0) {
        return QStringLiteral("0 seconds");
    }

    const auto nanoseconds = static_cast<std::uint64_t>(duration.count());
    if (nanoseconds < kNanosecondsPerSecond) {
        return QStringLiteral("less than 1 second");
    }
    if (nanoseconds < kNanosecondsPerMinute) {
        return pluralized(
            roundToNearest(nanoseconds, kNanosecondsPerSecond),
            QStringLiteral("second"),
            QStringLiteral("seconds"));
    }
    if (nanoseconds < kNanosecondsPerHour) {
        return pluralized(
            roundToNearest(nanoseconds, kNanosecondsPerMinute),
            QStringLiteral("minute"),
            QStringLiteral("minutes"));
    }
    if (nanoseconds < kNanosecondsPerDay) {
        const auto quarterHours = roundToNearest(nanoseconds, 15 * kNanosecondsPerMinute);
        const auto hours = quarterHours / 4;
        const auto minutes = (quarterHours % 4) * 15;
        QString result = pluralized(hours, QStringLiteral("hour"), QStringLiteral("hours"));
        if (minutes != 0) {
            result += QStringLiteral(" ") + pluralized(
                minutes, QStringLiteral("minute"), QStringLiteral("minutes"));
        }
        return result;
    }

    const auto roundedHours = roundToNearest(nanoseconds, kNanosecondsPerHour);
    const auto days = roundedHours / 24;
    const auto hours = roundedHours % 24;
    QString result = pluralized(days, QStringLiteral("day"), QStringLiteral("days"));
    if (hours != 0) {
        result += QStringLiteral(" ") + pluralized(
            hours, QStringLiteral("hour"), QStringLiteral("hours"));
    }
    return result;
}

QString batchRuntimeEstimateConfirmationText(const RuntimeEstimate& estimate)
{
    return batchRuntimeEstimateConfirmationText(
        estimate, BatchRuntimeEstimatePresentationMode::Standard);
}

QString batchRuntimeEstimateConfirmationText(
    const RuntimeEstimate& estimate,
    BatchRuntimeEstimatePresentationMode mode)
{
    QStringList paragraphs;
    if (const auto* duration = std::get_if<RuntimeDuration>(
            &estimate.estimatedTotalBatchDuration);
        duration != nullptr && duration->count() >= 0
        && estimate.availability == cryptobench::application::RuntimeEstimateAvailability::Available) {
        paragraphs.push_back(
            QStringLiteral("Estimated batch duration: approximately %1.")
                .arg(formatRuntimeDuration(*duration)));
        if (mode == BatchRuntimeEstimatePresentationMode::PragmaticReducedScope) {
            paragraphs.push_back(QStringLiteral(
                "This rough, approximate order-of-magnitude estimate is based on "
                "cryptographic-operation timings, not end-to-end Batch timing. It excludes "
                "worker startup, setup/preparation, IPC, checkpoint/persistence, and fixed "
                "per-entry and Batch overhead, so actual elapsed time may be longer, "
                "especially for many short runs. Source timings use 5 ms memory sampling; "
                "1–4 ms estimates assume comparable timing and were not measured separately. "
                "Actual timings may differ by machine."));
        }
    } else {
        paragraphs.push_back(durationUnavailableText(estimate));
    }

    if (estimate.missingMeasuredBlockEntryCount == estimate.perEntry.size()
        && !estimate.perEntry.empty()) {
        paragraphs.push_back(QStringLiteral("No measured-block duration estimates are available."));
    }
    const auto warning = shortRunWarning(estimate);
    if (!warning.isEmpty()) {
        paragraphs.push_back(warning);
    }
    paragraphs.push_back(QStringLiteral("Start the batch anyway?"));
    return paragraphs.join(QStringLiteral("\n\n"));
}

} // namespace cryptobench::gui
