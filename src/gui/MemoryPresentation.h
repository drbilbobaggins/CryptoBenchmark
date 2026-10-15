#pragma once

#include <algorithm>
#include <cmath>

#include <QString>

#include <cryptobench/core/Statistics.h>

namespace cryptobench::gui {

struct MemoryDisplayUnit {
    QString suffix;
    double divisor;
};

inline MemoryDisplayUnit memoryDisplayUnit(const core::Statistics<double>& statistics)
{
    const double magnitude = std::max({
        std::abs(statistics.mean),
        std::abs(statistics.median),
        std::abs(statistics.min),
        std::abs(statistics.max),
        std::abs(statistics.stddev)
    });
    if (magnitude < 1'024.0) return {QStringLiteral("B"), 1.0};
    if (magnitude < 1'048'576.0) return {QStringLiteral("KiB"), 1'024.0};
    return {QStringLiteral("MiB"), 1'048'576.0};
}

inline QString formatMemoryStatistic(double value, const MemoryDisplayUnit& unit)
{
    QString formatted = QString::number(value / unit.divisor, 'f', 3);
    while (formatted.endsWith(QLatin1Char('0'))) formatted.chop(1);
    if (formatted.endsWith(QLatin1Char('.'))) formatted.chop(1);
    return formatted;
}

} // namespace cryptobench::gui
