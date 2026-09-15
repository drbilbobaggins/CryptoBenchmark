#include <cryptobench/core/StatisticsCalculator.h>

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <vector>

namespace cryptobench::core {

Statistics<double> StatisticsCalculator::calculate(std::span<const double> values)
{
    if (values.empty()) {
        throw std::invalid_argument("StatisticsCalculator requires at least one value");
    }

    double sum = 0.0;
    double minimum = values.front();
    double maximum = values.front();
    for (const double value : values) {
        sum += value;
        minimum = std::min(minimum, value);
        maximum = std::max(maximum, value);
    }

    const double mean = sum / static_cast<double>(values.size());

    std::vector<double> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end());
    const auto middle = sorted.size() / 2;
    const double median = sorted.size() % 2 == 0
        ? (sorted[middle - 1] + sorted[middle]) / 2.0
        : sorted[middle];

    double squaredDifferenceSum = 0.0;
    for (const double value : values) {
        const double difference = value - mean;
        squaredDifferenceSum += difference * difference;
    }

    const double stddev = std::sqrt(squaredDifferenceSum / static_cast<double>(values.size()));
    return {mean, median, minimum, maximum, stddev};
}

} // namespace cryptobench::core
