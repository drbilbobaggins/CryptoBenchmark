#pragma once

#include <span>

#include <cryptobench/core/Statistics.h>

namespace cryptobench::core {

class StatisticsCalculator {
public:
    static Statistics<double> calculate(std::span<const double> values);
};

} // namespace cryptobench::core
