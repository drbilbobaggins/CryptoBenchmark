#include <cryptobench/core/StatisticsCalculator.h>

#include <array>
#include <cmath>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace cryptobench::tests {
namespace {

using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireNear(double actual, double expected, std::string_view message)
{
    require(std::abs(actual - expected) <= 1e-12, message);
}

void requireStatistics(
    const Statistics<double>& actual,
    double mean,
    double median,
    double minimum,
    double maximum,
    double stddev)
{
    requireNear(actual.mean, mean, "mean mismatch");
    requireNear(actual.median, median, "median mismatch");
    requireNear(actual.min, minimum, "minimum mismatch");
    requireNear(actual.max, maximum, "maximum mismatch");
    requireNear(actual.stddev, stddev, "standard deviation mismatch");
}

void testOddDataset()
{
    const std::array values{1.0, 2.0, 3.0, 4.0, 5.0};
    const auto statistics = StatisticsCalculator::calculate(values);
    requireStatistics(statistics, 3.0, 3.0, 1.0, 5.0, std::sqrt(2.0));
}

void testEvenMedian()
{
    const std::array values{1.0, 4.0, 2.0, 9.0};
    const auto statistics = StatisticsCalculator::calculate(values);
    requireNear(statistics.median, 3.0, "even median mismatch");
}

void testUnsortedInputIsNotMutated()
{
    const std::array values{5.0, 1.0, 4.0, 2.0, 3.0};
    const auto original = values;
    const auto statistics = StatisticsCalculator::calculate(values);
    requireStatistics(statistics, 3.0, 3.0, 1.0, 5.0, std::sqrt(2.0));
    require(values == original, "statistics calculation mutated input");
}

void testSingleValue()
{
    const std::array values{42.5};
    const auto statistics = StatisticsCalculator::calculate(values);
    requireStatistics(statistics, 42.5, 42.5, 42.5, 42.5, 0.0);
}

void testEmptyInputRejected()
{
    bool rejected = false;
    try {
        static_cast<void>(StatisticsCalculator::calculate(std::span<const double>{}));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "empty statistics input was accepted");
}

} // namespace

int runStatisticsTests()
{
    const auto tests = std::array{
        std::pair{"odd dataset", &testOddDataset},
        std::pair{"even median", &testEvenMedian},
        std::pair{"unsorted input and non-mutation", &testUnsortedInputIsNotMutated},
        std::pair{"single value", &testSingleValue},
        std::pair{"empty input rejection", &testEmptyInputRejected}
    };

    for (const auto& [name, test] : tests) {
        test();
        std::cout << "PASS " << name << '\n';
    }
    std::cout << "PASS statistics total=" << tests.size() << '\n';
    return static_cast<int>(tests.size());
}

} // namespace cryptobench::tests
