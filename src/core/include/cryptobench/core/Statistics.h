#pragma once

namespace cryptobench::core {

template <typename T>
struct Statistics {
    T mean;
    T median;
    T min;
    T max;
    T stddev;
};

} // namespace cryptobench::core
