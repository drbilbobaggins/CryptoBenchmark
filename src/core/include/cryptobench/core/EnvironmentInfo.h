#pragma once

#include <chrono>
#include <string>

namespace cryptobench::core {

struct EnvironmentInfo {
    std::string applicationVersion;
    std::string gitCommit;
    std::string opensslVersion;
    std::string operatingSystem;
    std::string architecture;
    std::string buildType;
    std::chrono::system_clock::time_point measuredAt;
};

} // namespace cryptobench::core
