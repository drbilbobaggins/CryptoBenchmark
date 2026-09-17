#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace cryptobench::tests {
namespace {

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void testBuildMetadata()
{
    const auto info = application::collectEnvironmentInfo();

    require(!info.applicationVersion.empty(), "application version is empty");
    require(info.applicationVersion == application::build_info::applicationVersion,
            "application version does not come from generated BuildInfo");
    require(!info.gitCommit.empty(), "git commit is empty");
    require(info.gitCommit == application::build_info::gitCommit,
            "git commit does not come from generated BuildInfo");
    require(!info.opensslVersion.empty(), "OpenSSL version is empty");
    require(info.opensslVersion == application::build_info::opensslVersion,
            "OpenSSL version does not come from generated BuildInfo");
    require(!info.buildType.empty(), "build type is empty");
    require(info.buildType == application::build_info::buildType,
            "build type does not come from generated BuildInfo");
}

void testRuntimeMetadataAndTimestamp()
{
    const auto before = std::chrono::system_clock::now();
    const auto info = application::collectEnvironmentInfo();
    const auto after = std::chrono::system_clock::now();

    require(!info.operatingSystem.empty(), "operating system is empty");
    require(!info.architecture.empty(), "architecture is empty");
    require(before <= info.measuredAt && info.measuredAt <= after,
            "measuredAt is outside the collection interval");
}

void testRepeatedCollection()
{
    const auto first = application::collectEnvironmentInfo();
    const auto second = application::collectEnvironmentInfo();

    require(first.applicationVersion == second.applicationVersion,
            "application version changed between collections");
    require(first.gitCommit == second.gitCommit,
            "git commit changed between collections");
    require(first.opensslVersion == second.opensslVersion,
            "OpenSSL version changed between collections");
    require(first.buildType == second.buildType,
            "build type changed between collections");
    require(first.measuredAt <= second.measuredAt,
            "repeated collection timestamps moved backwards");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testBuildMetadata();
        std::cout << "PASS build metadata\n";
        cryptobench::tests::testRuntimeMetadataAndTimestamp();
        std::cout << "PASS runtime metadata and timestamp\n";
        cryptobench::tests::testRepeatedCollection();
        std::cout << "PASS repeated collection\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL EnvironmentInfo: " << error.what() << '\n';
        return 1;
    }
}
