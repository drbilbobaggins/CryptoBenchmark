#include <cryptobench/application/EnvironmentInfoProvider.h>

#include <cryptobench/application/BuildInfo.h>

#include <QSysInfo>
#include <QString>

#include <chrono>
#include <string>

namespace cryptobench::application {
namespace {

std::string toUtf8(const QString& value)
{
    return value.toUtf8().toStdString();
}

std::string operatingSystem()
{
    QString value = QSysInfo::prettyProductName();
    if (value.isEmpty()) {
        value = QSysInfo::productType();
    }
    return value.isEmpty() ? "Unknown" : toUtf8(value);
}

std::string architecture()
{
    QString value = QSysInfo::currentCpuArchitecture();
    if (value.isEmpty()) {
        value = QSysInfo::buildCpuArchitecture();
    }
    return value.isEmpty() ? "Unknown" : toUtf8(value);
}

} // namespace

core::EnvironmentInfo collectEnvironmentInfo()
{
    return {
        std::string(build_info::applicationVersion),
        std::string(build_info::gitCommit),
        std::string(build_info::opensslVersion),
        operatingSystem(),
        architecture(),
        std::string(build_info::buildType),
        std::chrono::system_clock::now()
    };
}

} // namespace cryptobench::application
