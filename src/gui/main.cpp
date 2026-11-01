#include <QApplication>
#include <QCoreApplication>
#include <QDebug>

#include "MainWindow.h"

#include <utility>

#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/application/PragmaticRuntimeCalibrationProvider.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    const auto environment = cryptobench::application::collectEnvironmentInfo();
    const cryptobench::application::RuntimeCalibrationEnvironment
        expectedEnvironment{
            "memory-v2-calibration-v1",
            environment.operatingSystem,
            environment.architecture,
            environment.buildType,
            environment.opensslVersion};
    const auto resourcePath =
        cryptobench::application::runtimeCalibrationResourcePath(
            QCoreApplication::applicationFilePath());
    auto loadResult = cryptobench::application::loadRuntimeCalibrationResource(
        resourcePath,
        cryptobench::application::build_info::runtimeCalibrationResourceSha256,
        expectedEnvironment);
    if (loadResult.status
        != cryptobench::application::RuntimeCalibrationResourceStatus::Loaded) {
        qWarning().noquote()
            << "Pragmatic Batch ETA resource is unavailable:"
            << QString::fromStdString(loadResult.diagnostic);
    }
    auto provider =
        cryptobench::application::makePragmaticRuntimeCalibrationProvider(
            std::move(loadResult));
    MainWindow window(
        std::move(provider),
        cryptobench::gui::BatchRuntimeEstimatePresentationMode::PragmaticReducedScope);
    window.show();
    return app.exec();
}
