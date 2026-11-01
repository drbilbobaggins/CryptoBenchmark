#include <cryptobench/application/RuntimeCalibrationResource.h>

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

namespace application = cryptobench::application;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

int verifyCandidate(const QStringList& arguments)
{
    require(arguments.size() == 11,
        "expected --candidate <file> --sha256 <hex> --os <name> "
        "--architecture <name> --openssl <version>");
    require(arguments[1] == QStringLiteral("--candidate")
            && arguments[3] == QStringLiteral("--sha256")
            && arguments[5] == QStringLiteral("--os")
            && arguments[7] == QStringLiteral("--architecture")
            && arguments[9] == QStringLiteral("--openssl"),
        "candidate parser arguments must use the exact named option order");

    const auto resourcePath = arguments[2];
    const auto expectedSha256 = arguments[4].toStdString();
    const application::RuntimeCalibrationEnvironment environment{
        "memory-v2-calibration-v1",
        arguments[6].toStdString(),
        arguments[8].toStdString(),
        "Release",
        arguments[10].toStdString()};

    const auto loaded = application::loadRuntimeCalibrationResource(
        resourcePath, expectedSha256, environment);
    require(loaded.status == application::RuntimeCalibrationResourceStatus::Loaded
            && loaded.resource.has_value()
            && loaded.resource->dialect
                == application::RuntimeCalibrationResourceDialect::M23Pragmatic
            && loaded.resource->qualificationStatus == "reducedScopeApproximate"
            && loaded.resource->records.size() == 175,
        "candidate did not load through the production resource parser");
    const auto constantCount = std::count_if(
        loaded.resource->records.begin(),
        loaded.resource->records.end(),
        [](const auto& record) {
            return record.modelKind
                == application::RuntimeCalibrationMeasuredModelKind::ConstantPerOperation;
        });
    const auto affineCount = std::count_if(
        loaded.resource->records.begin(),
        loaded.resource->records.end(),
        [](const auto& record) {
            return record.modelKind
                == application::RuntimeCalibrationMeasuredModelKind::AnchoredAffinePerOperation;
        });
    require(constantCount == 78 && affineCount == 97
            && loaded.resource->approximationPolicy.has_value()
            && loaded.resource->approximationPolicy->warmupOperationsPerLogicalRun == 1
            && loaded.resource->approximationPolicy->fixedEntryOverhead.nanoseconds == 0
            && loaded.resource->approximationPolicy->batchOverhead.nanoseconds == 0
            && loaded.resource->approximationPolicy->samplingAssumptions.size() == 4
            && loaded.resource->pragmaticProvenance.has_value()
            && loaded.resource->pragmaticProvenance->missingFields.size() == 7,
        "candidate parsed model counts/policy/provenance do not match pragmatic schema");

    auto wrongSha256 = std::string(64, '0');
    if (wrongSha256 == expectedSha256) {
        wrongSha256.assign(64, '1');
    }
    require(application::loadRuntimeCalibrationResource(
                resourcePath, wrongSha256, environment).status
            == application::RuntimeCalibrationResourceStatus::Corrupt,
        "candidate parser accepted a wrong expected SHA-256");

    auto incompatibleEnvironment = environment;
    incompatibleEnvironment.opensslVersion += "-incompatible-test";
    require(application::loadRuntimeCalibrationResource(
                resourcePath, expectedSha256, incompatibleEnvironment).status
            == application::RuntimeCalibrationResourceStatus::Inapplicable,
        "candidate parser did not distinguish an incompatible runtime context");

    std::cout << "PASS pragmatic candidate: Loaded / wrong SHA: Corrupt / "
                 "incompatible context: Inapplicable; no benchmark executed\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        return verifyCandidate(application.arguments());
    } catch (const std::exception& error) {
        std::cerr << "FAIL pragmatic candidate parser check: "
                  << error.what() << '\n';
        return 1;
    }
}
