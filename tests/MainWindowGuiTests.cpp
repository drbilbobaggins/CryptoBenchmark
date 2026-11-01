#include "../src/gui/MainWindow.h"
#include "../src/gui/BatchCreatorWidget.h"
#include "../src/gui/BatchRuntimeEstimatePresentation.h"
#include "../src/gui/CreatorRowWidget.h"
#include "../src/gui/MemoryPresentation.h"

#include <QApplication>
#include <QComboBox>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QGroupBox>
#include <QHeaderView>
#include <QKeyEvent>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QTemporaryDir>

#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/BuildInfo.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/application/PragmaticRuntimeCalibrationProvider.h>
#include <cryptobench/application/RuntimeCalibrationResource.h>

#include <cstdlib>
#include <array>
#include <charconv>
#include <cstddef>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace cryptobench;
using application::RuntimeDuration;

namespace {

constexpr std::string_view kExpectedCsvHeader =
    "document.format,document.schemaVersion,document.mode,document.status,measurement.memorySamplingIntervalMilliseconds,measurement.memoryModel,measurement.workerLifecycle,entry.entryIndex,entry.id,entry.status,config.profileId,config.operation,config.iterationsPerRun,config.runs,config.parameters.inputMode,config.parameters.messageSizeBytes,config.parameters.plaintextSizeBytes,config.parameters.inputSizeBytes,structuralCharacteristics.type,structuralCharacteristics.publicKeyBytes,structuralCharacteristics.privateKeyBytes,structuralCharacteristics.signatureSizeBytes,structuralCharacteristics.signatureSizeKind,structuralCharacteristics.sharedSecretBytes,structuralCharacteristics.ciphertextBytes,structuralCharacteristics.keyBytes,structuralCharacteristics.nonceBytes,structuralCharacteristics.aadBytes,structuralCharacteristics.tagBytes,structuralCharacteristics.outputBytes,environment.applicationVersion,environment.gitCommit,environment.opensslVersion,environment.operatingSystem,environment.architecture,environment.buildType,environment.measuredAt,statistics.wallClockNanosecondsPerOperation.mean,statistics.wallClockNanosecondsPerOperation.median,statistics.wallClockNanosecondsPerOperation.min,statistics.wallClockNanosecondsPerOperation.max,statistics.wallClockNanosecondsPerOperation.stddev,statistics.processCpuNanosecondsPerOperation.mean,statistics.processCpuNanosecondsPerOperation.median,statistics.processCpuNanosecondsPerOperation.min,statistics.processCpuNanosecondsPerOperation.max,statistics.processCpuNanosecondsPerOperation.stddev,statistics.memory.unit,statistics.memory.readyStateDeltaBytes.mean,statistics.memory.readyStateDeltaBytes.median,statistics.memory.readyStateDeltaBytes.min,statistics.memory.readyStateDeltaBytes.max,statistics.memory.readyStateDeltaBytes.stddev,statistics.memory.preparationPeakDeltaBytes.mean,statistics.memory.preparationPeakDeltaBytes.median,statistics.memory.preparationPeakDeltaBytes.min,statistics.memory.preparationPeakDeltaBytes.max,statistics.memory.preparationPeakDeltaBytes.stddev,statistics.memory.executionPeakDeltaBytes.mean,statistics.memory.executionPeakDeltaBytes.median,statistics.memory.executionPeakDeltaBytes.min,statistics.memory.executionPeakDeltaBytes.max,statistics.memory.executionPeakDeltaBytes.stddev,statistics.memory.operationalPeakDeltaBytes.mean,statistics.memory.operationalPeakDeltaBytes.median,statistics.memory.operationalPeakDeltaBytes.min,statistics.memory.operationalPeakDeltaBytes.max,statistics.memory.operationalPeakDeltaBytes.stddev,error.code,error.stage,error.runIndex,error.technicalMessage,error.libraryDetails,batchError.code,batchError.stage,batchError.entryIndex,batchError.technicalMessage";

using CsvRecord = std::vector<std::string>;
using CsvRecords = std::vector<CsvRecord>;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

template <typename Widget>
Widget* widget(MainWindow& window, const char* name)
{
    auto* result = window.findChild<Widget*>(QString::fromLatin1(name));
    require(result != nullptr, std::string("missing widget: ") + name);
    return result;
}

template <typename Widget, typename Value>
void selectData(Widget* comboBox, Value value)
{
    const int index = comboBox->findData(static_cast<int>(value));
    require(index >= 0, "requested combo-box item was not found");
    comboBox->setCurrentIndex(index);
}

void waitUntil(const std::function<bool()>& condition, int timeoutMilliseconds)
{
    QEventLoop loop;
    QTimer timeout;
    QTimer probe;
    timeout.setSingleShot(true);
    probe.setInterval(10);

    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(&probe, &QTimer::timeout, &loop, [&] {
        if (condition()) loop.quit();
    });

    if (condition()) return;
    timeout.start(timeoutMilliseconds);
    probe.start();
    loop.exec();
    probe.stop();
    require(condition(), "GUI test timed out waiting for a condition");
}

void setScenario(const char* scenario)
{
    require(qputenv("CRYPTOBENCH_TEST_WORKER_SCENARIO", scenario),
            "failed to set scripted-worker scenario");
}

void clearScenario()
{
    qunsetenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
}

QString status(MainWindow& window)
{
    return widget<QLabel>(window, "statusLabel")->text();
}

void allowBatchExecution(MainWindow::DialogCallbacks& callbacks)
{
    callbacks.confirmBatchExecution = [](
        QWidget*,
        const application::RuntimeEstimate&) {
        return true;
    };
}

void configureHash(MainWindow& window)
{
    auto* category = widget<QComboBox>(window, "categoryComboBox");
    auto* profile = widget<QComboBox>(window, "profileComboBox");
    auto* operation = widget<QComboBox>(window, "operationComboBox");
    selectData(category, core::PrimitiveCategory::HashXof);
    selectData(profile, core::AlgorithmProfileId::Sha256);
    selectData(operation, core::BenchmarkOperation::Hash);
    widget<QSpinBox>(window, "workloadSizeSpinBox")->setValue(8);
    widget<QSpinBox>(window, "iterationsSpinBox")->setValue(2);
    widget<QSpinBox>(window, "runsSpinBox")->setValue(2);
}

gui::BatchCreatorWidget* creatorWidget(MainWindow& window)
{
    auto* creatorObject = window.findChild<QWidget*>(QStringLiteral("batchCreatorWidget"));
    require(creatorObject != nullptr, "Creator widget was not found");
    return static_cast<gui::BatchCreatorWidget*>(creatorObject);
}

void configureCreatorHash(gui::CreatorRowWidget* row, int inputSize, int iterations, int runs)
{
    selectData(row->categoryComboBox(), core::PrimitiveCategory::HashXof);
    selectData(row->profileComboBox(), core::AlgorithmProfileId::Sha256);
    selectData(row->operationComboBox(), core::BenchmarkOperation::Hash);
    row->workloadSizeSpinBox()->setValue(inputSize);
    row->iterationsSpinBox()->setValue(iterations);
    row->runsSpinBox()->setValue(runs);
}

struct RuntimeCalibrationFixture {
    application::CalibrationLookupResult entryEstimate{
        application::RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        application::RuntimeEstimateUnavailableReason::CalibrationPointMissing,
        application::RuntimeEstimateUnavailableReason::CalibrationPointMissing};
    application::RuntimeDurationComponent batchOverhead{
        application::RuntimeEstimateUnavailableReason::BatchOverheadUnavailable};
    std::vector<application::RuntimeCalibrationRequest> requests;
};

class FixtureRuntimeCalibrationProvider final
    : public application::RuntimeCalibrationProvider {
public:
    explicit FixtureRuntimeCalibrationProvider(
        std::shared_ptr<RuntimeCalibrationFixture> fixture)
        : fixture_(std::move(fixture))
    {
    }

    application::CalibrationLookupResult estimateEntry(
        application::RuntimeCalibrationRequest request) const override
    {
        fixture_->requests.push_back(std::move(request));
        return fixture_->entryEstimate;
    }

    application::RuntimeDurationComponent estimateBatchOverhead(
        const application::BatchDefinition&,
        core::MeasurementSettings) const override
    {
        return fixture_->batchOverhead;
    }

private:
    std::shared_ptr<RuntimeCalibrationFixture> fixture_;
};

std::unique_ptr<application::RuntimeCalibrationProvider>
makeInstalledPragmaticProvider()
{
    const auto executable = QFileInfo(QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("../bin/CryptoBenchmark.exe"))).absoluteFilePath();
    require(QFileInfo::exists(executable),
        "production application executable is missing from build-*/bin");
    const auto environment = application::collectEnvironmentInfo();
    const application::RuntimeCalibrationEnvironment expectedEnvironment{
        "memory-v2-calibration-v1",
        environment.operatingSystem,
        environment.architecture,
        environment.buildType,
        environment.opensslVersion};
    auto loadResult = application::loadRuntimeCalibrationResource(
        application::runtimeCalibrationResourcePath(executable),
        application::build_info::runtimeCalibrationResourceSha256,
        expectedEnvironment);
    if (environment.buildType == "Release") {
        require(loadResult.status == application::RuntimeCalibrationResourceStatus::Loaded,
            "approved pragmatic resource did not load in Release GUI test");
    } else if (environment.buildType == "Debug") {
        require(loadResult.status
                == application::RuntimeCalibrationResourceStatus::Inapplicable,
            "Release pragmatic resource was not inapplicable in Debug GUI test");
    } else {
        throw std::runtime_error("GUI resource test requires a Debug or Release build");
    }
    return application::makePragmaticRuntimeCalibrationProvider(
        std::move(loadResult));
}

application::RuntimeEstimate makeRuntimeEstimate(
    std::vector<application::EntryRuntimeEstimate> entries,
    application::RuntimeDurationComponent batchDuration,
    application::RuntimeEstimateAvailability availability,
    std::size_t missingMeasured,
    std::size_t missingTotal,
    std::vector<std::uint32_t> shortIndices = {})
{
    return {
        std::move(entries),
        std::move(batchDuration),
        availability,
        missingMeasured,
        missingTotal,
        std::move(shortIndices)};
}

bool sameDurationComponent(
    const application::RuntimeDurationComponent& left,
    const application::RuntimeDurationComponent& right)
{
    if (left.index() != right.index()) return false;
    if (const auto* duration = std::get_if<application::RuntimeDuration>(&left)) {
        return duration->count() == std::get<application::RuntimeDuration>(right).count();
    }
    return std::get<application::RuntimeEstimateUnavailableReason>(left)
        == std::get<application::RuntimeEstimateUnavailableReason>(right);
}

void requireEstimatesEquivalent(
    const application::RuntimeEstimate& left,
    const application::RuntimeEstimate& right)
{
    require(left.availability == right.availability
                && left.missingMeasuredBlockEntryCount == right.missingMeasuredBlockEntryCount
                && left.missingTotalEntryCount == right.missingTotalEntryCount
                && left.shortRunEntryIndices == right.shortRunEntryIndices
                && left.perEntry.size() == right.perEntry.size()
                && sameDurationComponent(
                    left.estimatedTotalBatchDuration, right.estimatedTotalBatchDuration),
            "runtime estimates differed semantically");
    for (std::size_t index = 0; index < left.perEntry.size(); ++index) {
        require(left.perEntry[index].entryIndex == right.perEntry[index].entryIndex
                    && sameDurationComponent(
                        left.perEntry[index].estimatedMeasuredBlockDurationPerRun,
                        right.perEntry[index].estimatedMeasuredBlockDurationPerRun)
                    && sameDurationComponent(
                        left.perEntry[index].estimatedTotalEntryDuration,
                        right.perEntry[index].estimatedTotalEntryDuration),
                "per-entry runtime estimates differed semantically");
    }
}

void configureSignatureAndKeyEstablishmentTransitions(MainWindow& window)
{
    auto* category = widget<QComboBox>(window, "categoryComboBox");
    auto* profile = widget<QComboBox>(window, "profileComboBox");
    auto* operation = widget<QComboBox>(window, "operationComboBox");
    auto* size = widget<QSpinBox>(window, "workloadSizeSpinBox");
    auto* mode = widget<QComboBox>(window, "signatureInputModeComboBox");

    selectData(category, core::PrimitiveCategory::KeyEstablishment);
    selectData(profile, core::AlgorithmProfileId::X25519);
    selectData(operation, core::BenchmarkOperation::Derive);
    require(!size->isVisible() && !size->isEnabled(),
            "key-establishment workload size remained available");

    selectData(category, core::PrimitiveCategory::Signature);
    selectData(profile, core::AlgorithmProfileId::RsaPss2048Sha256);
    selectData(operation, core::BenchmarkOperation::Sign);
    require(mode->findText(QStringLiteral("Prehashed")) >= 0 &&
                mode->findText(QStringLiteral("Message")) >= 0,
            "RSA-PSS did not expose both signature input modes");
    mode->setCurrentText(QStringLiteral("Prehashed"));
    require(!size->isVisible() && !size->isEnabled(),
            "prehashed signature still exposed workload size");
    mode->setCurrentText(QStringLiteral("Message"));
    require(size->isVisible() && size->isEnabled(),
            "message signature did not expose workload size");

    selectData(profile, core::AlgorithmProfileId::Ed25519);
    require(mode->count() == 1 && mode->currentText() == QStringLiteral("Message"),
            "MessageOnly signature exposed an invalid input mode");
}

void testIdleAndConfiguration()
{
    MainWindow window;
    window.show();
    auto* category = widget<QComboBox>(window, "categoryComboBox");
    auto* profile = widget<QComboBox>(window, "profileComboBox");
    auto* operation = widget<QComboBox>(window, "operationComboBox");
    require(category->count() > 0 && profile->count() > 0 && operation->count() > 0,
            "initial selectors were not populated");
    configureHash(window);
    auto* workloadLabel = widget<QLabel>(window, "workloadSizeLabel");
    auto* workloadSize = widget<QSpinBox>(window, "workloadSizeSpinBox");
    require(workloadLabel->isVisible() && workloadLabel->text() == QStringLiteral("Input size:"),
        "Hash/XOF input-size control was not presented correctly");
    require(workloadSize->isVisible() && workloadSize->isEnabled() && workloadSize->minimum() == 0,
        "Hash/XOF input-size spin box did not allow zero input");
    workloadSize->setValue(0);
    require(widget<QPushButton>(window, "runButton")->isEnabled(),
            "Run was not enabled for a valid zero-byte Hash configuration");
    require(!widget<QPushButton>(window, "cancelButton")->isEnabled(),
            "Cancel was enabled while idle");
    require(!widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "Export JSON was enabled before a Completed result");
    require(!widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Export CSV was enabled before a Completed result");
    require(!widget<QPushButton>(window, "batchExportCsvButton")->isEnabled(),
            "Batch Export CSV was enabled before a terminal Batch result");
    auto* recommendation = widget<QLabel>(window, "runDurationRecommendationLabel");
    require(recommendation->isVisible() && recommendation->text() == QStringLiteral(
                "Recommendation: aim for at least ~1 second of measured cryptographic work per run. Shorter runs may be more sensitive to fixed overhead and system noise."),
            "fixed run-duration recommendation was not presented exactly");
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    require(sampling->count() == 5 && sampling->isEnabled(),
            "global measurement selector did not expose the required idle defaults");
    for (int index = 0; index < 5; ++index) {
        require(sampling->itemText(index) == QStringLiteral("%1 ms").arg(index + 1) &&
                    sampling->itemData(index).toUInt() == static_cast<uint>(index + 1),
                "global measurement selector values were not ordered 1 ms through 5 ms");
    }
    require(sampling->currentText() == QStringLiteral("5 ms") &&
                sampling->currentData().toUInt() == 5,
            "global measurement selector did not default to 5 ms");
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0,
            "initial results table was not empty");
    require(widget<QTableWidget>(window, "memoryPhaseBreakdownTable")->rowCount() == 0 &&
                !widget<QGroupBox>(window, "memoryPhaseBreakdownGroupBox")->isVisible(),
            "initial Memory phase breakdown was not empty and hidden");

    const core::Statistics<double> negativeReady{-2048.0, -2048.0, -4096.0, -1024.0, 512.0};
    const auto negativeUnit = gui::memoryDisplayUnit(negativeReady);
    require(negativeUnit.suffix == QStringLiteral("KiB") &&
                gui::formatMemoryStatistic(-2048.0, negativeUnit) == QStringLiteral("-2"),
            "negative ReadyState formatting lost its sign or selected the wrong unit");
    const core::Statistics<double> largeNegativeReady{-1'048'576.0, -1'048'576.0,
                                                       -2'097'152.0, -524'288.0, 0.0};
    const auto largeNegativeUnit = gui::memoryDisplayUnit(largeNegativeReady);
    require(largeNegativeUnit.suffix == QStringLiteral("MiB") &&
                gui::formatMemoryStatistic(-1'048'576.0, largeNegativeUnit) == QStringLiteral("-1"),
            "large negative ReadyState formatting did not use magnitude-based units");

    configureSignatureAndKeyEstablishmentTransitions(window);
    configureHash(window);
    workloadSize->setValue(8);
    auto* iterations = widget<QSpinBox>(window, "iterationsSpinBox");
    auto* runs = widget<QSpinBox>(window, "runsSpinBox");
    iterations->setValue(500'000'000);
    runs->setValue(3);
    require(!widget<QPushButton>(window, "runButton")->isEnabled(),
            "invalid N*M budget left Run enabled");
    iterations->setValue(1'000);
    require(widget<QPushButton>(window, "runButton")->isEnabled(),
            "restoring a valid N*M budget did not re-enable Run");
}

void waitForCompleted(MainWindow& window)
{
    waitUntil([&] { return status(window) == QStringLiteral("Completed"); }, 20'000);
}

void requireStatisticRow(QTableWidget* table, int row, const QString& label)
{
    require(table->item(row, 0) != nullptr && table->item(row, 0)->text() == label,
            "Memory result row label was not canonical");
    for (int column = 1; column < 6; ++column) {
        const auto text = table->item(row, column) == nullptr
            ? QString{}
            : table->item(row, column)->text();
        require(!text.isEmpty() &&
                    (text.endsWith(QStringLiteral(" B")) ||
                     text.endsWith(QStringLiteral(" KiB")) ||
                     text.endsWith(QStringLiteral(" MiB")) ||
                     text.endsWith(QStringLiteral(" ns")) ||
                     text.endsWith(QStringLiteral(" µs")) ||
                     text.endsWith(QStringLiteral(" ms"))),
                "Memory result row is missing a statistic cell");
    }
}

void requireMemoryV2Presentation(MainWindow& window)
{
    auto* table = widget<QTableWidget>(window, "resultsTable");
    require(status(window) == QStringLiteral("Completed"),
            "Memory v2 completion did not report Completed");
    require(!widget<QLabel>(window, "resultsPlaceholderLabel")->isVisible(),
            "Completed Memory v2 result left the placeholder visible");
    require(table->rowCount() == 4, "Completed Memory v2 result did not populate four primary rows");
    requireStatisticRow(table, 0, QStringLiteral("Wall-clock / operation"));
    requireStatisticRow(table, 1, QStringLiteral("Process CPU time / operation"));
    requireStatisticRow(table, 2, QStringLiteral("Operational peak PrivateUsage delta"));
    requireStatisticRow(table, 3, QStringLiteral("Ready-state PrivateUsage delta"));
    for (int row = 0; row < table->rowCount(); ++row) {
        require(!table->item(row, 0)->text().startsWith(QStringLiteral("Peak PrivateUsage delta")),
                "Completed Memory v2 result retained the legacy peak row");
    }

    auto* breakdownGroup = widget<QGroupBox>(window, "memoryPhaseBreakdownGroupBox");
    auto* breakdown = widget<QTableWidget>(window, "memoryPhaseBreakdownTable");
    require(breakdownGroup->isVisible() && breakdown->rowCount() == 2,
            "Memory phase breakdown was not displayed with two rows");
    requireStatisticRow(breakdown, 0, QStringLiteral("Preparation peak PrivateUsage delta"));
    requireStatisticRow(breakdown, 1, QStringLiteral("Execution peak PrivateUsage delta"));
    require(table->horizontalScrollBarPolicy() == Qt::ScrollBarAsNeeded &&
                breakdown->horizontalScrollBarPolicy() == Qt::ScrollBarAsNeeded &&
                !table->horizontalHeader()->stretchLastSection() &&
                !breakdown->horizontalHeader()->stretchLastSection(),
            "Memory result tables did not retain content-sized scrolling behavior");
}

void requireStatisticGroup(const QJsonObject& group, const char* name)
{
    require(group.contains(QStringLiteral("mean")) &&
                group.contains(QStringLiteral("median")) &&
                group.contains(QStringLiteral("min")) &&
                group.contains(QStringLiteral("max")) &&
                group.contains(QStringLiteral("stddev")),
            std::string("missing statistic member in ") + name);
    require(group.value(QStringLiteral("mean")).isDouble() &&
                group.value(QStringLiteral("median")).isDouble() &&
                group.value(QStringLiteral("min")).isDouble() &&
                group.value(QStringLiteral("max")).isDouble() &&
                group.value(QStringLiteral("stddev")).isDouble(),
            std::string("non-numeric statistic member in ") + name);
}

void requireMemoryV2Export(const QJsonObject& root, int expectedInterval = 5)
{
    require(root.value(QStringLiteral("format")) == QStringLiteral("cryptobenchmark-result") &&
                root.value(QStringLiteral("schemaVersion")) == 2 &&
                root.value(QStringLiteral("mode")) == QStringLiteral("single") &&
                root.value(QStringLiteral("status")) == QStringLiteral("completed"),
            "GUI export had incorrect canonical document metadata");

    const auto measurement = root.value(QStringLiteral("measurement")).toObject();
    require(measurement.value(QStringLiteral("memorySamplingIntervalMilliseconds")) == expectedInterval &&
                measurement.value(QStringLiteral("memoryModel")) == QStringLiteral("memoryV2") &&
                measurement.value(QStringLiteral("workerLifecycle")) ==
                    QStringLiteral("freshWorkerPerLogicalRun"),
            "GUI export had incorrect measurement metadata");

    const auto entries = root.value(QStringLiteral("entries")).toArray();
    require(entries.size() == 1 &&
                entries.at(0).toObject().value(QStringLiteral("status")) ==
                    QStringLiteral("completed"),
            "GUI export did not contain exactly one Completed entry");

    const auto statistics = entries.at(0).toObject().value(QStringLiteral("statistics")).toObject();
    const auto wallClock = statistics.value(QStringLiteral("wallClockNanosecondsPerOperation")).toObject();
    const auto processCpu = statistics.value(QStringLiteral("processCpuNanosecondsPerOperation")).toObject();
    const auto memory = statistics.value(QStringLiteral("memory")).toObject();
    requireStatisticGroup(wallClock, "wallClockNanosecondsPerOperation");
    requireStatisticGroup(processCpu, "processCpuNanosecondsPerOperation");
    require(memory.value(QStringLiteral("unit")) == QStringLiteral("bytes") &&
                memory.contains(QStringLiteral("readyStateDelta")) &&
                memory.contains(QStringLiteral("preparationPeakDelta")) &&
                memory.contains(QStringLiteral("executionPeakDelta")) &&
                memory.contains(QStringLiteral("operationalPeakDelta")),
            "GUI export had incomplete Memory v2 statistics");
    requireStatisticGroup(memory.value(QStringLiteral("readyStateDelta")).toObject(), "readyStateDelta");
    requireStatisticGroup(memory.value(QStringLiteral("preparationPeakDelta")).toObject(),
                          "preparationPeakDelta");
    requireStatisticGroup(memory.value(QStringLiteral("executionPeakDelta")).toObject(),
                          "executionPeakDelta");
    requireStatisticGroup(memory.value(QStringLiteral("operationalPeakDelta")).toObject(),
                          "operationalPeakDelta");
    require(!statistics.contains(QStringLiteral("elapsedNanosecondsPerOperation")) &&
                !statistics.contains(QStringLiteral("peakDeltaBytes")) &&
                !statistics.contains(QStringLiteral("peakPrivateUsageDeltaBytes")) &&
                !memory.contains(QStringLiteral("peakDeltaBytes")) &&
                !memory.contains(QStringLiteral("peakPrivateUsageDeltaBytes")),
            "GUI export contained obsolete legacy memory fields");
}

void requireMemoryV2DocumentShape(const QJsonObject& root,
                                  const QString& mode,
                                  int expectedInterval)
{
    require(root.value(QStringLiteral("format")) == QStringLiteral("cryptobenchmark-result") &&
                root.value(QStringLiteral("schemaVersion")) == 2 &&
                root.value(QStringLiteral("mode")) == mode &&
                root.value(QStringLiteral("status")) == QStringLiteral("completed"),
            "integrated workflow document metadata was incorrect");
    const auto measurement = root.value(QStringLiteral("measurement")).toObject();
    require(measurement.value(QStringLiteral("memorySamplingIntervalMilliseconds")) == expectedInterval &&
                measurement.value(QStringLiteral("memoryModel")) == QStringLiteral("memoryV2") &&
                measurement.value(QStringLiteral("workerLifecycle")) ==
                    QStringLiteral("freshWorkerPerLogicalRun"),
            "integrated workflow measurement metadata was incorrect");

    const auto entries = root.value(QStringLiteral("entries")).toArray();
    require(entries.size() == 1 &&
                entries.at(0).toObject().value(QStringLiteral("status")) ==
                    QStringLiteral("completed"),
            "integrated workflow did not contain one Completed entry");
    const auto statistics = entries.at(0).toObject()
        .value(QStringLiteral("statistics")).toObject();
    requireStatisticGroup(
        statistics.value(QStringLiteral("wallClockNanosecondsPerOperation")).toObject(),
        "wallClockNanosecondsPerOperation");
    requireStatisticGroup(
        statistics.value(QStringLiteral("processCpuNanosecondsPerOperation")).toObject(),
        "processCpuNanosecondsPerOperation");
    const auto memory = statistics.value(QStringLiteral("memory")).toObject();
    require(memory.value(QStringLiteral("unit")) == QStringLiteral("bytes") &&
                memory.contains(QStringLiteral("readyStateDelta")) &&
                memory.contains(QStringLiteral("preparationPeakDelta")) &&
                memory.contains(QStringLiteral("executionPeakDelta")) &&
                memory.contains(QStringLiteral("operationalPeakDelta")),
            "integrated workflow lacked the Memory v2 statistic groups");
    requireStatisticGroup(memory.value(QStringLiteral("readyStateDelta")).toObject(),
                          "readyStateDelta");
    requireStatisticGroup(memory.value(QStringLiteral("preparationPeakDelta")).toObject(),
                          "preparationPeakDelta");
    requireStatisticGroup(memory.value(QStringLiteral("executionPeakDelta")).toObject(),
                          "executionPeakDelta");
    requireStatisticGroup(memory.value(QStringLiteral("operationalPeakDelta")).toObject(),
                          "operationalPeakDelta");
    require(!statistics.contains(QStringLiteral("peakDeltaBytes")) &&
                !statistics.contains(QStringLiteral("peakPrivateUsageDeltaBytes")) &&
                !memory.contains(QStringLiteral("peakDeltaBytes")) &&
                !memory.contains(QStringLiteral("peakPrivateUsageDeltaBytes")),
            "integrated workflow contained legacy memory fields");
}

void testCompletedAndReplacement()
{
    setScenario("completed");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* resultTable = widget<QTableWidget>(window, "resultsTable");
    auto* breakdownTable = widget<QTableWidget>(window, "memoryPhaseBreakdownTable");
    resultTable->setColumnWidth(0, 1);
    breakdownTable->setColumnWidth(0, 1);
    const int forcedResultWidth = resultTable->columnWidth(0);
    const int forcedBreakdownWidth = breakdownTable->columnWidth(0);
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    sampling->setCurrentIndex(sampling->findData(2));
    auto* run = widget<QPushButton>(window, "runButton");
    auto* cancel = widget<QPushButton>(window, "cancelButton");
    run->click();
    require(!run->isEnabled() && !widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                cancel->isEnabled() && !sampling->isEnabled() &&
                !widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Running state did not lock configuration and enable Cancel");
    waitForCompleted(window);
    require(!cancel->isEnabled(), "Cancel remained enabled after completion");
    require(widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "Completed result did not enable Export JSON");
    require(widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Completed result did not enable Export CSV");
    require(widget<QComboBox>(window, "categoryComboBox")->isEnabled(),
            "configuration was not restored after completion");
    require(sampling->isEnabled(), "measurement selector was not restored after completion");
    requireMemoryV2Presentation(window);
    require(resultTable->columnWidth(0) > forcedResultWidth &&
                breakdownTable->columnWidth(0) > forcedBreakdownWidth,
            "result population did not resize forced-narrow metric columns");

    widget<QSpinBox>(window, "workloadSizeSpinBox")->setValue(16);
    run->click();
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QLabel>(window, "resultsPlaceholderLabel")->isVisible() &&
                widget<QTableWidget>(window, "memoryPhaseBreakdownTable")->rowCount() == 0 &&
                !widget<QGroupBox>(window, "memoryPhaseBreakdownGroupBox")->isVisible() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled() &&
                !widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "old result was not cleared at new Run start");
    waitForCompleted(window);
    requireMemoryV2Presentation(window);
    clearScenario();
}

void testCancelAndReuse()
{
    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    auto* tabs = widget<QTabWidget>(window, "workflowTabWidget");
    auto* creatorWidget = window.findChild<QWidget*>(
        QStringLiteral("batchCreatorWidget"));
    require(creatorWidget != nullptr, "Creator widget was not found");
    auto* creator = static_cast<gui::BatchCreatorWidget*>(creatorWidget);
    require(creator->addRow(),
            "Creator draft row could not be initialized");
    auto* creatorRow = creator->rowAt(0);
    creatorRow->iterationsSpinBox()->setValue(17);
    tabs->setCurrentIndex(2);
    require(creatorRow->state().iterationsPerRun == 17,
            "Creator draft changed during initial tab switch");
    tabs->setCurrentIndex(0);
    configureHash(window);
    auto* run = widget<QPushButton>(window, "runButton");
    auto* cancel = widget<QPushButton>(window, "cancelButton");
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    run->click();
    waitUntil([&] { return cancel->isEnabled(); }, 5'000);
    require(!widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Single Export CSV was enabled while the benchmark was running");
    tabs->setCurrentIndex(2);
    creatorRow->iterationsSpinBox()->setValue(29);
    require(creatorRow->state().iterationsPerRun == 29,
            "Creator draft was not editable while Single was running");
    tabs->setCurrentIndex(0);
    cancel->click();
    require(status(window) == QStringLiteral("Cancelling...") && !cancel->isEnabled() &&
                !run->isEnabled() && !sampling->isEnabled() &&
                !widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Cancel did not enter the Cancelling presentation state");
    waitUntil([&] { return status(window) == QStringLiteral("Benchmark cancelled"); }, 10'000);
    tabs->setCurrentIndex(2);
    require(creatorRow->state().iterationsPerRun == 29,
            "Creator draft was not retained through Single cancellation");
    tabs->setCurrentIndex(0);
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                widget<QTableWidget>(window, "memoryPhaseBreakdownTable")->rowCount() == 0 &&
                !widget<QGroupBox>(window, "memoryPhaseBreakdownGroupBox")->isVisible() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled() &&
                !widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Cancelled result did not restore an empty idle GUI");

    setScenario("completed");
    run->click();
    waitForCompleted(window);
    requireMemoryV2Presentation(window);
    clearScenario();
}

void testFailedAndReuse()
{
    setScenario("failed-disconnect-immediately-v2");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* run = widget<QPushButton>(window, "runButton");
    run->click();
    waitUntil([&] { return status(window).startsWith(QStringLiteral("Benchmark failed:")); }, 10'000);
    require(status(window).contains(QStringLiteral("scripted v2 worker failure")),
            "Failed result did not expose the scripted worker technical message");
    require(!widget<QPushButton>(window, "cancelButton")->isEnabled() &&
                widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                widget<QTableWidget>(window, "memoryPhaseBreakdownTable")->rowCount() == 0 &&
                !widget<QGroupBox>(window, "memoryPhaseBreakdownGroupBox")->isVisible() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled() &&
                !widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "Failed result did not restore the idle empty GUI");

    setScenario("completed");
    run->click();
    waitForCompleted(window);
    requireMemoryV2Presentation(window);
    clearScenario();
}

QByteArray readFile(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "could not read export target");
    return file.readAll();
}

void writeFile(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "could not create export target");
    require(file.write(bytes) == bytes.size(), "could not write export target");
}

CsvRecords parseCsvRecords(const QByteArray& bytes)
{
    require(bytes.startsWith("\xEF\xBB\xBF"), "CSV output is missing its UTF-8 BOM");
    require(bytes.indexOf("\xEF\xBB\xBF", 3) == -1, "CSV output contains a second UTF-8 BOM");
    require(!bytes.mid(3).startsWith("sep=;"), "CSV output starts with a sep preamble");
    require(bytes.endsWith("\r\n"), "CSV output is missing its final CRLF");
    const std::string input(bytes.constData(), static_cast<std::size_t>(bytes.size()));
    CsvRecords records;
    CsvRecord record;
    std::string field;
    bool inQuotes = false;
    bool afterQuote = false;
    bool fieldStarted = false;
    bool endedWithRecordSeparator = false;

    for (std::size_t index = 3; index < input.size(); ++index) {
        const char character = input[index];
        endedWithRecordSeparator = false;
        if (inQuotes) {
            if (character == '"') {
                if (index + 1 < input.size() && input[index + 1] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    inQuotes = false;
                    afterQuote = true;
                }
            } else {
                field.push_back(character);
            }
            continue;
        }

        if (afterQuote) {
            if (character == ';') {
                record.push_back(std::move(field));
                field.clear();
                fieldStarted = false;
                afterQuote = false;
            } else if (character == '\r' && index + 1 < input.size() && input[index + 1] == '\n') {
                record.push_back(std::move(field));
                field.clear();
                records.push_back(std::move(record));
                record.clear();
                fieldStarted = false;
                afterQuote = false;
                ++index;
                endedWithRecordSeparator = true;
            } else {
                throw std::runtime_error("unexpected byte after a quoted CSV field");
            }
            continue;
        }

        if (character == '"' && !fieldStarted && field.empty()) {
            inQuotes = true;
            fieldStarted = true;
        } else if (character == ';') {
            record.push_back(std::move(field));
            field.clear();
            fieldStarted = false;
        } else if (character == '\r') {
            require(index + 1 < input.size() && input[index + 1] == '\n',
                    "CSV contains a lone CR outside a quoted field");
            record.push_back(std::move(field));
            field.clear();
            records.push_back(std::move(record));
            record.clear();
            fieldStarted = false;
            ++index;
            endedWithRecordSeparator = true;
        } else if (character == '\n') {
            throw std::runtime_error("CSV contains a lone LF outside a quoted field");
        } else if (character == '"') {
            throw std::runtime_error("CSV contains an unescaped quote");
        } else {
            field.push_back(character);
            fieldStarted = true;
        }
    }

    require(!inQuotes && endedWithRecordSeparator && field.empty() && record.empty(),
            "CSV ended with an incomplete record");
    return records;
}

void requireCsvShape(const CsvRecords& records, std::size_t dataRowCount)
{
    require(records.size() == dataRowCount + 1, "CSV record count did not match its data rows");
    require(records.front().size() == 77, "CSV header did not contain 77 columns");
    std::string header;
    for (std::size_t index = 0; index < records.front().size(); ++index) {
        if (index != 0) {
            header.push_back(';');
        }
        header.append(records.front()[index]);
    }
    std::string expectedHeader{kExpectedCsvHeader};
    for (char& character : expectedHeader) {
        if (character == ',') {
            character = ';';
        }
    }
    require(header == expectedHeader, "CSV header did not match the frozen 77-column contract");
    for (const auto& record : records) {
        require(record.size() == 77, "CSV record did not contain 77 columns");
    }
}

const std::string& csvCell(const CsvRecords& records, std::size_t row, std::string_view header)
{
    const auto& columns = records.front();
    for (std::size_t column = 0; column < columns.size(); ++column) {
        if (columns[column] == header) {
            return records.at(row).at(column);
        }
    }
    throw std::runtime_error("CSV output omitted an expected header column");
}

double csvDouble(const std::string& value)
{
    std::string normalized = value;
    for (char& character : normalized) {
        if (character == ',') {
            character = '.';
        }
    }
    double parsed = 0.0;
    const auto result = std::from_chars(
        normalized.data(), normalized.data() + normalized.size(), parsed, std::chars_format::general);
    require(result.ec == std::errc{} && result.ptr == normalized.data() + normalized.size(),
            "CSV numeric cell was not a valid decimal-comma double");
    return parsed;
}

void testSingleJsonExport()
{
    setScenario("completed");
    QTemporaryDir directory;
    require(directory.isValid(), "temporary export directory was not created");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    sampling->setCurrentIndex(sampling->findData(2));

    QString target;
    bool overwrite = false;
    QString messageTitle;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseSaveTarget = [&](QWidget*) { return target; };
    callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString&) { messageTitle = title; };
    window.setDialogCallbacks(std::move(callbacks));

    widget<QPushButton>(window, "runButton")->click();
    waitForCompleted(window);
    auto* exportButton = widget<QPushButton>(window, "exportJsonButton");
    require(exportButton->isEnabled(), "Completed result did not remain exportable");

    target = directory.filePath("single-result.json");
    exportButton->click();
    const auto firstPayload = readFile(target);
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(firstPayload, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject(),
            "successful export was not canonical JSON");
    requireMemoryV2Export(document.object(), 2);
    require(messageTitle == QStringLiteral("Export complete"),
            "successful export did not report completion");

    sampling->setCurrentIndex(sampling->findData(4));
    widget<QPushButton>(window, "runButton")->click();
    waitForCompleted(window);
    target = directory.filePath("second-single-result.json");
    exportButton->click();
    const auto secondPayload = readFile(target);
    const auto secondDocument = QJsonDocument::fromJson(secondPayload, &parseError);
    require(parseError.error == QJsonParseError::NoError && secondDocument.isObject(),
            "second Single export was not canonical JSON");
    requireMemoryV2Export(secondDocument.object(), 4);

    target.clear();
    messageTitle.clear();
    exportButton->click();
    require(messageTitle.isEmpty() && exportButton->isEnabled(),
        "cancelling the Single export target changed the retained Completed result");

    target = directory.filePath("single-result.json");
    const QByteArray original = "existing target";
    writeFile(target, original);
    overwrite = false;
    exportButton->click();
    require(readFile(target) == original, "declined overwrite changed the target");

    overwrite = true;
    exportButton->click();
    require(readFile(target) == secondPayload, "approved overwrite did not replace the target");

    const auto parentFile = directory.filePath("not-a-directory");
    writeFile(parentFile, "parent");
    target = parentFile + "/result.json";
    exportButton->click();
    require(status(window) == QStringLiteral("Completed"),
            "export failure changed the visible Completed status");
    require(exportButton->isEnabled(), "export failure discarded the retained result");
    require(messageTitle == QStringLiteral("Export failed"), "export failure was not reported");

    target = directory.filePath("retry-result.json");
    exportButton->click();
    require(readFile(target) == secondPayload, "retry export did not persist the retained result");
    require(exportButton->isEnabled(), "successful export discarded the retained result");
    clearScenario();
}

void testSingleCsvExport()
{
    setScenario("completed");
    QTemporaryDir directory;
    require(directory.isValid(), "temporary Single CSV export directory was not created");
    MainWindow window;
    window.show();
    configureHash(window);
    widget<QComboBox>(window, "memorySamplingIntervalComboBox")
        ->setCurrentIndex(widget<QComboBox>(window, "memorySamplingIntervalComboBox")->findData(2));

    QString target;
    bool overwrite = false;
    QString messageTitle;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseSaveTarget = [&](QWidget*) { return target; };
    callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString&) { messageTitle = title; };
    window.setDialogCallbacks(std::move(callbacks));

    auto* run = widget<QPushButton>(window, "runButton");
    auto* exportJson = widget<QPushButton>(window, "exportJsonButton");
    auto* exportCsv = widget<QPushButton>(window, "exportCsvButton");
    run->click();
    require(!exportCsv->isEnabled(), "Single Export CSV was enabled during a running benchmark");
    waitForCompleted(window);
    require(exportJson->isEnabled() && exportCsv->isEnabled(),
            "Completed Single did not enable JSON and CSV exports together");

    const auto jsonPath = directory.filePath("single-result.json");
    target = jsonPath;
    exportJson->click();
    const auto jsonBytes = readFile(jsonPath);
    QJsonParseError parseError;
    const auto jsonDocument = QJsonDocument::fromJson(jsonBytes, &parseError);
    require(parseError.error == QJsonParseError::NoError && jsonDocument.isObject(),
            "existing Single JSON export did not remain available");
    const auto jsonRoot = jsonDocument.object();
    const auto jsonEntry = jsonRoot.value(QStringLiteral("entries")).toArray().at(0).toObject();

    const auto csvPath = directory.filePath("single-result.csv");
    target = csvPath;
    exportCsv->click();
    const auto csvBytes = readFile(csvPath);
    const auto records = parseCsvRecords(csvBytes);
    requireCsvShape(records, 1);
    require(csvBytes.endsWith("\r\n"), "Single CSV was missing its final CRLF");
    require(QString::fromUtf8(csvBytes.constData() + 3, csvBytes.size() - 3).toUtf8()
                == csvBytes.mid(3),
            "Single CSV payload was not valid UTF-8");
    require(csvCell(records, 1, "document.format") == "cryptobenchmark-result"
                && csvCell(records, 1, "document.schemaVersion") == "2"
                && csvCell(records, 1, "document.mode") == "single"
                && csvCell(records, 1, "document.status") == "completed"
                && csvCell(records, 1, "measurement.memorySamplingIntervalMilliseconds") == "2"
                && csvCell(records, 1, "measurement.memoryModel") == "memoryV2"
                && csvCell(records, 1, "measurement.workerLifecycle") == "freshWorkerPerLogicalRun"
                && csvCell(records, 1, "entry.status") == "completed",
            "Single CSV omitted canonical document or measurement metadata");
    require(csvCell(records, 1, "config.profileId") ==
                jsonEntry.value(QStringLiteral("config")).toObject()
                    .value(QStringLiteral("profileId")).toString().toStdString()
                && csvCell(records, 1, "config.operation") == "hash"
                && csvCell(records, 1, "config.parameters.inputSizeBytes") == "8",
            "Single CSV did not use the retained typed result configuration");

    const auto jsonStatistics = jsonEntry.value(QStringLiteral("statistics")).toObject();
    const auto jsonWallClock = jsonStatistics.value(QStringLiteral("wallClockNanosecondsPerOperation")).toObject();
    const double jsonMean = jsonWallClock.value(QStringLiteral("mean")).toDouble();
    const double csvMean = csvDouble(csvCell(records, 1, "statistics.wallClockNanosecondsPerOperation.mean"));
    std::array<char, 128> exactMean{};
    const auto exactMeanResult = std::to_chars(
        exactMean.data(), exactMean.data() + exactMean.size(), jsonMean, std::chars_format::general);
    require(exactMeanResult.ec == std::errc{}, "could not format expected canonical wall-clock statistic");
    std::string expectedMean(exactMean.data(), exactMeanResult.ptr);
    for (char& character : expectedMean) {
        if (character == '.') {
            character = ',';
        }
    }
    require(csvMean == jsonMean &&
                csvCell(records, 1, "statistics.wallClockNanosecondsPerOperation.mean")
                    == expectedMean,
            "Single CSV rounded the canonical wall-clock statistic");
    const auto jsonReadyState = jsonStatistics.value(QStringLiteral("memory")).toObject()
        .value(QStringLiteral("readyStateDelta")).toObject().value(QStringLiteral("mean")).toDouble();
    require(csvDouble(csvCell(records, 1, "statistics.memory.readyStateDeltaBytes.mean")) == jsonReadyState
                && csvCell(records, 1, "statistics.memory.unit") == "bytes",
            "Single CSV changed the canonical Memory v2 statistic");
    require(messageTitle == QStringLiteral("CSV export complete"),
            "successful Single CSV export did not report completion");

    target.clear();
    messageTitle.clear();
    exportCsv->click();
    require(messageTitle.isEmpty() && readFile(csvPath) == csvBytes && exportCsv->isEnabled(),
            "cancelling the Single CSV target changed the retained result or target");

    const QByteArray existingBytes = "preserve CSV target";
    writeFile(csvPath, existingBytes);
    target = csvPath;
    overwrite = false;
    exportCsv->click();
    require(readFile(csvPath) == existingBytes && exportCsv->isEnabled(),
            "declined Single CSV overwrite changed the target or result");
    overwrite = true;
    exportCsv->click();
    require(readFile(csvPath) == csvBytes,
            "approved Single CSV overwrite did not replace the target");

    const auto parentFile = directory.filePath("csv-parent-file");
    writeFile(parentFile, "not a directory");
    target = parentFile + "/result.csv";
    exportCsv->click();
    require(messageTitle == QStringLiteral("CSV export failed")
                && exportCsv->isEnabled()
                && status(window) == QStringLiteral("Completed"),
            "Single CSV write failure was not reported or discarded the retained result");
    target = directory.filePath("single-csv-retry.csv");
    exportCsv->click();
    require(readFile(target) == csvBytes && exportCsv->isEnabled(),
            "Single CSV retry did not reuse the retained result");
    clearScenario();
}

void testSingleBatchMemoryV2ParityAndSnapshotIsolation()
{
    setScenario("completed");
    QTemporaryDir directory;
    require(directory.isValid(), "integrated workflow directory was not created");

    const auto batchInputPath = directory.filePath("equivalent-batch.json");
    writeFile(batchInputPath,
              R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[{"id":"equivalent","profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":8}}]})");
    const auto firstSinglePath = directory.filePath("single-4ms.json");
    const auto batchPath = directory.filePath("batch-4ms.json");
    const auto secondSinglePath = directory.filePath("single-1ms.json");

    QString selectedInput;
    QString selectedOutput;
    bool overwrite = false;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
    callbacks.reportMessage = [](QWidget*, const QString&, const QString&) {};
    allowBatchExecution(callbacks);

    MainWindow window;
    window.show();
    window.setDialogCallbacks(std::move(callbacks));
    configureHash(window);
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    sampling->setCurrentIndex(sampling->findData(4));
    auto* run = widget<QPushButton>(window, "runButton");
    auto* exportButton = widget<QPushButton>(window, "exportJsonButton");
    auto* exportCsvButton = widget<QPushButton>(window, "exportCsvButton");

    run->click();
    require(!sampling->isEnabled(), "Single did not lock the global selector");
    waitForCompleted(window);
    require(sampling->isEnabled() && exportButton->isEnabled() && exportCsvButton->isEnabled(),
            "Single did not return to Idle with an exportable result");

    selectedOutput = firstSinglePath;
    exportButton->click();
    const auto firstSinglePayload = readFile(firstSinglePath);
    const auto firstSingleRoot = QJsonDocument::fromJson(firstSinglePayload).object();
    requireMemoryV2DocumentShape(firstSingleRoot, QStringLiteral("single"), 4);
    const auto firstSingleEntry = firstSingleRoot.value(QStringLiteral("entries"))
        .toArray().at(0).toObject();
    const auto firstSingleConfig = firstSingleEntry.value(QStringLiteral("config")).toObject();

    selectedInput = batchInputPath;
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    selectedOutput = batchPath;
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    auto* batchRun = widget<QPushButton>(window, "batchRunButton");
    batchRun->click();
    require(!run->isEnabled() && !exportButton->isEnabled() && !exportCsvButton->isEnabled()
                && !sampling->isEnabled(),
            "Batch did not preserve Single/Batch mutual exclusion and selector lock");
    waitUntil([&] {
        return widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed");
    }, 30'000);
    require(sampling->isEnabled() && batchRun->isEnabled()
                && exportButton->isEnabled() && exportCsvButton->isEnabled(),
            "Batch did not return to Idle with the retained Single result exportable");

    const auto batchPayload = readFile(batchPath);
    const auto batchRoot = QJsonDocument::fromJson(batchPayload).object();
    requireMemoryV2DocumentShape(batchRoot, QStringLiteral("batch"), 4);
    const auto batchEntry = batchRoot.value(QStringLiteral("entries"))
        .toArray().at(0).toObject();
    require(batchEntry.value(QStringLiteral("config")).toObject() == firstSingleConfig,
            "equivalent Single and Batch configs were not semantically equal");
    require(batchEntry.value(QStringLiteral("statistics")).toObject().keys() ==
                firstSingleEntry.value(QStringLiteral("statistics")).toObject().keys(),
            "Single and Batch ResultDocument statistics shapes differed");

    overwrite = true;
    const auto retainedSingleCopyPath = directory.filePath("retained-single-copy.json");
    selectedOutput = retainedSingleCopyPath;
    exportButton->click();
    require(readFile(retainedSingleCopyPath) == firstSinglePayload,
            "Batch changed the retained Single result snapshot");

    const auto retainedSingleCsvPath = directory.filePath("retained-single-copy.csv");
    selectedOutput = retainedSingleCsvPath;
    exportCsvButton->click();
    const auto retainedSingleCsv = readFile(retainedSingleCsvPath);
    const auto retainedSingleCsvRecords = parseCsvRecords(retainedSingleCsv);
    requireCsvShape(retainedSingleCsvRecords, 1);
    require(csvCell(retainedSingleCsvRecords, 1, "document.mode") == "single"
                && csvCell(retainedSingleCsvRecords, 1, "entry.status") == "completed"
                && readFile(firstSinglePath) == firstSinglePayload
                && readFile(batchPath) == batchPayload,
            "Batch changed or invalidated the retained Single result during CSV export");

    sampling->setCurrentIndex(sampling->findData(1));
    run->click();
    require(!exportButton->isEnabled() && !exportCsvButton->isEnabled(),
            "new Single Run did not invalidate both retained-result export actions");
    waitForCompleted(window);
    selectedOutput = secondSinglePath;
    exportButton->click();
    const auto secondSingleRoot = QJsonDocument::fromJson(readFile(secondSinglePath)).object();
    requireMemoryV2DocumentShape(secondSingleRoot, QStringLiteral("single"), 1);
    require(readFile(firstSinglePath) == firstSinglePayload &&
                readFile(batchPath) == batchPayload &&
                QJsonDocument::fromJson(readFile(firstSinglePath)).object()
                .value(QStringLiteral("measurement")).toObject()
                .value(QStringLiteral("memorySamplingIntervalMilliseconds")) == 4 &&
                QJsonDocument::fromJson(readFile(batchPath)).object()
                    .value(QStringLiteral("measurement")).toObject()
                    .value(QStringLiteral("memorySamplingIntervalMilliseconds")) == 4,
            "previous 4 ms Single/Batch outputs were changed by the later Single run");
    clearScenario();
}

    void testRuntimeEstimatePresentationContract()
    {
        using application::RuntimeDuration;
        using application::RuntimeEstimateAvailability;
        using application::RuntimeEstimateUnavailableReason;

        require(gui::formatRuntimeDuration(RuntimeDuration{0}) == QStringLiteral("0 seconds"),
            "known zero duration formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{1}) == QStringLiteral("less than 1 second"),
            "positive subsecond duration formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{1'490'000'000})
                    == QStringLiteral("1 second"),
            "whole-second rounding below midpoint changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{1'500'000'000})
                    == QStringLiteral("2 seconds"),
            "whole-second midpoint rounding changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{59'500'000'000})
                    == QStringLiteral("60 seconds"),
            "seconds unit-boundary rounding changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{60'000'000'000})
                    == QStringLiteral("1 minute"),
            "minute boundary formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{3'570'000'000'000})
                    == QStringLiteral("60 minutes"),
            "whole-minute rounding changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{3'600'000'000'000})
                    == QStringLiteral("1 hour"),
            "hour boundary formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{4'080'000'000'000})
                    == QStringLiteral("1 hour 15 minutes"),
            "15-minute hour granularity changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{85'980'000'000'000})
                    == QStringLiteral("24 hours"),
            "hours unit-boundary rounding changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{86'400'000'000'000})
                    == QStringLiteral("1 day"),
            "day boundary formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{90'000'000'000'000})
                    == QStringLiteral("1 day 1 hour"),
            "day/hour formatting changed");
        require(gui::formatRuntimeDuration(RuntimeDuration{
                    std::numeric_limits<std::int64_t>::max()})
                    == QStringLiteral("106752 days"),
            "large representable duration overflowed or was misformatted");

        const auto allMissing = makeRuntimeEstimate(
            {{
                1,
                RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                RuntimeEstimateUnavailableReason::CalibrationPointMissing}},
            RuntimeEstimateUnavailableReason::CalibrationPointMissing,
            RuntimeEstimateAvailability::Unavailable,
            1,
            1);
        const auto allMissingText =
            gui::batchRuntimeEstimateConfirmationText(allMissing);
        require(allMissingText.contains(
                    QStringLiteral("Estimated duration unavailable: calibration data is missing for 1 of 1 entry."))
                    && allMissingText.contains(QStringLiteral(
                        "No measured-block duration estimates are available."))
                    && allMissingText.endsWith(QStringLiteral("Start the batch anyway?")),
            "single-entry missing-data wording changed");

        const auto partial = makeRuntimeEstimate(
            {{
                 1,
                 RuntimeDuration{700'000'000},
                 RuntimeEstimateUnavailableReason::NonMeasuredOverheadUnavailable},
                {
                 2,
                 RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                 RuntimeEstimateUnavailableReason::CalibrationPointMissing}},
            RuntimeEstimateUnavailableReason::NonMeasuredOverheadUnavailable,
            RuntimeEstimateAvailability::Partial,
            1,
            2,
            {1});
        const auto partialText = gui::batchRuntimeEstimateConfirmationText(partial);
        require(partialText.contains(QStringLiteral(
                    "Estimated total batch duration unavailable: calibration data is incomplete for 2 of 2 entries."))
                    && partialText.contains(QStringLiteral(
                        "The estimated measured cryptographic block duration per logical run is below 1 second for entry 1."))
                    && partialText.contains(QStringLiteral(
                        "Shorter runs may be more sensitive to fixed overhead and system noise."))
                    && !partialText.contains(QStringLiteral("approximately")),
            "partial coverage or short-run text changed");

        const auto overheadMissing = makeRuntimeEstimate(
            {{
                1,
                RuntimeDuration{1'200'000'000},
                RuntimeDuration{5'000'000'000}}},
            RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
            RuntimeEstimateAvailability::Partial,
            0,
            0);
        const auto overheadText =
            gui::batchRuntimeEstimateConfirmationText(overheadMissing);
        require(overheadText.contains(QStringLiteral(
                    "Estimated total batch duration unavailable: batch-level calibration overhead is missing."))
                    && !overheadText.contains(QStringLiteral("0 of 1 entries"))
                    && !overheadText.contains(QStringLiteral("below 1 second")),
            "Batch-overhead-only missing message was misleading");

        const auto invalid = makeRuntimeEstimate(
            {{
                1,
                RuntimeEstimateUnavailableReason::InvalidCalibrationData,
                RuntimeEstimateUnavailableReason::InvalidCalibrationData}},
            RuntimeEstimateUnavailableReason::InvalidCalibrationData,
            RuntimeEstimateAvailability::Unavailable,
            1,
            1);
        require(gui::batchRuntimeEstimateConfirmationText(invalid).contains(
                    QStringLiteral("the estimate cannot be calculated safely.")),
            "invalid calibration was presented as missing data");

        const auto overflow = makeRuntimeEstimate(
            {{
                1,
                RuntimeDuration{1},
                RuntimeEstimateUnavailableReason::ArithmeticOverflow}},
            RuntimeEstimateUnavailableReason::ArithmeticOverflow,
            RuntimeEstimateAvailability::Partial,
            0,
            1);
        require(gui::batchRuntimeEstimateConfirmationText(overflow).contains(
                    QStringLiteral("the estimate cannot be calculated safely.")),
            "arithmetic overflow was presented as missing data");

        const auto availableZero = makeRuntimeEstimate(
            {{1, RuntimeDuration{0}, RuntimeDuration{0}}},
            RuntimeDuration{0},
            RuntimeEstimateAvailability::Available,
            0,
            0);
        require(gui::batchRuntimeEstimateConfirmationText(availableZero).contains(
                    QStringLiteral("Estimated batch duration: approximately 0 seconds.")),
            "available zero was treated as missing");
        const auto pragmaticAvailableText =
            gui::batchRuntimeEstimateConfirmationText(
                availableZero,
                gui::BatchRuntimeEstimatePresentationMode::PragmaticReducedScope);
        require(pragmaticAvailableText.contains(QStringLiteral(
                    "rough, approximate order-of-magnitude estimate"))
                    && pragmaticAvailableText.contains(QStringLiteral(
                        "worker startup, setup/preparation, IPC, checkpoint/persistence"))
                    && pragmaticAvailableText.contains(QStringLiteral(
                        "actual elapsed time may be longer"))
                    && pragmaticAvailableText.contains(QStringLiteral(
                        "Source timings use 5 ms memory sampling"))
                    && pragmaticAvailableText.contains(QStringLiteral(
                        "1–4 ms estimates assume comparable timing and were not measured separately")),
            "pragmatic numerical disclosure omitted a required limitation");
        require(!gui::batchRuntimeEstimateConfirmationText(availableZero).contains(
                    QStringLiteral("order-of-magnitude estimate")),
            "legacy/fake-provider presentation unexpectedly enabled pragmatic disclosure");
        const auto pragmaticUnavailableText =
            gui::batchRuntimeEstimateConfirmationText(
                allMissing,
                gui::BatchRuntimeEstimatePresentationMode::PragmaticReducedScope);
        require(pragmaticUnavailableText.contains(QStringLiteral(
                    "Estimated duration unavailable: calibration data is missing"))
                    && !pragmaticUnavailableText.contains(QStringLiteral(
                        "order-of-magnitude estimate")),
            "unavailable pragmatic estimate received numeric disclosure");

        const auto warningFor = [](std::size_t count) {
            std::vector<std::uint32_t> indices;
            for (std::size_t index = 0; index < count; ++index) {
                indices.push_back(static_cast<std::uint32_t>(index + 1));
            }
            return gui::batchRuntimeEstimateConfirmationText(makeRuntimeEstimate(
                {},
                RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
                RuntimeEstimateAvailability::Unavailable,
                0,
                0,
                std::move(indices)));
        };
        require(!warningFor(0).contains(QStringLiteral("below 1 second")),
            "zero short entries produced a warning");
        require(warningFor(1).contains(QStringLiteral("for entry 1.")),
            "single short entry was not singular");
        const auto tenText = warningFor(10);
        require(tenText.contains(QStringLiteral("entries 1, 2, 3, 4, 5, 6, 7, 8, 9, 10."))
                    && !tenText.contains(QStringLiteral("plus")),
            "ten short entries were not listed exactly");
        require(warningFor(11).contains(QStringLiteral(
                    "entries 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, plus 1 more.")),
            "eleven short entries were not capped with exact remainder");
        require(warningFor(1000).contains(QStringLiteral(
                    "entries 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, plus 990 more.")),
            "1000 short entries were not capped with exact remainder");
    }

    QByteArray validBatchFixture();
    QByteArray multiEntryBatchFixture();

    void testProductionNoDataModalDeclineAndDismissal()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "production no-data dialog directory was not created");
        const auto inputPath = directory.filePath("no-data-input.json");
        const auto outputPath = directory.filePath("existing-result.json");
        writeFile(inputPath, multiEntryBatchFixture());
        const QByteArray originalOutput{"preserve this existing result"};
        writeFile(outputPath, originalOutput);

        MainWindow window;
        window.show();
        setScenario("completed");
        configureHash(window);
        widget<QPushButton>(window, "runButton")->click();
        waitForCompleted(window);
        clearScenario();
        require(widget<QPushButton>(window, "exportJsonButton")->isEnabled()
                    && widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "production no-data Batch test did not retain a Single result");
        QString selectedInput = inputPath;
        QString selectedOutput = outputPath;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
        callbacks.confirmOverwrite = [](QWidget*, const QString&) { return true; };
        window.setDialogCallbacks(std::move(callbacks));
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        const auto initialCompletedCount =
            widget<QLabel>(window, "batchCompletedCountLabel")->text();

        bool dialogSeen = false;
        bool exactTextSeen = false;
        bool noWasDefault = false;
        QTimer::singleShot(0, [&] {
            for (auto* topLevel : QApplication::topLevelWidgets()) {
                auto* dialog = qobject_cast<QMessageBox*>(topLevel);
                if (dialog == nullptr
                    || dialog->windowTitle() != QStringLiteral("Confirm Batch Execution")) {
                    continue;
                }
                dialogSeen = true;
                exactTextSeen =
                    dialog->text().contains(QStringLiteral(
                        "Estimated duration unavailable: calibration data is missing for 2 of 2 entries."))
                    && dialog->text().contains(QStringLiteral(
                        "No measured-block duration estimates are available."))
                    && dialog->text().endsWith(QStringLiteral("Start the batch anyway?"));
                noWasDefault = dialog->defaultButton() == dialog->button(QMessageBox::No)
                    && dialog->escapeButton() == dialog->button(QMessageBox::No)
                    && dialog->button(QMessageBox::Yes)->text().remove(QLatin1Char('&'))
                        == QStringLiteral("Yes")
                    && dialog->button(QMessageBox::No)->text().remove(QLatin1Char('&'))
                        == QStringLiteral("No");
                dialog->button(QMessageBox::No)->click();
                return;
            }
        });

        widget<QPushButton>(window, "batchRunButton")->click();
        require(dialogSeen && exactTextSeen && noWasDefault,
            "production no-data modal text or default No contract changed");
        const bool outputPreserved = readFile(outputPath) == originalOutput;
        const bool statusPreserved = widget<QLabel>(window, "batchStatusLabel")->text()
            == QStringLiteral("Not running.");
        const bool countersPreserved =
            widget<QLabel>(window, "batchCompletedCountLabel")->text() == initialCompletedCount;
        const bool runEnabled = widget<QPushButton>(window, "batchRunButton")->isEnabled();
        const bool targetPreserved =
            widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath;
        const bool sourcePreserved =
            widget<QLabel>(window, "batchInputSourceLabel")->text()
                == QStringLiteral("Input source: Batch input file");
        require(outputPreserved
                    && statusPreserved && countersPreserved && runEnabled
                    && targetPreserved && sourcePreserved
                    && widget<QPushButton>(window, "exportJsonButton")->isEnabled()
                    && widget<QPushButton>(window, "exportCsvButton")->isEnabled(),
            "No changed output, accepted Batch input, status or start availability");

        const auto runDismissal = [&](bool useEscape) {
            const auto dismissalOutput = directory.filePath(
                useEscape ? "escape-result.json" : "dismiss-result.json");
            MainWindow dismissedWindow;
            dismissedWindow.show();
            MainWindow::DialogCallbacks dismissalCallbacks;
            dismissalCallbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
            dismissalCallbacks.chooseSaveTarget = [&](QWidget*) { return dismissalOutput; };
            dismissedWindow.setDialogCallbacks(std::move(dismissalCallbacks));
            widget<QPushButton>(dismissedWindow, "batchInputBrowseButton")->click();
            widget<QPushButton>(dismissedWindow, "batchOutputBrowseButton")->click();
            bool dismissed = false;
            QTimer::singleShot(0, [&] {
                for (auto* topLevel : QApplication::topLevelWidgets()) {
                    auto* dialog = qobject_cast<QMessageBox*>(topLevel);
                    if (dialog == nullptr
                        || dialog->windowTitle() != QStringLiteral("Confirm Batch Execution")) {
                        continue;
                    }
                    dismissed = true;
                    if (useEscape) {
                        QKeyEvent escape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
                        QApplication::sendEvent(dialog, &escape);
                    } else {
                        dialog->close();
                    }
                    return;
                }
            });
            widget<QPushButton>(dismissedWindow, "batchRunButton")->click();
            require(dismissed && !QFileInfo::exists(dismissalOutput)
                        && widget<QPushButton>(dismissedWindow, "batchRunButton")->isEnabled()
                        && widget<QLabel>(dismissedWindow, "batchStatusLabel")->text()
                            == QStringLiteral("Not running."),
                useEscape ? "Escape was not treated as No"
                          : "dialog dismissal was not treated as No");
        };
        runDismissal(true);
        runDismissal(false);
    }

    void testFakeProviderEstimatesAndCapturedSettings()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "fake-provider integration directory was not created");
        const auto inputPath = directory.filePath("captured-settings-input.json");
        const auto outputPath = directory.filePath("captured-settings-output.json");
        writeFile(inputPath, validBatchFixture());

        auto fixture = std::make_shared<RuntimeCalibrationFixture>();
        fixture->entryEstimate = {
            RuntimeDuration{700'000'000},
            RuntimeDuration{4'000'000'000},
            RuntimeDuration{300'000'000}};
        fixture->batchOverhead = RuntimeDuration{0};
        setScenario("completed");
        MainWindow window(
            std::make_unique<FixtureRuntimeCalibrationProvider>(fixture));
        window.show();
        QString selectedInput = inputPath;
        QString selectedOutput = outputPath;
        std::size_t openChooserCalls = 0;
        std::size_t saveChooserCalls = 0;
        std::size_t confirmations = 0;
        bool controlsLockedDuringConfirmation = false;
        std::optional<application::RuntimeEstimate> estimateSeen;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) {
            ++openChooserCalls;
            return selectedInput;
        };
        callbacks.chooseSaveTarget = [&](QWidget*) {
            ++saveChooserCalls;
            return selectedOutput;
        };
        callbacks.confirmBatchExecution = [&](QWidget*, const application::RuntimeEstimate& estimate) {
            ++confirmations;
            estimateSeen = estimate;
            auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
            controlsLockedDuringConfirmation =
                !widget<QPushButton>(window, "batchRunButton")->isEnabled()
                && !widget<QPushButton>(window, "runButton")->isEnabled()
                && !widget<QPushButton>(window, "batchInputBrowseButton")->isEnabled()
                && !widget<QPushButton>(window, "batchOutputBrowseButton")->isEnabled()
                && !sampling->isEnabled()
                && !creatorWidget(window)->useInBatchButton()->isEnabled()
                && !creatorWidget(window)->exportBatchJsonButton()->isEnabled();
            sampling->setCurrentIndex(sampling->findData(5));
            widget<QPushButton>(window, "batchRunButton")->click();
            widget<QPushButton>(window, "runButton")->click();
            widget<QPushButton>(window, "batchInputBrowseButton")->click();
            widget<QPushButton>(window, "batchOutputBrowseButton")->click();
            creatorWidget(window)->useInBatchButton()->click();
            return true;
        };
        window.setDialogCallbacks(std::move(callbacks));
        auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
        sampling->setCurrentIndex(sampling->findData(1));
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        const auto chooserCallsBeforeConfirm = std::pair{openChooserCalls, saveChooserCalls};

        widget<QPushButton>(window, "batchRunButton")->click();
        waitUntil([&] {
            return widget<QLabel>(window, "batchStatusLabel")->text()
                == QStringLiteral("Completed");
        }, 30'000);
        clearScenario();

        require(confirmations == 1 && controlsLockedDuringConfirmation
                    && estimateSeen.has_value()
                    && estimateSeen->availability == application::RuntimeEstimateAvailability::Available
                    && std::get<RuntimeDuration>(
                        estimateSeen->perEntry[0].estimatedMeasuredBlockDurationPerRun).count()
                        == 700'000'000
                    && std::get<RuntimeDuration>(
                        estimateSeen->perEntry[0].estimatedTotalEntryDuration).count()
                        == 5'000'000'000
                    && std::get<RuntimeDuration>(
                        estimateSeen->estimatedTotalBatchDuration).count()
                        == 5'000'000'000
                    && estimateSeen->shortRunEntryIndices == std::vector<std::uint32_t>{1},
            "MainWindow did not pass the fake-provider estimate to confirmation");
        require(fixture->requests.size() == 1
                    && fixture->requests[0].key.measurementSettings
                        .memorySamplingIntervalMilliseconds == 1
                    && openChooserCalls == chooserCallsBeforeConfirm.first
                    && saveChooserCalls == chooserCallsBeforeConfirm.second,
            "confirmation callback reentered chooser or changed captured estimate context");
        const auto resultDocument = QJsonDocument::fromJson(readFile(outputPath)).object();
        require(resultDocument.value("measurement").toObject()
                    .value("memorySamplingIntervalMilliseconds").toInt() == 1
                    && resultDocument.value("status").toString() == QStringLiteral("completed"),
            "Batch execution did not use the exact settings captured for estimation");
        clearScenario();
    }

    void testFakeProviderAvailabilityAndSafetyCases()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "estimate-state test directory was not created");
        const auto inputPath = directory.filePath("estimate-state-input.json");
        writeFile(inputPath, validBatchFixture());

        struct Scenario {
            application::CalibrationLookupResult entry;
            application::RuntimeDurationComponent batch;
            application::RuntimeEstimateAvailability availability;
            std::size_t missingTotal;
            std::vector<std::uint32_t> shortIndices;
            QString expectedText;
        };
        const std::vector<Scenario> scenarios{
            {
                {RuntimeDuration{1'200'000'000}, RuntimeDuration{18'000'000'000},
                 RuntimeDuration{800'000'000}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Available,
                0,
                {},
                QStringLiteral("Estimated batch duration: approximately 20 seconds.")},
            {
                {RuntimeDuration{700'000'000},
                 application::RuntimeEstimateUnavailableReason::NonMeasuredOverheadUnavailable,
                 RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Partial,
                1,
                {1},
                QStringLiteral("calibration data is incomplete for 1 of 1 entry.")},
            {
                {application::RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                 application::RuntimeEstimateUnavailableReason::CalibrationPointMissing,
                 application::RuntimeEstimateUnavailableReason::CalibrationPointMissing},
                application::RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
                application::RuntimeEstimateAvailability::Unavailable,
                1,
                {},
                QStringLiteral("calibration data is missing for 1 of 1 entry.")},
            {
                {RuntimeDuration{1'200'000'000}, RuntimeDuration{0}, RuntimeDuration{0}},
                application::RuntimeEstimateUnavailableReason::BatchOverheadUnavailable,
                application::RuntimeEstimateAvailability::Partial,
                0,
                {},
                QStringLiteral("batch-level calibration overhead is missing.")},
            {
                {RuntimeDuration{-1}, RuntimeDuration{0}, RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Unavailable,
                1,
                {},
                QStringLiteral("the estimate cannot be calculated safely.")},
            {
                {RuntimeDuration{std::numeric_limits<std::int64_t>::max()},
                 RuntimeDuration{1},
                 RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Partial,
                1,
                {},
                QStringLiteral("the estimate cannot be calculated safely.")},
            {
                {RuntimeDuration{999'999'999}, RuntimeDuration{0}, RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Available,
                0,
                {1},
                QStringLiteral("Estimated batch duration: approximately less than 1 second.")},
            {
                {RuntimeDuration{1'000'000'000}, RuntimeDuration{0}, RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Available,
                0,
                {},
                QStringLiteral("Estimated batch duration: approximately 1 second.")},
            {
                {RuntimeDuration{1'000'000'001}, RuntimeDuration{0}, RuntimeDuration{0}},
                RuntimeDuration{0},
                application::RuntimeEstimateAvailability::Available,
                0,
                {},
                QStringLiteral("Estimated batch duration: approximately 1 second.")}};

        for (std::size_t index = 0; index < scenarios.size(); ++index) {
            const auto outputPath = directory.filePath(
                QStringLiteral("estimate-state-%1.json").arg(static_cast<qulonglong>(index)));
            auto fixture = std::make_shared<RuntimeCalibrationFixture>();
            fixture->entryEstimate = scenarios[index].entry;
            fixture->batchOverhead = scenarios[index].batch;
            MainWindow window(std::make_unique<FixtureRuntimeCalibrationProvider>(fixture));
            window.show();
            MainWindow::DialogCallbacks callbacks;
            callbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
            callbacks.chooseSaveTarget = [&](QWidget*) { return outputPath; };
            std::optional<application::RuntimeEstimate> estimateSeen;
            QString displayedText;
            callbacks.confirmBatchExecution =
                [&](QWidget*, const application::RuntimeEstimate& estimate) {
                    estimateSeen = estimate;
                    displayedText = gui::batchRuntimeEstimateConfirmationText(estimate);
                    return false;
                };
            window.setDialogCallbacks(std::move(callbacks));
            widget<QPushButton>(window, "batchInputBrowseButton")->click();
            widget<QPushButton>(window, "batchOutputBrowseButton")->click();
            widget<QPushButton>(window, "batchRunButton")->click();

            require(estimateSeen.has_value()
                        && estimateSeen->availability == scenarios[index].availability
                        && estimateSeen->missingTotalEntryCount == scenarios[index].missingTotal
                        && estimateSeen->shortRunEntryIndices == scenarios[index].shortIndices
                        && displayedText.contains(scenarios[index].expectedText)
                        && !QFileInfo::exists(outputPath)
                        && widget<QLabel>(window, "batchStatusLabel")->text()
                            == QStringLiteral("Not running."),
                "fake provider availability/reason was not faithfully presented");
        }
    }

    void testFileCreatorRuntimeEstimateParity()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "File/Creator parity directory was not created");
        const auto filePath = directory.filePath("parity-input.json");
        const auto fileOutput = directory.filePath("file-parity-output.json");
        const auto creatorOutput = directory.filePath("creator-parity-output.json");
        const QByteArray sameBatch =
            R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
            R"({"profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":8}},)"
            R"({"profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":2,"parameters":{"inputSizeBytes":8}}]})";
        writeFile(filePath, sameBatch);

        const auto createWindow = [](const std::shared_ptr<RuntimeCalibrationFixture>& fixture) {
            return std::make_unique<MainWindow>(
                std::make_unique<FixtureRuntimeCalibrationProvider>(fixture));
        };
        auto fileFixture = std::make_shared<RuntimeCalibrationFixture>();
        auto creatorFixture = std::make_shared<RuntimeCalibrationFixture>();
        for (const auto& fixture : {fileFixture, creatorFixture}) {
            fixture->entryEstimate = {
                RuntimeDuration{12},
                RuntimeDuration{3},
                RuntimeDuration{4}};
            fixture->batchOverhead = RuntimeDuration{5};
        }

        std::optional<application::RuntimeEstimate> fileEstimate;
        auto fileWindow = createWindow(fileFixture);
        fileWindow->show();
        MainWindow::DialogCallbacks fileCallbacks;
        fileCallbacks.chooseOpenTarget = [&](QWidget*) { return filePath; };
        fileCallbacks.chooseSaveTarget = [&](QWidget*) { return fileOutput; };
        fileCallbacks.confirmBatchExecution =
            [&](QWidget*, const application::RuntimeEstimate& estimate) {
                fileEstimate = estimate;
                return false;
            };
        fileWindow->setDialogCallbacks(std::move(fileCallbacks));
        widget<QPushButton>(*fileWindow, "batchInputBrowseButton")->click();
        widget<QPushButton>(*fileWindow, "batchOutputBrowseButton")->click();
        widget<QComboBox>(*fileWindow, "memorySamplingIntervalComboBox")
            ->setCurrentIndex(widget<QComboBox>(*fileWindow, "memorySamplingIntervalComboBox")
                                  ->findData(5));
        widget<QPushButton>(*fileWindow, "batchRunButton")->click();

        auto creatorWindow = createWindow(creatorFixture);
        creatorWindow->show();
        auto* creator = creatorWidget(*creatorWindow);
        require(creator->addRow() && creator->addRow(),
            "parity Creator rows could not be added");
        configureCreatorHash(creator->rowAt(0), 8, 2, 2);
        configureCreatorHash(creator->rowAt(1), 8, 2, 2);
        std::optional<application::RuntimeEstimate> creatorEstimate;
        MainWindow::DialogCallbacks creatorCallbacks;
        creatorCallbacks.chooseSaveTarget = [&](QWidget*) { return creatorOutput; };
        creatorCallbacks.confirmBatchExecution =
            [&](QWidget*, const application::RuntimeEstimate& estimate) {
                creatorEstimate = estimate;
                return false;
            };
        creatorWindow->setDialogCallbacks(std::move(creatorCallbacks));
        widget<QPushButton>(*creatorWindow, "batchOutputBrowseButton")->click();
        creator->useInBatchButton()->click();
        widget<QComboBox>(*creatorWindow, "memorySamplingIntervalComboBox")
            ->setCurrentIndex(widget<QComboBox>(*creatorWindow, "memorySamplingIntervalComboBox")
                                  ->findData(5));
        widget<QPushButton>(*creatorWindow, "batchRunButton")->click();

        require(fileEstimate.has_value() && creatorEstimate.has_value(),
            "File and Creator did not both reach the estimate confirmation path");
        requireEstimatesEquivalent(*fileEstimate, *creatorEstimate);
        require(fileEstimate->shortRunEntryIndices == std::vector<std::uint32_t>{1, 2}
                    && fileFixture->requests.size() == 2
                    && creatorFixture->requests.size() == 2
                    && fileFixture->requests[0].key == creatorFixture->requests[0].key
                    && fileFixture->requests[1].key == creatorFixture->requests[1].key
                    && !QFileInfo::exists(fileOutput)
                    && !QFileInfo::exists(creatorOutput),
            "File/Creator estimates diverged or No wrote output");
    }

    void testPragmaticProductionCandidateDisclosureAndFileCreatorParity()
    {
        QTemporaryDir directory;
        require(directory.isValid(),
            "production pragmatic GUI integration directory was not created");
        const auto inputPath = directory.filePath("production-pragmatic-input.json");
        const auto fileOutput = directory.filePath("production-pragmatic-file-output.json");
        const auto creatorOutput =
            directory.filePath("production-pragmatic-creator-output.json");
        const QByteArray sameBatch =
            R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[)"
            R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":8}},)"
            R"({"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":8}}]})";
        writeFile(inputPath, sameBatch);

        const auto captureAndDecline = [](MainWindow& window) {
            QString displayedText;
            bool dialogSeen = false;
            bool timedOut = false;
            QTimer poll;
            poll.setInterval(10);
            QObject::connect(&poll, &QTimer::timeout, &window, [&] {
                for (auto* topLevel : QApplication::topLevelWidgets()) {
                    auto* dialog = qobject_cast<QMessageBox*>(topLevel);
                    if (dialog == nullptr
                        || dialog->windowTitle()
                            != QStringLiteral("Confirm Batch Execution")) {
                        continue;
                    }
                    displayedText = dialog->text();
                    if (auto* noButton = dialog->button(QMessageBox::No)) {
                        dialogSeen = true;
                        noButton->click();
                        poll.stop();
                    }
                    return;
                }
            });
            QTimer watchdog;
            watchdog.setSingleShot(true);
            QObject::connect(&watchdog, &QTimer::timeout, &window, [&] {
                timedOut = true;
                for (auto* topLevel : QApplication::topLevelWidgets()) {
                    auto* dialog = qobject_cast<QMessageBox*>(topLevel);
                    if (dialog != nullptr
                        && dialog->windowTitle()
                            == QStringLiteral("Confirm Batch Execution")) {
                        if (auto* noButton = dialog->button(QMessageBox::No)) {
                            noButton->click();
                        }
                    }
                }
                poll.stop();
            });
            poll.start();
            watchdog.start(5'000);
            widget<QPushButton>(window, "batchRunButton")->click();
            poll.stop();
            watchdog.stop();
            require(dialogSeen && !timedOut,
                "production pragmatic Batch confirmation was not shown in time");
            require(widget<QPushButton>(window, "batchRunButton")->isEnabled()
                    && widget<QLabel>(window, "batchStatusLabel")->text()
                        == QStringLiteral("Not running."),
                "declining production pragmatic ETA changed Batch execution state");
            return displayedText;
        };

        MainWindow fileWindow(
            makeInstalledPragmaticProvider(),
            gui::BatchRuntimeEstimatePresentationMode::PragmaticReducedScope);
        fileWindow.show();
        MainWindow::DialogCallbacks fileCallbacks;
        fileCallbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
        fileCallbacks.chooseSaveTarget = [&](QWidget*) { return fileOutput; };
        fileWindow.setDialogCallbacks(std::move(fileCallbacks));
        widget<QPushButton>(fileWindow, "batchInputBrowseButton")->click();
        widget<QPushButton>(fileWindow, "batchOutputBrowseButton")->click();
        const auto fileText = captureAndDecline(fileWindow);

        MainWindow creatorWindow(
            makeInstalledPragmaticProvider(),
            gui::BatchRuntimeEstimatePresentationMode::PragmaticReducedScope);
        creatorWindow.show();
        MainWindow::DialogCallbacks creatorCallbacks;
        creatorCallbacks.chooseSaveTarget = [&](QWidget*) { return creatorOutput; };
        creatorWindow.setDialogCallbacks(std::move(creatorCallbacks));
        auto* creator = creatorWidget(creatorWindow);
        require(creator->addRow() && creator->addRow(),
            "production pragmatic parity Creator rows could not be added");
        configureCreatorHash(creator->rowAt(0), 8, 1, 1);
        configureCreatorHash(creator->rowAt(1), 8, 1, 1);
        widget<QPushButton>(creatorWindow, "batchOutputBrowseButton")->click();
        creator->useInBatchButton()->click();
        const auto creatorText = captureAndDecline(creatorWindow);

        require(fileText == creatorText,
            "equivalent File and Creator batches showed different production ETA text");
        require(!QFileInfo::exists(fileOutput)
                && !QFileInfo::exists(creatorOutput),
            "declining production pragmatic ETA created an output file");

        const auto environment = application::collectEnvironmentInfo();
        if (environment.buildType == "Release") {
            require(fileText.contains(QStringLiteral(
                        "Estimated batch duration: approximately "))
                    && fileText.contains(QStringLiteral(
                        "rough, approximate order-of-magnitude estimate"))
                    && fileText.contains(QStringLiteral(
                        "worker startup, setup/preparation, IPC, checkpoint/persistence"))
                    && fileText.contains(QStringLiteral(
                        "1–4 ms estimates assume comparable timing and were not measured separately")),
                "Release numeric ETA omitted its reduced-scope disclosure");
        } else {
            require(environment.buildType == "Debug"
                    && fileText.contains(QStringLiteral(
                        "Estimated total batch duration unavailable"))
                    && !fileText.contains(QStringLiteral(
                        "Estimated batch duration: approximately "))
                    && !fileText.contains(QStringLiteral(
                        "order-of-magnitude estimate")),
                "inapplicable Debug resource showed a numeric ETA or disclosure");
        }
    }

    void testConfirmationCloseAttemptCancelsStart()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "confirmation close-guard directory was not created");
        const auto inputPath = directory.filePath("close-guard-input.json");
        const auto outputPath = directory.filePath("close-guard-output.json");
        writeFile(inputPath, validBatchFixture());
        auto fixture = std::make_shared<RuntimeCalibrationFixture>();
        fixture->entryEstimate = {
            RuntimeDuration{1}, RuntimeDuration{0}, RuntimeDuration{0}};
        fixture->batchOverhead = RuntimeDuration{0};

        MainWindow window(std::make_unique<FixtureRuntimeCalibrationProvider>(fixture));
        window.show();
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return outputPath; };
        callbacks.confirmBatchExecution = [&](QWidget*, const application::RuntimeEstimate&) {
            window.close();
            return true;
        };
        window.setDialogCallbacks(std::move(callbacks));
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        widget<QPushButton>(window, "batchRunButton")->click();

        const bool guardPreserved = window.isVisible() && !QFileInfo::exists(outputPath)
                    && fixture->requests.size() == 1
                    && widget<QLabel>(window, "batchStatusLabel")->text()
                        == QStringLiteral("Not running.")
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled();
        require(guardPreserved,
            "close attempt during confirmation triggered a Batch start");
    }

    void testDeclinedEstimatePreservesTerminalBatch()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "terminal Batch retention directory was not created");
        const auto inputPath = directory.filePath("terminal-retention-input.json");
        const auto outputPath = directory.filePath("terminal-retention-output.json");
        writeFile(inputPath, validBatchFixture());

        setScenario("completed");
        MainWindow window;
        window.show();
        bool acceptNext = true;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return outputPath; };
        callbacks.confirmBatchExecution =
            [&](QWidget*, const application::RuntimeEstimate&) { return acceptNext; };
        window.setDialogCallbacks(std::move(callbacks));
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        widget<QPushButton>(window, "batchRunButton")->click();
        waitUntil([&] {
            return widget<QLabel>(window, "batchStatusLabel")->text()
                == QStringLiteral("Completed");
        }, 30'000);
        const auto terminalPayload = readFile(outputPath);
        const auto terminalCurrentEntry =
            widget<QLabel>(window, "batchCurrentEntryLabel")->text();
        const auto terminalCompletedCount =
            widget<QLabel>(window, "batchCompletedCountLabel")->text();
        require(widget<QPushButton>(window, "batchExportCsvButton")->isEnabled(),
            "completed Batch did not retain its terminal export");

        acceptNext = false;
        widget<QPushButton>(window, "batchRunButton")->click();
        require(readFile(outputPath) == terminalPayload
                    && widget<QLabel>(window, "batchStatusLabel")->text()
                        == QStringLiteral("Completed")
                    && widget<QLabel>(window, "batchCurrentEntryLabel")->text()
                        == terminalCurrentEntry
                    && widget<QLabel>(window, "batchCompletedCountLabel")->text()
                        == terminalCompletedCount
                    && widget<QPushButton>(window, "batchExportCsvButton")->isEnabled()
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
            "declining a later estimate changed the previous terminal Batch snapshot");
        clearScenario();
    }

    void testConfirmationExceptionRestoresIdle()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "confirmation-exception directory was not created");
        const auto inputPath = directory.filePath("exception-input.json");
        const auto outputPath = directory.filePath("exception-output.json");
        writeFile(inputPath, validBatchFixture());
        MainWindow window;
        window.show();
        std::size_t confirmationCalls = 0;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return inputPath; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return outputPath; };
        callbacks.confirmBatchExecution =
            [&](QWidget*, const application::RuntimeEstimate&) -> bool {
                ++confirmationCalls;
                if (confirmationCalls == 1) {
                    throw std::runtime_error("scripted confirmation callback failure");
                }
                return false;
            };
        window.setDialogCallbacks(std::move(callbacks));
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        widget<QPushButton>(window, "batchRunButton")->click();
        require(confirmationCalls == 1
                    && widget<QLabel>(window, "batchStatusLabel")->text().startsWith(
                        QStringLiteral("Batch confirmation failed:"))
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled()
                    && !QFileInfo::exists(outputPath),
            "confirmation callback exception left a pending or started Batch");

        widget<QPushButton>(window, "batchRunButton")->click();
        require(confirmationCalls == 2 && !QFileInfo::exists(outputPath)
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
            "pending guard was not cleared after confirmation callback exception");
    }

    QByteArray validBatchFixture()
    {
        return R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[{"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":8}}]})";
    }

    QByteArray invalidBatchFixture()
    {
        return R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[{"profileId":"unknown-profile","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":8}}]})";
    }

    void testBatchGui()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "temporary batch directory was not created");
        const auto validPath = directory.filePath("valid-batch.json");
        const auto invalidPath = directory.filePath("invalid-batch.json");
        writeFile(validPath, validBatchFixture());
        writeFile(invalidPath, invalidBatchFixture());

        MainWindow window;
        window.show();
        auto* tabs = widget<QTabWidget>(window, "workflowTabWidget");
        require(tabs->count() == 3 && tabs->tabText(0) == QStringLiteral("Single Benchmark") &&
            tabs->tabText(1) == QStringLiteral("Batch") &&
            tabs->tabText(2) == QStringLiteral("Batch Creator"),
            "single, batch, and creator workflows were not separated into the expected tabs");
        require(!widget<QPushButton>(window, "batchRunButton")->isEnabled() &&
            !widget<QPushButton>(window, "batchCancelButton")->isEnabled(),
            "batch execution controls were enabled before M13-C");
        require(!widget<QPushButton>(window, "batchSaveAsButton")->isEnabled(),
            "Batch Save As was enabled before a failed Batch existed");
        require(widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Not running.") &&
            widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("-"),
            "batch status placeholders were not initialized");

        QString selectedInput;
        QString selectedOutput;
        bool overwrite = false;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
        callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
        window.setDialogCallbacks(std::move(callbacks));

        auto* inputPath = widget<QLineEdit>(window, "batchInputPathLineEdit");
        auto* inputSource = widget<QLabel>(window, "batchInputSourceLabel");
        auto* validationSummary = widget<QLabel>(window, "batchValidationSummaryLabel");
        auto* issues = widget<QListWidget>(window, "batchValidationIssuesList");
        auto* inputBrowse = widget<QPushButton>(window, "batchInputBrowseButton");
        auto* outputPath = widget<QLineEdit>(window, "batchOutputPathLineEdit");
        auto* outputBrowse = widget<QPushButton>(window, "batchOutputBrowseButton");

        inputBrowse->click();
        require(inputPath->text().isEmpty() &&
                    inputSource->text() == QStringLiteral("Input source: None") &&
                    validationSummary->text() == QStringLiteral("No batch input selected."),
            "cancelling input browse changed batch state");

        selectedInput = validPath;
        inputBrowse->click();
        require(inputPath->text() == validPath &&
            inputSource->text() == QStringLiteral("Input source: Batch input file") &&
            validationSummary->text() == QStringLiteral("Valid batch - 1 entries") && issues->count() == 0,
            "valid batch input was not parsed and displayed correctly");

        selectedInput.clear();
        inputBrowse->click();
        require(inputPath->text() == validPath && validationSummary->text() == QStringLiteral("Valid batch - 1 entries"),
            "cancelled input browse discarded the accepted batch state");

        selectedInput = invalidPath;
        inputBrowse->click();
        require(inputPath->text() == invalidPath && validationSummary->text() == QStringLiteral("Invalid batch") &&
            inputSource->text() == QStringLiteral("Input source: Batch input file") &&
            issues->count() > 0 && issues->item(0)->text().contains(QStringLiteral("/entries/0/profileId")) &&
            issues->item(0)->text().contains(QStringLiteral("unknown")),
            "invalid batch parser issue was not displayed with path and message");
        require(!widget<QPushButton>(window, "batchRunButton")->isEnabled(),
            "invalid batch input left a batch action enabled");

        const auto acceptedOutput = directory.filePath("accepted-output.json");
        selectedOutput = acceptedOutput;
        outputBrowse->click();
        require(outputPath->text() == acceptedOutput && !QFileInfo::exists(acceptedOutput),
            "non-existing output target was not accepted without writing");

        selectedOutput.clear();
        outputBrowse->click();
        require(outputPath->text() == acceptedOutput, "cancelling output browse changed the accepted target");

        const auto existingOutput = directory.filePath("existing-output.json");
        const QByteArray original = "existing output";
        writeFile(existingOutput, original);
        selectedOutput = existingOutput;
        overwrite = false;
        outputBrowse->click();
        require(outputPath->text() == acceptedOutput && readFile(existingOutput) == original,
            "declined output overwrite changed target selection or file contents");

        overwrite = true;
        outputBrowse->click();
        require(outputPath->text() == existingOutput && readFile(existingOutput) == original,
            "approved output target selection wrote or changed the existing file");
    }

    void testCreatorUseExportAndSourceTransitions()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "Creator integration directory was not created");
        const auto outputPath = directory.filePath("batch-result.json");
        const auto validFilePath = directory.filePath("creator-roundtrip.json");
        const auto invalidFilePath = directory.filePath("invalid-batch.json");
        const auto existingExportPath = directory.filePath("existing-creator-input.json");
        const auto declinedOriginal = QByteArray("keep this target unchanged");
        writeFile(invalidFilePath, invalidBatchFixture());
        writeFile(existingExportPath, declinedOriginal);

        MainWindow window;
        window.show();
        auto* creator = creatorWidget(window);
        auto* tabs = widget<QTabWidget>(window, "workflowTabWidget");
        require(creator->addRow() && creator->addRow(),
                "Creator integration rows could not be added");
        configureCreatorHash(creator->rowAt(0), 8, 2, 2);
        configureCreatorHash(creator->rowAt(1), 16, 3, 2);

        QString selectedInput;
        QString selectedSaveTarget = outputPath;
        QString lastMessageTitle;
        QString lastMessageBody;
        bool overwrite = false;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
        callbacks.chooseSaveTarget = [&](QWidget*) { return selectedSaveTarget; };
        callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
        callbacks.reportMessage = [&](QWidget*, const QString& title, const QString& body) {
            lastMessageTitle = title;
            lastMessageBody = body;
        };
        allowBatchExecution(callbacks);
        window.setDialogCallbacks(std::move(callbacks));

        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        require(widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath,
                "Creator integration did not retain an independent Batch output target");
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: None"),
                "cancelled initial browse changed the source");

        creator->useInBatchButton()->click();
        require(tabs->currentIndex() == 1
                    && widget<QLabel>(window, "batchInputSourceLabel")->text()
                        == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty()
                    && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                        == QStringLiteral("Valid batch - 2 entries")
                    && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "Use in Batch did not adopt the Creator snapshot without a fake path");

        const auto acceptedSnapshot = creator->finalizeRows();
        require(acceptedSnapshot.isValid()
                    && acceptedSnapshot.definition->entries().size() == 2,
                "Creator snapshot could not be independently finalized for comparison");

        setScenario("completed");
        tabs->setCurrentIndex(0);
        configureHash(window);
        widget<QPushButton>(window, "runButton")->click();
        waitForCompleted(window);
        require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 4
                    && widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
                "Single result was not available before Creator JSON export");

        tabs->setCurrentIndex(2);
        selectedSaveTarget.clear();
        creator->exportBatchJsonButton()->click();
        require(readFile(existingExportPath) == declinedOriginal
                    && widget<QLabel>(window, "batchInputSourceLabel")->text()
                        == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty(),
                "cancelled Creator export changed the adopted Batch source");

        selectedSaveTarget = existingExportPath;
        overwrite = false;
        creator->exportBatchJsonButton()->click();
        require(readFile(existingExportPath) == declinedOriginal,
                "declined Creator export overwrite changed the target");

        overwrite = true;
        creator->exportBatchJsonButton()->click();
        const auto exportedBytes = readFile(existingExportPath);
        require(exportedBytes == acceptedSnapshot.inputBytes
                    && lastMessageTitle == QStringLiteral("Batch input JSON export complete"),
                "Creator export did not atomically write the finalized canonical bytes");
        const auto fileRoundtrip =
            application::BatchInputParser{}.parseFile(existingExportPath);
        require(fileRoundtrip.definition.has_value() && fileRoundtrip.issues.empty()
                    && fileRoundtrip.definition->entries().size() == 2
                    && fileRoundtrip.definition->entries()[0].entryIndex == 1
                    && fileRoundtrip.definition->entries()[1].entryIndex == 2
                    && !fileRoundtrip.definition->entries()[0].id.has_value()
                    && !fileRoundtrip.definition->entries()[1].id.has_value()
                    && application::benchmarkConfigToJson(
                        fileRoundtrip.definition->entries()[0].config)
                        == application::benchmarkConfigToJson(
                            acceptedSnapshot.definition->entries()[0].config)
                    && application::benchmarkConfigToJson(
                        fileRoundtrip.definition->entries()[1].config)
                        == application::benchmarkConfigToJson(
                            acceptedSnapshot.definition->entries()[1].config),
                "Creator export did not round-trip semantically through parseFile");
        require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 4
                    && widget<QPushButton>(window, "exportJsonButton")->isEnabled()
                    && widget<QLabel>(window, "batchInputSourceLabel")->text()
                        == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty()
                    && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath,
                "Creator export changed the Batch snapshot, target, or retained Single result");

        selectedSaveTarget = directory.filePath("missing-directory\\failed.json");
        creator->exportBatchJsonButton()->click();
        require(!lastMessageTitle.isEmpty()
                    && lastMessageTitle == QStringLiteral("Batch input JSON export failed")
                    && !QFileInfo::exists(selectedSaveTarget)
                    && widget<QLabel>(window, "batchInputSourceLabel")->text()
                        == QStringLiteral("Input source: Batch Creator"),
                "atomic Creator export failure was not reported or changed Batch selection");

        writeFile(validFilePath, acceptedSnapshot.inputBytes);
        selectedInput.clear();
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty(),
                "cancelled file browse discarded the accepted Creator source");

        selectedInput = validFilePath;
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == validFilePath
                    && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                        == QStringLiteral("Valid batch - 2 entries"),
                "File Batch selection did not replace the Creator source");

        creator->useInBatchButton()->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty(),
                "Creator did not replace the selected File Batch source");

        selectedInput = invalidFilePath;
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == invalidFilePath
                    && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                        == QStringLiteral("Invalid batch")
                    && !widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "invalid File Batch selection retained stale Creator state");
        selectedInput.clear();
        widget<QPushButton>(window, "batchInputBrowseButton")->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == invalidFilePath,
                "cancelled browse changed an invalid selected file source");

        creator->useInBatchButton()->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch Creator")
                    && widget<QLineEdit>(window, "batchInputPathLineEdit")->text().isEmpty()
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "successful Creator adoption did not replace invalid file state");

        creator->rowAt(1)->iterationsSpinBox()->setValue(1'000'000'000);
        creator->rowAt(1)->runsSpinBox()->setValue(2);
        creator->useInBatchButton()->click();
        require(creator->validationLabel()->text().contains(QStringLiteral("Entry 2"))
                    && creator->validationLabel()->text().contains(QStringLiteral("/entries/1"))
                    && widget<QLabel>(window, "batchInputSourceLabel")->text()
                        == QStringLiteral("Input source: Batch Creator")
                    && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                        == QStringLiteral("Valid batch - 2 entries")
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "failed Creator reuse overwrote the last valid Batch snapshot");
        selectedSaveTarget = directory.filePath("invalid-creator-export.json");
        creator->exportBatchJsonButton()->click();
        require(!QFileInfo::exists(selectedSaveTarget)
                    && creator->validationLabel()->text().contains(QStringLiteral("seriesIterationBudgetExceeded")),
                "invalid Creator rows produced an exported file or lacked a domain diagnostic");
        creator->rowAt(1)->iterationsSpinBox()->setValue(3);
        creator->rowAt(1)->runsSpinBox()->setValue(2);

        QElapsedTimer creatorConstructionTimer;
        creatorConstructionTimer.start();
        while (creator->rowCount() < gui::BatchCreatorWidget::kMaximumRows) {
            require(creator->addRow(), "Creator rejected an allowed row during UI export stress");
        }
        const auto creatorConstructionMilliseconds = creatorConstructionTimer.elapsed();
        configureCreatorHash(creator->rowAt(0), 0, 10, 2);
        configureCreatorHash(creator->rowAt(500), 8192, 20, 3);
        configureCreatorHash(creator->rowAt(999), 16384, 30, 4);
        QElapsedTimer creatorFinalizationTimer;
        creatorFinalizationTimer.start();
        const auto largeFinalization = creator->finalizeRows();
        const auto creatorFinalizationMilliseconds = creatorFinalizationTimer.elapsed();
        require(largeFinalization.isValid()
                    && largeFinalization.definition->entries().size()
                        == gui::BatchCreatorWidget::kMaximumRows,
                "1000-row MainWindow Creator draft did not finalize");
        const auto largeExportPath = directory.filePath("creator-1000-export.json");
        selectedSaveTarget = largeExportPath;
        creator->exportBatchJsonButton()->click();
        const auto largeExportBytes = readFile(largeExportPath);
        const auto largeFileRoundtrip =
            application::BatchInputParser{}.parseFile(largeExportPath);
        require(largeExportBytes == largeFinalization.inputBytes
                    && largeFileRoundtrip.definition.has_value()
                    && largeFileRoundtrip.issues.empty()
                    && largeFileRoundtrip.definition->entries().size()
                        == gui::BatchCreatorWidget::kMaximumRows
                    && !largeFileRoundtrip.definition->entries().front().id.has_value()
                    && !largeFileRoundtrip.definition->entries().back().id.has_value(),
                "1000-row UI export was not byte-identical or parseFile-roundtrippable");
        require(widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                    == QStringLiteral("Valid batch - 2 entries")
                    && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "1000-row Creator export replaced the accepted Batch snapshot or output target");
        std::cout << "EVIDENCE mainwindow_creator_1000 construction_ms="
                  << creatorConstructionMilliseconds << " finalize_ms="
                  << creatorFinalizationMilliseconds << " export_parseFile=PASS\n";

        setScenario("wait-before-measurement");
        tabs->setCurrentIndex(0);
        configureHash(window);
        auto* singleRun = widget<QPushButton>(window, "runButton");
        singleRun->click();
        waitUntil([&] { return widget<QPushButton>(window, "cancelButton")->isEnabled(); }, 5'000);
        require(!creator->useInBatchButton()->isEnabled()
                    && !creator->exportBatchJsonButton()->isEnabled(),
                "Creator finalization remained enabled during a Single run");
        creator->useInBatchButton()->click();
        require(widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch Creator"),
                "busy Single workflow changed the accepted Batch source");
        widget<QPushButton>(window, "cancelButton")->click();
        waitUntil([&] { return status(window) == QStringLiteral("Benchmark cancelled"); }, 10'000);
        clearScenario();
    }

    void testCreatorSnapshotBatchExecutionIsolation()
    {
        QTemporaryDir directory;
        require(directory.isValid(), "Creator Batch execution directory was not created");
        const auto outputPath = directory.filePath("creator-batch-result.json");
        MainWindow window;
        window.show();
        auto* creator = creatorWidget(window);
        require(creator->addRow() && creator->addRow(),
                "Creator execution rows could not be added");
        configureCreatorHash(creator->rowAt(0), 8, 2, 2);
        configureCreatorHash(creator->rowAt(1), 16, 3, 2);

        QString selectedOutput = outputPath;
        MainWindow::DialogCallbacks callbacks;
        callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
        allowBatchExecution(callbacks);
        window.setDialogCallbacks(std::move(callbacks));
        widget<QPushButton>(window, "batchOutputBrowseButton")->click();
        creator->useInBatchButton()->click();
        auto* tabs = widget<QTabWidget>(window, "workflowTabWidget");
        require(tabs->currentIndex() == 1
                    && widget<QPushButton>(window, "batchRunButton")->isEnabled(),
                "Creator snapshot was not ready for the existing BatchController");

        setScenario("wait-before-measurement");
        widget<QPushButton>(window, "batchRunButton")->click();
        auto* cancel = widget<QPushButton>(window, "batchCancelButton");
        waitUntil([&] { return cancel->isEnabled(); }, 5'000);
        require(!creator->useInBatchButton()->isEnabled()
                    && !creator->exportBatchJsonButton()->isEnabled(),
                "Creator finalization was enabled while Batch was active");
        creator->rowAt(0)->workloadSizeSpinBox()->setValue(128);
        creator->rowAt(1)->workloadSizeSpinBox()->setValue(256);
        require(creator->moveRowDown(0), "Creator draft could not be reordered during Batch");
        cancel->click();
        waitUntil([&] {
            return widget<QLabel>(window, "batchStatusLabel")->text()
                == QStringLiteral("Cancelled");
        }, 15'000);
        clearScenario();

        const auto cancelledDocument = QJsonDocument::fromJson(readFile(outputPath));
        const auto cancelledEntries = cancelledDocument.object()
            .value(QStringLiteral("entries")).toArray();
        require(cancelledEntries.size() == 2
                    && cancelledEntries[0].toObject().value(QStringLiteral("entryIndex")).toInt() == 1
                    && cancelledEntries[1].toObject().value(QStringLiteral("entryIndex")).toInt() == 2
                    && cancelledEntries[0].toObject().value(QStringLiteral("config")).toObject()
                        .value(QStringLiteral("parameters")).toObject()
                        .value(QStringLiteral("inputSizeBytes")).toInt() == 8
                    && cancelledEntries[1].toObject().value(QStringLiteral("config")).toObject()
                        .value(QStringLiteral("parameters")).toObject()
                        .value(QStringLiteral("inputSizeBytes")).toInt() == 16,
                "Creator edits/reordering changed the in-flight Batch snapshot");

        creator->useInBatchButton()->click();
        require(widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                    == QStringLiteral("Valid batch - 2 entries"),
                "successful re-Use did not replace the previous Batch snapshot");
        setScenario("completed");
        widget<QPushButton>(window, "batchRunButton")->click();
        waitUntil([&] {
            return widget<QLabel>(window, "batchStatusLabel")->text()
                == QStringLiteral("Completed");
        }, 30'000);
        clearScenario();
        const auto completedDocument = QJsonDocument::fromJson(readFile(outputPath));
        const auto completedEntries = completedDocument.object()
            .value(QStringLiteral("entries")).toArray();
        require(completedEntries.size() == 2
                    && completedEntries[0].toObject().value(QStringLiteral("config")).toObject()
                        .value(QStringLiteral("parameters")).toObject()
                        .value(QStringLiteral("inputSizeBytes")).toInt() == 256
                    && completedEntries[1].toObject().value(QStringLiteral("config")).toObject()
                        .value(QStringLiteral("parameters")).toObject()
                        .value(QStringLiteral("inputSizeBytes")).toInt() == 128
                    && widget<QLabel>(window, "batchCompletedCountLabel")->text()
                        == QStringLiteral("2"),
                "successful re-Use did not adopt and execute the updated ordered snapshot");
    }

    void answerMessageBox(QMessageBox::StandardButton answer)
{
    for (QWidget* topLevel : QApplication::topLevelWidgets()) {
        if (auto* messageBox = qobject_cast<QMessageBox*>(topLevel)) {
            if (auto* button = messageBox->button(answer)) {
                button->click();
                return;
            }
            throw std::runtime_error("close confirmation button was not found");
        }
    }
    throw std::runtime_error("close confirmation dialog was not found");
}

QByteArray multiEntryBatchFixture()
{
    return R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[{"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":8}},{"profileId":"sha256","operation":"hash","iterationsPerRun":1,"runs":1,"parameters":{"inputSizeBytes":16}}]})";
}

void testBatchRunAndCancel()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary batch execution directory was not created");
    const auto inputPath = directory.filePath("multi-entry-batch.json");
    const auto outputPath = directory.filePath("batch-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("completed");
    MainWindow window;
    window.show();
    QString selectedInput = inputPath;
    QString selectedOutput = outputPath;
    bool overwrite = false;
    QString messageTitle;
    QString messageText;
    int overwritePromptCount = 0;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    callbacks.confirmOverwrite = [&](QWidget*, const QString&) {
        ++overwritePromptCount;
        return overwrite;
    };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString& message) {
        messageTitle = title;
        messageText = message;
    };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));

    auto* inputBrowse = widget<QPushButton>(window, "batchInputBrowseButton");
    auto* outputBrowse = widget<QPushButton>(window, "batchOutputBrowseButton");
    auto* run = widget<QPushButton>(window, "batchRunButton");
    auto* cancel = widget<QPushButton>(window, "batchCancelButton");
    auto* batchCsvButton = widget<QPushButton>(window, "batchExportCsvButton");
    require(!batchCsvButton->isEnabled(), "Batch Export CSV was enabled before a terminal Batch state");
    auto* sampling = widget<QComboBox>(window, "memorySamplingIntervalComboBox");
    require(sampling->count() == 5 && sampling->currentData().toUInt() == 5,
        "Batch did not expose the global measurement selector");
    sampling->setCurrentIndex(sampling->findData(3));
    inputBrowse->click();
    require(!run->isEnabled(), "valid batch without an output target enabled Run Batch");
    outputBrowse->click();
    require(run->isEnabled(), "valid batch and accepted output target did not enable Run Batch");

    const auto invalidPath = directory.filePath("invalid-batch.json");
    writeFile(invalidPath, invalidBatchFixture());
    selectedInput = invalidPath;
    inputBrowse->click();
    require(!run->isEnabled(), "replacing valid input with invalid input left Run Batch enabled");
    selectedInput = inputPath;
    inputBrowse->click();
    require(run->isEnabled(), "selecting a valid input again did not restore Run Batch eligibility");

    run->click();
    require(!run->isEnabled() && cancel->isEnabled() &&
        !inputBrowse->isEnabled() && !outputBrowse->isEnabled() &&
        !sampling->isEnabled() &&
        !widget<QPushButton>(window, "runButton")->isEnabled() &&
        !widget<QPushButton>(window, "exportJsonButton")->isEnabled() &&
        !batchCsvButton->isEnabled(),
        "BatchRunning did not enforce mutual exclusion and control locking");
    waitUntil([&] {
        const auto currentStatus = widget<QLabel>(window, "batchStatusLabel")->text();
        return currentStatus == QStringLiteral("Completed") ||
               currentStatus.startsWith(QStringLiteral("Failed"));
    }, 30'000);
    require(widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed"),
            "Batch completion did not reach the Completed terminal status");
    require(!cancel->isEnabled() && run->isEnabled() && inputBrowse->isEnabled() &&
        outputBrowse->isEnabled() && sampling->isEnabled() && batchCsvButton->isEnabled(),
        "completed Batch did not return to Idle presentation");
    require(widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("2 / 2"),
            "terminal Batch did not retain the controller-supplied current entry");
    require(widget<QLabel>(window, "batchCompletedCountLabel")->text() == QStringLiteral("2") &&
        widget<QLabel>(window, "batchFailedCountLabel")->text() == QStringLiteral("0") &&
        widget<QLabel>(window, "batchCancelledCountLabel")->text() == QStringLiteral("0") &&
        widget<QLabel>(window, "batchNotStartedCountLabel")->text() == QStringLiteral("0"),
        "Batch terminal counters did not reflect controller progress");
    require(!widget<QPushButton>(window, "batchSaveAsButton")->isEnabled(),
            "Completed Batch incorrectly enabled Save As");
    const auto payload = readFile(outputPath);
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(payload, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject() &&
        document.object().value("mode") == QStringLiteral("batch"),
        "BatchController did not produce a batch result document");
    require(document.object().value("measurement").toObject()
                .value("memorySamplingIntervalMilliseconds").toInt() == 3,
            "Batch export did not preserve the selected measurement settings snapshot");
    const auto completedCsvPath = directory.filePath("completed-batch.csv");
    selectedOutput = completedCsvPath;
    batchCsvButton->click();
    const auto completedCsv = readFile(completedCsvPath);
    const auto completedRecords = parseCsvRecords(completedCsv);
    requireCsvShape(completedRecords, 2);
    require(csvCell(completedRecords, 1, "document.status") == "completed"
                && csvCell(completedRecords, 2, "document.status") == "completed"
                && csvCell(completedRecords, 1, "measurement.memorySamplingIntervalMilliseconds") == "3"
                && csvCell(completedRecords, 2, "measurement.memorySamplingIntervalMilliseconds") == "3"
                && csvCell(completedRecords, 1, "entry.entryIndex") == "1"
                && csvCell(completedRecords, 2, "entry.entryIndex") == "2"
                && csvCell(completedRecords, 1, "entry.status") == "completed"
                && csvCell(completedRecords, 2, "entry.status") == "completed"
                && readFile(outputPath) == payload
                && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath
                && batchCsvButton->isEnabled()
                && widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed"),
            "Completed Batch CSV changed execution/persistence state or failed canonical mapping");

    overwrite = true;
    const auto requireJsonTargetCollisionRejected = [&](const QString& candidate) {
        const int previousPromptCount = overwritePromptCount;
        selectedOutput = candidate;
        messageTitle.clear();
        messageText.clear();
        batchCsvButton->click();
        require(messageTitle == QStringLiteral("Batch CSV export failed")
                    && messageText.contains(QStringLiteral("canonical Batch JSON output file"))
                    && overwritePromptCount == previousPromptCount
                    && readFile(outputPath) == payload
                    && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == outputPath
                    && widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed"),
                "Batch CSV target collision reached overwrite confirmation or changed canonical JSON");
    };
    requireJsonTargetCollisionRejected(outputPath);
    require(QDir().mkpath(directory.filePath("normalized-path-alias")),
            "could not create normalized-path collision test directory");
    requireJsonTargetCollisionRejected(
        directory.filePath("normalized-path-alias/../batch-result.json"));
    requireJsonTargetCollisionRejected(outputPath.toUpper());

    selectedOutput.clear();
    messageTitle.clear();
    batchCsvButton->click();
    require(messageTitle.isEmpty() && readFile(outputPath) == payload && batchCsvButton->isEnabled(),
            "cancelling Batch CSV target changed the JSON target or terminal state");

    const QByteArray protectedCsvBytes = "preserve existing secondary target";
    writeFile(completedCsvPath, protectedCsvBytes);
    overwrite = false;
    selectedOutput = completedCsvPath;
    batchCsvButton->click();
    require(readFile(completedCsvPath) == protectedCsvBytes && readFile(outputPath) == payload,
            "declined Batch CSV overwrite changed a file");
    overwrite = true;
    batchCsvButton->click();
    require(readFile(completedCsvPath) == completedCsv && readFile(outputPath) == payload,
            "approved Batch CSV overwrite failed or changed canonical JSON");

    const auto csvParentFile = directory.filePath("batch-csv-parent-file");
    writeFile(csvParentFile, "not a directory");
    selectedOutput = csvParentFile + "/failed.csv";
    batchCsvButton->click();
    require(messageTitle == QStringLiteral("Batch CSV export failed")
                && batchCsvButton->isEnabled()
                && widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed")
                && readFile(outputPath) == payload,
            "Batch CSV write failure was not reported or changed execution/persistence state");
    const auto retryCsvPath = directory.filePath("completed-batch-retry.csv");
    selectedOutput = retryCsvPath;
    batchCsvButton->click();
    require(readFile(retryCsvPath) == completedCsv && readFile(outputPath) == payload,
            "Batch CSV retry changed JSON persistence or failed to reuse the terminal result");
    clearScenario();

    setScenario("wait-before-measurement");
    const auto cancelInputPath = directory.filePath("cancel-batch.json");
    const auto cancelOutputPath = directory.filePath("cancel-result.json");
    writeFile(cancelInputPath, multiEntryBatchFixture());
    MainWindow cancelWindow;
    cancelWindow.show();
    selectedInput = cancelInputPath;
    selectedOutput = cancelOutputPath;
    MainWindow::DialogCallbacks cancelCallbacks;
    cancelCallbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    cancelCallbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    cancelCallbacks.reportMessage = [](QWidget*, const QString&, const QString&) {};
    allowBatchExecution(cancelCallbacks);
    cancelWindow.setDialogCallbacks(std::move(cancelCallbacks));
    widget<QPushButton>(cancelWindow, "batchInputBrowseButton")->click();
    widget<QPushButton>(cancelWindow, "batchOutputBrowseButton")->click();
    auto* batchCancel = widget<QPushButton>(cancelWindow, "batchCancelButton");
    auto* cancelledCsvButton = widget<QPushButton>(cancelWindow, "batchExportCsvButton");
    auto* cancelSampling = widget<QComboBox>(cancelWindow, "memorySamplingIntervalComboBox");
    widget<QPushButton>(cancelWindow, "batchRunButton")->click();
    require(batchCancel->isEnabled() && !cancelledCsvButton->isEnabled(),
            "Batch Run did not enter BatchRunning presentation or disabled CSV export");
    waitUntil([&] {
        return widget<QLabel>(cancelWindow, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2") &&
               widget<QLabel>(cancelWindow, "batchCurrentBenchmarkLabel")->text() != QStringLiteral("-") &&
               widget<QLabel>(cancelWindow, "batchCurrentProgressLabel")->text() != QStringLiteral("-");
    }, 10'000);
    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::No); });
    cancelWindow.close();
    require(cancelWindow.isVisible(), "active Batch close with No unexpectedly closed the window");
    batchCancel->click();
    require(widget<QLabel>(cancelWindow, "batchStatusLabel")->text() == QStringLiteral("Cancelling...") &&
                !batchCancel->isEnabled() && !cancelSampling->isEnabled()
                && !cancelledCsvButton->isEnabled(),
        "Batch Cancel did not enter BatchCancelling presentation");
    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::No); });
    cancelWindow.close();
    require(cancelWindow.isVisible(), "close during BatchCancelling with No unexpectedly closed the window");
    waitUntil([&] {
        const auto currentStatus = widget<QLabel>(cancelWindow, "batchStatusLabel")->text();
        return currentStatus == QStringLiteral("Cancelled") ||
               currentStatus.startsWith(QStringLiteral("Failed"));
    }, 15'000);
    require(widget<QLabel>(cancelWindow, "batchStatusLabel")->text() == QStringLiteral("Cancelled"),
            "Batch cancellation did not reach the Cancelled terminal status");
    require(widget<QPushButton>(cancelWindow, "batchRunButton")->isEnabled() &&
        widget<QPushButton>(cancelWindow, "batchInputBrowseButton")->isEnabled() &&
        !widget<QPushButton>(cancelWindow, "batchSaveAsButton")->isEnabled()
        && cancelledCsvButton->isEnabled(),
        "cancelled Batch did not return to Idle presentation");
    const auto cancelledJson = readFile(cancelOutputPath);
    const auto cancelledCsvPath = directory.filePath("cancelled-batch.csv");
    selectedOutput = cancelledCsvPath;
    cancelledCsvButton->click();
    const auto cancelledRecords = parseCsvRecords(readFile(cancelledCsvPath));
    requireCsvShape(cancelledRecords, 2);
    require(csvCell(cancelledRecords, 1, "document.status") == "cancelled"
                && csvCell(cancelledRecords, 1, "entry.entryIndex") == "1"
                && csvCell(cancelledRecords, 1, "entry.status") == "cancelled"
                && csvCell(cancelledRecords, 2, "entry.entryIndex") == "2"
                && csvCell(cancelledRecords, 2, "entry.status") == "notStarted"
                && readFile(cancelOutputPath) == cancelledJson,
            "Cancelled Batch CSV did not preserve terminal order or JSON persistence");
    clearScenario();

    setScenario("failed-immediately");
    const auto failureOutputPath = directory.filePath("failure-result.json");
    MainWindow failureWindow;
    failureWindow.show();
    selectedInput = inputPath;
    selectedOutput = failureOutputPath;
    MainWindow::DialogCallbacks failureCallbacks;
    failureCallbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    failureCallbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    failureCallbacks.reportMessage = [](QWidget*, const QString&, const QString&) {};
    allowBatchExecution(failureCallbacks);
    failureWindow.setDialogCallbacks(std::move(failureCallbacks));
    widget<QPushButton>(failureWindow, "batchInputBrowseButton")->click();
    widget<QPushButton>(failureWindow, "batchOutputBrowseButton")->click();
    widget<QPushButton>(failureWindow, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(failureWindow, "batchStatusLabel")->text() ==
               QStringLiteral("Completed with failures");
    }, 30'000);
    require(widget<QLabel>(failureWindow, "batchFailedCountLabel")->text() == QStringLiteral("2") &&
                widget<QLabel>(failureWindow, "batchCompletedCountLabel")->text() == QStringLiteral("0") &&
                !widget<QPushButton>(failureWindow, "batchSaveAsButton")->isEnabled()
                && widget<QPushButton>(failureWindow, "batchExportCsvButton")->isEnabled(),
            "CompletedWithFailures did not display controller-supplied failed/completed counters");
    const auto failedEntriesJson = readFile(failureOutputPath);
    const auto failedEntriesCsvPath = directory.filePath("completed-with-failures.csv");
    selectedOutput = failedEntriesCsvPath;
    widget<QPushButton>(failureWindow, "batchExportCsvButton")->click();
    const auto failedEntriesRecords = parseCsvRecords(readFile(failedEntriesCsvPath));
    requireCsvShape(failedEntriesRecords, 2);
    require(csvCell(failedEntriesRecords, 1, "document.status") == "completedWithFailures"
                && csvCell(failedEntriesRecords, 1, "entry.status") == "failed"
                && csvCell(failedEntriesRecords, 2, "entry.status") == "failed"
                && csvCell(failedEntriesRecords, 1, "statistics.memory.unit").empty()
                && csvCell(failedEntriesRecords, 2, "statistics.memory.unit").empty()
                && readFile(failureOutputPath) == failedEntriesJson,
            "CompletedWithFailures CSV did not reflect the terminal snapshot");
    clearScenario();
}

void testBatchBusyCloseYes()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary Batch close directory was not created");
    const auto inputPath = directory.filePath("close-batch.json");
    const auto outputPath = directory.filePath("close-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    QString selectedInput = inputPath;
    QString selectedOutput = outputPath;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2");
    }, 10'000);

    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::Yes); });
    window.close();
    waitUntil([&] { return !window.isVisible(); }, 15'000);
    clearScenario();
}

bool tryAnswerMessageBox(QMessageBox::StandardButton answer);

void testBatchCloseDialogAfterTerminalization()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary Batch modal-race directory was not created");
    const auto inputPath = directory.filePath("modal-race-batch.json");
    const auto outputPath = directory.filePath("modal-race-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("completed");
    MainWindow window;
    window.show();
    QString selectedInput = inputPath;
    QString selectedOutput = outputPath;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();

    bool terminalObserved = false;
    bool answered = false;
    QTimer pollTimer;
    pollTimer.setInterval(10);
    QObject::connect(&pollTimer, &QTimer::timeout, &window, [&] {
        if (!terminalObserved &&
            widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed")) {
            terminalObserved = true;
        }
        if (terminalObserved && !answered) {
            answered = tryAnswerMessageBox(QMessageBox::Yes);
            if (answered) pollTimer.stop();
        }
    });
    pollTimer.start();
    window.close();
    pollTimer.stop();

    require(terminalObserved && answered,
        "Batch close dialog was not held open until terminalization");
    waitUntil([&] { return !window.isVisible(); }, 5'000);
    clearScenario();
}

void testBatchSaveAsRecovery()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary Batch recovery directory was not created");
    const auto inputPath = directory.filePath("recovery-batch.json");
    writeFile(inputPath, multiEntryBatchFixture());
    const auto invalidOutput = directory.filePath("missing-parent/result.json");
    const auto validOutput = directory.filePath("recovered-result.json");
    const auto existingOutput = directory.filePath("existing-recovery.json");
    writeFile(existingOutput, "keep this file");
    const auto invalidRecoveryTarget = directory.filePath("missing-recovery-parent/result.json");

    setScenario("completed");
    MainWindow window;
    window.show();
    QString selectedInput = inputPath;
    QString selectedOutput = invalidOutput;
    bool overwrite = false;
    QString messageTitle;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    callbacks.confirmOverwrite = [&](QWidget*, const QString&) { return overwrite; };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString&) { messageTitle = title; };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));

    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(window, "batchStatusLabel")->text().startsWith(QStringLiteral("Failed"));
    }, 10'000);

    auto* saveAs = widget<QPushButton>(window, "batchSaveAsButton");
    auto* exportCsv = widget<QPushButton>(window, "batchExportCsvButton");
    require(saveAs->isEnabled() && exportCsv->isEnabled(),
            "failed Batch did not enable Save As and terminal CSV export");
    require(widget<QLabel>(window, "batchStatusLabel")->text().size() > QStringLiteral("Failed: ").size(),
        "failed Batch did not retain the persistence technical message");

    overwrite = true;
    selectedOutput = invalidOutput;
    messageTitle.clear();
    exportCsv->click();
    require(messageTitle == QStringLiteral("Batch CSV export failed")
                && saveAs->isEnabled() && exportCsv->isEnabled()
                && !QFileInfo::exists(invalidOutput)
                && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == invalidOutput,
            "Failed Batch path collision created CSV at or interfered with its JSON recovery target");

    const auto invalidCsvTarget = directory.filePath("missing-csv-parent/recovery.csv");
    selectedOutput = invalidCsvTarget;
    exportCsv->click();
    require(messageTitle == QStringLiteral("Batch CSV export failed")
                && saveAs->isEnabled() && exportCsv->isEnabled()
                && widget<QLabel>(window, "batchStatusLabel")->text().startsWith(QStringLiteral("Failed"))
                && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == invalidOutput,
            "failed Batch CSV write changed Save As recovery or the canonical JSON target");

    const auto csvRecoveryTarget = directory.filePath("failed-batch-analysis.csv");
    selectedOutput = csvRecoveryTarget;
    exportCsv->click();
    const auto failedBatchRecords = parseCsvRecords(readFile(csvRecoveryTarget));
    requireCsvShape(failedBatchRecords, 2);
    require(csvCell(failedBatchRecords, 1, "document.mode") == "batch"
                && csvCell(failedBatchRecords, 1, "document.status") == "failed"
                && csvCell(failedBatchRecords, 1, "entry.status") == "notStarted"
                && csvCell(failedBatchRecords, 2, "entry.status") == "notStarted"
                && csvCell(failedBatchRecords, 1, "statistics.memory.unit").empty()
                && csvCell(failedBatchRecords, 2, "statistics.memory.unit").empty()
                && csvCell(failedBatchRecords, 1, "batchError.code") == "outputInitializationFailed"
                && csvCell(failedBatchRecords, 2, "batchError.code") == "outputInitializationFailed"
                && csvCell(failedBatchRecords, 1, "batchError.stage") == "outputInitialization"
                && csvCell(failedBatchRecords, 2, "batchError.stage") == "outputInitialization"
                && csvCell(failedBatchRecords, 1, "batchError.technicalMessage") ==
                    csvCell(failedBatchRecords, 2, "batchError.technicalMessage")
                && saveAs->isEnabled() && exportCsv->isEnabled()
                && widget<QLabel>(window, "batchStatusLabel")->text().startsWith(QStringLiteral("Failed"))
                && widget<QLineEdit>(window, "batchOutputPathLineEdit")->text() == invalidOutput,
            "successful Batch CSV export altered Failed state or its JSON recovery capability");

    selectedOutput = existingOutput;
    overwrite = false;
    saveAs->click();
    require(readFile(existingOutput) == QByteArray("keep this file"),
        "declined recovery overwrite changed the existing target");
    require(saveAs->isEnabled(), "declined recovery overwrite disabled Save As");

    overwrite = true;
    saveAs->click();
    const auto overwrittenPayload = readFile(existingOutput);
    QJsonParseError overwriteParseError;
    const auto overwrittenDocument = QJsonDocument::fromJson(overwrittenPayload, &overwriteParseError);
    require(overwriteParseError.error == QJsonParseError::NoError &&
        overwrittenDocument.isObject() &&
        overwrittenDocument.object().value("mode") == QStringLiteral("batch") &&
        overwrittenDocument.object().value("status") == QStringLiteral("failed"),
        "approved recovery overwrite did not replace the existing target");

    selectedOutput = invalidRecoveryTarget;
    saveAs->click();
    require(messageTitle == QStringLiteral("Batch Save As failed") && saveAs->isEnabled(),
        "failed recovery Save As did not preserve retryability");

    selectedOutput = validOutput;
    saveAs->click();
    const auto payload = readFile(validOutput);
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(payload, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject() &&
        document.object().value("mode") == QStringLiteral("batch") &&
        document.object().value("status") == QStringLiteral("failed"),
        "recovery Save As did not persist the failed Batch document");
    require(widget<QLabel>(window, "batchStatusLabel")->text().startsWith(QStringLiteral("Failed")) &&
        saveAs->isEnabled() && messageTitle == QStringLiteral("Batch Save As complete"),
        "successful recovery Save As changed failed-state presentation or retryability");
    clearScenario();
}


bool tryClickMessageBoxButton(const QString& text)
{
    for (QWidget* topLevel : QApplication::topLevelWidgets()) {
        if (auto* messageBox = qobject_cast<QMessageBox*>(topLevel)) {
            for (QAbstractButton* button : messageBox->buttons()) {
                if (button->text().contains(text)) {
                    button->click();
                    return true;
                }
            }
        }
    }
    return false;
}

bool messageBoxHasButton(const QString& text)
{
    for (QWidget* topLevel : QApplication::topLevelWidgets()) {
        if (auto* messageBox = qobject_cast<QMessageBox*>(topLevel)) {
            for (QAbstractButton* button : messageBox->buttons()) {
                if (button->text().contains(text)) return true;
            }
        }
    }
    return false;
}

std::string visibleMessageBoxes()
{
    std::string result;
    bool firstMessageBox = true;
    for (QWidget* topLevel : QApplication::topLevelWidgets()) {
        auto* messageBox = qobject_cast<QMessageBox*>(topLevel);
        if (messageBox == nullptr || !messageBox->isVisible()) continue;

        if (!firstMessageBox) result += "; ";
        firstMessageBox = false;
        result += "title=\"" + messageBox->windowTitle().toStdString() + "\" buttons=[";
        bool firstButton = true;
        for (QAbstractButton* button : messageBox->buttons()) {
            if (!firstButton) result += ", ";
            firstButton = false;
            result += "\"" + button->text().toStdString() + "\"";
        }
        result += ']';
    }
    return firstMessageBox ? "<none>" : result;
}

bool tryAnswerMessageBox(QMessageBox::StandardButton answer);

void clickMessageBoxButtonWhenShown(const QString& text, const std::function<void()>& beforeClick = {})
{
    bool clicked = false;
    waitUntil([&] {
        if (!clicked && beforeClick && messageBoxHasButton(text)) {
            beforeClick();
        }
        return clicked || (clicked = tryClickMessageBoxButton(text));
    }, 10'000);
}

void removeBatchOutputDirectory(const QString& outputDirectory, const QString& outputPath)
{
    require(QFile::exists(outputPath), "initial Batch snapshot was not written");
    require(QFile::remove(outputPath), "could not remove the initial Batch snapshot");
    require(QDir().rmdir(outputDirectory), "could not remove the dedicated Batch output directory");
}

void prepareBatchCloseFailure(
    MainWindow& window,
    const QString& inputPath,
    const QString& outputPath,
    const QString& outputDirectory,
    QString& selectedInput,
    QString& selectedOutput,
    MainWindow::DialogCallbacks callbacks)
{
    selectedInput = inputPath;
    selectedOutput = outputPath;
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2");
    }, 10'000);
    removeBatchOutputDirectory(outputDirectory, outputPath);
    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::Yes); });
    window.close();
}

void testBatchClosePersistenceFailureRecovery()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary close-recovery directory was not created");
    const auto inputPath = directory.filePath("close-failure-batch.json");
    const auto outputDirectory = directory.filePath("batch-output");
    require(QDir().mkpath(outputDirectory), "could not create dedicated Batch output directory");
    const auto outputPath = QDir(outputDirectory).filePath("batch-result.json");
    const auto recoveryTarget = directory.filePath("close-recovered-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    QString selectedInput;
    QString selectedOutput;
    QString messageTitle;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString&) { messageTitle = title; };
    prepareBatchCloseFailure(window, inputPath, outputPath, outputDirectory,
                             selectedInput, selectedOutput, std::move(callbacks));

    selectedOutput = recoveryTarget;
    bool csvDisabledDuringRecovery = false;
    clickMessageBoxButtonWhenShown(QStringLiteral("Save As..."), [&] {
        csvDisabledDuringRecovery =
            !widget<QPushButton>(window, "batchExportCsvButton")->isEnabled();
    });
    require(csvDisabledDuringRecovery,
            "Batch Export CSV remained enabled during close-after-terminal recovery");
    const auto payload = readFile(recoveryTarget);
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(payload, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject() &&
        document.object().value("mode") == QStringLiteral("batch") &&
        document.object().value("status") == QStringLiteral("failed"),
        "close-time recovery Save As did not persist the failed Batch document");
    waitUntil([&] { return !window.isVisible(); }, 10'000);
    require(messageTitle == QStringLiteral("Batch Save As complete"),
        "close-time recovery Save As did not report success");
    clearScenario();
}

void testBatchClosePersistenceFailureRecoveryRetry()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary recovery-retry directory was not created");
    const auto inputPath = directory.filePath("retry-close-failure-batch.json");
    const auto outputDirectory = directory.filePath("retry-output");
    require(QDir().mkpath(outputDirectory), "could not create recovery-retry output directory");
    const auto outputPath = QDir(outputDirectory).filePath("batch-result.json");
    const auto invalidRecoveryTarget = directory.filePath("missing-recovery-parent/result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    auto* creator = creatorWidget(window);
    require(creator->addRow(), "recovery Creator row could not be added");
    configureCreatorHash(creator->rowAt(0), 64, 7, 2);
    const auto draftIterations = creator->rowAt(0)->state().iterationsPerRun;
    require(creator->useInBatchButton()->isEnabled()
                && creator->exportBatchJsonButton()->isEnabled(),
            "idle recovery test did not begin with enabled Creator actions");
    QString selectedInput;
    QString selectedOutput;
    QString messageTitle;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    callbacks.reportMessage = [&](QWidget*, const QString& title, const QString&) { messageTitle = title; };
    prepareBatchCloseFailure(window, inputPath, outputPath, outputDirectory,
                             selectedInput, selectedOutput, std::move(callbacks));

    require(!creator->useInBatchButton()->isEnabled()
                && !creator->exportBatchJsonButton()->isEnabled()
                && widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file"),
            "Creator actions remained available during Batch close terminalization");
    selectedOutput = invalidRecoveryTarget;
    clickMessageBoxButtonWhenShown(QStringLiteral("Save As..."));
    require(messageTitle == QStringLiteral("Batch Save As failed") && window.isVisible() &&
                widget<QPushButton>(window, "batchSaveAsButton")->isEnabled()
                && widget<QLabel>(window, "batchStatusLabel")->text().startsWith(
                    QStringLiteral("Failed"))
                && creator->useInBatchButton()->isEnabled()
                && creator->exportBatchJsonButton()->isEnabled()
                && creator->rowAt(0)->state().iterationsPerRun == draftIterations
                && widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == inputPath,
        "failed close-time recovery Save As did not preserve retryability");
    clearScenario();
}

void testBatchClosePersistenceFailureRecoveryCancelSaveAs()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary recovery-cancel directory was not created");
    const auto inputPath = directory.filePath("cancel-close-failure-batch.json");
    const auto outputDirectory = directory.filePath("cancel-output");
    require(QDir().mkpath(outputDirectory), "could not create recovery-cancel output directory");
    const auto outputPath = QDir(outputDirectory).filePath("batch-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    auto* creator = creatorWidget(window);
    require(creator->addRow(), "cancel-recovery Creator row could not be added");
    configureCreatorHash(creator->rowAt(0), 128, 9, 2);
    const auto draftIterations = creator->rowAt(0)->state().iterationsPerRun;

    QString selectedInput;
    QString selectedOutput;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    prepareBatchCloseFailure(window, inputPath, outputPath, outputDirectory,
                             selectedInput, selectedOutput, std::move(callbacks));
    require(!creator->useInBatchButton()->isEnabled()
                && !creator->exportBatchJsonButton()->isEnabled(),
            "Creator finalization was enabled during cancelled Batch close");

    selectedOutput.clear();
    clickMessageBoxButtonWhenShown(QStringLiteral("Save As..."));
    require(window.isVisible()
                && widget<QLabel>(window, "batchStatusLabel")->text().startsWith(
                    QStringLiteral("Failed"))
                && widget<QPushButton>(window, "batchSaveAsButton")->isEnabled()
                && creator->useInBatchButton()->isEnabled()
                && creator->exportBatchJsonButton()->isEnabled()
                && creator->rowAt(0)->state().iterationsPerRun == draftIterations
                && widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == inputPath
                && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                    == QStringLiteral("Valid batch - 2 entries"),
            "cancelled close-time Save As did not restore idle Creator actions and Batch state");
    clearScenario();
}

void testBatchClosePersistenceFailureExitWithoutSaving()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary exit-without-saving directory was not created");
    const auto inputPath = directory.filePath("exit-batch.json");
    const auto outputDirectory = directory.filePath("exit-output");
    require(QDir().mkpath(outputDirectory), "could not create exit output directory");
    const auto outputPath = QDir(outputDirectory).filePath("batch-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    QString selectedInput;
    QString selectedOutput;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    prepareBatchCloseFailure(window, inputPath, outputPath, outputDirectory,
                             selectedInput, selectedOutput, std::move(callbacks));

    clickMessageBoxButtonWhenShown(QStringLiteral("Exit without saving"));
    waitUntil([&] { return !window.isVisible(); }, 10'000);
    require(!QFile::exists(outputPath), "Exit without saving unexpectedly retried persistence");
    clearScenario();
}

void testBatchCancellingCloseYes()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary Batch cancelling directory was not created");
    const auto inputPath = directory.filePath("cancelling-close-batch.json");
    const auto outputPath = directory.filePath("cancelling-close-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    QString selectedInput = inputPath;
    QString selectedOutput = outputPath;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2");
    }, 10'000);
    widget<QPushButton>(window, "batchCancelButton")->click();
    require(widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Cancelling..."),
        "Batch did not enter Cancelling before the second close attempt");

    QTimer answerTimer;
    answerTimer.setInterval(10);
    QObject::connect(&answerTimer, &QTimer::timeout, &window, [&] {
        if (tryAnswerMessageBox(QMessageBox::Yes)) answerTimer.stop();
    });
    answerTimer.start();
    window.close();
    answerTimer.stop();
    require(window.isVisible(), "close during BatchCancelling was not deferred");
    waitUntil([&] { return !window.isVisible(); }, 15'000);
    clearScenario();
}

void testBatchCancellingCloseDialogAfterFailedTerminalization()
{
    QTemporaryDir directory;
    require(directory.isValid(), "temporary cancelling modal-race directory was not created");
    const auto inputPath = directory.filePath("cancelling-modal-race-batch.json");
    const auto outputDirectory = directory.filePath("cancelling-modal-race-output");
    require(QDir().mkpath(outputDirectory), "could not create cancelling modal-race output directory");
    const auto outputPath = QDir(outputDirectory).filePath("batch-result.json");
    writeFile(inputPath, multiEntryBatchFixture());

    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    auto* creator = creatorWidget(window);
    require(creator->addRow(), "Keep open recovery Creator row could not be added");
    configureCreatorHash(creator->rowAt(0), 256, 11, 3);
    const auto draftIterations = creator->rowAt(0)->state().iterationsPerRun;
    require(creator->useInBatchButton()->isEnabled()
                && creator->exportBatchJsonButton()->isEnabled(),
            "Keep open recovery did not begin with enabled Creator actions");
    QString selectedInput = inputPath;
    QString selectedOutput = outputPath;
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    allowBatchExecution(callbacks);
    window.setDialogCallbacks(std::move(callbacks));
    bool failedObserved = false;
    bool answered = false;
    bool recoveryObserved = false;
    bool unexpectedTerminal = false;
    bool outputRemoved = false;
    bool recoveryDialogObserved = false;
    std::vector<std::string> eventSequence;
    const auto recordEvent = [&](std::string event) {
        eventSequence.push_back(std::move(event));
    };
    widget<QPushButton>(window, "batchInputBrowseButton")->click();
    widget<QPushButton>(window, "batchOutputBrowseButton")->click();
    widget<QPushButton>(window, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2");
    }, 10'000);
    require(!creator->useInBatchButton()->isEnabled()
                && !creator->exportBatchJsonButton()->isEnabled(),
            "Creator finalization was enabled while Batch was running");
    recordEvent("output removal started");
    removeBatchOutputDirectory(outputDirectory, outputPath);
    outputRemoved = true;
    recordEvent("output removal completed");
    widget<QPushButton>(window, "batchCancelButton")->click();
    require(widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Cancelling..."),
        "Batch did not enter Cancelling before the modal failed-terminal race");
    require(!creator->useInBatchButton()->isEnabled()
                && !creator->exportBatchJsonButton()->isEnabled(),
            "Creator finalization was enabled while Batch was cancelling");

    QTimer pollTimer;
    pollTimer.setInterval(10);
    QObject::connect(&pollTimer, &QTimer::timeout, &window, [&] {
        const auto batchStatus = widget<QLabel>(window, "batchStatusLabel")->text();
        if (!failedObserved &&
            batchStatus.startsWith(QStringLiteral("Failed"))) {
            failedObserved = true;
            recordEvent("Batch status transition: Failed");
        }
        if (!failedObserved && !unexpectedTerminal &&
            batchStatus == QStringLiteral("Cancelled")) {
            unexpectedTerminal = true;
            recordEvent("Batch status transition: Cancelled");
        }
        if ((failedObserved || unexpectedTerminal) && !answered) {
            answered = tryAnswerMessageBox(failedObserved ? QMessageBox::Yes : QMessageBox::No);
            if (answered) {
                recordEvent(failedObserved
                    ? "Batch cancelling confirmation response: Yes"
                    : "Batch cancelling confirmation response: No");
            }
        }
        if (!recoveryDialogObserved && messageBoxHasButton(QStringLiteral("Keep open"))) {
            recoveryDialogObserved = true;
            recordEvent("Batch recovery dialog detected");
        }
        if (answered && recoveryDialogObserved && !recoveryObserved) {
            recoveryObserved = true;
            if (tryClickMessageBoxButton(QStringLiteral("Keep open"))) {
                recordEvent("Batch recovery dialog response: Keep open");
            }
        }
    });
    pollTimer.start();
    QTimer safetyTimer;
    safetyTimer.setSingleShot(true);
    QObject::connect(&safetyTimer, &QTimer::timeout, &window, [&] {
        recordEvent("Safety timer activated");
        if (!answered) {
            answered = tryAnswerMessageBox(QMessageBox::No);
            if (answered) recordEvent("Safety confirmation response: No");
            pollTimer.stop();
        }
    });
    safetyTimer.start(10'000);
    window.close();
    pollTimer.stop();
    safetyTimer.stop();

    std::string diagnostic = "BatchCancelling close dialog was not held open until Failed terminalization"
        " [failedObserved=" + std::to_string(failedObserved)
        + ", unexpectedTerminal=" + std::to_string(unexpectedTerminal)
        + ", answered=" + std::to_string(answered)
        + ", recoveryObserved=" + std::to_string(recoveryObserved)
        + ", outputRemoved=" + std::to_string(outputRemoved)
        + ", finalBatchStatusLabel=\""
        + widget<QLabel>(window, "batchStatusLabel")->text().toStdString()
        + "\", windowVisible=" + std::to_string(window.isVisible())
        + ", recoveryDialogObserved=" + std::to_string(recoveryDialogObserved)
        + ", visibleMessageBoxes=" + visibleMessageBoxes()
        + ", eventSequence=[";
    for (std::size_t index = 0; index < eventSequence.size(); ++index) {
        if (index != 0) diagnostic += ", ";
        diagnostic += eventSequence[index];
    }
    diagnostic += ']';
    require(failedObserved && !unexpectedTerminal && answered && recoveryObserved, diagnostic);
    require(window.isVisible(),
        "failed BatchCancelling terminalization silently closed the window");
    require(window.isVisible() && widget<QPushButton>(window, "batchSaveAsButton")->isEnabled(),
        "failed BatchCancelling terminalization did not present recoverable failed state");
    require(creator->useInBatchButton()->isEnabled()
                && creator->exportBatchJsonButton()->isEnabled()
                && creator->rowAt(0)->state().iterationsPerRun == draftIterations
                && widget<QLabel>(window, "batchInputSourceLabel")->text()
                    == QStringLiteral("Input source: Batch input file")
                && widget<QLineEdit>(window, "batchInputPathLineEdit")->text() == inputPath
                && widget<QLabel>(window, "batchValidationSummaryLabel")->text()
                    == QStringLiteral("Valid batch - 2 entries"),
            "Keep open recovery did not restore Creator actions or preserve row/Batch state");
    clearScenario();
}
void testBusyCloseNo()
{
    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    configureHash(window);
    widget<QPushButton>(window, "runButton")->click();
    waitUntil([&] { return widget<QPushButton>(window, "cancelButton")->isEnabled(); }, 5'000);
    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::No); });
    require(!window.close(), "busy close with No unexpectedly accepted the close");
    require(window.isVisible() && widget<QPushButton>(window, "cancelButton")->isEnabled(),
            "busy close with No changed the active benchmark state");
    widget<QPushButton>(window, "cancelButton")->click();
    waitUntil([&] { return status(window) == QStringLiteral("Benchmark cancelled"); }, 10'000);
    clearScenario();
}

void testBusyCloseYes()
{
    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    configureHash(window);
    widget<QPushButton>(window, "runButton")->click();
    waitUntil([&] { return widget<QPushButton>(window, "cancelButton")->isEnabled(); }, 5'000);
    QTimer::singleShot(0, [&] { answerMessageBox(QMessageBox::Yes); });
    window.close();
    waitUntil([&] { return !window.isVisible(); }, 10'000);
    require(status(window) == QStringLiteral("Benchmark cancelled"),
            "Cancel-and-exit did not present the terminal cancelled status");
    clearScenario();
}

bool tryAnswerMessageBox(QMessageBox::StandardButton answer)
{
    for (QWidget* topLevel : QApplication::topLevelWidgets()) {
        if (auto* messageBox = qobject_cast<QMessageBox*>(topLevel)) {
            if (auto* button = messageBox->button(answer)) {
                button->click();
                return true;
            }
            return false;
        }
    }
    return false;
}

void testModalDialogRace()
{
    setScenario("completed");
    MainWindow window;
    window.show();
    configureHash(window);
    widget<QPushButton>(window, "runButton")->click();
    bool completionObserved = false;
    bool timedOut = false;
    bool dialogAnswered = false;
    QTimer pollTimer;
    pollTimer.setInterval(10);
    QObject::connect(&pollTimer, &QTimer::timeout, &window, [&] {
        if (!dialogAnswered && status(window) == QStringLiteral("Completed")) {
            completionObserved = true;
            dialogAnswered = tryAnswerMessageBox(QMessageBox::Yes);
            if (dialogAnswered) pollTimer.stop();
        }
    });
    QTimer safetyTimer;
    safetyTimer.setSingleShot(true);
    QObject::connect(&safetyTimer, &QTimer::timeout, &window, [&] {
        if (!dialogAnswered) {
            timedOut = true;
            dialogAnswered = tryAnswerMessageBox(QMessageBox::No);
            if (dialogAnswered) pollTimer.stop();
        }
    });
    pollTimer.start();
    safetyTimer.start(10'000);
    window.close();
    pollTimer.stop();
    safetyTimer.stop();
    require(completionObserved && !timedOut,
            "Completed status was not observed while the close dialog was open");
    require(!window.isVisible(), "modal-dialog race did not close the window normally");
    clearScenario();
}

} // namespace

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    try {
        std::cout << "CASE idle/configuration\n";
        testIdleAndConfiguration();
        std::cout << "CASE completed/replacement\n";
        testCompletedAndReplacement();
        std::cout << "CASE cancel/reuse\n";
        testCancelAndReuse();
        std::cout << "CASE failed/reuse\n";
        testFailedAndReuse();
        std::cout << "CASE single-json-export\n";
        testSingleJsonExport();
        std::cout << "CASE single-csv-export\n";
        testSingleCsvExport();
        std::cout << "CASE single-batch-single-parity\n";
        testSingleBatchMemoryV2ParityAndSnapshotIsolation();
        testRuntimeEstimatePresentationContract();
        testProductionNoDataModalDeclineAndDismissal();
        testFakeProviderEstimatesAndCapturedSettings();
        testFakeProviderAvailabilityAndSafetyCases();
        testFileCreatorRuntimeEstimateParity();
        testPragmaticProductionCandidateDisclosureAndFileCreatorParity();
        testConfirmationCloseAttemptCancelsStart();
        testDeclinedEstimatePreservesTerminalBatch();
        testConfirmationExceptionRestoresIdle();
        std::cout << "CASE batch-gui\n";
        testBatchGui();
        std::cout << "CASE creator-use-export-source-transitions\n";
        testCreatorUseExportAndSourceTransitions();
        std::cout << "CASE creator-snapshot-batch-execution\n";
        testCreatorSnapshotBatchExecutionIsolation();
        std::cout << "CASE batch-run-cancel\n";
        testBatchRunAndCancel();
        std::cout << "CASE batch-save-as-recovery\n";
        testBatchSaveAsRecovery();
        std::cout << "CASE batch-busy-close-yes\n";
        testBatchBusyCloseYes();
        std::cout << "CASE batch-close-dialog-after-terminalization\n";
        testBatchCloseDialogAfterTerminalization();
        std::cout << "CASE batch-close-persistence-failure-recovery\n";
        testBatchClosePersistenceFailureRecovery();
        std::cout << "CASE batch-close-persistence-failure-retry\n";
        testBatchClosePersistenceFailureRecoveryRetry();
        std::cout << "CASE batch-close-persistence-failure-cancel-save-as\n";
        testBatchClosePersistenceFailureRecoveryCancelSaveAs();
        std::cout << "CASE batch-close-persistence-failure-exit\n";
        testBatchClosePersistenceFailureExitWithoutSaving();
        std::cout << "CASE batch-cancelling-close-yes\n";
        testBatchCancellingCloseYes();
        std::cout << "CASE batch-cancelling-close-dialog-after-failed-terminalization\n";
        testBatchCancellingCloseDialogAfterFailedTerminalization();
        std::cout << "CASE busy-close-no\n";
        testBusyCloseNo();
        std::cout << "CASE busy-close-yes\n";
        testBusyCloseYes();
        std::cout << "CASE modal-dialog-race\n";
        testModalDialogRace();
        clearScenario();
        std::cout << "PASS MainWindowGuiTests\n";
        return 0;
    } catch (const std::exception& error) {
        clearScenario();
        std::cerr << "FAIL MainWindowGuiTests: " << error.what() << '\n';
        return 1;
    }
}
