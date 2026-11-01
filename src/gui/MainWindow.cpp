#include "MainWindow.h"
#include "CanonicalBenchmarkSelection.h"
#include "BatchRuntimeEstimatePresentation.h"
#include "BatchCreatorWidget.h"
#include "MemoryPresentation.h"

#include "ui_MainWindow.h"

#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QListWidget>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QSignalBlocker>
#include <QTimer>

#include <array>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <utility>
#include <variant>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchResultDocumentService.h>
#include <cryptobench/application/CsvResultExportService.h>
#include <cryptobench/application/JsonResultExportService.h>
#include <cryptobench/application/SingleResultDocumentService.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/RuntimeEstimateService.h>

namespace {

using cryptobench::core::AlgorithmProfileId;
using cryptobench::core::BenchmarkOperation;
using cryptobench::core::PrimitiveCategory;
using cryptobench::gui::SignatureInputMode;

constexpr int toItemData(PrimitiveCategory category) noexcept
{
    return static_cast<int>(category);
}

constexpr int toItemData(AlgorithmProfileId profileId) noexcept
{
    return static_cast<int>(profileId);
}

constexpr int toItemData(BenchmarkOperation operation) noexcept
{
    return static_cast<int>(operation);
}

constexpr int toItemData(SignatureInputMode mode) noexcept
{
    return static_cast<int>(mode);
}

QString phaseLabel(const cryptobench::core::ProgressInfo& progress)
{
    QString label;
    switch (progress.phase) {
        case cryptobench::core::BenchmarkPhase::Preparing:
            label = QStringLiteral("Preparing");
            break;
        case cryptobench::core::BenchmarkPhase::Warmup:
            label = QStringLiteral("Warm-up");
            break;
        case cryptobench::core::BenchmarkPhase::Measuring:
            label = QStringLiteral("Measuring");
            break;
        case cryptobench::core::BenchmarkPhase::Finalizing:
            label = QStringLiteral("Finalizing");
            break;
    }

    if (progress.runIndex) {
        label += QStringLiteral("; Run %1 / %2")
            .arg(static_cast<qulonglong>(*progress.runIndex) + 1)
            .arg(progress.totalRuns);
    }
    return label;
}

QString formatStatistic(double value, double divisor)
{
    QString formatted = QString::number(value / divisor, 'f', 3);
    while (formatted.endsWith(QLatin1Char('0'))) {
        formatted.chop(1);
    }
    if (formatted.endsWith(QLatin1Char('.'))) {
        formatted.chop(1);
    }
    return formatted;
}

struct DisplayUnit {
    QString suffix;
    double divisor;
};

DisplayUnit timeUnit(double mean)
{
    if (mean < 1'000.0) return {QStringLiteral("ns"), 1.0};
    if (mean < 1'000'000.0) return {QStringLiteral("µs"), 1'000.0};
    return {QStringLiteral("ms"), 1'000'000.0};
}

void setStatisticRow(
    QTableWidget* table,
    int row,
    const QString& label,
    const cryptobench::core::Statistics<double>& statistics,
    const DisplayUnit& unit)
{
    const auto formatValue = [&](double value) {
        return formatStatistic(value, unit.divisor) + QLatin1Char(' ') + unit.suffix;
    };
    table->setItem(row, 0, new QTableWidgetItem(label));
    table->setItem(row, 1, new QTableWidgetItem(formatValue(statistics.mean)));
    table->setItem(row, 2, new QTableWidgetItem(formatValue(statistics.median)));
    table->setItem(row, 3, new QTableWidgetItem(formatValue(statistics.min)));
    table->setItem(row, 4, new QTableWidgetItem(formatValue(statistics.max)));
    table->setItem(row, 5, new QTableWidgetItem(formatValue(statistics.stddev)));
}

void setMemoryStatisticRow(
    QTableWidget* table,
    int row,
    const QString& label,
    const cryptobench::core::Statistics<double>& statistics)
{
    const auto unit = cryptobench::gui::memoryDisplayUnit(statistics);
    const auto formatValue = [&](double value) {
        return cryptobench::gui::formatMemoryStatistic(value, unit) +
               QLatin1Char(' ') + unit.suffix;
    };
    table->setItem(row, 0, new QTableWidgetItem(label));
    table->setItem(row, 1, new QTableWidgetItem(
        formatValue(statistics.mean)));
    table->setItem(row, 2, new QTableWidgetItem(
        formatValue(statistics.median)));
    table->setItem(row, 3, new QTableWidgetItem(
        formatValue(statistics.min)));
    table->setItem(row, 4, new QTableWidgetItem(
        formatValue(statistics.max)));
    table->setItem(row, 5, new QTableWidgetItem(
        formatValue(statistics.stddev)));
}

void resizeResultTable(QTableWidget* table)
{
    table->horizontalHeader()->setStretchLastSection(false);
    table->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    table->resizeColumnsToContents();
}

void clearDisplayedResults(Ui::MainWindow* ui)
{
    ui->resultsTable->setRowCount(0);
    ui->memoryPhaseBreakdownTable->setRowCount(0);
    ui->memoryPhaseBreakdownGroupBox->setVisible(false);
    ui->resultsPlaceholderLabel->setVisible(true);
}

bool isTerminalBatchStatus(cryptobench::application::BatchStatus status)
{
    switch (status) {
    case cryptobench::application::BatchStatus::Completed:
    case cryptobench::application::BatchStatus::CompletedWithFailures:
    case cryptobench::application::BatchStatus::Cancelled:
    case cryptobench::application::BatchStatus::Failed:
        return true;
    case cryptobench::application::BatchStatus::InProgress:
        return false;
    }
    return false;
}

QString normalizedAbsolutePath(const QString& path)
{
    return QDir::cleanPath(QDir::fromNativeSeparators(QFileInfo(path).absoluteFilePath()));
}

bool sameFilePath(const QString& left, const QString& right)
{
    const QString normalizedLeft = normalizedAbsolutePath(left);
    const QString normalizedRight = normalizedAbsolutePath(right);
    if (QString::compare(normalizedLeft, normalizedRight, Qt::CaseInsensitive) == 0) {
        return true;
    }

    const QString canonicalLeft = QFileInfo(left).canonicalFilePath();
    const QString canonicalRight = QFileInfo(right).canonicalFilePath();
    return !canonicalLeft.isEmpty() && !canonicalRight.isEmpty()
        && QString::compare(
            QDir::cleanPath(QDir::fromNativeSeparators(canonicalLeft)),
            QDir::cleanPath(QDir::fromNativeSeparators(canonicalRight)),
            Qt::CaseInsensitive) == 0;
}

std::unique_ptr<cryptobench::application::RuntimeCalibrationProvider> requireRuntimeCalibrationProvider(
    std::unique_ptr<cryptobench::application::RuntimeCalibrationProvider> provider)
{
    if (!provider) {
        throw std::invalid_argument("MainWindow requires a runtime calibration provider");
    }
    return provider;
}

void displayCompletedResults(Ui::MainWindow* ui, const cryptobench::core::BenchmarkResult& result)
{
    if (!result.statistics) {
        clearDisplayedResults(ui);
        ui->statusLabel->setText(QStringLiteral(
            "Completed; result statistics are unavailable."));
        return;
    }

    const auto& statistics = *result.statistics;
    const auto* memory =
        std::get_if<cryptobench::core::MemoryV2Statistics>(&statistics.memory);
    if (memory == nullptr) {
        clearDisplayedResults(ui);
        ui->statusLabel->setText(QStringLiteral(
            "Completed; result statistics are unavailable."));
        return;
    }
    const auto elapsedUnit = timeUnit(statistics.elapsedNanosecondsPerOperation.mean);
    const auto cpuUnit = timeUnit(statistics.cpuNanosecondsPerOperation.mean);

    ui->resultsTable->setRowCount(4);
    setStatisticRow(ui->resultsTable, 0, QStringLiteral("Wall-clock / operation"),
                    statistics.elapsedNanosecondsPerOperation, elapsedUnit);
    setStatisticRow(ui->resultsTable, 1, QStringLiteral("Process CPU time / operation"),
                    statistics.cpuNanosecondsPerOperation, cpuUnit);
    setMemoryStatisticRow(ui->resultsTable, 2, QStringLiteral("Operational peak PrivateUsage delta"),
                          memory->operationalPeakPrivateUsageDeltaBytes);
    setMemoryStatisticRow(ui->resultsTable, 3, QStringLiteral("Ready-state PrivateUsage delta"),
                          memory->readyStatePrivateUsageDeltaBytes);
    resizeResultTable(ui->resultsTable);

    ui->memoryPhaseBreakdownTable->setRowCount(2);
    setMemoryStatisticRow(ui->memoryPhaseBreakdownTable, 0,
                          QStringLiteral("Preparation peak PrivateUsage delta"),
                          memory->preparationPeakPrivateUsageDeltaBytes);
    setMemoryStatisticRow(ui->memoryPhaseBreakdownTable, 1,
                          QStringLiteral("Execution peak PrivateUsage delta"),
                          memory->executionPeakPrivateUsageDeltaBytes);
    resizeResultTable(ui->memoryPhaseBreakdownTable);
    ui->memoryPhaseBreakdownGroupBox->setVisible(true);
    ui->resultsPlaceholderLabel->setVisible(false);
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : MainWindow(
          std::make_unique<cryptobench::application::NoDataRuntimeCalibrationProvider>(),
          cryptobench::gui::BatchRuntimeEstimatePresentationMode::Standard,
          parent)
{
}

MainWindow::MainWindow(
    std::unique_ptr<cryptobench::application::RuntimeCalibrationProvider>
        runtimeCalibrationProvider,
    QWidget* parent)
    : MainWindow(
          std::move(runtimeCalibrationProvider),
          cryptobench::gui::BatchRuntimeEstimatePresentationMode::Standard,
          parent)
{
}

MainWindow::MainWindow(
    std::unique_ptr<cryptobench::application::RuntimeCalibrationProvider>
        runtimeCalibrationProvider,
    cryptobench::gui::BatchRuntimeEstimatePresentationMode presentationMode,
    QWidget* parent)
    : QMainWindow(parent)
    , runtimeCalibrationProvider_(
          requireRuntimeCalibrationProvider(std::move(runtimeCalibrationProvider)))
    , batchRuntimeEstimatePresentationMode_(presentationMode)
    , ui(new Ui::MainWindow)
    , singleController_(std::make_unique<cryptobench::application::BenchmarkController>())
    , batchController_(std::make_unique<cryptobench::application::BatchController>(
          [this] {
              return cryptobench::core::MeasurementSettings{
                  static_cast<std::uint32_t>(ui->memorySamplingIntervalComboBox->currentData().toUInt())};
          }))
{
    ui->setupUi(this);
    batchCreatorWidget_ = new cryptobench::gui::BatchCreatorWidget(ui->creatorTab);
    ui->creatorTabLayout->addWidget(batchCreatorWidget_);

    connect(singleController_.get(), &cryptobench::application::BenchmarkController::progressChanged,
            this, &MainWindow::onProgressChanged);
    connect(singleController_.get(), &cryptobench::application::BenchmarkController::benchmarkFinished,
            this, &MainWindow::onBenchmarkFinished);
    connect(batchController_.get(), &cryptobench::application::BatchController::progressChanged,
            this, &MainWindow::onBatchProgressChanged);
    connect(batchController_.get(), &cryptobench::application::BatchController::batchFinished,
            this, &MainWindow::onBatchFinished);
    connect(ui->runButton, &QPushButton::clicked, this, &MainWindow::startBenchmark);
    connect(ui->cancelButton, &QPushButton::clicked, this, &MainWindow::requestCancel);
    connect(ui->batchRunButton, &QPushButton::clicked, this, &MainWindow::startBatch);
    connect(ui->batchCancelButton, &QPushButton::clicked, this, &MainWindow::requestBatchCancel);
    connect(ui->batchSaveAsButton, &QPushButton::clicked, this, &MainWindow::saveBatchAs);
    connect(ui->exportJsonButton, &QPushButton::clicked, this, &MainWindow::exportSingleResult);
    connect(ui->exportCsvButton, &QPushButton::clicked, this, &MainWindow::exportSingleCsvResult);
    connect(ui->batchExportCsvButton, &QPushButton::clicked, this, &MainWindow::exportBatchCsvResult);
    connect(ui->batchInputBrowseButton, &QPushButton::clicked, this, &MainWindow::browseBatchInput);
    connect(ui->batchOutputBrowseButton, &QPushButton::clicked, this, &MainWindow::browseBatchOutput);
    connect(batchCreatorWidget_->useInBatchButton(), &QPushButton::clicked,
            this, &MainWindow::useCreatorInBatch);
    connect(batchCreatorWidget_->exportBatchJsonButton(), &QPushButton::clicked,
            this, &MainWindow::exportCreatorBatchJson);

    connect(ui->categoryComboBox, &QComboBox::currentIndexChanged, this, [this](int) {
        const auto category = static_cast<PrimitiveCategory>(ui->categoryComboBox->currentData().toInt());
        populateProfiles(category, false);
    });
    connect(ui->profileComboBox, &QComboBox::currentIndexChanged, this, [this](int) {
        const QVariant data = ui->profileComboBox->currentData();
        if (!data.isValid()) {
            populateOperations(nullptr, true);
            return;
        }

        const auto profileId = static_cast<AlgorithmProfileId>(data.toInt());
        populateOperations(&profileId, true);
    });
    connect(ui->operationComboBox, &QComboBox::currentIndexChanged, this, [this](int) {
        updateInputControls();
    });
    connect(ui->signatureInputModeComboBox, &QComboBox::currentIndexChanged, this, [this](int) {
        updateInputControls();
    });
    connect(ui->workloadSizeSpinBox, &QSpinBox::valueChanged, this, [this](int) {
        updateInputControls();
    });
    connect(ui->iterationsSpinBox, &QSpinBox::valueChanged, this, [this](int) {
        updateInputControls();
    });
    connect(ui->runsSpinBox, &QSpinBox::valueChanged, this, [this](int) {
        updateInputControls();
    });

    ui->workloadSizeSpinBox->setRange(0, static_cast<int>(cryptobench::core::kMaxWorkloadBytes));
    ui->workloadSizeSpinBox->setValue(1024);
    ui->iterationsSpinBox->setRange(
        static_cast<int>(cryptobench::core::kMinIterationsPerRun),
        static_cast<int>(cryptobench::core::kMaxIterationsPerRun));
    ui->iterationsSpinBox->setValue(1000);
    ui->iterationsSpinBox->setEnabled(true);
    ui->runsSpinBox->setRange(
        static_cast<int>(cryptobench::core::kMinRuns),
        static_cast<int>(cryptobench::core::kMaxRuns));
    ui->runsSpinBox->setValue(3);
    ui->runsSpinBox->setEnabled(true);
    populateMeasurementSettings();
    populateCategories();
    applyPresentationState();
    updateBatchPresentation();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setDialogCallbacks(DialogCallbacks callbacks)
{
    dialogCallbacks_ = std::move(callbacks);
}

void MainWindow::populateMeasurementSettings()
{
    const QSignalBlocker blocker(ui->memorySamplingIntervalComboBox);
    ui->memorySamplingIntervalComboBox->clear();
    for (std::uint32_t interval = 1; interval <= 5; ++interval) {
        ui->memorySamplingIntervalComboBox->addItem(
            QStringLiteral("%1 ms").arg(interval), static_cast<quint32>(interval));
    }
    ui->memorySamplingIntervalComboBox->setCurrentIndex(
        ui->memorySamplingIntervalComboBox->findData(
            static_cast<quint32>(cryptobench::core::kDefaultMemorySamplingIntervalMilliseconds)));
}

void MainWindow::populateCategories()
{
    const QSignalBlocker blocker(ui->categoryComboBox);
    ui->categoryComboBox->clear();
    for (const auto& choice : cryptobench::gui::canonicalCategories()) {
        ui->categoryComboBox->addItem(
            QString::fromUtf8(choice.label.data(), static_cast<qsizetype>(choice.label.size())),
            toItemData(choice.category));
    }
    ui->categoryComboBox->setCurrentIndex(0);
    ui->categoryComboBox->setEnabled(ui->categoryComboBox->count() > 0);

    const auto category = static_cast<PrimitiveCategory>(ui->categoryComboBox->currentData().toInt());
    populateProfiles(category, false);
}

void MainWindow::populateProfiles(PrimitiveCategory category, bool preserveOperation)
{
    const QSignalBlocker blocker(ui->profileComboBox);
    ui->profileComboBox->clear();

    for (const auto* profile : cryptobench::gui::profilesForCategory(category)) {
        ui->profileComboBox->addItem(QString::fromUtf8(profile->displayName.data(),
            static_cast<qsizetype>(profile->displayName.size())), toItemData(profile->id));
    }

    ui->profileComboBox->setCurrentIndex(ui->profileComboBox->count() > 0 ? 0 : -1);
    ui->profileComboBox->setEnabled(ui->profileComboBox->count() > 0);

    const QVariant data = ui->profileComboBox->currentData();
    if (!data.isValid()) {
        populateOperations(nullptr, preserveOperation);
        return;
    }

    const auto profileId = static_cast<AlgorithmProfileId>(data.toInt());
    populateOperations(&profileId, preserveOperation);
}

void MainWindow::populateOperations(const AlgorithmProfileId* profileId, bool preserveOperation)
{
    const QVariant previousOperation = ui->operationComboBox->currentData();
    const QSignalBlocker blocker(ui->operationComboBox);
    ui->operationComboBox->clear();

    const auto* profile = profileId == nullptr ? nullptr : cryptobench::core::AlgorithmRegistry::find(*profileId);
    if (profile != nullptr) {
        for (const BenchmarkOperation operation : cryptobench::gui::operationsForProfile(*profileId)) {
            const auto label = cryptobench::gui::operationDisplayName(operation);
            ui->operationComboBox->addItem(
                QString::fromUtf8(label.data(), static_cast<qsizetype>(label.size())),
                toItemData(operation));
        }
    }

    ui->operationComboBox->setEnabled(ui->operationComboBox->count() > 0);
    if (ui->operationComboBox->count() == 0) {
        ui->operationComboBox->setCurrentIndex(-1);
    } else if (preserveOperation && previousOperation.isValid()) {
        const int preservedIndex = ui->operationComboBox->findData(previousOperation);
        ui->operationComboBox->setCurrentIndex(preservedIndex >= 0 ? preservedIndex : 0);
    } else {
        ui->operationComboBox->setCurrentIndex(0);
    }

    updateInputControls();
}

void MainWindow::updateInputControls()
{
    const QVariant profileData = ui->profileComboBox->currentData();
    const QVariant operationData = ui->operationComboBox->currentData();
    const auto* profile = profileData.isValid()
        ? cryptobench::core::AlgorithmRegistry::find(
              static_cast<AlgorithmProfileId>(profileData.toInt()))
        : nullptr;
    const auto operation = operationData.isValid()
        ? static_cast<BenchmarkOperation>(operationData.toInt())
        : BenchmarkOperation::KeyGen;

    const QVariant previousMode = ui->signatureInputModeComboBox->currentData();
    const QSignalBlocker modeBlocker(ui->signatureInputModeComboBox);
    ui->signatureInputModeComboBox->clear();
    cryptobench::gui::SelectionControls controls;
    if (profile != nullptr && operationData.isValid()) {
        controls = cryptobench::gui::selectionControlsFor(profile->id, operation, std::nullopt);
    }
    for (const auto mode : controls.signatureInputModes) {
        const auto label = cryptobench::gui::signatureInputModeDisplayName(mode);
        ui->signatureInputModeComboBox->addItem(
            QString::fromUtf8(label.data(), static_cast<qsizetype>(label.size())),
            toItemData(mode));
    }
    const int preservedMode = previousMode.isValid()
        ? ui->signatureInputModeComboBox->findData(previousMode)
        : -1;
    if (ui->signatureInputModeComboBox->count() > 0) {
        ui->signatureInputModeComboBox->setCurrentIndex(
            preservedMode >= 0 ? preservedMode : 0);
    }

    const bool showSignatureMode = !controls.signatureInputModes.empty();
    const QVariant selectedModeData = ui->signatureInputModeComboBox->currentData();
    const auto selectedMode = selectedModeData.isValid()
        ? std::optional<SignatureInputMode>{
            static_cast<SignatureInputMode>(selectedModeData.toInt())}
        : std::nullopt;
    if (profile != nullptr && operationData.isValid()) {
        controls = cryptobench::gui::selectionControlsFor(profile->id, operation, selectedMode);
    }
    const bool showSize = controls.workload.has_value();

    ui->signatureInputModeLabel->setVisible(showSignatureMode);
    ui->signatureInputModeComboBox->setVisible(showSignatureMode);
    ui->signatureInputModeComboBox->setEnabled(showSignatureMode && ui->signatureInputModeComboBox->count() > 0);
    if (showSize) {
        const auto label = controls.workload->label;
        ui->workloadSizeLabel->setText(
            QString::fromUtf8(label.data(), static_cast<qsizetype>(label.size())));
    }
    ui->workloadSizeLabel->setVisible(showSize);
    ui->workloadSizeSpinBox->setVisible(showSize);
    ui->workloadUnitLabel->setVisible(showSize);
    ui->workloadSizeSpinBox->setEnabled(showSize);

    if (showSize) {
        const int minimum = static_cast<int>(controls.workload->minimum);
        ui->workloadSizeSpinBox->setRange(
            minimum, static_cast<int>(cryptobench::core::kMaxWorkloadBytes));
        if (ui->workloadSizeSpinBox->value() < minimum) {
            ui->workloadSizeSpinBox->setValue(minimum);
        }
    }

    cryptobench::core::ValidationResult validation;
    const auto config = buildBenchmarkConfig(validation);
    if (config.has_value()) {
        if (!singleController_->isBusy() && presentationState_ == PresentationState::Idle) {
            ui->statusLabel->setText(QStringLiteral("Configuration valid; ready to run."));
        }
    } else if (!validation.errors.empty()) {
        if (!singleController_->isBusy() && presentationState_ == PresentationState::Idle) {
            ui->statusLabel->setText(QStringLiteral("Configuration invalid: %1")
                .arg(QString::fromStdString(validation.errors.front().technicalMessage)));
        }
    } else if (!singleController_->isBusy() && presentationState_ == PresentationState::Idle) {
        ui->statusLabel->setText(QStringLiteral("Select a valid benchmark configuration."));
    }
    updateRunAvailability();
}

void MainWindow::setConfigurationEnabled(bool enabled)
{
    ui->categoryComboBox->setEnabled(enabled);
    ui->profileComboBox->setEnabled(enabled && ui->profileComboBox->count() > 0);
    ui->operationComboBox->setEnabled(enabled && ui->operationComboBox->count() > 0);
    ui->signatureInputModeComboBox->setEnabled(
        enabled && ui->signatureInputModeComboBox->isVisible() &&
        ui->signatureInputModeComboBox->count() > 0);
    ui->workloadSizeSpinBox->setEnabled(enabled && ui->workloadSizeSpinBox->isVisible());
    ui->iterationsSpinBox->setEnabled(enabled);
    ui->runsSpinBox->setEnabled(enabled);
}

void MainWindow::updateRunAvailability()
{
    cryptobench::core::ValidationResult validation;
    ui->runButton->setEnabled(
        presentationState_ == PresentationState::Idle &&
        !batchConfirmationPending_ &&
        buildBenchmarkConfig(validation).has_value());
}

void MainWindow::applyPresentationState()
{
    const bool idle = presentationState_ == PresentationState::Idle;
    const bool singleRunning = presentationState_ == PresentationState::SingleRunning;

    setConfigurationEnabled(idle && !batchConfirmationPending_);
    ui->memorySamplingIntervalComboBox->setEnabled(idle && !batchConfirmationPending_);
    ui->workflowTabWidget->setEnabled(!batchConfirmationPending_);
    batchCreatorWidget_->setFinalizationEnabled(
        idle && !batchConfirmationPending_
        && !singleController_->isBusy() && !batchController_->isBusy()
        && !closeAfterTerminal_ && !closeAfterBatchTerminal_);
    ui->cancelButton->setEnabled(singleRunning);
    ui->exportJsonButton->setEnabled(
        idle && !batchConfirmationPending_ && exportableSingleResult_.has_value());
    ui->exportCsvButton->setEnabled(
        idle && !batchConfirmationPending_
        && !singleController_->isBusy() && !batchController_->isBusy()
        && !closeAfterTerminal_ && !closeAfterBatchTerminal_
        && exportableSingleResult_.has_value()
        && exportableSingleResult_->status == cryptobench::core::BenchmarkStatus::Completed);
    updateRunAvailability();
    updateBatchPresentation();
}

void MainWindow::updateBatchPresentation()
{
    const bool idle = presentationState_ == PresentationState::Idle;
    const bool batchRunning = presentationState_ == PresentationState::BatchRunning;
    ui->batchInputPathLineEdit->setEnabled(idle && !batchConfirmationPending_);
    ui->batchInputBrowseButton->setEnabled(idle && !batchConfirmationPending_);
    ui->batchOutputPathLineEdit->setEnabled(idle && !batchConfirmationPending_);
    ui->batchOutputBrowseButton->setEnabled(idle && !batchConfirmationPending_);
    ui->batchRunButton->setEnabled(
        idle && !batchConfirmationPending_
        && batchDefinition_.has_value() && !batchOutputTarget_.isEmpty());
    ui->batchCancelButton->setEnabled(batchRunning);
    ui->batchSaveAsButton->setEnabled(
        idle && !batchConfirmationPending_ && !batchController_->isBusy() &&
        batchController_->state().status == cryptobench::application::BatchStatus::Failed);
    ui->batchExportCsvButton->setEnabled(
        idle && !batchConfirmationPending_
        && !singleController_->isBusy() && !batchController_->isBusy()
        && !closeAfterTerminal_ && !closeAfterBatchTerminal_
        && isTerminalBatchStatus(batchController_->state().status));
    updateBatchInputSourcePresentation();
}

void MainWindow::updateBatchInputSourcePresentation()
{
    switch (batchInputSource_) {
    case BatchInputSource::None:
        ui->batchInputSourceLabel->setText(QStringLiteral("Input source: None"));
        ui->batchInputPathLineEdit->clear();
        break;
    case BatchInputSource::File:
        ui->batchInputSourceLabel->setText(QStringLiteral("Input source: Batch input file"));
        break;
    case BatchInputSource::Creator:
        ui->batchInputSourceLabel->setText(QStringLiteral("Input source: Batch Creator"));
        ui->batchInputPathLineEdit->clear();
        break;
    }
}

void MainWindow::displayBatchIssues(
    const std::vector<cryptobench::application::BatchInputIssue>& issues)
{
    ui->batchValidationIssuesList->clear();
    for (const auto& issue : issues) {
        const QString path = QString::fromStdString(issue.path);
        const QString message = QString::fromStdString(issue.technicalMessage);
        const QString context = path.isEmpty() ? QStringLiteral("(document)") : path;
        ui->batchValidationIssuesList->addItem(context + QStringLiteral(": ") + message);
    }
}

void MainWindow::browseBatchInput()
{
    if (batchConfirmationPending_) return;
    const auto chooseOpenTarget = dialogCallbacks_.chooseOpenTarget
        ? dialogCallbacks_.chooseOpenTarget
        : [this](QWidget*) {
              return QFileDialog::getOpenFileName(
                  this, QStringLiteral("Select batch input"), {}, QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseOpenTarget(this);
    if (target.isEmpty()) return;

    const auto result = cryptobench::application::BatchInputParser{}.parseFile(target);
    batchInputSource_ = BatchInputSource::File;
    ui->batchInputPathLineEdit->setText(target);
    batchDefinition_ = result.definition;
    if (batchDefinition_.has_value() && result.issues.empty()) {
        ui->batchValidationSummaryLabel->setText(
            QStringLiteral("Valid batch - %1 entries").arg(batchDefinition_->entries().size()));
        displayBatchIssues({});
        updateBatchPresentation();
        return;
    }
    batchDefinition_.reset();
    ui->batchValidationSummaryLabel->setText(QStringLiteral("Invalid batch"));
    displayBatchIssues(result.issues);
    updateBatchPresentation();
}

void MainWindow::browseBatchOutput()
{
    if (batchConfirmationPending_) return;
    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Select batch output"), {}, QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) return;

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) return;
    }

    batchOutputTarget_ = target;
    ui->batchOutputPathLineEdit->setText(batchOutputTarget_);
    updateBatchPresentation();
}

void MainWindow::startBenchmark()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy() ||
        batchController_->isBusy()) return;

    cryptobench::core::ValidationResult validation;
    const auto config = buildBenchmarkConfig(validation);
    if (!config) {
        updateInputControls();
        return;
    }

    try {
        singleController_->setMeasurementSettings({
            static_cast<std::uint32_t>(ui->memorySamplingIntervalComboBox->currentData().toUInt())});
    } catch (const std::exception& error) {
        ui->statusLabel->setText(QStringLiteral("Benchmark failed to start: %1")
            .arg(QString::fromUtf8(error.what())));
        return;
    }

    exportableSingleResult_.reset();
    clearDisplayedResults(ui);
    ui->resultsPlaceholderLabel->setText(QStringLiteral("No benchmark results available."));
    presentationState_ = PresentationState::SingleRunning;
    applyPresentationState();
    ui->statusLabel->setText(QStringLiteral("Preparing"));

    try {
        singleController_->start(*config);
    } catch (const std::exception& error) {
        presentationState_ = PresentationState::Idle;
        ui->statusLabel->setText(QStringLiteral("Benchmark failed to start: %1")
            .arg(QString::fromUtf8(error.what())));
        applyPresentationState();
        return;
    }

    if (!singleController_->isBusy()) {
        presentationState_ = PresentationState::Idle;
        applyPresentationState();
    }
}

void MainWindow::startBatch()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy() || batchController_->isBusy() ||
        !batchDefinition_.has_value() || batchDefinition_->entries().empty() ||
        batchOutputTarget_.isEmpty() || closeAfterTerminal_ || closeAfterBatchTerminal_) {
        return;
    }

    const auto capturedDefinition = *batchDefinition_;
    const auto capturedOutputTarget = batchOutputTarget_;
    const auto samplingInterval = ui->memorySamplingIntervalComboBox->currentData().toUInt();
    const cryptobench::core::MeasurementSettings capturedSettings{samplingInterval};
    if (!cryptobench::core::isValidMeasurementSettings(capturedSettings)) {
        return;
    }

    QPointer<MainWindow> lifetimeGuard(this);
    batchConfirmationPending_ = true;
    batchConfirmationCloseRequested_ = false;
    applyPresentationState();

    cryptobench::application::RuntimeEstimate estimate;
    try {
        estimate = cryptobench::application::RuntimeEstimateService{}.estimate(
            capturedDefinition, capturedSettings, *runtimeCalibrationProvider_);
    } catch (const std::exception& error) {
        if (lifetimeGuard.isNull()) return;
        batchConfirmationPending_ = false;
        batchConfirmationCloseRequested_ = false;
        applyPresentationState();
        ui->batchStatusLabel->setText(
            QStringLiteral("Batch estimate failed: %1").arg(QString::fromUtf8(error.what())));
        return;
    }
    if (lifetimeGuard.isNull()) return;
    if (batchConfirmationCloseRequested_) {
        batchConfirmationPending_ = false;
        batchConfirmationCloseRequested_ = false;
        applyPresentationState();
        return;
    }

    bool accepted = false;
    try {
        if (dialogCallbacks_.confirmBatchExecution) {
            accepted = dialogCallbacks_.confirmBatchExecution(this, estimate);
        } else {
            QMessageBox confirmation(
                QMessageBox::Question,
                QStringLiteral("Confirm Batch Execution"),
                cryptobench::gui::batchRuntimeEstimateConfirmationText(
                    estimate, batchRuntimeEstimatePresentationMode_),
                QMessageBox::Yes | QMessageBox::No,
                this);
            confirmation.setDefaultButton(QMessageBox::No);
            confirmation.setEscapeButton(QMessageBox::No);
            accepted = confirmation.exec() == QMessageBox::Yes;
        }
    } catch (const std::exception& error) {
        if (lifetimeGuard.isNull()) return;
        batchConfirmationPending_ = false;
        batchConfirmationCloseRequested_ = false;
        applyPresentationState();
        ui->batchStatusLabel->setText(
            QStringLiteral("Batch confirmation failed: %1").arg(QString::fromUtf8(error.what())));
        return;
    }

    if (lifetimeGuard.isNull()) return;
    const bool closeRequested = batchConfirmationCloseRequested_;
    batchConfirmationPending_ = false;
    batchConfirmationCloseRequested_ = false;
    if (!accepted || closeRequested || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy() || batchController_->isBusy() ||
        closeAfterTerminal_ || closeAfterBatchTerminal_) {
        applyPresentationState();
        return;
    }

    presentationState_ = PresentationState::BatchRunning;
    applyPresentationState();
    ui->batchStatusLabel->setText(QStringLiteral("Preparing"));
    ui->batchCurrentEntryLabel->setText(QStringLiteral("-"));
    ui->batchCurrentBenchmarkLabel->setText(QStringLiteral("-"));
    ui->batchCurrentProgressLabel->setText(QStringLiteral("-"));
    ui->batchCompletedCountLabel->setText(QStringLiteral("0"));
    ui->batchFailedCountLabel->setText(QStringLiteral("0"));
    ui->batchCancelledCountLabel->setText(QStringLiteral("0"));
    ui->batchNotStartedCountLabel->setText(QStringLiteral("0"));

    try {
        batchController_->start(
            capturedDefinition, capturedOutputTarget, capturedSettings);
    } catch (const std::exception& error) {
        presentationState_ = PresentationState::Idle;
        ui->batchStatusLabel->setText(QStringLiteral("Batch failed to start: %1")
            .arg(QString::fromUtf8(error.what())));
        applyPresentationState();
    }
}

void MainWindow::useCreatorInBatch()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy()
        || batchController_->isBusy() || closeAfterTerminal_ || closeAfterBatchTerminal_) {
        return;
    }

    const auto finalized = batchCreatorWidget_->finalizeRows();
    if (!finalized.isValid()) {
        batchCreatorWidget_->showFinalizationIssues(finalized.issues);
        return;
    }

    const auto entryCount = finalized.definition->entries().size();
    batchDefinition_ = finalized.definition;
    batchInputSource_ = BatchInputSource::Creator;
    ui->batchValidationSummaryLabel->setText(
        QStringLiteral("Valid batch - %1 entries").arg(entryCount));
    displayBatchIssues({});
    updateBatchPresentation();
    batchCreatorWidget_->showFinalizationSuccess(entryCount);
    ui->workflowTabWidget->setCurrentWidget(ui->batchTab);
}

void MainWindow::exportCreatorBatchJson()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy()
        || batchController_->isBusy() || closeAfterTerminal_ || closeAfterBatchTerminal_) {
        return;
    }

    const auto finalized = batchCreatorWidget_->finalizeRows();
    if (!finalized.isValid()) {
        batchCreatorWidget_->showFinalizationIssues(finalized.issues);
        return;
    }

    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Export Batch input JSON"), {},
                  QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) {
        return;
    }

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) {
            return;
        }
    }

    cryptobench::application::WriteResult writeResult;
    try {
        writeResult = cryptobench::application::AtomicFileWriter{}.writeAtomically(
            target, finalized.inputBytes);
    } catch (const std::exception& error) {
        writeResult = {false, QString::fromUtf8(error.what())};
    }

    if (!writeResult.success) {
        const QString message = writeResult.technicalMessage.isEmpty()
            ? QStringLiteral("Batch input JSON export failed.")
            : writeResult.technicalMessage;
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(
                this, QStringLiteral("Batch input JSON export failed"), message);
        } else {
            QMessageBox::warning(
                this, QStringLiteral("Batch input JSON export failed"), message);
        }
        return;
    }

    batchCreatorWidget_->showFinalizationSuccess(finalized.definition->entries().size());
    if (dialogCallbacks_.reportMessage) {
        dialogCallbacks_.reportMessage(
            this, QStringLiteral("Batch input JSON export complete"),
            QStringLiteral("Canonical Batch input JSON v1 was exported successfully."));
    } else {
        QMessageBox::information(
            this, QStringLiteral("Batch input JSON export complete"),
            QStringLiteral("Canonical Batch input JSON v1 was exported successfully."));
    }
}

void MainWindow::requestCancel()
{
    if (presentationState_ != PresentationState::SingleRunning || cancelRequested_) return;

    cancelRequested_ = true;
    presentationState_ = PresentationState::SingleCancelling;
    applyPresentationState();
    ui->statusLabel->setText(QStringLiteral("Cancelling..."));
    singleController_->requestCancel();
}

void MainWindow::requestBatchCancel()
{
    if (presentationState_ != PresentationState::BatchRunning || !batchController_->isBusy()) return;

    presentationState_ = PresentationState::BatchCancelling;
    applyPresentationState();
    ui->batchStatusLabel->setText(QStringLiteral("Cancelling..."));
    batchController_->requestCancel();
}

void MainWindow::onProgressChanged(const cryptobench::core::ProgressInfo& progress)
{
    ui->statusLabel->setText(phaseLabel(progress));
}

void MainWindow::onBenchmarkFinished(const cryptobench::core::BenchmarkResult& result)
{
    cancelRequested_ = false;
    const bool closeAfterTerminal = closeAfterTerminal_;
    if (!closeAfterTerminal) {
        setConfigurationEnabled(true);
    }
    ui->cancelButton->setEnabled(false);
    switch (result.status) {
        case cryptobench::core::BenchmarkStatus::Completed:
            exportableSingleResult_ = result;
            ui->statusLabel->setText(QStringLiteral("Completed"));
            displayCompletedResults(ui, result);
            break;
        case cryptobench::core::BenchmarkStatus::Cancelled:
            exportableSingleResult_.reset();
            ui->statusLabel->setText(QStringLiteral("Benchmark cancelled"));
            clearDisplayedResults(ui);
            break;
        case cryptobench::core::BenchmarkStatus::Failed:
            exportableSingleResult_.reset();
            if (result.error && !result.error->technicalMessage.empty()) {
                ui->statusLabel->setText(QStringLiteral("Benchmark failed: %1")
                    .arg(QString::fromStdString(result.error->technicalMessage)));
            } else {
                ui->statusLabel->setText(QStringLiteral("Benchmark failed"));
            }
            clearDisplayedResults(ui);
            break;
    }

    if (closeAfterTerminal) {
        presentationState_ = PresentationState::Idle;
        applyPresentationState();
        setConfigurationEnabled(false);
        ui->runButton->setEnabled(false);
        ui->cancelButton->setEnabled(false);
        ui->exportJsonButton->setEnabled(false);
        ui->exportCsvButton->setEnabled(false);
        QTimer::singleShot(0, this, [this]() {
            if (!singleController_->isBusy()) {
                closeAfterTerminal_ = false;
                close();
            }
        });
        return;
    }

    presentationState_ = PresentationState::Idle;
    applyPresentationState();
}

void MainWindow::onBatchProgressChanged(const cryptobench::application::BatchProgress& progress)
{
    if (progress.persistenceInProgress) {
        ui->batchStatusLabel->setText(QStringLiteral("Saving results..."));
    } else if (presentationState_ == PresentationState::BatchCancelling) {
        ui->batchStatusLabel->setText(QStringLiteral("Cancelling..."));
    } else {
        ui->batchStatusLabel->setText(QStringLiteral("Running"));
    }

    ui->batchCurrentEntryLabel->setText(progress.currentEntryIndex
        ? QStringLiteral("%1 / %2").arg(*progress.currentEntryIndex).arg(progress.totalEntries)
        : QStringLiteral("-"));
    ui->batchCompletedCountLabel->setText(QString::number(progress.completedCount));
    ui->batchFailedCountLabel->setText(QString::number(progress.failedCount));
    ui->batchCancelledCountLabel->setText(QString::number(progress.cancelledCount));
    ui->batchNotStartedCountLabel->setText(QString::number(progress.notStartedCount));

    if (progress.currentProfile && progress.currentOperation) {
        const auto* profile = cryptobench::core::AlgorithmRegistry::find(*progress.currentProfile);
        ui->batchCurrentBenchmarkLabel->setText(profile == nullptr
            ? QStringLiteral("-")
            : QString::fromUtf8(profile->displayName.data(),
                                static_cast<int>(profile->displayName.size())) +
                  QStringLiteral(" - ") + QString::fromUtf8(
                      cryptobench::gui::operationDisplayName(*progress.currentOperation).data(),
                      static_cast<qsizetype>(
                          cryptobench::gui::operationDisplayName(*progress.currentOperation).size())));
    } else {
        ui->batchCurrentBenchmarkLabel->setText(QStringLiteral("-"));
    }
    ui->batchCurrentProgressLabel->setText(progress.currentProgress
        ? phaseLabel(*progress.currentProgress)
        : QStringLiteral("-"));
}

void MainWindow::onBatchFinished(const cryptobench::application::BatchExecutionState& state)
{
    const auto finalProgress = batchController_->progress();
    onBatchProgressChanged(finalProgress);
    QString terminalStatus;

    switch (state.status) {
    case cryptobench::application::BatchStatus::Completed:
        terminalStatus = QStringLiteral("Completed");
        break;
    case cryptobench::application::BatchStatus::CompletedWithFailures:
        terminalStatus = QStringLiteral("Completed with failures");
        break;
    case cryptobench::application::BatchStatus::Cancelled:
        terminalStatus = QStringLiteral("Cancelled");
        break;
    case cryptobench::application::BatchStatus::Failed:
        if (state.batchError && !state.batchError->technicalMessage.empty()) {
            terminalStatus = QStringLiteral("Failed: %1")
                .arg(QString::fromStdString(state.batchError->technicalMessage));
        } else {
            terminalStatus = QStringLiteral("Failed");
        }
        break;
    case cryptobench::application::BatchStatus::InProgress:
        return;
    }

    presentationState_ = PresentationState::Idle;
    applyPresentationState();
    ui->batchStatusLabel->setText(terminalStatus);

    if (closeAfterBatchTerminal_ && !batchController_->isBusy()) {
        handleBatchCloseAfterTerminal();
    }
}

void MainWindow::handleBatchCloseAfterTerminal()
{
    if (!closeAfterBatchTerminal_ || batchController_->isBusy() ||
        presentationState_ != PresentationState::Idle) {
        return;
    }

    if (batchController_->state().status != cryptobench::application::BatchStatus::Failed) {
        closeAfterBatchTerminal_ = false;
        QTimer::singleShot(0, this, [this]() {
            if (!batchController_->isBusy()) close();
        });
        return;
    }

    QMessageBox recoveryDialog(this);
    recoveryDialog.setWindowTitle(QStringLiteral("Batch persistence failed"));
    recoveryDialog.setText(QStringLiteral("The final Batch state could not be persisted."));
    recoveryDialog.setInformativeText(QStringLiteral("Choose how to finish closing the application."));
    auto* saveButton = recoveryDialog.addButton(QStringLiteral("Save As..."), QMessageBox::AcceptRole);
    auto* exitButton = recoveryDialog.addButton(QStringLiteral("Exit without saving"), QMessageBox::DestructiveRole);
    auto* keepButton = recoveryDialog.addButton(QStringLiteral("Keep open"), QMessageBox::RejectRole);
    recoveryDialog.exec();

    if (recoveryDialog.clickedButton() == exitButton) {
        closeAfterBatchTerminal_ = false;
        close();
        return;
    }
    if (recoveryDialog.clickedButton() == saveButton && saveBatchAs()) {
        closeAfterBatchTerminal_ = false;
        QTimer::singleShot(0, this, [this]() {
            if (!batchController_->isBusy()) close();
        });
        return;
    }

    Q_UNUSED(keepButton);
    closeAfterBatchTerminal_ = false;
    applyPresentationState();
}

bool MainWindow::saveBatchAs()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        batchController_->isBusy() ||
        batchController_->state().status != cryptobench::application::BatchStatus::Failed) {
        return false;
    }

    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Save batch result as"), {},
                  QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) return false;

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) return false;
    }

    cryptobench::application::WriteResult writeResult;
    try {
        writeResult = batchController_->saveAs(target);
    } catch (const std::exception& error) {
        writeResult = {false, QString::fromUtf8(error.what())};
    }

    if (!writeResult.success) {
        const QString message = writeResult.technicalMessage.isEmpty()
            ? QStringLiteral("Batch Save As failed.")
            : writeResult.technicalMessage;
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(this, QStringLiteral("Batch Save As failed"), message);
        } else {
            QMessageBox::warning(this, QStringLiteral("Batch Save As failed"), message);
        }
        return false;
    }

    if (dialogCallbacks_.reportMessage) {
        dialogCallbacks_.reportMessage(this, QStringLiteral("Batch Save As complete"),
                                       QStringLiteral("The Batch result was saved successfully."));
    } else {
        QMessageBox::information(this, QStringLiteral("Batch Save As complete"),
                                 QStringLiteral("The Batch result was saved successfully."));
    }
    return true;
}

void MainWindow::exportSingleResult()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        !exportableSingleResult_.has_value()) return;

    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Export JSON"), {}, QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) return;

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) return;
    }

    try {
        const auto document = cryptobench::application::SingleResultDocumentService{}.create(
            *exportableSingleResult_);
        const auto json = cryptobench::application::JsonResultExportService{}.serialize(document);
        const auto writeResult = cryptobench::application::AtomicFileWriter{}.writeAtomically(target, json);
        if (!writeResult.success) {
            if (dialogCallbacks_.reportMessage) {
                dialogCallbacks_.reportMessage(this, QStringLiteral("Export failed"), writeResult.technicalMessage);
            } else {
                QMessageBox::warning(this, QStringLiteral("Export failed"), writeResult.technicalMessage);
            }
            return;
        }
    } catch (const std::exception& error) {
        const QString message = QString::fromUtf8(error.what());
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(this, QStringLiteral("Export failed"), message);
        } else {
            QMessageBox::warning(this, QStringLiteral("Export failed"), message);
        }
        return;
    }

    if (dialogCallbacks_.reportMessage) {
        dialogCallbacks_.reportMessage(this, QStringLiteral("Export complete"),
                                       QStringLiteral("JSON was exported successfully."));
    } else {
        QMessageBox::information(this, QStringLiteral("Export complete"),
                                 QStringLiteral("JSON was exported successfully."));
    }
}

void MainWindow::exportSingleCsvResult()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy() ||
        batchController_->isBusy() || closeAfterTerminal_ || closeAfterBatchTerminal_ ||
        !exportableSingleResult_.has_value() ||
        exportableSingleResult_->status != cryptobench::core::BenchmarkStatus::Completed) {
        return;
    }

    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Export CSV"), {},
                  QStringLiteral("CSV files (*.csv);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) {
        return;
    }

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) {
            return;
        }
    }

    try {
        const auto document = cryptobench::application::SingleResultDocumentService{}.create(
            *exportableSingleResult_);
        const auto csv = cryptobench::application::CsvResultExportService{}.serialize(document);
        const auto writeResult =
            cryptobench::application::AtomicFileWriter{}.writeAtomically(target, csv);
        if (!writeResult.success) {
            const QString message = writeResult.technicalMessage.isEmpty()
                ? QStringLiteral("CSV export failed.")
                : writeResult.technicalMessage;
            if (dialogCallbacks_.reportMessage) {
                dialogCallbacks_.reportMessage(this, QStringLiteral("CSV export failed"), message);
            } else {
                QMessageBox::warning(this, QStringLiteral("CSV export failed"), message);
            }
            return;
        }
    } catch (const std::exception& error) {
        const QString message = QString::fromUtf8(error.what());
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(this, QStringLiteral("CSV export failed"), message);
        } else {
            QMessageBox::warning(this, QStringLiteral("CSV export failed"), message);
        }
        return;
    }

    if (dialogCallbacks_.reportMessage) {
        dialogCallbacks_.reportMessage(this, QStringLiteral("CSV export complete"),
                                       QStringLiteral("CSV was exported successfully."));
    } else {
        QMessageBox::information(this, QStringLiteral("CSV export complete"),
                                 QStringLiteral("CSV was exported successfully."));
    }
}

void MainWindow::exportBatchCsvResult()
{
    if (batchConfirmationPending_ || presentationState_ != PresentationState::Idle ||
        singleController_->isBusy() ||
        batchController_->isBusy() || closeAfterTerminal_ || closeAfterBatchTerminal_ ||
        !isTerminalBatchStatus(batchController_->state().status)) {
        return;
    }

    const auto chooseSaveTarget = dialogCallbacks_.chooseSaveTarget
        ? dialogCallbacks_.chooseSaveTarget
        : [this](QWidget*) {
              QString defaultTarget;
              if (!batchOutputTarget_.isEmpty()) {
                  const QFileInfo jsonTarget(batchOutputTarget_);
                  defaultTarget = jsonTarget.dir().filePath(
                      jsonTarget.completeBaseName() + QStringLiteral("-analysis.csv"));
              }
              return QFileDialog::getSaveFileName(
                  this, QStringLiteral("Export Batch CSV"), defaultTarget,
                  QStringLiteral("CSV files (*.csv);;All files (*)"));
          };
    const QString target = chooseSaveTarget(this);
    if (target.isEmpty()) {
        return;
    }

    if (!batchOutputTarget_.isEmpty() && sameFilePath(target, batchOutputTarget_)) {
        const QString message = QStringLiteral(
            "The CSV target resolves to the canonical Batch JSON output file. Choose a different target.");
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(this, QStringLiteral("Batch CSV export failed"), message);
        } else {
            QMessageBox::warning(this, QStringLiteral("Batch CSV export failed"), message);
        }
        return;
    }

    if (QFileInfo::exists(target)) {
        const auto confirmOverwrite = dialogCallbacks_.confirmOverwrite
            ? dialogCallbacks_.confirmOverwrite
            : [this](QWidget*, const QString& path) {
                  return QMessageBox::question(
                             this, QStringLiteral("Replace existing file"),
                             QStringLiteral("The target already exists. Replace it?\n%1").arg(path),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                      == QMessageBox::Yes;
              };
        if (!confirmOverwrite(this, target)) {
            return;
        }
    }

    try {
        const auto& state = batchController_->state();
        const auto document = cryptobench::application::BatchResultDocumentService{}.create(state);
        const auto csv = cryptobench::application::CsvResultExportService{}.serialize(document);
        const auto writeResult =
            cryptobench::application::AtomicFileWriter{}.writeAtomically(target, csv);
        if (!writeResult.success) {
            const QString message = writeResult.technicalMessage.isEmpty()
                ? QStringLiteral("Batch CSV export failed.")
                : writeResult.technicalMessage;
            if (dialogCallbacks_.reportMessage) {
                dialogCallbacks_.reportMessage(this, QStringLiteral("Batch CSV export failed"), message);
            } else {
                QMessageBox::warning(this, QStringLiteral("Batch CSV export failed"), message);
            }
            return;
        }
    } catch (const std::exception& error) {
        const QString message = QString::fromUtf8(error.what());
        if (dialogCallbacks_.reportMessage) {
            dialogCallbacks_.reportMessage(this, QStringLiteral("Batch CSV export failed"), message);
        } else {
            QMessageBox::warning(this, QStringLiteral("Batch CSV export failed"), message);
        }
        return;
    }

    if (dialogCallbacks_.reportMessage) {
        dialogCallbacks_.reportMessage(this, QStringLiteral("Batch CSV export complete"),
                                       QStringLiteral("Batch CSV was exported successfully."));
    } else {
        QMessageBox::information(this, QStringLiteral("Batch CSV export complete"),
                                 QStringLiteral("Batch CSV was exported successfully."));
    }
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (batchConfirmationPending_) {
        batchConfirmationCloseRequested_ = true;
        event->ignore();
        return;
    }

    if (presentationState_ == PresentationState::BatchRunning) {
        const auto decision = QMessageBox::question(
            this, QStringLiteral("Batch running"),
            QStringLiteral("Batch is running. Cancel and exit?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (decision != QMessageBox::Yes) {
            event->ignore();
            return;
        }

        event->ignore();
        closeAfterBatchTerminal_ = true;
        if (batchController_->isBusy()) {
            requestBatchCancel();
        } else {
            handleBatchCloseAfterTerminal();
        }
        return;
    }

    if (presentationState_ == PresentationState::BatchCancelling) {
        const auto decision = QMessageBox::question(
            this, QStringLiteral("Batch cancelling"),
            QStringLiteral("Exit after Batch cancellation and cleanup?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        closeAfterBatchTerminal_ = decision == QMessageBox::Yes;
        if (closeAfterBatchTerminal_ && !batchController_->isBusy()) {
            handleBatchCloseAfterTerminal();
        }
        event->ignore();
        return;
    }

    if (presentationState_ == PresentationState::Idle && !singleController_->isBusy()) {
        event->accept();
        return;
    }

    const auto decision = QMessageBox::question(
        this,
        QStringLiteral("Benchmark running"),
        QStringLiteral("Benchmark is running. Cancel and exit?"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (decision != QMessageBox::Yes) {
        event->ignore();
        return;
    }

    event->ignore();
    if (!singleController_->isBusy()) {
        event->accept();
        return;
    }

    closeAfterTerminal_ = true;
    if (!cancelRequested_) {
        requestCancel();
    }
}

std::optional<cryptobench::core::BenchmarkConfig> MainWindow::buildBenchmarkConfig(
    cryptobench::core::ValidationResult& validation) const
{
    cryptobench::gui::BenchmarkSelection selection;
    const QVariant categoryData = ui->categoryComboBox->currentData();
    const QVariant profileData = ui->profileComboBox->currentData();
    const QVariant operationData = ui->operationComboBox->currentData();
    if (categoryData.isValid()) {
        selection.category = static_cast<PrimitiveCategory>(categoryData.toInt());
    }
    if (profileData.isValid()) {
        selection.profile = static_cast<AlgorithmProfileId>(profileData.toInt());
    }
    if (operationData.isValid()) {
        selection.operation = static_cast<BenchmarkOperation>(operationData.toInt());
    }
    const QVariant modeData = ui->signatureInputModeComboBox->currentData();
    if (modeData.isValid()) {
        selection.signatureInputMode = static_cast<SignatureInputMode>(modeData.toInt());
    }
    selection.workloadSizeBytes =
        static_cast<cryptobench::core::WorkloadBytes>(ui->workloadSizeSpinBox->value());
    selection.iterationsPerRun = static_cast<std::uint64_t>(ui->iterationsSpinBox->value());
    selection.runs = static_cast<std::uint32_t>(ui->runsSpinBox->value());

    auto config = cryptobench::gui::benchmarkConfigFromSelection(selection);
    if (!config.has_value()) {
        return std::nullopt;
    }
    validation = cryptobench::core::ConfigValidator{}.validate(*config);
    if (!validation.isValid()) {
        return std::nullopt;
    }
    return config;
}
