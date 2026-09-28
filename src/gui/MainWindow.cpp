#include "MainWindow.h"

#include "ui_MainWindow.h"

#include <QFileDialog>
#include <QFileInfo>
#include <QListWidget>
#include <QLineEdit>
#include <QMessageBox>
#include <QSignalBlocker>
#include <QTimer>

#include <array>
#include <exception>
#include <utility>
#include <variant>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/InputCapability.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/JsonResultExportService.h>
#include <cryptobench/application/SingleResultDocumentService.h>
#include <cryptobench/application/BatchInputParser.h>

namespace {

using cryptobench::core::AlgorithmProfileId;
using cryptobench::core::BenchmarkOperation;
using cryptobench::core::PrimitiveCategory;
using cryptobench::core::SignatureInputSupport;

enum class SignatureInputMode {
    Prehashed,
    Message
};

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

QString operationLabel(BenchmarkOperation operation)
{
    switch (operation) {
        case BenchmarkOperation::KeyGen: return QStringLiteral("Key generation");
        case BenchmarkOperation::Sign: return QStringLiteral("Sign");
        case BenchmarkOperation::Verify: return QStringLiteral("Verify");
        case BenchmarkOperation::Derive: return QStringLiteral("Derive");
        case BenchmarkOperation::Encapsulate: return QStringLiteral("Encapsulate");
        case BenchmarkOperation::Decapsulate: return QStringLiteral("Decapsulate");
        case BenchmarkOperation::Encrypt: return QStringLiteral("Encrypt");
        case BenchmarkOperation::Decrypt: return QStringLiteral("Decrypt");
        case BenchmarkOperation::Hash: return QStringLiteral("Hash");
        case BenchmarkOperation::Xof: return QStringLiteral("XOF");
    }

    return {};
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

DisplayUnit memoryUnit(double mean)
{
    if (mean < 1'024.0) return {QStringLiteral("B"), 1.0};
    if (mean < 1'048'576.0) return {QStringLiteral("KiB"), 1'024.0};
    return {QStringLiteral("MiB"), 1'048'576.0};
}

void setStatisticRow(
    QTableWidget* table,
    int row,
    const QString& label,
    const cryptobench::core::Statistics<double>& statistics,
    const DisplayUnit& unit)
{
    table->setItem(row, 0, new QTableWidgetItem(label + QStringLiteral(" (") + unit.suffix + QLatin1Char(')')));
    table->setItem(row, 1, new QTableWidgetItem(formatStatistic(statistics.mean, unit.divisor)));
    table->setItem(row, 2, new QTableWidgetItem(formatStatistic(statistics.median, unit.divisor)));
    table->setItem(row, 3, new QTableWidgetItem(formatStatistic(statistics.min, unit.divisor)));
    table->setItem(row, 4, new QTableWidgetItem(formatStatistic(statistics.max, unit.divisor)));
    table->setItem(row, 5, new QTableWidgetItem(formatStatistic(statistics.stddev, unit.divisor)));
}

void clearDisplayedResults(Ui::MainWindow* ui)
{
    ui->resultsTable->setRowCount(0);
    ui->resultsPlaceholderLabel->setVisible(true);
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
    const auto elapsedUnit = timeUnit(statistics.elapsedNanosecondsPerOperation.mean);
    const auto cpuUnit = timeUnit(statistics.cpuNanosecondsPerOperation.mean);
    const auto memoryDisplayUnit = memoryUnit(statistics.peakDeltaBytes.mean);

    ui->resultsTable->setRowCount(3);
    setStatisticRow(ui->resultsTable, 0, QStringLiteral("Wall-clock / operation"),
                    statistics.elapsedNanosecondsPerOperation, elapsedUnit);
    setStatisticRow(ui->resultsTable, 1, QStringLiteral("Process CPU time / operation"),
                    statistics.cpuNanosecondsPerOperation, cpuUnit);
    setStatisticRow(ui->resultsTable, 2, QStringLiteral("Peak PrivateUsage delta"),
                    statistics.peakDeltaBytes, memoryDisplayUnit);
    ui->resultsPlaceholderLabel->setVisible(false);
}

constexpr std::array<BenchmarkOperation, 10> kOperations = {
    BenchmarkOperation::KeyGen,
    BenchmarkOperation::Sign,
    BenchmarkOperation::Verify,
    BenchmarkOperation::Derive,
    BenchmarkOperation::Encapsulate,
    BenchmarkOperation::Decapsulate,
    BenchmarkOperation::Encrypt,
    BenchmarkOperation::Decrypt,
    BenchmarkOperation::Hash,
    BenchmarkOperation::Xof
};

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , singleController_(std::make_unique<cryptobench::application::BenchmarkController>())
    , batchController_(std::make_unique<cryptobench::application::BatchController>())
{
    ui->setupUi(this);

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
    connect(ui->exportJsonButton, &QPushButton::clicked, this, &MainWindow::exportSingleResult);
    connect(ui->batchInputBrowseButton, &QPushButton::clicked, this, &MainWindow::browseBatchInput);
    connect(ui->batchOutputBrowseButton, &QPushButton::clicked, this, &MainWindow::browseBatchOutput);

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

void MainWindow::populateCategories()
{
    const QSignalBlocker blocker(ui->categoryComboBox);
    ui->categoryComboBox->clear();
    ui->categoryComboBox->addItem(QStringLiteral("Digital signatures"), toItemData(PrimitiveCategory::Signature));
    ui->categoryComboBox->addItem(QStringLiteral("Key establishment / KEM"), toItemData(PrimitiveCategory::KeyEstablishment));
    ui->categoryComboBox->addItem(QStringLiteral("AEAD"), toItemData(PrimitiveCategory::Aead));
    ui->categoryComboBox->addItem(QStringLiteral("Hash / XOF"), toItemData(PrimitiveCategory::HashXof));
    ui->categoryComboBox->setCurrentIndex(0);
    ui->categoryComboBox->setEnabled(ui->categoryComboBox->count() > 0);

    const auto category = static_cast<PrimitiveCategory>(ui->categoryComboBox->currentData().toInt());
    populateProfiles(category, false);
}

void MainWindow::populateProfiles(PrimitiveCategory category, bool preserveOperation)
{
    const QSignalBlocker blocker(ui->profileComboBox);
    ui->profileComboBox->clear();

    for (const auto& profile : cryptobench::core::AlgorithmRegistry::all()) {
        if (profile.category == category) {
            ui->profileComboBox->addItem(QString::fromUtf8(profile.displayName.data(),
                static_cast<int>(profile.displayName.size())), toItemData(profile.id));
        }
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
        for (const BenchmarkOperation operation : kOperations) {
            if (profile->operations.contains(operation)) {
                ui->operationComboBox->addItem(operationLabel(operation), toItemData(operation));
            }
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

    bool showSignatureMode = false;
    bool showSize = false;
    bool enableSize = false;
    QString sizeLabel;

    if (profile != nullptr && profile->category == PrimitiveCategory::Signature) {
        const bool messageOperation = operation == BenchmarkOperation::Sign ||
                                      operation == BenchmarkOperation::Verify;
        if (messageOperation) {
            const QVariant previousMode = ui->signatureInputModeComboBox->currentData();
            const QSignalBlocker blocker(ui->signatureInputModeComboBox);
            ui->signatureInputModeComboBox->clear();
            if (const auto* capability = std::get_if<cryptobench::core::SignatureInputCapability>(
                    &profile->inputCapability)) {
                if (capability->support == SignatureInputSupport::PrehashedAndMessage) {
                    ui->signatureInputModeComboBox->addItem(
                        QStringLiteral("Prehashed"), toItemData(SignatureInputMode::Prehashed));
                }
                ui->signatureInputModeComboBox->addItem(
                    QStringLiteral("Message"), toItemData(SignatureInputMode::Message));
                const int preservedIndex = previousMode.isValid()
                    ? ui->signatureInputModeComboBox->findData(previousMode)
                    : -1;
                ui->signatureInputModeComboBox->setCurrentIndex(
                    preservedIndex >= 0 ? preservedIndex : 0);
            }
            showSignatureMode = ui->signatureInputModeComboBox->count() > 0;

            const auto mode = static_cast<SignatureInputMode>(
                ui->signatureInputModeComboBox->currentData().toInt());
            showSize = mode == SignatureInputMode::Message;
            enableSize = showSize;
            sizeLabel = QStringLiteral("Message size:");
        } else {
            const QSignalBlocker blocker(ui->signatureInputModeComboBox);
            ui->signatureInputModeComboBox->clear();
        }
    } else if (profile != nullptr && profile->category == PrimitiveCategory::Aead) {
        showSize = true;
        enableSize = true;
        sizeLabel = QStringLiteral("Plaintext size:");
    } else if (profile != nullptr && profile->category == PrimitiveCategory::HashXof) {
        showSize = true;
        enableSize = true;
        sizeLabel = QStringLiteral("Input size:");
    } else {
        const QSignalBlocker blocker(ui->signatureInputModeComboBox);
        ui->signatureInputModeComboBox->clear();
    }

    ui->signatureInputModeLabel->setVisible(showSignatureMode);
    ui->signatureInputModeComboBox->setVisible(showSignatureMode);
    ui->signatureInputModeComboBox->setEnabled(showSignatureMode && ui->signatureInputModeComboBox->count() > 0);
    ui->workloadSizeLabel->setText(sizeLabel);
    ui->workloadSizeLabel->setVisible(showSize);
    ui->workloadSizeSpinBox->setVisible(showSize);
    ui->workloadUnitLabel->setVisible(showSize);
    ui->workloadSizeSpinBox->setEnabled(enableSize);

    if (showSize) {
        const int minimum = profile != nullptr && profile->category == PrimitiveCategory::HashXof ? 0 : 1;
        ui->workloadSizeSpinBox->setRange(minimum, static_cast<int>(cryptobench::core::kMaxWorkloadBytes));
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
        buildBenchmarkConfig(validation).has_value());
}

void MainWindow::applyPresentationState()
{
    const bool idle = presentationState_ == PresentationState::Idle;
    const bool singleRunning = presentationState_ == PresentationState::SingleRunning;

    setConfigurationEnabled(idle);
    ui->cancelButton->setEnabled(singleRunning);
    ui->exportJsonButton->setEnabled(idle && exportableSingleResult_.has_value());
    updateRunAvailability();
    updateBatchPresentation();
}

void MainWindow::updateBatchPresentation()
{
    const bool idle = presentationState_ == PresentationState::Idle;
    const bool batchRunning = presentationState_ == PresentationState::BatchRunning;
    ui->batchInputPathLineEdit->setEnabled(idle);
    ui->batchInputBrowseButton->setEnabled(idle);
    ui->batchOutputPathLineEdit->setEnabled(idle);
    ui->batchOutputBrowseButton->setEnabled(idle);
    ui->batchRunButton->setEnabled(
        idle && batchDefinition_.has_value() && !batchOutputTarget_.isEmpty());
    ui->batchCancelButton->setEnabled(batchRunning);
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
    const auto chooseOpenTarget = dialogCallbacks_.chooseOpenTarget
        ? dialogCallbacks_.chooseOpenTarget
        : [this](QWidget*) {
              return QFileDialog::getOpenFileName(
                  this, QStringLiteral("Select batch input"), {}, QStringLiteral("JSON files (*.json);;All files (*)"));
          };
    const QString target = chooseOpenTarget(this);
    if (target.isEmpty()) return;

    const auto result = cryptobench::application::BatchInputParser{}.parseFile(target);
    batchDefinition_ = result.definition;
    if (batchDefinition_.has_value() && result.issues.empty()) {
        ui->batchInputPathLineEdit->setText(target);
        ui->batchValidationSummaryLabel->setText(
            QStringLiteral("Valid batch - %1 entries").arg(batchDefinition_->entries().size()));
        displayBatchIssues({});
        updateBatchPresentation();
        return;
    }

    batchDefinition_.reset();
    ui->batchInputPathLineEdit->setText(target);
    ui->batchValidationSummaryLabel->setText(QStringLiteral("Invalid batch"));
    displayBatchIssues(result.issues);
    updateBatchPresentation();
}

void MainWindow::browseBatchOutput()
{
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
    if (presentationState_ != PresentationState::Idle || singleController_->isBusy() ||
        batchController_->isBusy()) return;

    cryptobench::core::ValidationResult validation;
    const auto config = buildBenchmarkConfig(validation);
    if (!config) {
        updateInputControls();
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
    if (presentationState_ != PresentationState::Idle || singleController_->isBusy() ||
        batchController_->isBusy() || !batchDefinition_.has_value() || batchOutputTarget_.isEmpty()) {
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
        batchController_->start(*batchDefinition_, batchOutputTarget_);
    } catch (const std::exception& error) {
        presentationState_ = PresentationState::Idle;
        ui->batchStatusLabel->setText(QStringLiteral("Batch failed to start: %1")
            .arg(QString::fromUtf8(error.what())));
        applyPresentationState();
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
                  QStringLiteral(" - ") + operationLabel(*progress.currentOperation));
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
}

void MainWindow::exportSingleResult()
{
    if (presentationState_ != PresentationState::Idle || !exportableSingleResult_.has_value()) return;

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

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (presentationState_ == PresentationState::BatchRunning ||
        presentationState_ == PresentationState::BatchCancelling) {
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
    const QVariant profileData = ui->profileComboBox->currentData();
    const QVariant operationData = ui->operationComboBox->currentData();
    if (!profileData.isValid() || !operationData.isValid()) {
        return std::nullopt;
    }

    const auto profileId = static_cast<AlgorithmProfileId>(profileData.toInt());
    const auto operation = static_cast<BenchmarkOperation>(operationData.toInt());
    const auto* profile = cryptobench::core::AlgorithmRegistry::find(profileId);
    if (profile == nullptr || !profile->operations.contains(operation)) {
        return std::nullopt;
    }

    cryptobench::core::PrimitiveConfig parameters;
    switch (profile->category) {
        case PrimitiveCategory::Signature: {
            if (operation == BenchmarkOperation::KeyGen) {
                parameters = cryptobench::core::SignatureConfig{
                    cryptobench::core::NoSignatureInput{}};
                break;
            }

            const auto* capability = std::get_if<cryptobench::core::SignatureInputCapability>(
                &profile->inputCapability);
            if (capability == nullptr ||
                (capability->support == SignatureInputSupport::MessageOnly &&
                 ui->signatureInputModeComboBox->currentData().toInt() !=
                     toItemData(SignatureInputMode::Message))) {
                return std::nullopt;
            }

            const auto mode = static_cast<SignatureInputMode>(
                ui->signatureInputModeComboBox->currentData().toInt());
            if (mode == SignatureInputMode::Prehashed) {
                if (capability->support != SignatureInputSupport::PrehashedAndMessage) {
                    return std::nullopt;
                }
                parameters = cryptobench::core::SignatureConfig{
                    cryptobench::core::PrehashedInput{}};
            } else if (mode == SignatureInputMode::Message) {
                parameters = cryptobench::core::SignatureConfig{
                    cryptobench::core::MessageInput{
                        static_cast<cryptobench::core::WorkloadBytes>(ui->workloadSizeSpinBox->value())}};
            } else {
                return std::nullopt;
            }
            break;
        }
        case PrimitiveCategory::KeyEstablishment:
            parameters = cryptobench::core::KeyEstablishmentConfig{};
            break;
        case PrimitiveCategory::Aead:
            parameters = cryptobench::core::AeadConfig{
                static_cast<cryptobench::core::WorkloadBytes>(ui->workloadSizeSpinBox->value())};
            break;
        case PrimitiveCategory::HashXof:
            parameters = cryptobench::core::HashConfig{
                static_cast<cryptobench::core::WorkloadBytes>(ui->workloadSizeSpinBox->value())};
            break;
    }

    cryptobench::core::BenchmarkConfig config{
        profileId,
        operation,
        static_cast<std::uint64_t>(ui->iterationsSpinBox->value()),
        static_cast<std::uint32_t>(ui->runsSpinBox->value()),
        std::move(parameters)};
    validation = cryptobench::core::ConfigValidator{}.validate(config);
    if (!validation.isValid()) {
        return std::nullopt;
    }

    return config;
}
