#pragma once

#include <QCloseEvent>
#include <QMainWindow>

#include <functional>
#include <memory>
#include <optional>

#include <cryptobench/application/BenchmarkController.h>
#include <cryptobench/application/BatchController.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/ConfigValidation.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProgressInfo.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    struct DialogCallbacks {
        std::function<QString(QWidget*)> chooseOpenTarget;
        std::function<QString(QWidget*)> chooseSaveTarget;
        std::function<bool(QWidget*, const QString&)> confirmOverwrite;
        std::function<void(QWidget*, const QString&, const QString&)> reportMessage;
    };

    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void setDialogCallbacks(DialogCallbacks callbacks);

private:
    enum class PresentationState {
        Idle,
        SingleRunning,
        SingleCancelling,
        BatchRunning,
        BatchCancelling
    };

    void populateCategories();
    void populateProfiles(cryptobench::core::PrimitiveCategory category, bool preserveOperation);
    void populateOperations(const cryptobench::core::AlgorithmProfileId* profileId, bool preserveOperation);
    void updateInputControls();
    void setConfigurationEnabled(bool enabled);
    void updateRunAvailability();
    void applyPresentationState();
    void startBenchmark();
    void startBatch();
    void requestCancel();
    void requestBatchCancel();
    void exportSingleResult();
    void browseBatchInput();
    void browseBatchOutput();
    void updateBatchPresentation();
    void displayBatchIssues(const std::vector<cryptobench::application::BatchInputIssue>& issues);
    void onProgressChanged(const cryptobench::core::ProgressInfo& progress);
    void onBenchmarkFinished(const cryptobench::core::BenchmarkResult& result);
    void onBatchProgressChanged(const cryptobench::application::BatchProgress& progress);
    void onBatchFinished(const cryptobench::application::BatchExecutionState& state);
    std::optional<cryptobench::core::BenchmarkConfig> buildBenchmarkConfig(
        cryptobench::core::ValidationResult& validation) const;
    void closeEvent(QCloseEvent* event) override;

    Ui::MainWindow* ui;
    std::unique_ptr<cryptobench::application::BenchmarkController> singleController_;
    std::unique_ptr<cryptobench::application::BatchController> batchController_;
    PresentationState presentationState_ = PresentationState::Idle;
    std::optional<cryptobench::core::BenchmarkResult> exportableSingleResult_;
    std::optional<cryptobench::application::BatchDefinition> batchDefinition_;
    QString batchOutputTarget_;
    DialogCallbacks dialogCallbacks_;
    bool cancelRequested_ = false;
    bool closeAfterTerminal_ = false;
};
