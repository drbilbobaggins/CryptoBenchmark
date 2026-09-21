#pragma once

#include <QCloseEvent>
#include <QMainWindow>

#include <memory>
#include <optional>

#include <cryptobench/application/BenchmarkController.h>
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
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    void populateCategories();
    void populateProfiles(cryptobench::core::PrimitiveCategory category, bool preserveOperation);
    void populateOperations(const cryptobench::core::AlgorithmProfileId* profileId, bool preserveOperation);
    void updateInputControls();
    void setConfigurationEnabled(bool enabled);
    void updateRunAvailability();
    void startBenchmark();
    void requestCancel();
    void onProgressChanged(const cryptobench::core::ProgressInfo& progress);
    void onBenchmarkFinished(const cryptobench::core::BenchmarkResult& result);
    std::optional<cryptobench::core::BenchmarkConfig> buildBenchmarkConfig(
        cryptobench::core::ValidationResult& validation) const;
    void closeEvent(QCloseEvent* event) override;

    Ui::MainWindow* ui;
    std::unique_ptr<cryptobench::application::BenchmarkController> controller_;
    bool cancelRequested_ = false;
    bool closeAfterTerminal_ = false;
};
