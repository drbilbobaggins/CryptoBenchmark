#include "../src/gui/MainWindow.h"

#include <QApplication>
#include <QComboBox>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
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

#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace cryptobench;

namespace {

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
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0,
            "initial results table was not empty");

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

void requireCompletedTable(MainWindow& window)
{
    auto* table = widget<QTableWidget>(window, "resultsTable");
    require(table->rowCount() == 3, "Completed result did not contain exactly three rows");
    for (int row = 0; row < 3; ++row) {
        require(table->item(row, 0) != nullptr &&
                    (table->item(row, 0)->text().contains(QStringLiteral("ns")) ||
                     table->item(row, 0)->text().contains(QStringLiteral("µs")) ||
                     table->item(row, 0)->text().contains(QStringLiteral("ms")) ||
                     table->item(row, 0)->text().contains(QStringLiteral("B")) ||
                     table->item(row, 0)->text().contains(QStringLiteral("KiB")) ||
                     table->item(row, 0)->text().contains(QStringLiteral("MiB"))),
                "result row did not contain a presentation unit");
        for (int column = 1; column < 6; ++column) {
            require(table->item(row, column) != nullptr &&
                        !table->item(row, column)->text().isEmpty(),
                    "result statistic cell was empty");
        }
    }
    require(!widget<QLabel>(window, "resultsPlaceholderLabel")->isVisible(),
            "results placeholder remained visible after completion");
}

void testCompletedAndReplacement()
{
    setScenario("completed");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* run = widget<QPushButton>(window, "runButton");
    auto* cancel = widget<QPushButton>(window, "cancelButton");
    run->click();
    require(!run->isEnabled() && !widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                cancel->isEnabled(),
            "Running state did not lock configuration and enable Cancel");
    waitForCompleted(window);
    require(!cancel->isEnabled(), "Cancel remained enabled after completion");
    require(widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "Completed result did not enable Export JSON");
    require(widget<QComboBox>(window, "categoryComboBox")->isEnabled(),
            "configuration was not restored after completion");
    requireCompletedTable(window);

    widget<QSpinBox>(window, "workloadSizeSpinBox")->setValue(16);
    run->click();
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QLabel>(window, "resultsPlaceholderLabel")->isVisible() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "old result was not cleared at new Run start");
    waitForCompleted(window);
    requireCompletedTable(window);
    clearScenario();
}

void testCancelAndReuse()
{
    setScenario("wait-before-measurement");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* run = widget<QPushButton>(window, "runButton");
    auto* cancel = widget<QPushButton>(window, "cancelButton");
    run->click();
    waitUntil([&] { return cancel->isEnabled(); }, 5'000);
    cancel->click();
    require(status(window) == QStringLiteral("Cancelling...") && !cancel->isEnabled() &&
                !run->isEnabled(),
            "Cancel did not enter the Cancelling presentation state");
    waitUntil([&] { return status(window) == QStringLiteral("Benchmark cancelled"); }, 10'000);
    require(widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "Cancelled result did not restore an empty idle GUI");

    setScenario("completed");
    run->click();
    waitForCompleted(window);
    requireCompletedTable(window);
    clearScenario();
}

void testFailedAndReuse()
{
    setScenario("failed-disconnect-immediately");
    MainWindow window;
    window.show();
    configureHash(window);
    auto* run = widget<QPushButton>(window, "runButton");
    run->click();
    waitUntil([&] { return status(window).startsWith(QStringLiteral("Benchmark failed:")); }, 10'000);
    require(status(window).contains(QStringLiteral("scripted worker failure")),
            "Failed result did not expose the scripted worker technical message");
    require(!widget<QPushButton>(window, "cancelButton")->isEnabled() &&
                widget<QTableWidget>(window, "resultsTable")->rowCount() == 0 &&
                widget<QComboBox>(window, "categoryComboBox")->isEnabled() &&
                !widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
            "Failed result did not restore the idle empty GUI");

    setScenario("completed");
    run->click();
    waitForCompleted(window);
    requireCompletedTable(window);
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

void testSingleJsonExport()
{
    setScenario("completed");
    QTemporaryDir directory;
    require(directory.isValid(), "temporary export directory was not created");
    MainWindow window;
    window.show();
    configureHash(window);

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
    require(document.object().value("mode") == QStringLiteral("single") &&
                document.object().value("status") == QStringLiteral("completed"),
            "successful export had incorrect document status");
    require(messageTitle == QStringLiteral("Export complete"),
            "successful export did not report completion");

    const QByteArray original = "existing target";
    writeFile(target, original);
    overwrite = false;
    exportButton->click();
    require(readFile(target) == original, "declined overwrite changed the target");

    overwrite = true;
    exportButton->click();
    require(readFile(target) == firstPayload, "approved overwrite did not replace the target");

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
    require(readFile(target) == firstPayload, "retry export did not persist the retained result");
    require(exportButton->isEnabled(), "successful export discarded the retained result");
    clearScenario();
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
        require(tabs->count() == 2 && tabs->tabText(0) == QStringLiteral("Single Benchmark") &&
            tabs->tabText(1) == QStringLiteral("Batch"),
            "single and batch workflows were not separated into the expected tabs");
        require(!widget<QPushButton>(window, "batchRunButton")->isEnabled() &&
            !widget<QPushButton>(window, "batchCancelButton")->isEnabled(),
            "batch execution controls were enabled before M13-C");
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
        auto* validationSummary = widget<QLabel>(window, "batchValidationSummaryLabel");
        auto* issues = widget<QListWidget>(window, "batchValidationIssuesList");
        auto* inputBrowse = widget<QPushButton>(window, "batchInputBrowseButton");
        auto* outputPath = widget<QLineEdit>(window, "batchOutputPathLineEdit");
        auto* outputBrowse = widget<QPushButton>(window, "batchOutputBrowseButton");

        inputBrowse->click();
        require(inputPath->text().isEmpty() && validationSummary->text() == QStringLiteral("No batch input selected."),
            "cancelling input browse changed batch state");

        selectedInput = validPath;
        inputBrowse->click();
        require(inputPath->text() == validPath &&
            validationSummary->text() == QStringLiteral("Valid batch - 1 entries") && issues->count() == 0,
            "valid batch input was not parsed and displayed correctly");

        selectedInput.clear();
        inputBrowse->click();
        require(inputPath->text() == validPath && validationSummary->text() == QStringLiteral("Valid batch - 1 entries"),
            "cancelled input browse discarded the accepted batch state");

        selectedInput = invalidPath;
        inputBrowse->click();
        require(inputPath->text() == invalidPath && validationSummary->text() == QStringLiteral("Invalid batch") &&
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
    MainWindow::DialogCallbacks callbacks;
    callbacks.chooseOpenTarget = [&](QWidget*) { return selectedInput; };
    callbacks.chooseSaveTarget = [&](QWidget*) { return selectedOutput; };
    window.setDialogCallbacks(std::move(callbacks));

    auto* inputBrowse = widget<QPushButton>(window, "batchInputBrowseButton");
    auto* outputBrowse = widget<QPushButton>(window, "batchOutputBrowseButton");
    auto* run = widget<QPushButton>(window, "batchRunButton");
    auto* cancel = widget<QPushButton>(window, "batchCancelButton");
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
        !widget<QPushButton>(window, "runButton")->isEnabled() &&
        !widget<QPushButton>(window, "exportJsonButton")->isEnabled(),
        "BatchRunning did not enforce mutual exclusion and control locking");
    waitUntil([&] {
        const auto currentStatus = widget<QLabel>(window, "batchStatusLabel")->text();
        return currentStatus == QStringLiteral("Completed") ||
               currentStatus.startsWith(QStringLiteral("Failed"));
    }, 30'000);
    require(widget<QLabel>(window, "batchStatusLabel")->text() == QStringLiteral("Completed"),
            "Batch completion did not reach the Completed terminal status");
    require(!cancel->isEnabled() && run->isEnabled() && inputBrowse->isEnabled() &&
        outputBrowse->isEnabled(),
        "completed Batch did not return to Idle presentation");
    require(widget<QLabel>(window, "batchCurrentEntryLabel")->text() == QStringLiteral("2 / 2"),
            "terminal Batch did not retain the controller-supplied current entry");
    require(widget<QLabel>(window, "batchCompletedCountLabel")->text() == QStringLiteral("2") &&
        widget<QLabel>(window, "batchFailedCountLabel")->text() == QStringLiteral("0") &&
        widget<QLabel>(window, "batchCancelledCountLabel")->text() == QStringLiteral("0") &&
        widget<QLabel>(window, "batchNotStartedCountLabel")->text() == QStringLiteral("0"),
        "Batch terminal counters did not reflect controller progress");
    const auto payload = readFile(outputPath);
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(payload, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject() &&
        document.object().value("mode") == QStringLiteral("batch"),
        "BatchController did not produce a batch result document");
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
    cancelWindow.setDialogCallbacks(std::move(cancelCallbacks));
    widget<QPushButton>(cancelWindow, "batchInputBrowseButton")->click();
    widget<QPushButton>(cancelWindow, "batchOutputBrowseButton")->click();
    auto* batchCancel = widget<QPushButton>(cancelWindow, "batchCancelButton");
    widget<QPushButton>(cancelWindow, "batchRunButton")->click();
    require(batchCancel->isEnabled(), "Batch Run did not enter BatchRunning presentation");
    waitUntil([&] {
        return widget<QLabel>(cancelWindow, "batchCurrentEntryLabel")->text() == QStringLiteral("1 / 2") &&
               widget<QLabel>(cancelWindow, "batchCurrentBenchmarkLabel")->text() != QStringLiteral("-") &&
               widget<QLabel>(cancelWindow, "batchCurrentProgressLabel")->text() != QStringLiteral("-");
    }, 10'000);
    require(!cancelWindow.close() && cancelWindow.isVisible(),
        "active Batch close attempt was not rejected by the M13-C boundary");
    batchCancel->click();
    require(widget<QLabel>(cancelWindow, "batchStatusLabel")->text() == QStringLiteral("Cancelling...") &&
                !batchCancel->isEnabled(),
        "Batch Cancel did not enter BatchCancelling presentation");
    waitUntil([&] {
        const auto currentStatus = widget<QLabel>(cancelWindow, "batchStatusLabel")->text();
        return currentStatus == QStringLiteral("Cancelled") ||
               currentStatus.startsWith(QStringLiteral("Failed"));
    }, 15'000);
    require(widget<QLabel>(cancelWindow, "batchStatusLabel")->text() == QStringLiteral("Cancelled"),
            "Batch cancellation did not reach the Cancelled terminal status");
    require(widget<QPushButton>(cancelWindow, "batchRunButton")->isEnabled() &&
        widget<QPushButton>(cancelWindow, "batchInputBrowseButton")->isEnabled(),
        "cancelled Batch did not return to Idle presentation");
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
    failureWindow.setDialogCallbacks(std::move(failureCallbacks));
    widget<QPushButton>(failureWindow, "batchInputBrowseButton")->click();
    widget<QPushButton>(failureWindow, "batchOutputBrowseButton")->click();
    widget<QPushButton>(failureWindow, "batchRunButton")->click();
    waitUntil([&] {
        return widget<QLabel>(failureWindow, "batchStatusLabel")->text() ==
               QStringLiteral("Completed with failures");
    }, 30'000);
    require(widget<QLabel>(failureWindow, "batchFailedCountLabel")->text() == QStringLiteral("2") &&
                widget<QLabel>(failureWindow, "batchCompletedCountLabel")->text() == QStringLiteral("0"),
            "CompletedWithFailures did not display controller-supplied failed/completed counters");
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
        std::cout << "CASE batch-gui\n";
        testBatchGui();
        std::cout << "CASE batch-run-cancel\n";
        testBatchRunAndCancel();
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
