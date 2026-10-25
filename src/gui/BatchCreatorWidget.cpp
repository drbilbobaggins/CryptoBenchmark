#include "BatchCreatorWidget.h"

#include "CanonicalBenchmarkSelection.h"
#include "CreatorRowWidget.h"

#include <QHBoxLayout>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QVBoxLayout>

#include <cryptobench/application/BatchInputDocumentBuilder.h>
#include <cryptobench/application/BatchInputParser.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <utility>

namespace cryptobench::gui {
namespace {

QString formatParserIssue(const application::BatchInputIssue& issue)
{
    QString prefix = QStringLiteral("Batch input");
    constexpr std::string_view entriesPrefix = "/entries/";
    if (issue.path.starts_with(entriesPrefix)) {
        const auto indexStart = entriesPrefix.size();
        const auto indexEnd = issue.path.find('/', indexStart);
        const auto indexText = issue.path.substr(
            indexStart, indexEnd == std::string::npos
                ? std::string::npos
                : indexEnd - indexStart);
        bool indexValid = false;
        const auto index = QString::fromStdString(indexText).toULongLong(&indexValid);
        if (indexValid) {
            prefix = QStringLiteral("Entry %1").arg(index + 1);
        }
    }

    QString message = prefix;
    if (!issue.path.empty()) {
        message += QStringLiteral(" (%1)").arg(QString::fromStdString(issue.path));
    }
    const auto stableCode = application::toStableString(issue.code);
    message += QStringLiteral(" [%1]: %2")
        .arg(QString::fromUtf8(stableCode.data(), static_cast<qsizetype>(stableCode.size())))
        .arg(QString::fromStdString(issue.technicalMessage));
    if (issue.domainCode.has_value()) {
        const auto domainCode = application::toStableString(*issue.domainCode);
        message += QStringLiteral(" (%1)")
            .arg(QString::fromUtf8(domainCode.data(), static_cast<qsizetype>(domainCode.size())));
    }
    return message;
}

} // namespace

BatchCreatorWidget::BatchCreatorWidget(QWidget* parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("batchCreatorWidget"));
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* actionsLayout = new QHBoxLayout;
    addRowButton_ = new QPushButton(QStringLiteral("Add row"), this);
    addRowButton_->setObjectName(QStringLiteral("creatorAddRowButton"));
    addRowButton_->setToolTip(QStringLiteral("Add a new benchmark configuration row"));
    actionsLayout->addWidget(addRowButton_);
    actionsLayout->addStretch(1);
    layout->addLayout(actionsLayout);

    scrollArea_ = new QScrollArea(this);
    scrollArea_->setObjectName(QStringLiteral("creatorRowsScrollArea"));
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    rowsContainer_ = new QWidget;
    rowsContainer_->setObjectName(QStringLiteral("creatorRowsContainer"));
    rowsLayout_ = new QVBoxLayout(rowsContainer_);
    rowsLayout_->setContentsMargins(2, 2, 2, 2);
    rowsLayout_->setSpacing(5);
    emptyLabel_ = new QLabel(QStringLiteral("No rows. Add a row to start."), rowsContainer_);
    emptyLabel_->setObjectName(QStringLiteral("creatorEmptyLabel"));
    rowsLayout_->addWidget(emptyLabel_);
    rowsLayout_->addStretch(1);
    scrollArea_->setWidget(rowsContainer_);
    layout->addWidget(scrollArea_, 1);

    auto* bottomLayout = new QVBoxLayout;
    validationLabel_ = new QLabel(this);
    validationLabel_->setObjectName(QStringLiteral("creatorValidationLabel"));
    validationLabel_->setWordWrap(true);
    validationLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    bottomLayout->addWidget(validationLabel_);

    auto* finalizationLayout = new QHBoxLayout;
    finalizationLayout->addStretch(1);
    useInBatchButton_ = new QPushButton(QStringLiteral("Use in Batch"), this);
    useInBatchButton_->setObjectName(QStringLiteral("creatorUseInBatchButton"));
    useInBatchButton_->setToolTip(QStringLiteral(
        "Validate this draft and adopt it as the current Batch input"));
    exportBatchJsonButton_ = new QPushButton(QStringLiteral("Export Batch JSON..."), this);
    exportBatchJsonButton_->setObjectName(QStringLiteral("creatorExportBatchJsonButton"));
    exportBatchJsonButton_->setToolTip(QStringLiteral(
        "Validate this draft and export canonical Batch input JSON v1"));
    finalizationLayout->addWidget(useInBatchButton_);
    finalizationLayout->addWidget(exportBatchJsonButton_);
    bottomLayout->addLayout(finalizationLayout);
    layout->addLayout(bottomLayout);

    connect(addRowButton_, &QPushButton::clicked, this, [this] { addRow(); });
    updateBoundaryControls();
}

int BatchCreatorWidget::rowCount() const noexcept
{
    return static_cast<int>(rows_.size());
}

CreatorRowWidget* BatchCreatorWidget::rowAt(int index) const noexcept
{
    if (index < 0 || index >= rowCount()) {
        return nullptr;
    }
    return rows_[static_cast<std::size_t>(index)];
}

std::vector<CreatorRowState> BatchCreatorWidget::rowStates()
{
    std::vector<CreatorRowState> states;
    states.reserve(rows_.size());
    for (auto* row : rows_) {
        states.push_back(row->state());
    }
    return states;
}

BatchCreatorFinalizationResult BatchCreatorWidget::finalizeRows()
{
    BatchCreatorFinalizationResult result;
    const auto states = rowStates();
    std::vector<core::BenchmarkConfig> configs;
    configs.reserve(states.size());

    for (std::size_t index = 0; index < states.size(); ++index) {
        auto config = benchmarkConfigFromSelection(states[index].selection());
        if (!config.has_value()) {
            result.issues.push_back(
                QStringLiteral("Entry %1 (/entries/%2): incomplete or incoherent Creator selection.")
                    .arg(static_cast<qulonglong>(index + 1))
                    .arg(static_cast<qulonglong>(index)));
            continue;
        }
        configs.push_back(std::move(*config));
    }
    if (!result.issues.isEmpty()) {
        return result;
    }

    try {
        result.inputBytes = application::BatchInputDocumentBuilder{}.build(configs);
        const auto parsed = application::BatchInputParser{}.parseData(result.inputBytes);
        if (!parsed.issues.empty()) {
            for (const auto& issue : parsed.issues) {
                result.issues.push_back(formatParserIssue(issue));
            }
            return result;
        }
        if (!parsed.definition.has_value()) {
            result.issues.push_back(
                QStringLiteral("Batch input parser returned no definition and no validation issue."));
            return result;
        }
        result.definition = parsed.definition;
    } catch (const std::exception& error) {
        result.issues.push_back(
            QStringLiteral("Creator finalization failed: %1").arg(QString::fromUtf8(error.what())));
    }
    return result;
}

bool BatchCreatorWidget::addRow()
{
    if (rowCount() >= kMaximumRows) {
        return false;
    }
    insertRow(rowCount(), defaultCreatorRowState());
    return true;
}

bool BatchCreatorWidget::deleteRow(int index)
{
    auto* row = rowAt(index);
    if (row == nullptr) {
        return false;
    }
    rowsLayout_->removeWidget(row);
    rows_.erase(rows_.begin() + index);
    row->deleteLater();
    clearFinalizationFeedback();
    updateBoundaryControls();
    updateEmptyLabel();
    return true;
}

bool BatchCreatorWidget::cloneRow(int index)
{
    auto* source = rowAt(index);
    if (source == nullptr || rowCount() >= kMaximumRows) {
        return false;
    }
    const auto copiedState = source->state();
    insertRow(index + 1, copiedState);
    clearFinalizationFeedback();
    return true;
}

bool BatchCreatorWidget::moveRowUp(int index)
{
    if (index <= 0 || index >= rowCount()) {
        return false;
    }
    auto* row = rows_[static_cast<std::size_t>(index)];
    rowsLayout_->removeWidget(row);
    rows_.erase(rows_.begin() + index);
    rows_.insert(rows_.begin() + index - 1, row);
    rowsLayout_->insertWidget(index - 1, row);
    clearFinalizationFeedback();
    updateBoundaryControls();
    return true;
}

bool BatchCreatorWidget::moveRowDown(int index)
{
    if (index < 0 || index + 1 >= rowCount()) {
        return false;
    }
    auto* row = rows_[static_cast<std::size_t>(index)];
    rowsLayout_->removeWidget(row);
    rows_.erase(rows_.begin() + index);
    rows_.insert(rows_.begin() + index + 1, row);
    rowsLayout_->insertWidget(index + 1, row);
    clearFinalizationFeedback();
    updateBoundaryControls();
    return true;
}

QPushButton* BatchCreatorWidget::addRowButton() const noexcept
{
    return addRowButton_;
}

QScrollArea* BatchCreatorWidget::scrollArea() const noexcept
{
    return scrollArea_;
}

QPushButton* BatchCreatorWidget::useInBatchButton() const noexcept
{
    return useInBatchButton_;
}

QPushButton* BatchCreatorWidget::exportBatchJsonButton() const noexcept
{
    return exportBatchJsonButton_;
}

QLabel* BatchCreatorWidget::validationLabel() const noexcept
{
    return validationLabel_;
}

void BatchCreatorWidget::setFinalizationEnabled(bool enabled)
{
    finalizationEnabled_ = enabled;
    updateBoundaryControls();
}

void BatchCreatorWidget::showFinalizationIssues(const QStringList& issues)
{
    validationLabel_->setText(issues.join(QLatin1Char('\n')));
}

void BatchCreatorWidget::showFinalizationSuccess(std::size_t entryCount)
{
    validationLabel_->setText(
        QStringLiteral("Draft validated successfully: %1 entries.")
            .arg(static_cast<qulonglong>(entryCount)));
}

void BatchCreatorWidget::clearFinalizationFeedback()
{
    validationLabel_->clear();
}

void BatchCreatorWidget::insertRow(int index, const CreatorRowState& state)
{
    auto* row = new CreatorRowWidget(state, rowsContainer_);
    connect(row->deleteButton(), &QPushButton::clicked, this, [this, row] {
        const auto found = std::find(rows_.begin(), rows_.end(), row);
        if (found != rows_.end()) {
            deleteRow(static_cast<int>(std::distance(rows_.begin(), found)));
        }
    });
    connect(row->cloneButton(), &QPushButton::clicked, this, [this, row] {
        const auto found = std::find(rows_.begin(), rows_.end(), row);
        if (found != rows_.end()) {
            cloneRow(static_cast<int>(std::distance(rows_.begin(), found)));
        }
    });
    connect(row->moveUpButton(), &QPushButton::clicked, this, [this, row] {
        const auto found = std::find(rows_.begin(), rows_.end(), row);
        if (found != rows_.end()) {
            moveRowUp(static_cast<int>(std::distance(rows_.begin(), found)));
        }
    });
    connect(row->moveDownButton(), &QPushButton::clicked, this, [this, row] {
        const auto found = std::find(rows_.begin(), rows_.end(), row);
        if (found != rows_.end()) {
            moveRowDown(static_cast<int>(std::distance(rows_.begin(), found)));
        }
    });
    connect(row->categoryComboBox(), &QComboBox::currentIndexChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->profileComboBox(), &QComboBox::currentIndexChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->operationComboBox(), &QComboBox::currentIndexChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->signatureInputModeComboBox(), &QComboBox::currentIndexChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->workloadSizeSpinBox(), &QSpinBox::valueChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->iterationsSpinBox(), &QSpinBox::valueChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    connect(row->runsSpinBox(), &QSpinBox::valueChanged,
            this, [this](int) { clearFinalizationFeedback(); });
    rows_.insert(rows_.begin() + index, row);
    emptyLabel_->hide();
    rowsLayout_->insertWidget(index, row);
    clearFinalizationFeedback();
    updateBoundaryControls();
    updateEmptyLabel();
}

void BatchCreatorWidget::updateBoundaryControls()
{
    addRowButton_->setEnabled(rowCount() < kMaximumRows);
    const bool canFinalize = finalizationEnabled_ && rowCount() > 0;
    useInBatchButton_->setEnabled(canFinalize);
    exportBatchJsonButton_->setEnabled(canFinalize);
    for (int index = 0; index < rowCount(); ++index) {
        rows_[static_cast<std::size_t>(index)]->setMoveAvailability(
            index > 0, index + 1 < rowCount());
        rows_[static_cast<std::size_t>(index)]->cloneButton()->setEnabled(
            rowCount() < kMaximumRows);
    }
}

void BatchCreatorWidget::updateEmptyLabel()
{
    emptyLabel_->setVisible(rows_.empty());
}

} // namespace cryptobench::gui
