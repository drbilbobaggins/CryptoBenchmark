#include "BatchCreatorWidget.h"

#include "CreatorRowWidget.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

#include <algorithm>

namespace cryptobench::gui {

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

    connect(addRowButton_, &QPushButton::clicked, this, [this] { addRow(); });
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
    rows_.insert(rows_.begin() + index, row);
    emptyLabel_->hide();
    rowsLayout_->insertWidget(index, row);
    updateBoundaryControls();
    updateEmptyLabel();
}

void BatchCreatorWidget::updateBoundaryControls()
{
    addRowButton_->setEnabled(rowCount() < kMaximumRows);
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
