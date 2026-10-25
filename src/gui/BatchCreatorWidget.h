#pragma once

#include <QWidget>

#include <vector>

#include "CreatorRowState.h"

class QLabel;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

namespace cryptobench::gui {

class CreatorRowWidget;

class BatchCreatorWidget final : public QWidget {
public:
    static constexpr int kMaximumRows = 1000;

    explicit BatchCreatorWidget(QWidget* parent = nullptr);

    int rowCount() const noexcept;
    CreatorRowWidget* rowAt(int index) const noexcept;
    std::vector<CreatorRowState> rowStates();

    bool addRow();
    bool deleteRow(int index);
    bool cloneRow(int index);
    bool moveRowUp(int index);
    bool moveRowDown(int index);

    QPushButton* addRowButton() const noexcept;
    QScrollArea* scrollArea() const noexcept;

private:
    void insertRow(int index, const CreatorRowState& state);
    void updateBoundaryControls();
    void updateEmptyLabel();

    QPushButton* addRowButton_ = nullptr;
    QScrollArea* scrollArea_ = nullptr;
    QWidget* rowsContainer_ = nullptr;
    QVBoxLayout* rowsLayout_ = nullptr;
    QLabel* emptyLabel_ = nullptr;
    std::vector<CreatorRowWidget*> rows_;
};

} // namespace cryptobench::gui
