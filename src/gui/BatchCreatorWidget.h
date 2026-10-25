#pragma once

#include <QWidget>
#include <QByteArray>
#include <QStringList>

#include <optional>
#include <vector>

#include <cryptobench/application/BatchTypes.h>

#include "CreatorRowState.h"

class QLabel;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

namespace cryptobench::gui {

class CreatorRowWidget;

struct BatchCreatorFinalizationResult {
    std::optional<application::BatchDefinition> definition;
    QByteArray inputBytes;
    QStringList issues;

    bool isValid() const noexcept
    {
        return definition.has_value() && issues.isEmpty();
    }
};

class BatchCreatorWidget final : public QWidget {
public:
    static constexpr int kMaximumRows = 1000;

    explicit BatchCreatorWidget(QWidget* parent = nullptr);

    int rowCount() const noexcept;
    CreatorRowWidget* rowAt(int index) const noexcept;
    std::vector<CreatorRowState> rowStates();
    BatchCreatorFinalizationResult finalizeRows();

    bool addRow();
    bool deleteRow(int index);
    bool cloneRow(int index);
    bool moveRowUp(int index);
    bool moveRowDown(int index);

    QPushButton* addRowButton() const noexcept;
    QScrollArea* scrollArea() const noexcept;
    QPushButton* useInBatchButton() const noexcept;
    QPushButton* exportBatchJsonButton() const noexcept;
    QLabel* validationLabel() const noexcept;
    void setFinalizationEnabled(bool enabled);
    void showFinalizationIssues(const QStringList& issues);
    void showFinalizationSuccess(std::size_t entryCount);
    void clearFinalizationFeedback();

private:
    void insertRow(int index, const CreatorRowState& state);
    void updateBoundaryControls();
    void updateEmptyLabel();

    QPushButton* addRowButton_ = nullptr;
    QScrollArea* scrollArea_ = nullptr;
    QWidget* rowsContainer_ = nullptr;
    QVBoxLayout* rowsLayout_ = nullptr;
    QLabel* emptyLabel_ = nullptr;
    QPushButton* useInBatchButton_ = nullptr;
    QPushButton* exportBatchJsonButton_ = nullptr;
    QLabel* validationLabel_ = nullptr;
    std::vector<CreatorRowWidget*> rows_;
    bool finalizationEnabled_ = true;
};

} // namespace cryptobench::gui
