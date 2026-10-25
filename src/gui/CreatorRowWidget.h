#pragma once

#include <QWidget>

#include <optional>

#include "CreatorRowState.h"

class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;

namespace cryptobench::gui {

class CreatorRowWidget final : public QWidget {
public:
    explicit CreatorRowWidget(CreatorRowState state, QWidget* parent = nullptr);

    CreatorRowState state();
    std::optional<core::BenchmarkConfig> benchmarkConfig();
    void setState(const CreatorRowState& state);
    void setMoveAvailability(bool canMoveUp, bool canMoveDown);

    QComboBox* categoryComboBox() const noexcept;
    QComboBox* profileComboBox() const noexcept;
    QComboBox* operationComboBox() const noexcept;
    QComboBox* signatureInputModeComboBox() const noexcept;
    QSpinBox* workloadSizeSpinBox() const noexcept;
    QSpinBox* iterationsSpinBox() const noexcept;
    QSpinBox* runsSpinBox() const noexcept;
    QPushButton* cloneButton() const noexcept;
    QPushButton* deleteButton() const noexcept;
    QPushButton* moveUpButton() const noexcept;
    QPushButton* moveDownButton() const noexcept;

private:
    void populateCategoryChoices();
    void refreshDependentControls();
    void handleCategoryChanged();
    void handleProfileChanged();
    void handleOperationChanged();
    void handleInputModeChanged();
    void synchronizeNumericState();

    CreatorRowState state_;
    QComboBox* categoryComboBox_ = nullptr;
    QComboBox* profileComboBox_ = nullptr;
    QComboBox* operationComboBox_ = nullptr;
    QComboBox* signatureInputModeComboBox_ = nullptr;
    QLabel* signatureInputModeLabel_ = nullptr;
    QLabel* workloadSizeLabel_ = nullptr;
    QLabel* workloadUnitLabel_ = nullptr;
    QSpinBox* workloadSizeSpinBox_ = nullptr;
    QSpinBox* iterationsSpinBox_ = nullptr;
    QSpinBox* runsSpinBox_ = nullptr;
    QPushButton* cloneButton_ = nullptr;
    QPushButton* deleteButton_ = nullptr;
    QPushButton* moveUpButton_ = nullptr;
    QPushButton* moveDownButton_ = nullptr;
};

} // namespace cryptobench::gui
