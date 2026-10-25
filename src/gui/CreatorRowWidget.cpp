#include "CreatorRowWidget.h"

#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVBoxLayout>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/ConfigValidation.h>

#include <algorithm>
#include <stdexcept>

namespace cryptobench::gui {
namespace {

int itemData(core::PrimitiveCategory category)
{
    return static_cast<int>(category);
}

int itemData(core::AlgorithmProfileId profile)
{
    return static_cast<int>(profile);
}

int itemData(core::BenchmarkOperation operation)
{
    return static_cast<int>(operation);
}

int itemData(SignatureInputMode mode)
{
    return static_cast<int>(mode);
}

QString stringFromUtf8(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QLabel* makeLabel(const QString& text, QWidget* buddy, QWidget* parent)
{
    auto* label = new QLabel(text, parent);
    label->setBuddy(buddy);
    return label;
}

} // namespace

BenchmarkSelection CreatorRowState::selection() const
{
    return {category, profile, operation, signatureInputMode, workloadSizeBytes,
            iterationsPerRun, runs};
}

CreatorRowState defaultCreatorRowState()
{
    const auto categories = canonicalCategories();
    if (categories.empty()) {
        throw std::logic_error("canonical category list is empty");
    }
    const auto profiles = profilesForCategory(categories.front().category);
    if (profiles.empty()) {
        throw std::logic_error("canonical registry has no profile for the default category");
    }
    const auto operations = operationsForProfile(profiles.front()->id);
    if (operations.empty()) {
        throw std::logic_error("canonical profile has no supported operation");
    }
    return {categories.front().category, profiles.front()->id, operations.front(),
            std::nullopt, 1024, 1000, 3};
}

CreatorRowWidget::CreatorRowWidget(CreatorRowState state, QWidget* parent)
    : QWidget(parent)
    , state_(state)
{
    setObjectName(QStringLiteral("creatorRowWidget"));
    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(6, 4, 6, 4);
    outerLayout->setSpacing(3);

    auto* selectionLayout = new QHBoxLayout;
    selectionLayout->setSpacing(6);
    categoryComboBox_ = new QComboBox(this);
    categoryComboBox_->setObjectName(QStringLiteral("creatorCategoryComboBox"));
    categoryComboBox_->setMinimumWidth(150);
    profileComboBox_ = new QComboBox(this);
    profileComboBox_->setObjectName(QStringLiteral("creatorProfileComboBox"));
    profileComboBox_->setMinimumWidth(190);
    profileComboBox_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    profileComboBox_->setMinimumContentsLength(20);
    operationComboBox_ = new QComboBox(this);
    operationComboBox_->setObjectName(QStringLiteral("creatorOperationComboBox"));
    operationComboBox_->setMinimumWidth(130);
    selectionLayout->addWidget(makeLabel(QStringLiteral("Category:"), categoryComboBox_, this));
    selectionLayout->addWidget(categoryComboBox_, 1);
    selectionLayout->addWidget(makeLabel(QStringLiteral("Profile:"), profileComboBox_, this));
    selectionLayout->addWidget(profileComboBox_, 2);
    selectionLayout->addWidget(makeLabel(QStringLiteral("Operation:"), operationComboBox_, this));
    selectionLayout->addWidget(operationComboBox_, 1);

    cloneButton_ = new QPushButton(QStringLiteral("Clone"), this);
    cloneButton_->setObjectName(QStringLiteral("creatorCloneButton"));
    cloneButton_->setToolTip(QStringLiteral("Clone this row directly below it"));
    moveUpButton_ = new QPushButton(QStringLiteral("Move up"), this);
    moveUpButton_->setObjectName(QStringLiteral("creatorMoveUpButton"));
    moveDownButton_ = new QPushButton(QStringLiteral("Move down"), this);
    moveDownButton_->setObjectName(QStringLiteral("creatorMoveDownButton"));
    deleteButton_ = new QPushButton(QStringLiteral("Delete"), this);
    deleteButton_->setObjectName(QStringLiteral("creatorDeleteButton"));
    for (auto* button : {cloneButton_, moveUpButton_, moveDownButton_, deleteButton_}) {
        button->setFocusPolicy(Qt::StrongFocus);
        selectionLayout->addWidget(button);
    }
    outerLayout->addLayout(selectionLayout);

    auto* inputsLayout = new QHBoxLayout;
    inputsLayout->setSpacing(6);
    signatureInputModeComboBox_ = new QComboBox(this);
    signatureInputModeComboBox_->setObjectName(QStringLiteral("creatorSignatureInputModeComboBox"));
    workloadSizeSpinBox_ = new QSpinBox(this);
    workloadSizeSpinBox_->setObjectName(QStringLiteral("creatorWorkloadSizeSpinBox"));
    workloadSizeSpinBox_->setMaximum(static_cast<int>(core::kMaxWorkloadBytes));
    workloadSizeSpinBox_->setKeyboardTracking(false);
    workloadSizeLabel_ = makeLabel(QStringLiteral("Input size:"), workloadSizeSpinBox_, this);
    workloadSizeLabel_->setObjectName(QStringLiteral("creatorWorkloadSizeLabel"));
    workloadUnitLabel_ = new QLabel(QStringLiteral("bytes"), this);
    workloadUnitLabel_->setObjectName(QStringLiteral("creatorWorkloadUnitLabel"));

    iterationsSpinBox_ = new QSpinBox(this);
    iterationsSpinBox_->setObjectName(QStringLiteral("creatorIterationsSpinBox"));
    iterationsSpinBox_->setRange(static_cast<int>(core::kMinIterationsPerRun),
                                 static_cast<int>(core::kMaxIterationsPerRun));
    iterationsSpinBox_->setKeyboardTracking(false);
    runsSpinBox_ = new QSpinBox(this);
    runsSpinBox_->setObjectName(QStringLiteral("creatorRunsSpinBox"));
    runsSpinBox_->setRange(static_cast<int>(core::kMinRuns),
                           static_cast<int>(core::kMaxRuns));
    runsSpinBox_->setKeyboardTracking(false);
    signatureInputModeLabel_ =
        makeLabel(QStringLiteral("Signature input:"), signatureInputModeComboBox_, this);
    signatureInputModeLabel_->setObjectName(QStringLiteral("signatureInputModeLabel"));
    inputsLayout->addWidget(signatureInputModeLabel_);
    inputsLayout->addWidget(signatureInputModeComboBox_);
    inputsLayout->addWidget(workloadSizeLabel_);
    inputsLayout->addWidget(workloadSizeSpinBox_);
    inputsLayout->addWidget(workloadUnitLabel_);
    inputsLayout->addWidget(makeLabel(QStringLiteral("Iterations per run (N):"),
                                      iterationsSpinBox_, this));
    inputsLayout->addWidget(iterationsSpinBox_);
    inputsLayout->addWidget(makeLabel(QStringLiteral("Runs (M):"), runsSpinBox_, this));
    inputsLayout->addWidget(runsSpinBox_);
    inputsLayout->addStretch(1);
    outerLayout->addLayout(inputsLayout);

    populateCategoryChoices();
    refreshDependentControls();

    connect(categoryComboBox_, &QComboBox::currentIndexChanged,
            this, [this](int) { handleCategoryChanged(); });
    connect(profileComboBox_, &QComboBox::currentIndexChanged,
            this, [this](int) { handleProfileChanged(); });
    connect(operationComboBox_, &QComboBox::currentIndexChanged,
            this, [this](int) { handleOperationChanged(); });
    connect(signatureInputModeComboBox_, &QComboBox::currentIndexChanged,
            this, [this](int) { handleInputModeChanged(); });
    connect(workloadSizeSpinBox_, &QSpinBox::valueChanged, this, [this](int value) {
        state_.workloadSizeBytes = static_cast<core::WorkloadBytes>(value);
    });
    connect(iterationsSpinBox_, &QSpinBox::valueChanged, this, [this](int value) {
        state_.iterationsPerRun = static_cast<std::uint64_t>(value);
    });
    connect(runsSpinBox_, &QSpinBox::valueChanged, this, [this](int value) {
        state_.runs = static_cast<std::uint32_t>(value);
    });
}

CreatorRowState CreatorRowWidget::state()
{
    synchronizeNumericState();
    return state_;
}

std::optional<core::BenchmarkConfig> CreatorRowWidget::benchmarkConfig()
{
    return benchmarkConfigFromSelection(state().selection());
}

void CreatorRowWidget::setState(const CreatorRowState& state)
{
    state_ = state;
    refreshDependentControls();
}

void CreatorRowWidget::setMoveAvailability(bool canMoveUp, bool canMoveDown)
{
    moveUpButton_->setEnabled(canMoveUp);
    moveDownButton_->setEnabled(canMoveDown);
}

QComboBox* CreatorRowWidget::categoryComboBox() const noexcept { return categoryComboBox_; }
QComboBox* CreatorRowWidget::profileComboBox() const noexcept { return profileComboBox_; }
QComboBox* CreatorRowWidget::operationComboBox() const noexcept { return operationComboBox_; }
QComboBox* CreatorRowWidget::signatureInputModeComboBox() const noexcept { return signatureInputModeComboBox_; }
QSpinBox* CreatorRowWidget::workloadSizeSpinBox() const noexcept { return workloadSizeSpinBox_; }
QSpinBox* CreatorRowWidget::iterationsSpinBox() const noexcept { return iterationsSpinBox_; }
QSpinBox* CreatorRowWidget::runsSpinBox() const noexcept { return runsSpinBox_; }
QPushButton* CreatorRowWidget::cloneButton() const noexcept { return cloneButton_; }
QPushButton* CreatorRowWidget::deleteButton() const noexcept { return deleteButton_; }
QPushButton* CreatorRowWidget::moveUpButton() const noexcept { return moveUpButton_; }
QPushButton* CreatorRowWidget::moveDownButton() const noexcept { return moveDownButton_; }

void CreatorRowWidget::populateCategoryChoices()
{
    const QSignalBlocker blocker(categoryComboBox_);
    categoryComboBox_->clear();
    for (const auto& choice : canonicalCategories()) {
        categoryComboBox_->addItem(stringFromUtf8(choice.label), itemData(choice.category));
    }
}

void CreatorRowWidget::refreshDependentControls()
{
    {
        const QSignalBlocker blocker(categoryComboBox_);
        categoryComboBox_->setCurrentIndex(
            categoryComboBox_->findData(itemData(state_.category)));
    }

    const auto profiles = profilesForCategory(state_.category);
    {
        const QSignalBlocker blocker(profileComboBox_);
        profileComboBox_->clear();
        for (const auto* profile : profiles) {
            profileComboBox_->addItem(stringFromUtf8(profile->displayName),
                                      itemData(profile->id));
        }
        if (profileComboBox_->findData(itemData(state_.profile)) < 0 && !profiles.empty()) {
            state_.profile = profiles.front()->id;
        }
        profileComboBox_->setCurrentIndex(profileComboBox_->findData(itemData(state_.profile)));
    }

    const auto operations = operationsForProfile(state_.profile);
    {
        const QSignalBlocker blocker(operationComboBox_);
        operationComboBox_->clear();
        for (const auto operation : operations) {
            operationComboBox_->addItem(
                stringFromUtf8(operationDisplayName(operation)), itemData(operation));
        }
        if (std::find(operations.begin(), operations.end(), state_.operation) == operations.end()
            && !operations.empty()) {
            state_.operation = operations.front();
        }
        operationComboBox_->setCurrentIndex(
            operationComboBox_->findData(itemData(state_.operation)));
    }

    auto controls = selectionControlsFor(
        state_.profile, state_.operation, state_.signatureInputMode);
    const bool modeIsValid = state_.signatureInputMode.has_value()
        && std::find(controls.signatureInputModes.begin(), controls.signatureInputModes.end(),
                     *state_.signatureInputMode)
            != controls.signatureInputModes.end();
    if (!modeIsValid) {
        state_.signatureInputMode = controls.signatureInputModes.empty()
            ? std::nullopt
            : std::optional<SignatureInputMode>{controls.signatureInputModes.front()};
    }
    controls = selectionControlsFor(state_.profile, state_.operation, state_.signatureInputMode);

    {
        const QSignalBlocker blocker(signatureInputModeComboBox_);
        signatureInputModeComboBox_->clear();
        for (const auto mode : controls.signatureInputModes) {
            signatureInputModeComboBox_->addItem(
                stringFromUtf8(signatureInputModeDisplayName(mode)), itemData(mode));
        }
        if (state_.signatureInputMode.has_value()) {
            signatureInputModeComboBox_->setCurrentIndex(
                signatureInputModeComboBox_->findData(itemData(*state_.signatureInputMode)));
        }
    }

    const bool showMode = !controls.signatureInputModes.empty();
    signatureInputModeLabel_->setVisible(showMode);
    signatureInputModeComboBox_->setVisible(showMode);
    const bool showWorkload = controls.workload.has_value();
    if (showWorkload) {
        workloadSizeLabel_->setText(stringFromUtf8(controls.workload->label));
        workloadSizeSpinBox_->setRange(
            static_cast<int>(controls.workload->minimum),
            static_cast<int>(core::kMaxWorkloadBytes));
    }
    workloadSizeLabel_->setVisible(showWorkload);
    workloadSizeSpinBox_->setVisible(showWorkload);
    workloadUnitLabel_->setVisible(showWorkload);
    signatureInputModeComboBox_->setEnabled(showMode);
    workloadSizeSpinBox_->setEnabled(showWorkload);

    workloadSizeSpinBox_->setValue(static_cast<int>(state_.workloadSizeBytes));
    iterationsSpinBox_->setValue(static_cast<int>(state_.iterationsPerRun));
    runsSpinBox_->setValue(static_cast<int>(state_.runs));
    state_.workloadSizeBytes = static_cast<core::WorkloadBytes>(workloadSizeSpinBox_->value());
    state_.iterationsPerRun = static_cast<std::uint64_t>(iterationsSpinBox_->value());
    state_.runs = static_cast<std::uint32_t>(runsSpinBox_->value());
}

void CreatorRowWidget::handleCategoryChanged()
{
    synchronizeNumericState();
    const auto data = categoryComboBox_->currentData();
    if (!data.isValid()) {
        return;
    }
    state_.category = static_cast<core::PrimitiveCategory>(data.toInt());
    const auto profiles = profilesForCategory(state_.category);
    if (profiles.empty()) {
        return;
    }
    state_.profile = profiles.front()->id;
    const auto operations = operationsForProfile(state_.profile);
    if (!operations.empty()) {
        state_.operation = operations.front();
    }
    state_.signatureInputMode.reset();
    refreshDependentControls();
}

void CreatorRowWidget::handleProfileChanged()
{
    synchronizeNumericState();
    const auto data = profileComboBox_->currentData();
    if (!data.isValid()) {
        return;
    }
    state_.profile = static_cast<core::AlgorithmProfileId>(data.toInt());
    const auto operations = operationsForProfile(state_.profile);
    if (std::find(operations.begin(), operations.end(), state_.operation) == operations.end()
        && !operations.empty()) {
        state_.operation = operations.front();
    }
    refreshDependentControls();
}

void CreatorRowWidget::handleOperationChanged()
{
    synchronizeNumericState();
    const auto data = operationComboBox_->currentData();
    if (!data.isValid()) {
        return;
    }
    state_.operation = static_cast<core::BenchmarkOperation>(data.toInt());
    refreshDependentControls();
}

void CreatorRowWidget::handleInputModeChanged()
{
    synchronizeNumericState();
    const auto data = signatureInputModeComboBox_->currentData();
    state_.signatureInputMode = data.isValid()
        ? std::optional<SignatureInputMode>{
            static_cast<SignatureInputMode>(data.toInt())}
        : std::nullopt;
    const auto controls = selectionControlsFor(
        state_.profile, state_.operation, state_.signatureInputMode);
    const bool showWorkload = controls.workload.has_value();
    workloadSizeLabel_->setVisible(showWorkload);
    workloadSizeSpinBox_->setVisible(showWorkload);
    workloadUnitLabel_->setVisible(showWorkload);
    workloadSizeSpinBox_->setEnabled(showWorkload);
    if (showWorkload) {
        workloadSizeLabel_->setText(stringFromUtf8(controls.workload->label));
        workloadSizeSpinBox_->setRange(
            static_cast<int>(controls.workload->minimum),
            static_cast<int>(core::kMaxWorkloadBytes));
        state_.workloadSizeBytes = static_cast<core::WorkloadBytes>(
            workloadSizeSpinBox_->value());
    }
}

void CreatorRowWidget::synchronizeNumericState()
{
    const QSignalBlocker workloadBlocker(workloadSizeSpinBox_);
    const QSignalBlocker iterationsBlocker(iterationsSpinBox_);
    const QSignalBlocker runsBlocker(runsSpinBox_);
    workloadSizeSpinBox_->interpretText();
    iterationsSpinBox_->interpretText();
    runsSpinBox_->interpretText();
    state_.workloadSizeBytes =
        static_cast<core::WorkloadBytes>(workloadSizeSpinBox_->value());
    state_.iterationsPerRun = static_cast<std::uint64_t>(iterationsSpinBox_->value());
    state_.runs = static_cast<std::uint32_t>(runsSpinBox_->value());
}

} // namespace cryptobench::gui
