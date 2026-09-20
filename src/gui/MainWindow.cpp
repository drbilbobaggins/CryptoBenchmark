#include "MainWindow.h"

#include "ui_MainWindow.h"

#include <QSignalBlocker>

#include <array>
#include <string_view>

#include <cryptobench/core/AlgorithmRegistry.h>

namespace {

using cryptobench::core::AlgorithmProfileId;
using cryptobench::core::BenchmarkOperation;
using cryptobench::core::PrimitiveCategory;

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
{
    ui->setupUi(this);

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

    populateCategories();
}

MainWindow::~MainWindow()
{
    delete ui;
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
}
