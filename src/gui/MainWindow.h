#pragma once

#include <QMainWindow>

#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/DomainTypes.h>

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

    Ui::MainWindow* ui;
};
