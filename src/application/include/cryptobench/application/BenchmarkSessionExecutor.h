#pragma once

#include <QCoreApplication>
#include <QObject>
#include <QMetaObject>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/ProgressInfo.h>

#include <memory>

namespace cryptobench::application {

class BatchController;

class BenchmarkSessionExecutor : public QObject {
    Q_OBJECT

public:
    explicit BenchmarkSessionExecutor(QObject* parent = nullptr)
        : QObject(parent)
    {
    }

    ~BenchmarkSessionExecutor() override = default;

    static std::shared_ptr<BenchmarkSessionExecutor> adopt(
        std::unique_ptr<BenchmarkSessionExecutor> executor)
    {
        return {executor.release(), [](BenchmarkSessionExecutor* value) {
            if (!value) return;
            if (auto* application = QCoreApplication::instance()) {
                QMetaObject::invokeMethod(
                    application,
                    [value] { value->deferOwnedDeletion(); },
                    Qt::QueuedConnection);
            } else {
                value->deferOwnedDeletion();
            }
        }};
    }

    virtual void start(const core::BenchmarkConfig& config) = 0;
    virtual void requestCancel() = 0;
    virtual bool isBusy() const noexcept = 0;

protected:
    void emitBenchmarkFinished(const core::BenchmarkResult& result)
    {
        auto keepAlive = emissionLifetimeOwner_.lock();
        emit benchmarkFinished(result);
    }

signals:
    void progressChanged(const cryptobench::core::ProgressInfo& progress);
    void benchmarkFinished(const cryptobench::core::BenchmarkResult& result);

private:
    friend class BatchController;

    void deferOwnedDeletion() noexcept
    {
        deleteLater();
    }

    void setEmissionLifetimeOwner(const std::shared_ptr<BenchmarkSessionExecutor>& owner)
    {
        emissionLifetimeOwner_ = owner;
    }

    std::weak_ptr<BenchmarkSessionExecutor> emissionLifetimeOwner_;
};

} // namespace cryptobench::application