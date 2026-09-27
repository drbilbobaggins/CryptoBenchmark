#pragma once

#include <QObject>

#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/BenchmarkResult.h>
#include <cryptobench/core/ProgressInfo.h>

namespace cryptobench::application {

class BenchmarkSessionExecutor : public QObject {
    Q_OBJECT

public:
    explicit BenchmarkSessionExecutor(QObject* parent = nullptr)
        : QObject(parent)
    {
    }

    ~BenchmarkSessionExecutor() override = default;

    virtual void start(const core::BenchmarkConfig& config) = 0;
    virtual void requestCancel() = 0;
    virtual bool isBusy() const noexcept = 0;

signals:
    void progressChanged(const cryptobench::core::ProgressInfo& progress);
    void benchmarkFinished(const cryptobench::core::BenchmarkResult& result);
};

} // namespace cryptobench::application