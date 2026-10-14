#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <QObject>

#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchResultDocumentService.h>
#include <cryptobench/application/BatchTypes.h>
#include <cryptobench/application/BenchmarkSessionExecutor.h>
#include <cryptobench/application/JsonResultExportService.h>

namespace cryptobench::application {

class BatchController final : public QObject {
    Q_OBJECT

public:
    using SnapshotPersister = std::function<WriteResult(const QString&, const QByteArray&)>;
    using SnapshotSerializer = std::function<QByteArray(const ResultDocument&)>;
    using ExecutorFactory = std::function<std::unique_ptr<BenchmarkSessionExecutor>(
        const core::MeasurementSettings&)>;
    using MeasurementSettingsProvider = std::function<core::MeasurementSettings()>;

    explicit BatchController(QObject* parent = nullptr);
    explicit BatchController(MeasurementSettingsProvider settingsProvider, QObject* parent = nullptr);
    BatchController(
        std::unique_ptr<BenchmarkSessionExecutor> executor,
        SnapshotPersister persister,
        SnapshotSerializer serializer,
        core::MeasurementSettings executorSettings,
        QObject* parent = nullptr);
    BatchController(
        ExecutorFactory executorFactory,
        SnapshotPersister persister = {},
        SnapshotSerializer serializer = {},
        MeasurementSettingsProvider settingsProvider = {},
        QObject* parent = nullptr);
    ~BatchController() override = default;

    void start(const BatchDefinition& definition, const QString& outputTarget);
    void requestCancel();
    WriteResult saveAs(const QString& newTarget);
    bool isBusy() const noexcept;
    const BatchExecutionState& state() const noexcept;
    BatchProgress progress() const;

signals:
    void progressChanged(const cryptobench::application::BatchProgress& progress);
    void batchFinished(const cryptobench::application::BatchExecutionState& state);

private:
    enum class State {
        Idle,
        InitializingOutput,
        ReadyToAdvance,
        RunningEntry,
        CancellingEntry,
        DrainingFatalEntry,
        PersistingSnapshot,
        Terminal
    };

    enum class PersistenceIntent {
        Initial,
        EntryCheckpoint,
        NaturalFinal,
        CancelledFinal
    };

    void advance();
    void finalizePendingFatal();
    void onExecutorProgress(const core::ProgressInfo& progress);
    void onExecutorFinished(const core::BenchmarkResult& result);
    void persistSnapshot(PersistenceIntent intent);
    void failBatch(BatchErrorCode code, BatchErrorStage stage, std::string message);
    void finishTerminal();
    void emitProgress();
    void connectExecutor();
    void retireExecutor();
    bool nextEntryGate(std::size_t position) const;
    std::optional<BatchStatus> naturalFinalStatus() const;

    std::shared_ptr<BenchmarkSessionExecutor> executor_;
    ExecutorFactory executorFactory_;
    MeasurementSettingsProvider settingsProvider_;
    std::optional<core::MeasurementSettings> fixedExecutorSettings_;
    std::vector<std::shared_ptr<BenchmarkSessionExecutor>> retiredExecutors_;
    SnapshotPersister persister_;
    SnapshotSerializer serializer_;
    BatchResultDocumentService documentService_;
    JsonResultExportService exportService_;
    AtomicFileWriter fileWriter_;

    State state_ = State::Idle;
    BatchExecutionState batchState_;
    std::vector<bool> startedPositions_;
    std::optional<std::size_t> nextPosition_;
    std::optional<std::size_t> activePosition_;
    std::optional<core::ProgressInfo> currentProgress_;
    PersistenceIntent persistenceIntent_ = PersistenceIntent::Initial;
    std::optional<BatchError> pendingFatalError_;
    bool requiredSnapshotCommitted_ = false;
    bool terminalEmitted_ = false;
};

} // namespace cryptobench::application
