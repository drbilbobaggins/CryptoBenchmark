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

    explicit BatchController(QObject* parent = nullptr);
    BatchController(
        std::unique_ptr<BenchmarkSessionExecutor> executor,
        SnapshotPersister persister,
        SnapshotSerializer serializer = {},
        QObject* parent = nullptr);
    ~BatchController() override = default;

    void start(const BatchDefinition& definition, const QString& outputTarget);
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
        PersistingSnapshot,
        Terminal
    };

    void advance();
    void onExecutorProgress(const core::ProgressInfo& progress);
    void onExecutorFinished(const core::BenchmarkResult& result);
    void persistSnapshot(bool initialSnapshot);
    void failBatch(BatchErrorCode code, BatchErrorStage stage, std::string message);
    void finishTerminal();
    void emitProgress();
    bool nextEntryGate(std::size_t position) const;
    std::optional<BatchStatus> naturalFinalStatus() const;

    std::unique_ptr<BenchmarkSessionExecutor> executor_;
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
    bool requiredSnapshotCommitted_ = false;
    bool terminalEmitted_ = false;
};

} // namespace cryptobench::application
