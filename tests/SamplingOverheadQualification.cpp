#include <cryptobench/application/AtomicFileWriter.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/EnvironmentInfoProvider.h>
#include <cryptobench/application/ResultJsonMapping.h>
#include <cryptobench/core/MemoryRunMeasurement.h>
#include <cryptobench/ipc/ParentIpcChannel.h>
#include <cryptobench/ipc/WireProtocol.h>
#include <cryptobench/platform/windows/WorkerMemorySampler.h>
#include <cryptobench/platform/windows/WindowsWorkerProcess.h>

#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

using namespace cryptobench;

namespace {

constexpr int kSessionTimeoutMilliseconds = 120'000;
constexpr std::uint32_t kSamplingIntervalMilliseconds = 5;

enum class SamplingMode {
    Off,
    On
};

const char* samplingModeString(SamplingMode mode)
{
    return mode == SamplingMode::Off ? "off" : "on";
}

struct RunRecord {
    std::uint32_t runIndex;
    core::WorkerRunMeasurement workerMeasurement;
    std::optional<core::MemoryRunMeasurement> memory;
};

struct SessionRecord {
    std::uint32_t pairIndex;
    std::uint32_t sessionOrder;
    SamplingMode samplingMode;
    std::vector<RunRecord> runs;
};

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

QString makeEndpoint()
{
    return QStringLiteral("CryptoBenchmark_SamplingQualification_%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

QString issueSummary(const application::BatchParseResult& result)
{
    QString summary;
    for (const auto& issue : result.issues) {
        if (!summary.isEmpty()) summary += QStringLiteral("; ");
        summary += QString::fromStdString(issue.path + ": " + issue.technicalMessage);
    }
    return summary;
}

class QualificationSession final : public QObject {
public:
    QualificationSession()
    {
        connect(&ipcChannel_, &ipc::ParentIpcChannel::workerReadyReceived,
                this, [this](const ipc::WorkerReady& value) { onWorkerReady(value); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::progressReceived,
                this, [this](const core::ProgressInfo& value) { onProgress(value); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::measurementReadyReceived,
                this, [this](std::uint32_t runIndex) { onMeasurementReady(runIndex); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::measurementFinishedReceived,
                this, [this](std::uint32_t runIndex) { onMeasurementFinished(runIndex); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::workerRunMeasurementReceived,
                this, [this](const core::WorkerRunMeasurement& value) { onWorkerRunMeasurement(value); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::workerOutcomeReceived,
                this, [this](const ipc::WorkerOutcome& value) { onWorkerOutcome(value); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::transportError,
                this, [this](const QString& message) { fail(message.toStdString()); });
        connect(&ipcChannel_, &ipc::ParentIpcChannel::disconnected,
                this, [this] {
                    if (state_ != State::WaitingForWorkerExit && state_ != State::Done) {
                        fail("worker IPC channel disconnected unexpectedly");
                    }
                });
        connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::errorOccurred,
                this, [this](QProcess::ProcessError, const QString& message) {
                    fail(message.toStdString());
                });
        connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::finished,
                this, [this](int exitCode, QProcess::ExitStatus exitStatus) {
                    onWorkerFinished(exitCode, exitStatus);
                });
        connect(&timeout_, &QTimer::timeout, this, [this] { fail("worker session timed out"); });
        timeout_.setSingleShot(true);
    }

    SessionRecord run(const core::BenchmarkConfig& config, SamplingMode mode,
                      std::uint32_t pairIndex, std::uint32_t sessionOrder)
    {
        config_ = &config;
        mode_ = mode;
        pairIndex_ = pairIndex;
        sessionOrder_ = sessionOrder;
        expectedRunIndex_ = 0;
        state_ = State::WaitingForWorkerReady;
        processExited_ = false;
        runs_.clear();
        pendingMemory_.reset();
        failure_.reset();
        activeLoop_ = nullptr;

        const auto endpoint = makeEndpoint();
        try {
            ipcChannel_.startListening(endpoint);
            workerProcess_.start(endpoint);
        } catch (const std::exception& error) {
            fail(error.what());
        }

        QEventLoop loop;
        activeLoop_ = &loop;
        if (!failure_) {
            timeout_.start(kSessionTimeoutMilliseconds);
            loop.exec();
        }
        activeLoop_ = nullptr;
        timeout_.stop();

        const auto failure = failure_;
        cleanup();
        if (failure) throw std::runtime_error(*failure);

        return {pairIndex_, sessionOrder_, mode_, std::move(runs_)};
    }

private:
    enum class State {
        WaitingForWorkerReady,
        WaitingForMeasurementReady,
        Measuring,
        WaitingForWorkerRunMeasurement,
        WaitingForWorkerOutcome,
        WaitingForWorkerExit,
        Done,
        Failed
    };

    void fail(const std::string& message)
    {
        if (failure_ || state_ == State::Done) return;
        failure_ = message;
        state_ = State::Failed;
        if (activeLoop_) activeLoop_->quit();
    }

    void onWorkerReady(const ipc::WorkerReady& value)
    {
        if (state_ != State::WaitingForWorkerReady) {
            fail("WorkerReady arrived in an invalid session state");
            return;
        }
        if (value.protocolVersion != ipc::kProtocolVersion) {
            fail("worker protocol version is unsupported");
            return;
        }
        try {
            ipcChannel_.sendBenchmarkRequest({*config_});
            state_ = State::WaitingForMeasurementReady;
        } catch (const std::exception& error) {
            fail(error.what());
        }
    }

    void onProgress(const core::ProgressInfo& value)
    {
        if (state_ == State::Measuring) {
            fail("Progress arrived during a measured memory window");
            return;
        }
        if (value.totalRuns != config_->runs ||
            (value.runIndex && *value.runIndex >= config_->runs)) {
            fail("worker progress did not match the configured run range");
        }
    }

    void onMeasurementReady(std::uint32_t runIndex)
    {
        if (state_ != State::WaitingForMeasurementReady ||
            runIndex != expectedRunIndex_ || runIndex >= config_->runs) {
            fail("MeasurementReady did not match the expected run");
            return;
        }

        const auto processId = workerProcess_.processId();
        if (processId <= 0 || static_cast<std::uint64_t>(processId) >
                                  std::numeric_limits<std::uint32_t>::max()) {
            fail("worker process ID is invalid");
            return;
        }

        try {
            if (mode_ == SamplingMode::On) {
                memorySampler_.start(static_cast<std::uint32_t>(processId), runIndex);
            }
            ipcChannel_.sendStartMeasurement(runIndex);
            state_ = State::Measuring;
        } catch (const std::exception& error) {
            fail(error.what());
        }
    }

    void onMeasurementFinished(std::uint32_t runIndex)
    {
        if (state_ != State::Measuring || runIndex != expectedRunIndex_) {
            fail("MeasurementFinished did not match the active run");
            return;
        }

        try {
            if (mode_ == SamplingMode::On) {
                if (!memorySampler_.isActive()) {
                    throw std::logic_error("memory sampler was not active");
                }
                pendingMemory_ = memorySampler_.stopAndCollect();
                if (pendingMemory_->runIndex != runIndex) {
                    throw std::logic_error("memory measurement run index mismatch");
                }
            }
            ipcChannel_.sendMemoryWindowClosed(runIndex);
            state_ = State::WaitingForWorkerRunMeasurement;
        } catch (const std::exception& error) {
            fail(error.what());
        }
    }

    void onWorkerRunMeasurement(const core::WorkerRunMeasurement& value)
    {
        if (state_ != State::WaitingForWorkerRunMeasurement ||
            value.runIndex != expectedRunIndex_ ||
            (mode_ == SamplingMode::On && !pendingMemory_) ||
            (mode_ == SamplingMode::Off && pendingMemory_)) {
            fail("WorkerRunMeasurement did not match the expected run");
            return;
        }

        runs_.push_back({value.runIndex, value, pendingMemory_ ?
            std::optional<core::MemoryRunMeasurement>(pendingMemory_->memory) : std::nullopt});
        pendingMemory_.reset();
        ++expectedRunIndex_;
        state_ = expectedRunIndex_ < config_->runs
            ? State::WaitingForMeasurementReady
            : State::WaitingForWorkerOutcome;
    }

    void onWorkerOutcome(const ipc::WorkerOutcome& value)
    {
        if (value.status == ipc::WorkerOutcomeStatus::Failed) {
            fail(value.error ? value.error->technicalMessage : "worker reported failure without ErrorInfo");
            return;
        }
        if (state_ != State::WaitingForWorkerOutcome || expectedRunIndex_ != config_->runs ||
            runs_.size() != config_->runs || pendingMemory_ || memorySampler_.isActive() || value.error) {
            fail("Completed outcome arrived before the session was complete");
            return;
        }
        if (processExited_) {
            state_ = State::Done;
            if (activeLoop_) activeLoop_->quit();
        } else {
            state_ = State::WaitingForWorkerExit;
        }
    }

    void onWorkerFinished(int exitCode, QProcess::ExitStatus exitStatus)
    {
        processExited_ = true;
        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            fail(exitStatus == QProcess::CrashExit ? "worker process crashed"
                                                    : "worker exited before the session completed");
            return;
        }
        if (state_ == State::WaitingForWorkerExit) {
            state_ = State::Done;
            if (activeLoop_) activeLoop_->quit();
        } else if (state_ != State::WaitingForWorkerOutcome) {
            fail("worker exited before the session completed");
        }
    }

    void cleanup()
    {
        memorySampler_.stopAndDiscard();
        if (workerProcess_.isRunning()) {
            workerProcess_.kill();
            QEventLoop cleanupLoop;
            QTimer cleanupTimer;
            cleanupTimer.setSingleShot(true);
            connect(&workerProcess_, &platform::windows::WindowsWorkerProcess::finished,
                    &cleanupLoop, &QEventLoop::quit);
            connect(&cleanupTimer, &QTimer::timeout, &cleanupLoop, &QEventLoop::quit);
            cleanupTimer.start(2'000);
            cleanupLoop.exec();
        }
        require(!workerProcess_.isRunning(), "worker process did not terminate; possible orphan");
        ipcChannel_.close();
    }

    const core::BenchmarkConfig* config_ = nullptr;
    SamplingMode mode_ = SamplingMode::Off;
    std::uint32_t pairIndex_ = 0;
    std::uint32_t sessionOrder_ = 0;
    std::uint32_t expectedRunIndex_ = 0;
    bool processExited_ = false;
    State state_ = State::Failed;
    std::vector<RunRecord> runs_;
    std::optional<core::ParentRunMemoryMeasurement> pendingMemory_;
    std::optional<std::string> failure_;
    QEventLoop* activeLoop_ = nullptr;
    ipc::ParentIpcChannel ipcChannel_;
    platform::windows::WindowsWorkerProcess workerProcess_;
    platform::windows::WorkerMemorySampler memorySampler_;
    QTimer timeout_;
};

QJsonObject runToJson(const RunRecord& run, std::uint64_t iterationsPerRun)
{
    QJsonObject result{
        {"runIndex", static_cast<qint64>(run.runIndex)},
        {"iterationsPerRun", QString::number(iterationsPerRun)},
        {"workerTotalElapsedNanoseconds", QString::number(run.workerMeasurement.elapsedNanoseconds)},
        {"workerTotalCpuNanoseconds", QString::number(run.workerMeasurement.processCpuNanoseconds)}
    };
    if (run.memory) {
        result["memory"] = QJsonObject{
            {"baselineBytes", QString::number(run.memory->baselineBytes)},
            {"sampledPeakBytes", QString::number(run.memory->peakSampledBytes)},
            {"peakDeltaBytes", QString::number(run.memory->peakDeltaBytes)}
        };
    }
    return result;
}

QJsonDocument makeQualificationDocument(const core::BenchmarkConfig& config,
                                        const core::EnvironmentInfo& environment,
                                        std::uint32_t pairCount,
                                        const std::vector<SessionRecord>& sessions)
{
    QJsonArray sessionArray;
    for (const auto& session : sessions) {
        QJsonArray runArray;
        for (const auto& run : session.runs) {
            runArray.append(runToJson(run, config.iterationsPerRun));
        }
        sessionArray.append(QJsonObject{
            {"pairIndex", static_cast<qint64>(session.pairIndex)},
            {"sessionOrder", static_cast<qint64>(session.sessionOrder)},
            {"samplingMode", samplingModeString(session.samplingMode)},
            {"runs", runArray}
        });
    }

    return QJsonDocument(QJsonObject{
        {"format", "cryptobenchmark-sampling-overhead-qualification"},
        {"schemaVersion", 1},
        {"environment", application::environmentInfoToJson(environment)},
        {"benchmarkConfig", application::benchmarkConfigToJson(config)},
        {"samplingIntervalMilliseconds", static_cast<qint64>(kSamplingIntervalMilliseconds)},
        {"requestedPairCount", static_cast<qint64>(pairCount)},
        {"sessions", sessionArray},
        {"status", "completed"}
    });
}

void writeInputFile(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "self-test input could not be opened");
    const auto input = QByteArrayLiteral(
        R"({"format":"cryptobenchmark-batch-input","schemaVersion":1,"entries":[{"profileId":"sha256","operation":"hash","iterationsPerRun":2,"runs":1,"parameters":{"inputSizeBytes":8}}]})");
    require(file.write(input) == input.size(), "self-test input could not be written");
}

void validateQualificationDocument(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "qualification output could not be opened");
    const auto document = QJsonDocument::fromJson(file.readAll());
    require(document.isObject(), "qualification output is not a JSON object");
    const auto object = document.object();
    require(object.value("format") == QStringLiteral("cryptobenchmark-sampling-overhead-qualification"),
            "qualification output format mismatch");
    require(object.value("schemaVersion").toInt() == 1, "qualification output schema mismatch");
        require(object.value("status") == QStringLiteral("completed"),
            "qualification output status mismatch");
        require(object.value("samplingIntervalMilliseconds").toInt() == 5,
            "qualification sampling interval mismatch");
        require(object.value("requestedPairCount").toInt() == 2,
            "qualification pair count mismatch");
    const auto sessions = object.value("sessions").toArray();
        require(sessions.size() == 4, "self-test did not produce four sessions");
        const std::array<std::tuple<int, int, const char*>, 4> expected = {{
        {0, 0, "off"},
        {0, 1, "on"},
        {1, 0, "on"},
        {1, 1, "off"}
        }};
        for (int index = 0; index < sessions.size(); ++index) {
        const auto session = sessions[index].toObject();
        const auto [pairIndex, sessionOrder, mode] = expected[static_cast<std::size_t>(index)];
        require(session.value("pairIndex").toInt() == pairIndex &&
                session.value("sessionOrder").toInt() == sessionOrder &&
                session.value("samplingMode") == QString::fromLatin1(mode),
            "self-test session pair/order/mode mismatch");
        const auto runs = session.value("runs").toArray();
        require(runs.size() == 1, "self-test session run count mismatch");
        const auto run = runs[0].toObject();
        require(run.value("runIndex").toInt() == 0,
            "self-test run index was not preserved");
        if (QString::fromLatin1(mode) == QStringLiteral("off")) {
            require(!run.contains("memory"), "OFF run contains fabricated memory data");
        } else {
            require(run.contains("memory"), "ON run does not contain memory data");
        }
        }
}

struct Arguments {
    QString input;
    QString output;
    std::uint32_t pairs = 0;
    bool selfTest = false;
};

Arguments parseArguments(const QStringList& arguments)
{
    Arguments result;
    for (int index = 1; index < arguments.size(); ++index) {
        const auto& argument = arguments[index];
        if (argument == QStringLiteral("--self-test")) {
            require(!result.selfTest && result.input.isEmpty() && result.output.isEmpty() && result.pairs == 0,
                    "--self-test cannot be combined with normal arguments");
            result.selfTest = true;
        } else if (argument == QStringLiteral("--input") || argument == QStringLiteral("--output") ||
                   argument == QStringLiteral("--pairs")) {
            require(index + 1 < arguments.size(), "missing command-line value");
            const auto value = arguments[++index];
            if (argument == QStringLiteral("--input")) result.input = value;
            else if (argument == QStringLiteral("--output")) result.output = value;
            else {
                bool ok = false;
                const auto pairs = value.toUInt(&ok);
                require(ok && pairs > 0, "--pairs must be a positive integer");
                result.pairs = pairs;
            }
        } else {
            throw std::runtime_error("unknown command-line argument: " + argument.toStdString());
        }
    }
    require(result.selfTest || (!result.input.isEmpty() && !result.output.isEmpty() && result.pairs > 0),
            "usage: --input <batch-json> --pairs <positive-integer> --output <qualification-json>");
    return result;
}

int executeQualification(const QString& inputPath, std::uint32_t pairCount, const QString& outputPath)
{
    const auto parsed = application::BatchInputParser{}.parseFile(inputPath);
    require(parsed.issues.empty() && parsed.definition.has_value(),
            "batch input is invalid: " + issueSummary(parsed).toStdString());
    require(parsed.definition->entries().size() == 1,
            "batch input must contain exactly one valid entry");
    const auto config = parsed.definition->entries().front().config;
    const auto environment = application::collectEnvironmentInfo();

    QualificationSession session;
    std::vector<SessionRecord> sessions;
    sessions.reserve(static_cast<std::size_t>(pairCount) * 2U);
    for (std::uint32_t pairIndex = 0; pairIndex < pairCount; ++pairIndex) {
        const auto firstMode = pairIndex % 2 == 0 ? SamplingMode::Off : SamplingMode::On;
        const auto secondMode = firstMode == SamplingMode::Off ? SamplingMode::On : SamplingMode::Off;
        sessions.push_back(session.run(config, firstMode, pairIndex, 0));
        sessions.push_back(session.run(config, secondMode, pairIndex, 1));
    }

    const auto document = makeQualificationDocument(config, environment, pairCount, sessions);
    const auto writeResult = application::AtomicFileWriter{}.writeAtomically(
        outputPath, document.toJson(QJsonDocument::Indented));
    require(writeResult.success, writeResult.technicalMessage.toStdString());
    return 0;
}

int executeSelfTest()
{
    QTemporaryDir directory;
    require(directory.isValid(), "self-test temporary directory is invalid");
    const auto input = directory.filePath(QStringLiteral("input.json"));
    const auto output = directory.filePath(QStringLiteral("qualification.json"));
    writeInputFile(input);
    executeQualification(input, 2, output);
    validateQualificationDocument(output);
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    try {
        const auto arguments = parseArguments(application.arguments());
        if (arguments.selfTest) return executeSelfTest();
        return executeQualification(arguments.input, arguments.pairs, arguments.output);
    } catch (const std::exception& error) {
        std::cerr << "Sampling overhead qualification failed: " << error.what() << '\n';
        return 1;
    }
}
