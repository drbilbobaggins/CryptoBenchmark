#include <cryptobench/application/CsvResultExportService.h>

#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/ResultJsonMapping.h>
#include <cryptobench/core/AlgorithmProfileId.h>
#include <cryptobench/core/BenchmarkStatistics.h>
#include <cryptobench/core/MemoryV2.h>
#include <cryptobench/core/StructuralCharacteristics.h>

namespace cryptobench::application {
namespace {

enum class Column : std::size_t {
    DocumentFormat,
    DocumentSchemaVersion,
    DocumentMode,
    DocumentStatus,
    MemorySamplingIntervalMilliseconds,
    MemoryModel,
    WorkerLifecycle,
    EntryIndex,
    EntryId,
    EntryStatus,
    ProfileId,
    Operation,
    IterationsPerRun,
    Runs,
    InputMode,
    MessageSizeBytes,
    PlaintextSizeBytes,
    InputSizeBytes,
    CharacteristicsType,
    PublicKeyBytes,
    PrivateKeyBytes,
    SignatureSizeBytes,
    SignatureSizeKind,
    SharedSecretBytes,
    CiphertextBytes,
    KeyBytes,
    NonceBytes,
    AadBytes,
    TagBytes,
    OutputBytes,
    ApplicationVersion,
    GitCommit,
    OpenSslVersion,
    OperatingSystem,
    Architecture,
    BuildType,
    MeasuredAt,
    WallClockMean,
    WallClockMedian,
    WallClockMin,
    WallClockMax,
    WallClockStddev,
    ProcessCpuMean,
    ProcessCpuMedian,
    ProcessCpuMin,
    ProcessCpuMax,
    ProcessCpuStddev,
    MemoryUnit,
    ReadyStateMean,
    ReadyStateMedian,
    ReadyStateMin,
    ReadyStateMax,
    ReadyStateStddev,
    PreparationPeakMean,
    PreparationPeakMedian,
    PreparationPeakMin,
    PreparationPeakMax,
    PreparationPeakStddev,
    ExecutionPeakMean,
    ExecutionPeakMedian,
    ExecutionPeakMin,
    ExecutionPeakMax,
    ExecutionPeakStddev,
    OperationalPeakMean,
    OperationalPeakMedian,
    OperationalPeakMin,
    OperationalPeakMax,
    OperationalPeakStddev,
    ErrorCode,
    ErrorStage,
    ErrorRunIndex,
    ErrorTechnicalMessage,
    ErrorLibraryDetails,
    BatchErrorCode,
    BatchErrorStage,
    BatchErrorEntryIndex,
    BatchErrorTechnicalMessage,
    Count
};

template <typename>
inline constexpr bool dependentFalse = false;

constexpr std::size_t kColumnCount = static_cast<std::size_t>(Column::Count);
static_assert(kColumnCount == 77);

constexpr std::array<std::string_view, kColumnCount> kHeader{
    "document.format",
    "document.schemaVersion",
    "document.mode",
    "document.status",
    "measurement.memorySamplingIntervalMilliseconds",
    "measurement.memoryModel",
    "measurement.workerLifecycle",
    "entry.entryIndex",
    "entry.id",
    "entry.status",
    "config.profileId",
    "config.operation",
    "config.iterationsPerRun",
    "config.runs",
    "config.parameters.inputMode",
    "config.parameters.messageSizeBytes",
    "config.parameters.plaintextSizeBytes",
    "config.parameters.inputSizeBytes",
    "structuralCharacteristics.type",
    "structuralCharacteristics.publicKeyBytes",
    "structuralCharacteristics.privateKeyBytes",
    "structuralCharacteristics.signatureSizeBytes",
    "structuralCharacteristics.signatureSizeKind",
    "structuralCharacteristics.sharedSecretBytes",
    "structuralCharacteristics.ciphertextBytes",
    "structuralCharacteristics.keyBytes",
    "structuralCharacteristics.nonceBytes",
    "structuralCharacteristics.aadBytes",
    "structuralCharacteristics.tagBytes",
    "structuralCharacteristics.outputBytes",
    "environment.applicationVersion",
    "environment.gitCommit",
    "environment.opensslVersion",
    "environment.operatingSystem",
    "environment.architecture",
    "environment.buildType",
    "environment.measuredAt",
    "statistics.wallClockNanosecondsPerOperation.mean",
    "statistics.wallClockNanosecondsPerOperation.median",
    "statistics.wallClockNanosecondsPerOperation.min",
    "statistics.wallClockNanosecondsPerOperation.max",
    "statistics.wallClockNanosecondsPerOperation.stddev",
    "statistics.processCpuNanosecondsPerOperation.mean",
    "statistics.processCpuNanosecondsPerOperation.median",
    "statistics.processCpuNanosecondsPerOperation.min",
    "statistics.processCpuNanosecondsPerOperation.max",
    "statistics.processCpuNanosecondsPerOperation.stddev",
    "statistics.memory.unit",
    "statistics.memory.readyStateDeltaBytes.mean",
    "statistics.memory.readyStateDeltaBytes.median",
    "statistics.memory.readyStateDeltaBytes.min",
    "statistics.memory.readyStateDeltaBytes.max",
    "statistics.memory.readyStateDeltaBytes.stddev",
    "statistics.memory.preparationPeakDeltaBytes.mean",
    "statistics.memory.preparationPeakDeltaBytes.median",
    "statistics.memory.preparationPeakDeltaBytes.min",
    "statistics.memory.preparationPeakDeltaBytes.max",
    "statistics.memory.preparationPeakDeltaBytes.stddev",
    "statistics.memory.executionPeakDeltaBytes.mean",
    "statistics.memory.executionPeakDeltaBytes.median",
    "statistics.memory.executionPeakDeltaBytes.min",
    "statistics.memory.executionPeakDeltaBytes.max",
    "statistics.memory.executionPeakDeltaBytes.stddev",
    "statistics.memory.operationalPeakDeltaBytes.mean",
    "statistics.memory.operationalPeakDeltaBytes.median",
    "statistics.memory.operationalPeakDeltaBytes.min",
    "statistics.memory.operationalPeakDeltaBytes.max",
    "statistics.memory.operationalPeakDeltaBytes.stddev",
    "error.code",
    "error.stage",
    "error.runIndex",
    "error.technicalMessage",
    "error.libraryDetails",
    "batchError.code",
    "batchError.stage",
    "batchError.entryIndex",
    "batchError.technicalMessage"
};

static_assert(kHeader.size() == 77);

template <typename Integer>
std::string formatInteger(Integer value)
{
    static_assert(std::is_integral_v<Integer>);
    std::array<char, 32> buffer{};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (result.ec != std::errc{}) {
        throw std::runtime_error("failed to format CSV integer");
    }
    return {buffer.data(), result.ptr};
}

std::string formatDouble(double value)
{
    if (!std::isfinite(value)) {
        throw std::invalid_argument("benchmark statistics must be finite");
    }

    std::array<char, 128> buffer{};
    const auto result = std::to_chars(
        buffer.data(), buffer.data() + buffer.size(), value, std::chars_format::general);
    if (result.ec != std::errc{}) {
        throw std::runtime_error("failed to format CSV floating-point value");
    }
    return {buffer.data(), result.ptr};
}

template <typename Fields>
void setText(Fields& fields, Column column, std::string_view value)
{
    fields[static_cast<std::size_t>(column)].assign(value);
}

template <typename Fields, typename Integer>
void setInteger(Fields& fields, Column column, Integer value)
{
    fields[static_cast<std::size_t>(column)] = formatInteger(value);
}

template <typename Fields, typename Integer>
void setOptionalInteger(Fields& fields, Column column, const std::optional<Integer>& value)
{
    if (value.has_value()) {
        setInteger(fields, column, *value);
    }
}

template <typename Fields>
void setDouble(Fields& fields, std::size_t column, double value)
{
    fields[column] = formatDouble(value);
}

template <typename Fields>
void setStatistics(Fields& fields, Column firstColumn, const core::Statistics<double>& statistics)
{
    const auto firstIndex = static_cast<std::size_t>(firstColumn);
    setDouble(fields, firstIndex, statistics.mean);
    setDouble(fields, firstIndex + 1, statistics.median);
    setDouble(fields, firstIndex + 2, statistics.min);
    setDouble(fields, firstIndex + 3, statistics.max);
    setDouble(fields, firstIndex + 4, statistics.stddev);
}

template <typename Fields>
void setConfiguration(Fields& fields, const core::BenchmarkConfig& config)
{
    const auto profileId = core::toStableProfileId(config.profile);
    setText(fields, Column::ProfileId, profileId);
    setText(fields, Column::Operation, toStableOperationString(config.operation));
    setInteger(fields, Column::IterationsPerRun, config.iterationsPerRun);
    setInteger(fields, Column::Runs, config.runs);

    std::visit([&fields](const auto& parameters) {
        using Parameters = std::decay_t<decltype(parameters)>;
        if constexpr (std::is_same_v<Parameters, core::SignatureConfig>) {
            if (const auto inputMode = signatureInputModeToStableString(parameters)) {
                setText(fields, Column::InputMode, *inputMode);
            }
            if (const auto* message = std::get_if<core::MessageInput>(&parameters.input)) {
                setInteger(fields, Column::MessageSizeBytes, message->messageSize);
            }
        } else if constexpr (std::is_same_v<Parameters, core::KeyEstablishmentConfig>) {
            static_cast<void>(parameters);
        } else if constexpr (std::is_same_v<Parameters, core::AeadConfig>) {
            setInteger(fields, Column::PlaintextSizeBytes, parameters.plaintextSize);
        } else if constexpr (std::is_same_v<Parameters, core::HashConfig>) {
            setInteger(fields, Column::InputSizeBytes, parameters.inputSize);
        } else {
            static_assert(dependentFalse<Parameters>, "unsupported primitive configuration alternative");
        }
    }, config.parameters);
}

template <typename Fields>
void setCharacteristics(Fields& fields, const core::StructuralCharacteristics& characteristics)
{
    setText(fields, Column::CharacteristicsType,
            structuralCharacteristicsTypeToStableString(characteristics));
    std::visit([&fields](const auto& value) {
        using Characteristics = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Characteristics, core::SignatureCharacteristics>) {
            setOptionalInteger(fields, Column::PublicKeyBytes, value.publicKeyBytes);
            setOptionalInteger(fields, Column::PrivateKeyBytes, value.privateKeyBytes);
            if (value.signatureSize.has_value()) {
                setInteger(fields, Column::SignatureSizeBytes, value.signatureSize->bytes);
                setText(fields, Column::SignatureSizeKind, toStableString(value.signatureSize->kind));
            }
        } else if constexpr (std::is_same_v<Characteristics, core::KeyEstablishmentCharacteristics>) {
            setInteger(fields, Column::SharedSecretBytes, value.sharedSecretBytes);
            setOptionalInteger(fields, Column::PublicKeyBytes, value.publicKeyBytes);
            setOptionalInteger(fields, Column::PrivateKeyBytes, value.privateKeyBytes);
            setOptionalInteger(fields, Column::CiphertextBytes, value.ciphertextBytes);
        } else if constexpr (std::is_same_v<Characteristics, core::AeadCharacteristics>) {
            setInteger(fields, Column::KeyBytes, value.keyBytes);
            setInteger(fields, Column::NonceBytes, value.nonceBytes);
            setInteger(fields, Column::AadBytes, value.aadBytes);
            setInteger(fields, Column::TagBytes, value.tagBytes);
        } else if constexpr (std::is_same_v<Characteristics, core::HashCharacteristics>) {
            setInteger(fields, Column::OutputBytes, value.outputBytes);
        } else {
            static_assert(dependentFalse<Characteristics>,
                          "unsupported structural characteristics alternative");
        }
    }, characteristics);
}

template <typename Fields>
void setEnvironment(Fields& fields, const std::optional<core::EnvironmentInfo>& environment)
{
    if (!environment.has_value()) {
        return;
    }

    setText(fields, Column::ApplicationVersion, environment->applicationVersion);
    setText(fields, Column::GitCommit, environment->gitCommit);
    setText(fields, Column::OpenSslVersion, environment->opensslVersion);
    setText(fields, Column::OperatingSystem, environment->operatingSystem);
    setText(fields, Column::Architecture, environment->architecture);
    setText(fields, Column::BuildType, environment->buildType);
    setText(fields, Column::MeasuredAt, measuredAtToStableString(environment->measuredAt));
}

template <typename Fields>
void setError(Fields& fields, const std::optional<core::ErrorInfo>& error)
{
    if (!error.has_value()) {
        return;
    }

    setText(fields, Column::ErrorCode, toStableString(error->code));
    setText(fields, Column::ErrorStage, toStableString(error->stage));
    setOptionalInteger(fields, Column::ErrorRunIndex, error->runIndex);
    setText(fields, Column::ErrorTechnicalMessage, error->technicalMessage);
    if (error->libraryDetails.has_value()) {
        setText(fields, Column::ErrorLibraryDetails, *error->libraryDetails);
    }
}

template <typename Fields>
void setBatchError(Fields& fields, const std::optional<BatchError>& error)
{
    if (!error.has_value()) {
        return;
    }

    setText(fields, Column::BatchErrorCode, toStableString(error->code));
    setText(fields, Column::BatchErrorStage, toStableString(error->stage));
    setOptionalInteger(fields, Column::BatchErrorEntryIndex, error->entryIndex);
    setText(fields, Column::BatchErrorTechnicalMessage, error->technicalMessage);
}

template <typename Fields>
void setEntryFields(Fields& fields, const ResultDocument& document, const ExportEntry& entry)
{
    setText(fields, Column::DocumentFormat, "cryptobenchmark-result");
    setInteger(fields, Column::DocumentSchemaVersion, 2);
    setText(fields, Column::DocumentMode, toStableString(document.mode));
    setText(fields, Column::DocumentStatus, toStableString(document.status));
    setInteger(fields, Column::MemorySamplingIntervalMilliseconds,
               document.measurement->measurementSettings.memorySamplingIntervalMilliseconds);
    setText(fields, Column::MemoryModel, "memoryV2");
    setText(fields, Column::WorkerLifecycle, "freshWorkerPerLogicalRun");

    setInteger(fields, Column::EntryIndex, entry.entryIndex);
    if (entry.id.has_value()) {
        setText(fields, Column::EntryId, *entry.id);
    }
    setText(fields, Column::EntryStatus, toStableString(entry.status));
    setConfiguration(fields, entry.config);
    setCharacteristics(fields, entry.characteristics);
    setEnvironment(fields, entry.environment);

    if (entry.statistics.has_value()) {
        setStatistics(fields, Column::WallClockMean, entry.statistics->elapsedNanosecondsPerOperation);
        setStatistics(fields, Column::ProcessCpuMean, entry.statistics->cpuNanosecondsPerOperation);
        const auto* memory = std::get_if<core::MemoryV2Statistics>(&entry.statistics->memory);
        if (memory == nullptr) {
            throw std::invalid_argument("Memory v2 statistics require result schema v2");
        }
        setText(fields, Column::MemoryUnit, "bytes");
        setStatistics(fields, Column::ReadyStateMean, memory->readyStatePrivateUsageDeltaBytes);
        setStatistics(fields, Column::PreparationPeakMean, memory->preparationPeakPrivateUsageDeltaBytes);
        setStatistics(fields, Column::ExecutionPeakMean, memory->executionPeakPrivateUsageDeltaBytes);
        setStatistics(fields, Column::OperationalPeakMean, memory->operationalPeakPrivateUsageDeltaBytes);
    }

    setError(fields, entry.error);
    setBatchError(fields, document.batchError);
}

template <std::size_t Size>
void appendEscapedRecord(QByteArray& output, const std::array<std::string, Size>& fields)
{
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (index != 0) {
            output.append(',');
        }

        const auto& field = fields[index];
        const bool quote = field.find_first_of(",\"\r\n") != std::string::npos;
        if (quote) {
            output.append('"');
        }
        for (const char character : field) {
            if (character == '"') {
                output.append("\"\"");
            } else {
                output.append(character);
            }
        }
        if (quote) {
            output.append('"');
        }
    }
    output.append("\r\n");
}

void appendHeader(QByteArray& output)
{
    for (std::size_t index = 0; index < kHeader.size(); ++index) {
        if (index != 0) {
            output.append(',');
        }
        const auto name = kHeader[index];
        output.append(name.data(), static_cast<qsizetype>(name.size()));
    }
    output.append("\r\n");
}

} // namespace

QByteArray CsvResultExportService::serialize(const ResultDocument& document) const
{
    if (document.batchError.has_value()
        && (document.mode != ResultMode::Batch || document.status != ResultDocumentStatus::Failed)) {
        throw std::invalid_argument("batch error requires a failed batch result document");
    }
    if (!document.measurement.has_value()
        || !core::isValidMeasurementSettings(document.measurement->measurementSettings)) {
        throw std::invalid_argument("result document is missing valid measurement metadata");
    }

    static_cast<void>(toStableString(document.mode));
    static_cast<void>(toStableString(document.status));

    QByteArray output;
    appendHeader(output);
    for (const auto& entry : document.entries) {
        std::array<std::string, kColumnCount> fields{};
        setEntryFields(fields, document, entry);
        appendEscapedRecord(output, fields);
    }
    return output;
}

} // namespace cryptobench::application
