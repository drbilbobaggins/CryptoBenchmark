#include <cryptobench\application\BenchmarkConfigJson.h>
#include <cryptobench\application\CsvResultExportService.h>
#include <cryptobench\application\JsonResultExportService.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <locale>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QString>

#include <cryptobench\application\ResultJsonMapping.h>
#include <cryptobench\core\AlgorithmProfileId.h>
#include <cryptobench\core\BenchmarkStatistics.h>
#include <cryptobench\core\MemoryV2.h>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace core;

constexpr std::array<std::string_view, 77> kExpectedHeader{
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

using CsvRecord = std::vector<std::string>;
using CsvRecords = std::vector<CsvRecord>;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string toUtf8(const QString& value)
{
    const auto bytes = value.toUtf8();
    return {bytes.constData(), static_cast<std::size_t>(bytes.size())};
}

CsvRecords parseCsv(const QByteArray& bytes)
{
    const std::string input(bytes.constData(), static_cast<std::size_t>(bytes.size()));
    CsvRecords records;
    CsvRecord record;
    std::string field;
    bool inQuotes = false;
    bool afterQuote = false;
    bool fieldStarted = false;
    bool endedWithRecordSeparator = false;

    for (std::size_t index = 0; index < input.size(); ++index) {
        const char character = input[index];
        endedWithRecordSeparator = false;

        if (inQuotes) {
            if (character == '"') {
                if (index + 1 < input.size() && input[index + 1] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    inQuotes = false;
                    afterQuote = true;
                }
            } else {
                field.push_back(character);
            }
            continue;
        }

        if (afterQuote) {
            if (character == ',') {
                record.push_back(std::move(field));
                field.clear();
                fieldStarted = false;
                afterQuote = false;
            } else if (character == '\r' && index + 1 < input.size() && input[index + 1] == '\n') {
                record.push_back(std::move(field));
                field.clear();
                records.push_back(std::move(record));
                record.clear();
                fieldStarted = false;
                afterQuote = false;
                ++index;
                endedWithRecordSeparator = true;
            } else {
                throw std::runtime_error("unexpected byte after a quoted CSV field");
            }
            continue;
        }

        if (character == '"' && !fieldStarted && field.empty()) {
            inQuotes = true;
            fieldStarted = true;
        } else if (character == ',') {
            record.push_back(std::move(field));
            field.clear();
            fieldStarted = false;
        } else if (character == '\r') {
            require(index + 1 < input.size() && input[index + 1] == '\n',
                    "CSV contains a lone CR record separator");
            record.push_back(std::move(field));
            field.clear();
            records.push_back(std::move(record));
            record.clear();
            fieldStarted = false;
            ++index;
            endedWithRecordSeparator = true;
        } else if (character == '\n') {
            throw std::runtime_error("CSV contains a lone LF outside a quoted field");
        } else if (character == '"') {
            throw std::runtime_error("CSV contains an unescaped quote");
        } else {
            field.push_back(character);
            fieldStarted = true;
        }
    }

    require(!inQuotes, "CSV contains an unterminated quoted field");
    require(afterQuote || !fieldStarted || endedWithRecordSeparator,
            "CSV is missing its final CRLF record separator");
    require(endedWithRecordSeparator, "CSV is missing its final CRLF record separator");
    require(field.empty() && record.empty(), "CSV parser ended with an incomplete record");
    return records;
}

std::size_t columnIndex(const CsvRecord& header, std::string_view name)
{
    for (std::size_t index = 0; index < header.size(); ++index) {
        if (header[index] == name) {
            return index;
        }
    }
    throw std::runtime_error("CSV header is missing a required column");
}

const std::string& cell(const CsvRecords& records, std::size_t row, std::string_view name)
{
    return records.at(row).at(columnIndex(records.front(), name));
}

void requireCsvShape(const CsvRecords& records, std::size_t entryCount)
{
    require(records.size() == entryCount + 1, "CSV record count does not match entry count");
    for (const auto& record : records) {
        require(record.size() == kExpectedHeader.size(), "CSV record does not contain 77 fields");
    }
}

MeasurementSettings measurement()
{
    return {5};
}

ResultDocument emptyDocument(ResultMode mode = ResultMode::Single,
                             ResultDocumentStatus status = ResultDocumentStatus::Completed)
{
    return {mode, status, {}, std::nullopt, ResultMeasurementMetadata{measurement()}};
}

BenchmarkStatistics completeStatistics()
{
    return {
        Statistics<double>{0.000000123456789012345, 1.23456789012345, 1.0e-300, 1.0e300, -0.0},
        Statistics<double>{2.5e-250, 3.125, 4.5, 5.75, 6.875},
        MemoryV2Statistics{
            Statistics<double>{-1.0, -2.0, -3.0, -4.0, -5.0},
            Statistics<double>{11.0, 12.0, 13.0, 14.0, 15.0},
            Statistics<double>{21.0, 22.0, 23.0, 24.0, 25.0},
            Statistics<double>{31.0, 32.0, 33.0, 34.0, 35.0}}
    };
}

BenchmarkConfig hashConfig()
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 64, 2, HashConfig{128}};
}

ExportEntry makeEntry(std::uint32_t index, ExportEntryStatus status, BenchmarkConfig config,
                      StructuralCharacteristics characteristics,
                      std::optional<EnvironmentInfo> environment = std::nullopt,
                      std::optional<BenchmarkStatistics> statistics = std::nullopt,
                      std::optional<ErrorInfo> error = std::nullopt,
                      std::optional<std::string> id = std::nullopt)
{
    return {index, std::move(id), status, std::move(config), std::move(characteristics),
            std::move(environment), std::move(statistics), std::move(error)};
}

void testExactHeaderAndEmptyDocument()
{
    const auto bytes = CsvResultExportService{}.serialize(emptyDocument());
    require(!bytes.startsWith("\xEF\xBB\xBF"), "CSV unexpectedly contains a UTF-8 BOM");
    require(bytes.endsWith("\r\n"), "empty CSV does not end in CRLF");

    std::string expected;
    for (std::size_t index = 0; index < kExpectedHeader.size(); ++index) {
        if (index != 0) {
            expected.push_back(',');
        }
        expected.append(kExpectedHeader[index]);
    }
    expected.append("\r\n");
    require(std::string(bytes.constData(), static_cast<std::size_t>(bytes.size())) == expected,
            "CSV header text or column order differs from the frozen contract");

    const auto records = parseCsv(bytes);
    requireCsvShape(records, 0);
    require(records.front().size() == 77, "CSV header does not contain exactly 77 columns");
    for (std::size_t index = 0; index < kExpectedHeader.size(); ++index) {
        require(records.front()[index] == kExpectedHeader[index], "CSV header column mismatch");
    }
}

void testConfigurationAndStructuralUnions()
{
    constexpr std::uint64_t largeInteger = 9007199254740993ULL;
    const auto messageProfile = AlgorithmProfileId::Ed25519;
    const auto keyExchangeProfile = AlgorithmProfileId::X25519;
    const auto aeadProfile = AlgorithmProfileId::Aes128Gcm;
    const auto xofProfile = AlgorithmProfileId::Shake128_64B;
    const std::vector<ExportEntry> entries{
        makeEntry(1, ExportEntryStatus::Completed,
                  {AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, 64, 2,
                   SignatureConfig{NoSignatureInput{}}},
                  SignatureCharacteristics{ByteCount{0}, ByteCount{128}, SignatureSizeReference{0, SignatureSizeReferenceKind::Fixed}},
                  std::nullopt, std::nullopt, std::nullopt, "no-input"),
        makeEntry(2, ExportEntryStatus::Completed,
                  {AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, 64, 2,
                   SignatureConfig{PrehashedInput{}}},
                  SignatureCharacteristics{std::nullopt, std::nullopt, std::nullopt},
                  std::nullopt, std::nullopt, std::nullopt, "prehashed"),
        makeEntry(3, ExportEntryStatus::Completed,
                  {messageProfile, BenchmarkOperation::Sign, largeInteger, 2,
                   SignatureConfig{MessageInput{largeInteger}}},
                  SignatureCharacteristics{ByteCount{1952}, ByteCount{4032},
                      SignatureSizeReference{ByteCount{72}, SignatureSizeReferenceKind::MaximumDerEncoded}},
                  std::nullopt, std::nullopt, std::nullopt, "message"),
        makeEntry(4, ExportEntryStatus::Completed,
                  {keyExchangeProfile, BenchmarkOperation::Derive, 64, 2, KeyEstablishmentConfig{}},
                  KeyEstablishmentCharacteristics{ByteCount{0}, ByteCount{1184}, ByteCount{2400}, ByteCount{1088}},
                  std::nullopt, std::nullopt, std::nullopt, "key-establishment"),
        makeEntry(5, ExportEntryStatus::Completed,
                  {aeadProfile, BenchmarkOperation::Encrypt, 64, 2, AeadConfig{0}},
                  AeadCharacteristics{ByteCount{16}, ByteCount{12}, ByteCount{0}, ByteCount{16}},
                  std::nullopt, std::nullopt, std::nullopt, "aead"),
        makeEntry(6, ExportEntryStatus::Completed,
                  {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 64, 2, HashConfig{largeInteger}},
                  HashCharacteristics{ByteCount{32}},
                  std::nullopt, std::nullopt, std::nullopt, "hash"),
        makeEntry(7, ExportEntryStatus::Completed,
                  {xofProfile, BenchmarkOperation::Xof, 64, 2, HashConfig{1024}},
                  HashCharacteristics{ByteCount{64}},
                  std::nullopt, std::nullopt, std::nullopt, "xof"),
        makeEntry(8, ExportEntryStatus::Completed,
                  {keyExchangeProfile, BenchmarkOperation::Decapsulate, 64, 2, KeyEstablishmentConfig{}},
                  KeyEstablishmentCharacteristics{ByteCount{32}, std::nullopt, std::nullopt, std::nullopt},
                  std::nullopt, std::nullopt, std::nullopt, "key-establishment-without-optionals")
    };
    const ResultDocument document{
        ResultMode::Batch, ResultDocumentStatus::Completed, entries, std::nullopt,
        ResultMeasurementMetadata{measurement()}};
    const auto records = parseCsv(CsvResultExportService{}.serialize(document));
    requireCsvShape(records, entries.size());

    const std::array<std::string_view, 8> inputModes{"", "prehashed", "message", "", "", "", "", ""};
    const std::array<std::string_view, 8> characteristicTypes{
        "signature", "signature", "signature", "keyEstablishment", "aead", "hashXof", "hashXof",
        "keyEstablishment"};
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto row = index + 1;
        require(cell(records, row, "entry.id") == *entries[index].id, "entry order or id changed");
        require(cell(records, row, "config.profileId") == core::toStableProfileId(entries[index].config.profile),
                "profile id mapping mismatch");
        require(cell(records, row, "config.operation") == toStableOperationString(entries[index].config.operation),
                "operation mapping mismatch");
        require(cell(records, row, "config.parameters.inputMode") == inputModes[index],
                "signature input mode mapping mismatch");
        require(cell(records, row, "structuralCharacteristics.type") == characteristicTypes[index],
                "structural variant mapping mismatch");
        require(cell(records, row, "statistics.memory.unit").empty(),
                "memory unit was emitted without statistics");
    }

    require(cell(records, 1, "structuralCharacteristics.publicKeyBytes") == "0",
            "present zero optional public-key size was lost");
    require(cell(records, 1, "structuralCharacteristics.signatureSizeBytes") == "0",
            "present zero signature size was lost");
    require(cell(records, 1, "structuralCharacteristics.signatureSizeKind") == "fixed",
            "fixed signature size kind mismatch");
    require(cell(records, 2, "structuralCharacteristics.publicKeyBytes").empty()
                && cell(records, 2, "structuralCharacteristics.signatureSizeBytes").empty(),
            "absent signature fields were not empty");
    require(cell(records, 3, "config.iterationsPerRun") == "9007199254740993",
            "large integer iteration count lost precision");
    require(cell(records, 3, "config.parameters.messageSizeBytes") == "9007199254740993",
            "large message size lost precision");
    require(cell(records, 3, "structuralCharacteristics.signatureSizeKind") == "maximumDerEncoded",
            "maximum DER-encoded signature size kind mismatch");
    require(cell(records, 4, "structuralCharacteristics.sharedSecretBytes") == "0",
            "present zero shared-secret size was lost");
    require(cell(records, 4, "structuralCharacteristics.ciphertextBytes") == "1088",
            "present ciphertext size was lost");
    require(cell(records, 8, "structuralCharacteristics.publicKeyBytes").empty()
                && cell(records, 8, "structuralCharacteristics.privateKeyBytes").empty()
                && cell(records, 8, "structuralCharacteristics.ciphertextBytes").empty(),
            "absent key-establishment sizes were not empty");
    require(cell(records, 5, "config.parameters.plaintextSizeBytes") == "0"
                && cell(records, 5, "structuralCharacteristics.aadBytes") == "0",
            "present zero AEAD values were lost");
    require(cell(records, 6, "config.parameters.inputSizeBytes") == "9007199254740993",
            "large hash input size lost precision");
    require(cell(records, 7, "config.parameters.inputSizeBytes") == "1024"
                && cell(records, 7, "structuralCharacteristics.outputBytes") == "64",
            "XOF workload or structural output mapping mismatch");
}

struct CommaDecimalPoint final : std::numpunct<char> {
    char do_decimal_point() const override
    {
        return ',';
    }
};

class GlobalLocaleGuard {
public:
    GlobalLocaleGuard()
        : previous_(std::locale())
    {
        std::locale::global(std::locale(previous_, new CommaDecimalPoint));
    }

    ~GlobalLocaleGuard()
    {
        std::locale::global(previous_);
    }

private:
    std::locale previous_;
};

double parseDouble(const std::string& value)
{
    double parsed = 0.0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed,
                                        std::chars_format::general);
    require(result.ec == std::errc{} && result.ptr == value.data() + value.size(),
            "CSV statistic is not a locale-independent decimal");
    return parsed;
}

void testStatisticsRoundTripAndLocaleIndependence()
{
    const auto statistics = completeStatistics();
    const ResultDocument document{
        ResultMode::Single, ResultDocumentStatus::Completed,
        {makeEntry(1, ExportEntryStatus::Completed, hashConfig(), HashCharacteristics{32},
                   std::nullopt, statistics)},
        std::nullopt, ResultMeasurementMetadata{measurement()}};

    QByteArray bytes;
    {
        GlobalLocaleGuard localeGuard;
        bytes = CsvResultExportService{}.serialize(document);
    }
    const auto records = parseCsv(bytes);
    requireCsvShape(records, 1);
    require(cell(records, 1, "statistics.memory.unit") == "bytes", "Memory v2 unit missing");

    const std::array<std::pair<std::string_view, double>, 30> expected{{
        {"statistics.wallClockNanosecondsPerOperation.mean", 0.000000123456789012345},
        {"statistics.wallClockNanosecondsPerOperation.median", 1.23456789012345},
        {"statistics.wallClockNanosecondsPerOperation.min", 1.0e-300},
        {"statistics.wallClockNanosecondsPerOperation.max", 1.0e300},
        {"statistics.wallClockNanosecondsPerOperation.stddev", -0.0},
        {"statistics.processCpuNanosecondsPerOperation.mean", 2.5e-250},
        {"statistics.processCpuNanosecondsPerOperation.median", 3.125},
        {"statistics.processCpuNanosecondsPerOperation.min", 4.5},
        {"statistics.processCpuNanosecondsPerOperation.max", 5.75},
        {"statistics.processCpuNanosecondsPerOperation.stddev", 6.875},
        {"statistics.memory.readyStateDeltaBytes.mean", -1.0},
        {"statistics.memory.readyStateDeltaBytes.median", -2.0},
        {"statistics.memory.readyStateDeltaBytes.min", -3.0},
        {"statistics.memory.readyStateDeltaBytes.max", -4.0},
        {"statistics.memory.readyStateDeltaBytes.stddev", -5.0},
        {"statistics.memory.preparationPeakDeltaBytes.mean", 11.0},
        {"statistics.memory.preparationPeakDeltaBytes.median", 12.0},
        {"statistics.memory.preparationPeakDeltaBytes.min", 13.0},
        {"statistics.memory.preparationPeakDeltaBytes.max", 14.0},
        {"statistics.memory.preparationPeakDeltaBytes.stddev", 15.0},
        {"statistics.memory.executionPeakDeltaBytes.mean", 21.0},
        {"statistics.memory.executionPeakDeltaBytes.median", 22.0},
        {"statistics.memory.executionPeakDeltaBytes.min", 23.0},
        {"statistics.memory.executionPeakDeltaBytes.max", 24.0},
        {"statistics.memory.executionPeakDeltaBytes.stddev", 25.0},
        {"statistics.memory.operationalPeakDeltaBytes.mean", 31.0},
        {"statistics.memory.operationalPeakDeltaBytes.median", 32.0},
        {"statistics.memory.operationalPeakDeltaBytes.min", 33.0},
        {"statistics.memory.operationalPeakDeltaBytes.max", 34.0},
        {"statistics.memory.operationalPeakDeltaBytes.stddev", 35.0}
    }};
    for (const auto& [name, original] : expected) {
        const auto& text = cell(records, 1, name);
        const double parsed = parseDouble(text);
        require(parsed == original, "CSV statistic did not round-trip to its canonical double");
        require(std::signbit(parsed) == std::signbit(original),
                "CSV statistic did not preserve the sign of zero or a negative value");
    }
    require(cell(records, 1, "statistics.wallClockNanosecondsPerOperation.stddev") == "-0",
            "negative zero was not encoded canonically");
    require(cell(records, 1, "statistics.wallClockNanosecondsPerOperation.mean").find('.') != std::string::npos,
            "CSV double formatting was affected by a comma-decimal locale");
}

EnvironmentInfo specialEnvironment()
{
    const auto measuredAt = std::chrono::system_clock::time_point{std::chrono::milliseconds{1790035200177LL}};
    return {
        "1.2, \"quoted\"\rline\nnext\r\nárvíztűrő",
        "commit-\"x\"",
        "OpenSSL, 3.6",
        "Windows\r\n11",
        "x64",
        "Debug",
        measuredAt
    };
}

void testEscapingStatusesAndErrors()
{
    const std::string specialText = "comma, quote \" CR\r LF\n CRLF\r\n Unicode: árvíztűrő tükörfúrógép";
    const ResultDocument document{
        ResultMode::Batch,
        ResultDocumentStatus::Failed,
        {
            makeEntry(9, ExportEntryStatus::Completed, hashConfig(), HashCharacteristics{32},
                     specialEnvironment(), completeStatistics(), std::nullopt,
                     ",first \"entry\",\r\ná"),
            makeEntry(4, ExportEntryStatus::Failed, hashConfig(), HashCharacteristics{32},
                     std::nullopt, std::nullopt,
                     ErrorInfo{ErrorCode::CryptoOperationFailed, FailureStage::Measurement, 0,
                               specialText, specialText},
                     "failed"),
            makeEntry(7, ExportEntryStatus::Cancelled, hashConfig(), HashCharacteristics{32},
                     std::nullopt, std::nullopt, std::nullopt, "cancelled"),
            makeEntry(8, ExportEntryStatus::NotStarted, hashConfig(), HashCharacteristics{32}),
            makeEntry(10, ExportEntryStatus::Failed, hashConfig(), HashCharacteristics{32},
                     std::nullopt, std::nullopt,
                     ErrorInfo{ErrorCode::InternalError, FailureStage::ResultAssembly, std::nullopt,
                               "error without optional fields", std::nullopt},
                     "failed-without-optionals")
        },
        BatchError{BatchErrorCode::OutputWriteFailed, BatchErrorStage::SnapshotPersistence, 0, specialText},
        ResultMeasurementMetadata{measurement()}
    };

    const auto bytes = CsvResultExportService{}.serialize(document);
    require(!bytes.startsWith("\xEF\xBB\xBF"), "CSV unexpectedly contains a UTF-8 BOM");
    require(bytes.endsWith("\r\n"), "CSV output is missing its mandatory final CRLF");
    require(bytes.contains("\xC3\xA1"), "CSV output did not preserve non-ASCII UTF-8 bytes");
    require(bytes.contains("\"\""), "CSV output did not double embedded quotes");

    const auto records = parseCsv(bytes);
    requireCsvShape(records, document.entries.size());
    const std::array<std::string_view, 5> entryStatuses{
        "completed", "failed", "cancelled", "notStarted", "failed"};
    const std::array<std::string_view, 5> entryIds{
        ",first \"entry\",\r\ná", "failed", "cancelled", "", "failed-without-optionals"};
    for (std::size_t index = 0; index < document.entries.size(); ++index) {
        const auto row = index + 1;
        require(cell(records, row, "entry.entryIndex") == std::to_string(document.entries[index].entryIndex),
                "CSV entry order or index changed");
        require(cell(records, row, "entry.status") == entryStatuses[index], "entry status mapping mismatch");
        require(cell(records, row, "entry.id") == entryIds[index], "entry id escaping changed its content");
        require(cell(records, row, "document.format") == "cryptobenchmark-result"
                    && cell(records, row, "document.schemaVersion") == "2"
                    && cell(records, row, "document.mode") == "batch"
                    && cell(records, row, "document.status") == "failed",
                "document metadata was not repeated in each row");
        require(cell(records, row, "measurement.memorySamplingIntervalMilliseconds") == "5"
                    && cell(records, row, "measurement.memoryModel") == "memoryV2"
                    && cell(records, row, "measurement.workerLifecycle") == "freshWorkerPerLogicalRun",
                "measurement metadata was not repeated in each row");
        require(cell(records, row, "batchError.code") == "outputWriteFailed"
                    && cell(records, row, "batchError.stage") == "snapshotPersistence"
                    && cell(records, row, "batchError.entryIndex") == "0"
                    && cell(records, row, "batchError.technicalMessage") == specialText,
                "document BatchError was not repeated faithfully in each row");
    }
    require(cell(records, 1, "environment.applicationVersion") == specialEnvironment().applicationVersion,
            "environment applicationVersion escaping mismatch");
    require(cell(records, 1, "environment.gitCommit") == "commit-\"x\""
                && cell(records, 1, "environment.opensslVersion") == "OpenSSL, 3.6"
                && cell(records, 1, "environment.operatingSystem") == "Windows\r\n11"
                && cell(records, 1, "environment.architecture") == "x64"
                && cell(records, 1, "environment.buildType") == "Debug",
            "environment fields were not preserved");
    require(cell(records, 1, "environment.measuredAt") == "2026-09-22T00:00:00.177Z",
            "measuredAt does not use the canonical UTC ISO millisecond format");
    require(cell(records, 2, "error.code") == "cryptoOperationFailed"
                && cell(records, 2, "error.stage") == "measurement"
                && cell(records, 2, "error.runIndex") == "0"
                && cell(records, 2, "error.technicalMessage") == specialText
                && cell(records, 2, "error.libraryDetails") == specialText,
            "entry ErrorInfo fields were not preserved separately");
    require(cell(records, 5, "error.code") == "internalError"
                && cell(records, 5, "error.technicalMessage") == "error without optional fields"
                && cell(records, 5, "error.runIndex").empty()
                && cell(records, 5, "error.libraryDetails").empty(),
            "absent ErrorInfo optionals were not encoded as empty cells");
    require(cell(records, 1, "error.code").empty()
                && cell(records, 2, "statistics.memory.unit").empty()
                && cell(records, 4, "entry.id").empty()
                && cell(records, 4, "environment.measuredAt").empty(),
            "absent optionals were not encoded as empty cells");
}

void requireStatisticsRejected(const BenchmarkStatistics& statistics, std::string_view message)
{
    const ResultDocument document{
        ResultMode::Single, ResultDocumentStatus::Completed,
        {makeEntry(1, ExportEntryStatus::Completed, hashConfig(), HashCharacteristics{32},
                   std::nullopt, statistics)},
        std::nullopt, ResultMeasurementMetadata{measurement()}};
    bool rejected = false;
    try {
        static_cast<void>(CsvResultExportService{}.serialize(document));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void testValidationMatchesJsonResultContract()
{
    const auto service = CsvResultExportService{};

    auto missingMeasurement = emptyDocument();
    missingMeasurement.measurement.reset();
    bool missingRejected = false;
    try {
        static_cast<void>(service.serialize(missingMeasurement));
    } catch (const std::invalid_argument&) {
        missingRejected = true;
    }
    require(missingRejected, "missing measurement metadata was accepted");

    for (const auto interval : {0U, 6U}) {
        auto invalidMeasurement = emptyDocument();
        invalidMeasurement.measurement->measurementSettings.memorySamplingIntervalMilliseconds = interval;
        bool rejected = false;
        try {
            static_cast<void>(service.serialize(invalidMeasurement));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "invalid measurement settings were accepted");
    }

    const BatchError batchError{BatchErrorCode::InternalError, BatchErrorStage::Orchestration,
                                std::nullopt, "failure"};
    for (const auto& invalidDocument : {
             ResultDocument{ResultMode::Single, ResultDocumentStatus::Failed, {}, batchError,
                            ResultMeasurementMetadata{measurement()}},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::Completed, {}, batchError,
                            ResultMeasurementMetadata{measurement()}},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::InProgress, {}, batchError,
                            ResultMeasurementMetadata{measurement()}}}) {
        bool rejected = false;
        try {
            static_cast<void>(service.serialize(invalidDocument));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BatchError in an invalid document state was accepted");
    }

    const ResultDocument missingBatchIndex{
        ResultMode::Batch, ResultDocumentStatus::Failed,
        {makeEntry(1, ExportEntryStatus::Failed, hashConfig(), HashCharacteristics{32}),
         makeEntry(2, ExportEntryStatus::Failed, hashConfig(), HashCharacteristics{32})},
        BatchError{BatchErrorCode::InternalError, BatchErrorStage::Orchestration, std::nullopt, "batch failed"},
        ResultMeasurementMetadata{measurement()}};
    const auto missingBatchIndexRecords = parseCsv(service.serialize(missingBatchIndex));
    requireCsvShape(missingBatchIndexRecords, 2);
    require(cell(missingBatchIndexRecords, 1, "batchError.entryIndex").empty()
                && cell(missingBatchIndexRecords, 2, "batchError.entryIndex").empty(),
            "absent BatchError entry index was not encoded as empty cells");

    auto nan = completeStatistics();
    nan.elapsedNanosecondsPerOperation.mean = std::numeric_limits<double>::quiet_NaN();
    requireStatisticsRejected(nan, "NaN timing statistic was accepted");
    auto infinity = completeStatistics();
    infinity.cpuNanosecondsPerOperation.stddev = std::numeric_limits<double>::infinity();
    requireStatisticsRejected(infinity, "infinite CPU statistic was accepted");
    auto negativeInfinity = completeStatistics();
    std::get<MemoryV2Statistics>(negativeInfinity.memory).readyStatePrivateUsageDeltaBytes.min =
        -std::numeric_limits<double>::infinity();
    requireStatisticsRejected(negativeInfinity, "infinite ReadyState statistic was accepted");
    auto prepNan = completeStatistics();
    std::get<MemoryV2Statistics>(prepNan.memory).preparationPeakPrivateUsageDeltaBytes.max =
        std::numeric_limits<double>::quiet_NaN();
    requireStatisticsRejected(prepNan, "NaN preparation statistic was accepted");
    auto executionNan = completeStatistics();
    std::get<MemoryV2Statistics>(executionNan.memory).executionPeakPrivateUsageDeltaBytes.median =
        std::numeric_limits<double>::quiet_NaN();
    requireStatisticsRejected(executionNan, "NaN execution statistic was accepted");
    auto operationalNan = completeStatistics();
    std::get<MemoryV2Statistics>(operationalNan.memory).operationalPeakPrivateUsageDeltaBytes.stddev =
        std::numeric_limits<double>::quiet_NaN();
    requireStatisticsRejected(operationalNan, "NaN operational statistic was accepted");

    const BenchmarkStatistics legacy{
        Statistics<double>{1.0, 1.0, 1.0, 1.0, 0.0},
        Statistics<double>{2.0, 2.0, 2.0, 2.0, 0.0},
        Statistics<double>{3.0, 3.0, 3.0, 3.0, 0.0}};
    requireStatisticsRejected(legacy, "legacy memory statistics were accepted as Memory v2");
}

void requireJsonString(const QJsonObject& object, const char* key, std::string_view expected)
{
    const auto value = object.value(key);
    require(value.isString() && toUtf8(value.toString()) == expected, "JSON/CSV string parity mismatch");
}

void requireJsonNumber(const QJsonObject& object, const char* key, const std::string& csvValue)
{
    const auto value = object.value(key);
    require(value.isDouble() && value.toDouble() == parseDouble(csvValue), "JSON/CSV number parity mismatch");
}

void testSemanticParityWithJson()
{
    const auto measuredAt = std::chrono::system_clock::time_point{std::chrono::milliseconds{1790035200177LL}};
    const EnvironmentInfo environment{"1.2.3", "abc123", "OpenSSL 3.6", "Windows 11", "x64", "Debug", measuredAt};
    const ErrorInfo entryError{ErrorCode::CryptoOperationFailed, FailureStage::Measurement, 2,
                               "crypto failed", "library diagnostic"};
    const ResultDocument document{
        ResultMode::Batch,
        ResultDocumentStatus::Failed,
        {
            makeEntry(1, ExportEntryStatus::Completed,
                      {AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 64, 2,
                       SignatureConfig{MessageInput{128}}},
                      SignatureCharacteristics{ByteCount{32}, ByteCount{64},
                          SignatureSizeReference{ByteCount{64}, SignatureSizeReferenceKind::Fixed}},
                      environment, completeStatistics(), std::nullopt, "completed"),
            makeEntry(2, ExportEntryStatus::Failed,
                      {AlgorithmProfileId::X25519, BenchmarkOperation::Derive, 32, 3, KeyEstablishmentConfig{}},
                      KeyEstablishmentCharacteristics{ByteCount{32}, ByteCount{1184}, ByteCount{2400}, ByteCount{1088}},
                      std::nullopt, std::nullopt, entryError, "failed")
        },
        BatchError{BatchErrorCode::OutputWriteFailed, BatchErrorStage::SnapshotPersistence, 2, "batch failed"},
        ResultMeasurementMetadata{measurement()}
    };

    const auto jsonBytes = JsonResultExportService{}.serialize(document);
    const auto csvBytes = CsvResultExportService{}.serialize(document);
    QJsonParseError parseError;
    const auto json = QJsonDocument::fromJson(jsonBytes, &parseError);
    require(parseError.error == QJsonParseError::NoError && json.isObject(), "canonical JSON result failed to parse");
    const auto root = json.object();
    const auto records = parseCsv(csvBytes);
    requireCsvShape(records, document.entries.size());

    requireJsonString(root, "format", cell(records, 1, "document.format"));
    requireJsonNumber(root, "schemaVersion", cell(records, 1, "document.schemaVersion"));
    requireJsonString(root, "mode", cell(records, 1, "document.mode"));
    requireJsonString(root, "status", cell(records, 1, "document.status"));
    const auto measurementJson = root.value("measurement").toObject();
    requireJsonNumber(measurementJson, "memorySamplingIntervalMilliseconds",
                      cell(records, 1, "measurement.memorySamplingIntervalMilliseconds"));
    requireJsonString(measurementJson, "memoryModel", cell(records, 1, "measurement.memoryModel"));
    requireJsonString(measurementJson, "workerLifecycle", cell(records, 1, "measurement.workerLifecycle"));

    const auto entriesJson = root.value("entries").toArray();
    require(entriesJson.size() == 2, "JSON/CSV entry count mismatch");
    const auto first = entriesJson.at(0).toObject();
    const auto firstCsvRow = std::size_t{1};
    requireJsonNumber(first, "entryIndex", cell(records, firstCsvRow, "entry.entryIndex"));
    requireJsonString(first, "id", cell(records, firstCsvRow, "entry.id"));
    requireJsonString(first, "status", cell(records, firstCsvRow, "entry.status"));

    const auto config = first.value("config").toObject();
    requireJsonString(config, "profileId", cell(records, firstCsvRow, "config.profileId"));
    requireJsonString(config, "operation", cell(records, firstCsvRow, "config.operation"));
    requireJsonNumber(config, "iterationsPerRun", cell(records, firstCsvRow, "config.iterationsPerRun"));
    requireJsonNumber(config, "runs", cell(records, firstCsvRow, "config.runs"));
    const auto parameters = config.value("parameters").toObject();
    requireJsonString(parameters, "inputMode", cell(records, firstCsvRow, "config.parameters.inputMode"));
    requireJsonNumber(parameters, "messageSizeBytes", cell(records, firstCsvRow, "config.parameters.messageSizeBytes"));

    const auto characteristics = first.value("structuralCharacteristics").toObject();
    requireJsonString(characteristics, "type",
                      cell(records, firstCsvRow, "structuralCharacteristics.type"));
    requireJsonNumber(characteristics, "publicKeyBytes",
                      cell(records, firstCsvRow, "structuralCharacteristics.publicKeyBytes"));
    requireJsonNumber(characteristics, "privateKeyBytes",
                      cell(records, firstCsvRow, "structuralCharacteristics.privateKeyBytes"));
    const auto signatureSize = characteristics.value("signatureSize").toObject();
    requireJsonNumber(signatureSize, "bytes",
                      cell(records, firstCsvRow, "structuralCharacteristics.signatureSizeBytes"));
    requireJsonString(signatureSize, "kind",
                      cell(records, firstCsvRow, "structuralCharacteristics.signatureSizeKind"));

    const auto environmentJson = first.value("environment").toObject();
    for (const auto& mapping : std::array<std::pair<const char*, std::string_view>, 7>{{
             {"applicationVersion", "environment.applicationVersion"},
             {"gitCommit", "environment.gitCommit"},
             {"opensslVersion", "environment.opensslVersion"},
             {"operatingSystem", "environment.operatingSystem"},
             {"architecture", "environment.architecture"},
             {"buildType", "environment.buildType"},
             {"measuredAt", "environment.measuredAt"}}}) {
        requireJsonString(environmentJson, mapping.first, cell(records, firstCsvRow, mapping.second));
    }

    const auto statisticsJson = first.value("statistics").toObject();
    const auto wallJson = statisticsJson.value("wallClockNanosecondsPerOperation").toObject();
    const auto cpuJson = statisticsJson.value("processCpuNanosecondsPerOperation").toObject();
    const auto memoryJson = statisticsJson.value("memory").toObject();
    requireJsonString(memoryJson, "unit", cell(records, firstCsvRow, "statistics.memory.unit"));
    struct StatisticColumn {
        std::string_view family;
        std::string_view member;
        std::string_view csvName;
    };
    const std::array<StatisticColumn, 30> statisticColumns{{
        {"wallClockNanosecondsPerOperation", "mean", "statistics.wallClockNanosecondsPerOperation.mean"},
        {"wallClockNanosecondsPerOperation", "median", "statistics.wallClockNanosecondsPerOperation.median"},
        {"wallClockNanosecondsPerOperation", "min", "statistics.wallClockNanosecondsPerOperation.min"},
        {"wallClockNanosecondsPerOperation", "max", "statistics.wallClockNanosecondsPerOperation.max"},
        {"wallClockNanosecondsPerOperation", "stddev", "statistics.wallClockNanosecondsPerOperation.stddev"},
        {"processCpuNanosecondsPerOperation", "mean", "statistics.processCpuNanosecondsPerOperation.mean"},
        {"processCpuNanosecondsPerOperation", "median", "statistics.processCpuNanosecondsPerOperation.median"},
        {"processCpuNanosecondsPerOperation", "min", "statistics.processCpuNanosecondsPerOperation.min"},
        {"processCpuNanosecondsPerOperation", "max", "statistics.processCpuNanosecondsPerOperation.max"},
        {"processCpuNanosecondsPerOperation", "stddev", "statistics.processCpuNanosecondsPerOperation.stddev"},
        {"readyStateDelta", "mean", "statistics.memory.readyStateDeltaBytes.mean"},
        {"readyStateDelta", "median", "statistics.memory.readyStateDeltaBytes.median"},
        {"readyStateDelta", "min", "statistics.memory.readyStateDeltaBytes.min"},
        {"readyStateDelta", "max", "statistics.memory.readyStateDeltaBytes.max"},
        {"readyStateDelta", "stddev", "statistics.memory.readyStateDeltaBytes.stddev"},
        {"preparationPeakDelta", "mean", "statistics.memory.preparationPeakDeltaBytes.mean"},
        {"preparationPeakDelta", "median", "statistics.memory.preparationPeakDeltaBytes.median"},
        {"preparationPeakDelta", "min", "statistics.memory.preparationPeakDeltaBytes.min"},
        {"preparationPeakDelta", "max", "statistics.memory.preparationPeakDeltaBytes.max"},
        {"preparationPeakDelta", "stddev", "statistics.memory.preparationPeakDeltaBytes.stddev"},
        {"executionPeakDelta", "mean", "statistics.memory.executionPeakDeltaBytes.mean"},
        {"executionPeakDelta", "median", "statistics.memory.executionPeakDeltaBytes.median"},
        {"executionPeakDelta", "min", "statistics.memory.executionPeakDeltaBytes.min"},
        {"executionPeakDelta", "max", "statistics.memory.executionPeakDeltaBytes.max"},
        {"executionPeakDelta", "stddev", "statistics.memory.executionPeakDeltaBytes.stddev"},
        {"operationalPeakDelta", "mean", "statistics.memory.operationalPeakDeltaBytes.mean"},
        {"operationalPeakDelta", "median", "statistics.memory.operationalPeakDeltaBytes.median"},
        {"operationalPeakDelta", "min", "statistics.memory.operationalPeakDeltaBytes.min"},
        {"operationalPeakDelta", "max", "statistics.memory.operationalPeakDeltaBytes.max"},
        {"operationalPeakDelta", "stddev", "statistics.memory.operationalPeakDeltaBytes.stddev"}
    }};
    for (const auto& mapping : statisticColumns) {
        QJsonObject familyObject;
        if (mapping.family == "wallClockNanosecondsPerOperation") {
            familyObject = wallJson;
        } else if (mapping.family == "processCpuNanosecondsPerOperation") {
            familyObject = cpuJson;
        } else {
            familyObject = memoryJson.value(
                QString::fromUtf8(mapping.family.data(), static_cast<qsizetype>(mapping.family.size()))).toObject();
        }
        const auto jsonMember = std::string(mapping.member);
        requireJsonNumber(familyObject, jsonMember.c_str(), cell(records, firstCsvRow, mapping.csvName));
    }

    const auto second = entriesJson.at(1).toObject();
    const auto secondCsvRow = std::size_t{2};
    requireJsonString(second, "status", cell(records, secondCsvRow, "entry.status"));
    const auto errorJson = second.value("error").toObject();
    requireJsonString(errorJson, "code", cell(records, secondCsvRow, "error.code"));
    requireJsonString(errorJson, "stage", cell(records, secondCsvRow, "error.stage"));
    requireJsonNumber(errorJson, "runIndex", cell(records, secondCsvRow, "error.runIndex"));
    requireJsonString(errorJson, "technicalMessage", cell(records, secondCsvRow, "error.technicalMessage"));
    requireJsonString(errorJson, "libraryDetails", cell(records, secondCsvRow, "error.libraryDetails"));

    const auto batchErrorJson = root.value("batchError").toObject();
    for (std::size_t row = 1; row < records.size(); ++row) {
        requireJsonString(batchErrorJson, "code", cell(records, row, "batchError.code"));
        requireJsonString(batchErrorJson, "stage", cell(records, row, "batchError.stage"));
        requireJsonNumber(batchErrorJson, "entryIndex", cell(records, row, "batchError.entryIndex"));
        requireJsonString(batchErrorJson, "technicalMessage", cell(records, row, "batchError.technicalMessage"));
    }
}

void testDocumentStatuses()
{
    const std::array statuses{
        std::pair{ResultDocumentStatus::Completed, "completed"},
        std::pair{ResultDocumentStatus::CompletedWithFailures, "completedWithFailures"},
        std::pair{ResultDocumentStatus::Cancelled, "cancelled"},
        std::pair{ResultDocumentStatus::Failed, "failed"}
    };
    for (const auto& [status, expected] : statuses) {
        const ResultDocument document{
            ResultMode::Batch, status,
            {makeEntry(1, ExportEntryStatus::NotStarted, hashConfig(), HashCharacteristics{32})},
            std::nullopt, ResultMeasurementMetadata{measurement()}};
        const auto records = parseCsv(CsvResultExportService{}.serialize(document));
        requireCsvShape(records, 1);
        require(cell(records, 1, "document.status") == expected,
                "terminal document status mapping mismatch");
    }
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testExactHeaderAndEmptyDocument();
        std::cout << "PASS exact header and empty document\n";
        cryptobench::tests::testConfigurationAndStructuralUnions();
        std::cout << "PASS configuration and structural unions\n";
        cryptobench::tests::testStatisticsRoundTripAndLocaleIndependence();
        std::cout << "PASS statistics round-trip and locale independence\n";
        cryptobench::tests::testEscapingStatusesAndErrors();
        std::cout << "PASS escaping, statuses, and errors\n";
        cryptobench::tests::testValidationMatchesJsonResultContract();
        std::cout << "PASS JSON-equivalent validation\n";
        cryptobench::tests::testSemanticParityWithJson();
        std::cout << "PASS semantic JSON/CSV parity\n";
        cryptobench::tests::testDocumentStatuses();
        std::cout << "PASS document statuses\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL CsvResultExportService: " << error.what() << '\n';
        return 1;
    }
}
