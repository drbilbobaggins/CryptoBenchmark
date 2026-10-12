#include <cryptobench/application/JsonResultExportService.h>

#include <chrono>
#include <cmath>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QString>

namespace cryptobench::tests {
namespace {

using namespace application;
using namespace core;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void requireString(const QJsonObject& object, const char* key, std::string_view expected)
{
    const auto value = object.value(key);
    require(value.isString() && value.toString().toUtf8().toStdString() == expected, "JSON string field mismatch");
}

void requireNumber(const QJsonObject& object, const char* key, double expected)
{
    const auto value = object.value(key);
    require(value.isDouble() && value.toDouble() == expected, "JSON number field mismatch");
}

void requireKeys(const QJsonObject& object, std::initializer_list<const char*> keys)
{
    require(object.size() == static_cast<int>(keys.size()), "JSON object field count mismatch");
    for (const auto key : keys) {
        require(object.contains(key), "JSON object field missing");
    }
}

BenchmarkConfig sampleConfig()
{
    return {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 64, 2, HashConfig{128}};
}

StructuralCharacteristics sampleCharacteristics()
{
    return HashCharacteristics{32};
}

EnvironmentInfo sampleEnvironment(std::string applicationVersion = "0.1.0")
{
    return {std::move(applicationVersion), "abc123", "3.6.4", "Windows", "x64", "Debug",
            std::chrono::system_clock::time_point{}};
}

BenchmarkStatistics sampleStatistics()
{
    return {
        Statistics<double>{1.25, 1.5, 1.0, 2.0, 0.125},
        Statistics<double>{2.0, 2.0, 2.0, 2.0, 0.0},
        MemoryV2Statistics{
            Statistics<double>{-1.0, -1.0, -2.0, 0.0, 0.0},
            Statistics<double>{3.0, 3.0, 3.0, 3.0, 0.0},
            Statistics<double>{4.0, 4.0, 4.0, 4.0, 0.0},
            Statistics<double>{5.0, 5.0, 5.0, 5.0, 0.0}}
    };
}

ResultMeasurementMetadata measurement()
{
    return {MeasurementSettings{5}};
}

ErrorInfo sampleError()
{
    return {ErrorCode::InternalError, FailureStage::ResultAssembly, std::uint32_t{2}, "failed", "details"};
}

ExportEntry entry(std::uint32_t index, ExportEntryStatus status, std::optional<std::string> id,
                  std::optional<EnvironmentInfo> environment, std::optional<BenchmarkStatistics> statistics,
                  std::optional<ErrorInfo> error)
{
    return {index, std::move(id), status, sampleConfig(), sampleCharacteristics(), std::move(environment),
            std::move(statistics), std::move(error)};
}

QJsonObject parseObject(const QByteArray& bytes)
{
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    require(error.error == QJsonParseError::NoError, "serialized JSON did not parse");
    require(document.isObject(), "serialized JSON is not an object");
    return document.object();
}

void requireNoNullOptionals(const QJsonObject& value)
{
    for (const auto key : {"id", "environment", "statistics", "error"}) {
        require(!value.contains(key) || !value.value(key).isNull(), "absent optional was emitted as null");
    }
}

BatchError sampleBatchError(std::optional<std::uint32_t> entryIndex = std::uint32_t{5})
{
    return {BatchErrorCode::OutputWriteFailed, BatchErrorStage::SnapshotPersistence, entryIndex,
            "mentési hiba: árvíztűrő tükörfúrógép"};
}

void testSingleCompletedDocument()
{
    const ResultDocument document{
        ResultMode::Single,
        ResultDocumentStatus::Completed,
        {entry(1, ExportEntryStatus::Completed, "single-é", sampleEnvironment(), sampleStatistics(), std::nullopt)},
        std::nullopt,
        measurement()};

    const auto serialized = JsonResultExportService{}.serialize(document);
        require(serialized.contains("\n    \"") && serialized.contains("\n        \""),
            "JSON was not serialized with indentation");
    const auto root = parseObject(serialized);
    requireKeys(root, {"format", "schemaVersion", "mode", "status", "measurement", "entries"});
    requireString(root, "format", "cryptobenchmark-result");
    requireNumber(root, "schemaVersion", 2.0);
    requireString(root, "mode", "single");
    requireString(root, "status", "completed");
    requireNumber(root.value("measurement").toObject(), "memorySamplingIntervalMilliseconds", 5.0);

    const auto entries = root.value("entries").toArray();
    require(entries.size() == 1, "single document entry count mismatch");
    const auto value = entries.at(0).toObject();
    requireKeys(value, {"entryIndex", "id", "status", "config", "structuralCharacteristics", "environment", "statistics"});
    requireNumber(value, "entryIndex", 1.0);
    requireString(value, "id", "single-é");
    requireString(value, "status", "completed");
    require(value.value("config").toObject().value("profileId").toString() == "sha256", "config mapping missing");
    require(value.value("structuralCharacteristics").toObject().value("type").toString() == "hashXof",
            "structural mapping missing");
    require(value.value("environment").toObject().contains("applicationVersion"), "environment mapping missing");
    requireNumber(value.value("statistics").toObject().value("wallClockNanosecondsPerOperation").toObject(),
                  "mean", 1.25);
    requireNoNullOptionals(value);
    require(JsonResultExportService{}.serialize(document).contains("\xC3\xA9"), "UTF-8 bytes missing");
}

void testEntryFieldMatricesAndOrder()
{
    const ResultDocument document{
        ResultMode::Batch,
        ResultDocumentStatus::InProgress,
        {
            entry(7, ExportEntryStatus::Completed, "done", sampleEnvironment(), sampleStatistics(), std::nullopt),
            entry(8, ExportEntryStatus::Failed, std::nullopt, sampleEnvironment(), std::nullopt, sampleError()),
            entry(9, ExportEntryStatus::Cancelled, "cancelled", sampleEnvironment(), std::nullopt, std::nullopt),
            entry(10, ExportEntryStatus::NotStarted, std::nullopt, std::nullopt, std::nullopt, std::nullopt)
        },
        std::nullopt,
        measurement()
    };

    const auto root = parseObject(JsonResultExportService{}.serialize(document));
    requireString(root, "mode", "batch");
    requireString(root, "status", "inProgress");
    const auto values = root.value("entries").toArray();
    require(values.size() == 4, "batch entry count mismatch");

    const std::vector<std::string> statuses{"completed", "failed", "cancelled", "notStarted"};
    for (qsizetype index = 0; index < values.size(); ++index) {
        const auto value = values.at(index).toObject();
        requireNumber(value, "entryIndex", static_cast<double>(index + 7));
        requireString(value, "status", statuses.at(static_cast<std::size_t>(index)));
        require(value.value("config").isObject(), "config mapping missing");
        require(value.value("structuralCharacteristics").isObject(), "structural mapping missing");
        requireNoNullOptionals(value);
    }

    const auto completed = values.at(0).toObject();
    require(completed.contains("environment") && completed.contains("statistics") && !completed.contains("error"),
            "completed field matrix mismatch");
    const auto failed = values.at(1).toObject();
    require(!failed.contains("statistics") && failed.contains("environment") && failed.contains("error"),
            "failed field matrix mismatch");
    require(failed.value("error").toObject().value("technicalMessage").toString() == "failed",
            "error mapping missing");
    const auto cancelled = values.at(2).toObject();
    require(cancelled.contains("environment") && !cancelled.contains("statistics") && !cancelled.contains("error"),
            "cancelled field matrix mismatch");
    const auto notStarted = values.at(3).toObject();
    require(!notStarted.contains("environment") && !notStarted.contains("statistics") && !notStarted.contains("error"),
            "not-started field matrix mismatch");
    require(!notStarted.contains("id"), "absent id was emitted");
}

void testBatchStatuses()
{
    const auto service = JsonResultExportService{};
    for (const auto status : {ResultDocumentStatus::Completed, ResultDocumentStatus::CompletedWithFailures,
                              ResultDocumentStatus::Cancelled}) {
        const auto root = parseObject(service.serialize(
            ResultDocument{ResultMode::Batch, status, {}, std::nullopt, measurement()}));
        require(root.value("status").toString() == QString::fromUtf8(toStableString(status).data(),
                                                                        static_cast<qsizetype>(toStableString(status).size())),
                "batch status mapping mismatch");
        require(root.value("entries").toArray().isEmpty(), "empty batch entries mismatch");
    }
}

void testFailedBatchErrorWithEntryError()
{
    const ResultDocument document{
        ResultMode::Batch,
        ResultDocumentStatus::Failed,
        {entry(5, ExportEntryStatus::Failed, std::nullopt, sampleEnvironment(), std::nullopt, sampleError())},
        sampleBatchError(),
        measurement()
    };

    const auto root = parseObject(JsonResultExportService{}.serialize(document));
    requireKeys(root, {"format", "schemaVersion", "mode", "status", "measurement", "entries", "batchError"});
    const auto batchError = root.value("batchError").toObject();
    requireKeys(batchError, {"code", "stage", "entryIndex", "technicalMessage"});
    requireString(batchError, "code", "outputWriteFailed");
    requireString(batchError, "stage", "snapshotPersistence");
    requireNumber(batchError, "entryIndex", 5.0);
    require(batchError.value("technicalMessage").toString() == QString::fromUtf8("mentési hiba: árvíztűrő tükörfúrógép"),
            "batch error UTF-8 message mismatch");
    require(root.value("entries").toArray().at(0).toObject().contains("error"),
            "entry-level error was not preserved separately");
    require(root.value("entries").toArray().at(0).toObject().value("error").toObject().contains("runIndex"),
            "entry-level run index was not preserved");
}

void testFailedBatchErrorWithoutEntryIndex()
{
    const ResultDocument document{
        ResultMode::Batch, ResultDocumentStatus::Failed, {}, sampleBatchError(std::nullopt), measurement()
    };
    const auto batchError = parseObject(JsonResultExportService{}.serialize(document)).value("batchError").toObject();
    requireKeys(batchError, {"code", "stage", "technicalMessage"});
    require(!batchError.contains("entryIndex"), "absent batch entry index was emitted");
    require(batchError.value("entryIndex").isUndefined(), "absent batch entry index was not undefined");
}

void testBatchErrorAbsentFromNormalDocuments()
{
    const auto service = JsonResultExportService{};
    const auto single = parseObject(service.serialize(ResultDocument{
        ResultMode::Single, ResultDocumentStatus::Completed, {}, std::nullopt, measurement()
    }));
    requireKeys(single, {"format", "schemaVersion", "mode", "status", "measurement", "entries"});
    require(!single.contains("batchError"), "single document unexpectedly contains batch error");

    for (const auto status : {ResultDocumentStatus::InProgress, ResultDocumentStatus::Completed,
                              ResultDocumentStatus::CompletedWithFailures, ResultDocumentStatus::Cancelled}) {
        const auto root = parseObject(service.serialize(
            ResultDocument{ResultMode::Batch, status, {}, std::nullopt, measurement()}));
        require(!root.contains("batchError"), "normal batch document unexpectedly contains batch error");
    }
}

void testBatchErrorModeAndStatusAreValidated()
{
    const auto service = JsonResultExportService{};
    const BatchError error = sampleBatchError();
    for (const auto document : {
             ResultDocument{ResultMode::Single, ResultDocumentStatus::Completed, {}, error},
             ResultDocument{ResultMode::Single, ResultDocumentStatus::Failed, {}, error},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::InProgress, {}, error},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::Completed, {}, error},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::CompletedWithFailures, {}, error},
             ResultDocument{ResultMode::Batch, ResultDocumentStatus::Cancelled, {}, error}}) {
        bool rejected = false;
        try {
            static_cast<void>(service.serialize(document));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "invalid batch error placement was accepted");
    }
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testSingleCompletedDocument();
        std::cout << "PASS single completed export\n";
        cryptobench::tests::testEntryFieldMatricesAndOrder();
        std::cout << "PASS entry matrices and order\n";
        cryptobench::tests::testBatchStatuses();
        std::cout << "PASS batch statuses\n";
        cryptobench::tests::testFailedBatchErrorWithEntryError();
        std::cout << "PASS failed batch error with entry error\n";
        cryptobench::tests::testFailedBatchErrorWithoutEntryIndex();
        std::cout << "PASS failed batch error without entry index\n";
        cryptobench::tests::testBatchErrorAbsentFromNormalDocuments();
        std::cout << "PASS normal documents omit batch error\n";
        cryptobench::tests::testBatchErrorModeAndStatusAreValidated();
        std::cout << "PASS batch error placement validation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL JsonResultExportService: " << error.what() << '\n';
        return 1;
    }
}
