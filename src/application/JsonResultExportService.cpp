#include <cryptobench/application/JsonResultExportService.h>

#include <QString>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/application/ResultJsonMapping.h>

namespace cryptobench::application {
namespace {

QString stableString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QJsonObject entryToJson(const ExportEntry& entry)
{
    QJsonObject result{
        {"entryIndex", static_cast<qint64>(entry.entryIndex)},
        {"status", stableString(toStableString(entry.status))},
        {"config", benchmarkConfigToJson(entry.config)},
        {"structuralCharacteristics", structuralCharacteristicsToJson(entry.characteristics)}
    };

    if (entry.id.has_value()) {
        result["id"] = QString::fromStdString(*entry.id);
    }
    if (entry.environment.has_value()) {
        result["environment"] = environmentInfoToJson(*entry.environment);
    }
    if (entry.statistics.has_value()) {
        result["statistics"] = benchmarkStatisticsToJson(*entry.statistics);
    }
    if (entry.error.has_value()) {
        result["error"] = errorInfoToJson(*entry.error);
    }

    return result;
}

} // namespace

QByteArray JsonResultExportService::serialize(const ResultDocument& document) const
{
    QJsonArray entries;
    for (const auto& entry : document.entries) {
        entries.append(entryToJson(entry));
    }

    const QJsonObject result{
        {"format", "cryptobenchmark-result"},
        {"schemaVersion", 1},
        {"mode", stableString(toStableString(document.mode))},
        {"status", stableString(toStableString(document.status))},
        {"entries", entries}
    };

    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

} // namespace cryptobench::application
