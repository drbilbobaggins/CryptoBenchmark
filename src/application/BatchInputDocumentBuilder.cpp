#include <cryptobench/application/BatchInputDocumentBuilder.h>

#include <cryptobench/application/BenchmarkConfigJson.h>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace cryptobench::application {

QByteArray BatchInputDocumentBuilder::build(const std::vector<core::BenchmarkConfig>& configs) const
{
    QJsonArray entries;
    for (const auto& config : configs) {
        entries.append(benchmarkConfigToJson(config));
    }

    const QJsonObject document{
        {"format", "cryptobenchmark-batch-input"},
        {"schemaVersion", 1},
        {"entries", entries}
    };
    return QJsonDocument(document).toJson(QJsonDocument::Indented);
}

} // namespace cryptobench::application
