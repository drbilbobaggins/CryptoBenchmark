#pragma once

#include <QJsonDocument>
#include <QString>

#include <cryptobench/core/BenchmarkConfig.h>

namespace cryptobench::tests {

struct M19_4CategorySpec {
    QString id;
    core::BenchmarkConfig config;
};

QJsonDocument m19_4QualificationMatrix();
QString m19_4ProductionWorkerPath();
void validateM19_4QualificationMatrix(const QJsonDocument& document);
void validateM19_4CampaignEvidence(const QString& outputDirectory);
int executeM19_4Qualification(const QString& outputDirectory);

} // namespace cryptobench::tests
