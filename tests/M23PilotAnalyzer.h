#pragma once

#include <vector>

#include <QJsonObject>

namespace cryptobench::tests {

std::vector<QJsonObject> syntheticM23PilotEvidenceForTests();
QJsonObject analyzeM23PilotEvidence(
    const std::vector<QJsonObject>& evidenceFiles,
    bool allowSyntheticTestFixtures = false);

} // namespace cryptobench::tests
