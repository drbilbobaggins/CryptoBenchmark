#pragma once

#include <QJsonDocument>
#include <QString>

#include <cstdint>
#include <stdexcept>

namespace cryptobench::tests {

enum class SyntheticOutcome {
    Completed,
    WorkerFailure,
    AbnormalExit,
    WaitForCancellation
};

struct SyntheticScenario {
    std::uint64_t preparationBytes = 0;
    std::uint64_t executionBytes = 0;
    std::uint32_t preparationHoldMilliseconds = 80;
    std::uint32_t executionHoldMilliseconds = 80;
    bool releasePreparationBeforeBoundary = true;
    bool releaseExecutionBeforeEnd = true;
    SyntheticOutcome outcome = SyntheticOutcome::Completed;
};

SyntheticScenario parseSyntheticScenario(const QString& encoded);
QJsonDocument encodeSyntheticScenario(const SyntheticScenario& scenario);
void validateSyntheticScenario(const SyntheticScenario& scenario);
QString syntheticOutcomeName(SyntheticOutcome outcome);

} // namespace cryptobench::tests
