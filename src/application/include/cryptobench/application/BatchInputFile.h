#pragma once

#include <variant>

#include <QByteArray>
#include <QString>
#include <QtGlobal>

#include <cryptobench/application/BatchTypes.h>

namespace cryptobench::application {

inline constexpr qint64 kMaxBatchInputFileBytes = 4'194'304;

std::variant<QByteArray, BatchInputIssue> readBatchInputFile(const QString& filePath);

} // namespace cryptobench::application
