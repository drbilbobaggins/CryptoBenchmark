#pragma once

#include <optional>

#include <QByteArray>

#include <cryptobench/application/BatchTypes.h>

namespace cryptobench::application {

// Expects the bounded, BOM-normalized, strictly UTF-8 buffer returned by M11.2.
std::optional<BatchInputIssue> strictJsonPreflight(const QByteArray& utf8Bytes);

} // namespace cryptobench::application
