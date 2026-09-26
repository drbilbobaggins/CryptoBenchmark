#pragma once

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <QByteArray>

#include <cryptobench/application/BatchTypes.h>

namespace cryptobench::application {

// Expects the bounded, BOM-normalized, strictly UTF-8 buffer returned by M11.2.
std::optional<BatchInputIssue> strictJsonPreflight(const QByteArray& utf8Bytes);

struct JsonNumberToken {
	std::string path;
	QByteArray lexeme;
	qsizetype startOffset = 0;
	qsizetype endOffset = 0;
};

using JsonNumberTokenResult = std::variant<std::vector<JsonNumberToken>, BatchInputIssue>;

JsonNumberTokenResult inspectJsonNumberTokens(const QByteArray& utf8Bytes);

} // namespace cryptobench::application
