#include <cryptobench/application/BatchInputDocumentBuilder.h>
#include <cryptobench/application/BatchInputParser.h>
#include <cryptobench/application/BenchmarkConfigJson.h>
#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkConfig.h>
#include <cryptobench/core/ConfigValidation.h>

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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

std::vector<BenchmarkConfig> representativeConfigs()
{
    return {
        {AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, 1, 1,
         SignatureConfig{NoSignatureInput{}}},
        {AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, 2, 3,
         SignatureConfig{PrehashedInput{}}},
        {AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 10, 2,
         SignatureConfig{MessageInput{64}}},
        {AlgorithmProfileId::X25519, BenchmarkOperation::Derive, 3, 4,
         KeyEstablishmentConfig{}},
        {AlgorithmProfileId::Aes256Gcm, BenchmarkOperation::Encrypt, 5, 6,
         AeadConfig{1024}},
        {AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, 7, 8, HashConfig{0}},
        {AlgorithmProfileId::Shake128_32B, BenchmarkOperation::Xof, 9, 10, HashConfig{2048}},
        {AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, 10, 2,
         SignatureConfig{MessageInput{64}}},
        {AlgorithmProfileId::Ed25519, BenchmarkOperation::Verify, 100, 5,
         SignatureConfig{MessageInput{777}}}
    };
}

QString writeInput(const QTemporaryDir& directory, const QByteArray& bytes)
{
    const auto path = directory.filePath(QStringLiteral("builder-output.json"));
    QFile file(path);
    require(file.open(QIODevice::WriteOnly), "temporary builder output could not be opened");
    require(file.write(bytes) == bytes.size(), "temporary builder output could not be written");
    return path;
}

void requireEquivalent(const BatchParseResult& left, const BatchParseResult& right)
{
    require(left.definition.has_value() == right.definition.has_value(),
            "parser paths disagree on definition presence");
    require(left.issues.size() == right.issues.size(), "parser paths returned different issue counts");
    for (std::size_t index = 0; index < left.issues.size(); ++index) {
        require(left.issues[index].code == right.issues[index].code
                    && left.issues[index].path == right.issues[index].path
                    && left.issues[index].technicalMessage == right.issues[index].technicalMessage
                    && left.issues[index].domainCode == right.issues[index].domainCode,
                "parser paths returned different issue details");
    }
    if (!left.definition.has_value()) {
        return;
    }

    const auto& leftEntries = left.definition->entries();
    const auto& rightEntries = right.definition->entries();
    require(leftEntries.size() == rightEntries.size(), "parser paths returned different entry counts");
    for (std::size_t index = 0; index < leftEntries.size(); ++index) {
        require(leftEntries[index].entryIndex == rightEntries[index].entryIndex
                    && leftEntries[index].id == rightEntries[index].id
                    && benchmarkConfigToJson(leftEntries[index].config)
                        == benchmarkConfigToJson(rightEntries[index].config)
                    && leftEntries[index].characteristics.index()
                        == rightEntries[index].characteristics.index(),
                "parser paths returned different entry semantics");
    }
}

void testCanonicalIndentedDocumentAndRoundtrip()
{
    const auto configs = representativeConfigs();
    const auto bytes = BatchInputDocumentBuilder{}.build(configs);
    require(bytes.contains("\n    \"entries\"") && bytes.contains("\n        {"),
            "builder output is not indented");

    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(bytes, &parseError);
    require(parseError.error == QJsonParseError::NoError && document.isObject(),
            "builder output is not a JSON object");
    const auto root = document.object();
    require(root.size() == 3 && root.contains("format") && root.contains("schemaVersion")
                && root.contains("entries"),
            "builder root does not contain exactly the v1 fields");
    require(root.value("format").toString() == QStringLiteral("cryptobenchmark-batch-input"),
            "builder format is incorrect");
    require(root.value("schemaVersion").isDouble() && root.value("schemaVersion").toInt() == 1,
            "builder schemaVersion is not numeric v1");

    const auto entries = root.value("entries").toArray();
    require(entries.size() == static_cast<qsizetype>(configs.size()),
            "builder changed the number of entries");
    for (qsizetype index = 0; index < entries.size(); ++index) {
        const auto entry = entries[index].toObject();
        const auto expectedProfile = toStableProfileId(configs[static_cast<std::size_t>(index)].profile);
        require(entry.size() == 5 && !entry.contains("id"),
                "builder entry contains an ID or unexpected fields");
        require(entry.contains("profileId") && entry.contains("operation")
                    && entry.contains("iterationsPerRun") && entry.contains("runs")
                    && entry.contains("parameters"),
                "builder entry is missing canonical fields");
        require(entry.value("iterationsPerRun").isDouble() && entry.value("runs").isDouble(),
                "builder emitted non-numeric iteration fields");
        require(entry.value("iterationsPerRun").toDouble()
                        == static_cast<double>(configs[static_cast<std::size_t>(index)].iterationsPerRun)
                    && entry.value("runs").toDouble()
                        == static_cast<double>(configs[static_cast<std::size_t>(index)].runs),
                "builder changed numeric iteration fields");
        require(entry.value("profileId").toString()
                    == QString::fromUtf8(expectedProfile.data(), static_cast<qsizetype>(expectedProfile.size())),
                "builder changed entry order");
    }
    require(entries[2].toObject().value("parameters").toObject()
                .value("messageSizeBytes").isDouble(),
            "builder emitted message size as a non-numeric value");

    const auto memoryResult = BatchInputParser{}.parseData(bytes);
    require(memoryResult.issues.empty() && memoryResult.definition.has_value(),
            "builder output was rejected by parseData");
    const auto& parsedEntries = memoryResult.definition->entries();
    require(parsedEntries.size() == configs.size(), "builder roundtrip entry count mismatch");
    for (std::size_t index = 0; index < configs.size(); ++index) {
        require(parsedEntries[index].entryIndex == index + 1 && !parsedEntries[index].id.has_value(),
                "builder roundtrip changed index or added an ID");
        require(benchmarkConfigToJson(parsedEntries[index].config) == benchmarkConfigToJson(configs[index]),
                "builder roundtrip changed a benchmark configuration");
        const auto* profile = AlgorithmRegistry::find(parsedEntries[index].config.profile);
        require(profile != nullptr
                    && parsedEntries[index].characteristics.index() == profile->characteristics.index(),
                "builder roundtrip changed structural characteristic type");
    }

    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory could not be created");
    const auto fileResult = BatchInputParser{}.parseFile(writeInput(directory, bytes));
    requireEquivalent(memoryResult, fileResult);
}

void testParserOwnsEntryCountAndDomainValidation()
{
    const auto builder = BatchInputDocumentBuilder{};
    const auto emptyResult = BatchInputParser{}.parseData(builder.build({}));
    require(!emptyResult.definition.has_value() && emptyResult.issues.size() == 1
                && emptyResult.issues.front().code == BatchInputIssueCode::InvalidEntryCount
                && emptyResult.issues.front().path == "/entries",
            "empty document was not rejected by the authoritative parser");

    auto configs = representativeConfigs();
    configs.resize(1000, configs.front());
    const auto maximumResult = BatchInputParser{}.parseData(builder.build(configs));
    require(maximumResult.definition.has_value() && maximumResult.issues.empty()
                && maximumResult.definition->entries().size() == 1000,
            "the authoritative parser rejected the maximum entry count");

    configs.resize(1001, configs.front());
    const auto oversizedResult = BatchInputParser{}.parseData(builder.build(configs));
    require(!oversizedResult.definition.has_value() && oversizedResult.issues.size() == 1
                && oversizedResult.issues.front().code == BatchInputIssueCode::InvalidEntryCount
                && oversizedResult.issues.front().path == "/entries",
            "oversized document was not rejected by the authoritative parser");

    const std::vector<BenchmarkConfig> invalidConfigs{
        {AlgorithmProfileId::Sha256, BenchmarkOperation::Encrypt, 1, 1, HashConfig{1}}
    };
    const auto invalidResult = BatchInputParser{}.parseData(builder.build(invalidConfigs));
    require(!invalidResult.definition.has_value() && invalidResult.issues.size() == 1
                && invalidResult.issues.front().code == BatchInputIssueCode::ConfigurationInvalid
                && invalidResult.issues.front().domainCode == ValidationErrorCode::UnsupportedOperation,
            "invalid configuration was not rejected by ConfigValidator through the parser");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testCanonicalIndentedDocumentAndRoundtrip();
        std::cout << "PASS canonical builder, multi-entry memory/file parity\n";
        cryptobench::tests::testParserOwnsEntryCountAndDomainValidation();
        std::cout << "PASS parser-owned count and domain validation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchInputDocumentBuilder: " << error.what() << '\n';
        return 1;
    }
}
