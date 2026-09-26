#include <cryptobench/application/BatchInputSchema.h>
#include <cryptobench/application/BatchPrimitiveParameters.h>

#include <QJsonDocument>
#include <QJsonObject>

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

namespace cryptobench::tests {
namespace {

using namespace application;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

QJsonObject parametersFor(const QByteArray& parameters)
{
    const auto document = QJsonDocument::fromJson(parameters);
    require(document.isObject(), "test parameters are not an object");
    return document.object();
}

BatchInputSchema decodeSchema(const QByteArray& parameters)
{
    const auto input = "{\"format\":\"cryptobenchmark-batch-input\",\"schemaVersion\":1,\"entries\":[{\"profileId\":\"p\",\"operation\":\"o\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":"
                       + parameters + "}]}";
    const auto result = decodeBatchInputSchema(input);
    require(std::holds_alternative<BatchInputSchema>(result), "schema fixture was rejected");
    return std::get<BatchInputSchema>(result);
}

BatchPrimitiveParametersResult decode(core::PrimitiveCategory category, const QByteArray& parameters)
{
    const auto schema = decodeSchema(parameters);
    return decodeBatchPrimitiveParameters(category, schema.entries.front().value("parameters").toObject(),
                                          "/entries/0/parameters", schema.numberTokens);
}

void requireFailure(const BatchPrimitiveParametersResult& result, BatchInputIssueCode code, std::string_view path)
{
    require(std::holds_alternative<std::vector<BatchInputIssue>>(result), "invalid parameters were accepted");
    const auto& issues = std::get<std::vector<BatchInputIssue>>(result);
    require(!issues.empty() && issues.front().code == code && issues.front().path == path,
            "parameter issue code or path mismatch");
    require(!issues.front().technicalMessage.empty() && !issues.front().domainCode.has_value(),
            "parameter issue metadata is invalid");
}

void testTypedAlternatives()
{
    const auto emptySignature = decode(core::PrimitiveCategory::Signature, "{}");
    require(std::holds_alternative<core::PrimitiveConfig>(emptySignature)
                && std::holds_alternative<core::SignatureConfig>(std::get<core::PrimitiveConfig>(emptySignature))
                && std::holds_alternative<core::NoSignatureInput>(
                    std::get<core::SignatureConfig>(std::get<core::PrimitiveConfig>(emptySignature)).input),
            "empty signature parameters did not decode to NoSignatureInput");
    const auto prehashed = decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"prehashed\"}");
    require(std::holds_alternative<core::PrimitiveConfig>(prehashed)
                && std::holds_alternative<core::PrehashedInput>(std::get<core::SignatureConfig>(std::get<core::PrimitiveConfig>(prehashed)).input),
            "prehashed signature did not decode");
    const auto message = decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"message\",\"messageSizeBytes\":1.01e2}");
    require(std::holds_alternative<core::PrimitiveConfig>(message)
                && std::get<core::MessageInput>(std::get<core::SignatureConfig>(std::get<core::PrimitiveConfig>(message)).input).messageSize == 101,
            "message signature size was not exact");
    const auto keyEstablishment = decode(core::PrimitiveCategory::KeyEstablishment, "{}");
    require(std::holds_alternative<core::PrimitiveConfig>(keyEstablishment)
                && std::holds_alternative<core::KeyEstablishmentConfig>(std::get<core::PrimitiveConfig>(keyEstablishment)),
            "key-establishment parameters did not decode to KeyEstablishmentConfig");
    const auto aead = decode(core::PrimitiveCategory::Aead, "{\"plaintextSizeBytes\":0}");
    require(std::holds_alternative<core::AeadConfig>(std::get<core::PrimitiveConfig>(aead))
                && std::get<core::AeadConfig>(std::get<core::PrimitiveConfig>(aead)).plaintextSize == 0,
            "AEAD size was not preserved");
    const auto hash = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":300000000}");
    require(std::holds_alternative<core::HashConfig>(std::get<core::PrimitiveConfig>(hash))
                && std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(hash)).inputSize == 300000000,
            "hash size was not preserved");
}

void testErrorsAndExactNumbers()
{
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"MESSAGE\"}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputMode");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"message\"}"),
                   BatchInputIssueCode::MissingField, "/entries/0/parameters/messageSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"messageSizeBytes\":1}"),
                   BatchInputIssueCode::MissingField, "/entries/0/parameters/inputMode");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"this-mode-is-too-long\"}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputMode");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":1}"),
                   BatchInputIssueCode::InvalidType, "/entries/0/parameters/inputMode");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"prehashed\",\"messageSizeBytes\":1}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/messageSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"message\",\"messageSizeBytes\":1,\"extra\":true}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/extra");
    requireFailure(decode(core::PrimitiveCategory::Signature, "{\"inputMode\":\"message\",\"messageSizeBytes\":\"1\"}"),
                   BatchInputIssueCode::InvalidType, "/entries/0/parameters/messageSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Aead, "{\"plaintextSizeBytes\":1.5}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/plaintextSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Aead, "{}"),
                   BatchInputIssueCode::MissingField, "/entries/0/parameters/plaintextSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Aead, "{\"plaintextSizeBytes\":\"1\"}"),
                   BatchInputIssueCode::InvalidType, "/entries/0/parameters/plaintextSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::Aead, "{\"plaintextSizeBytes\":1,\"extra\":true}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/extra");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1.0000000000000001}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{}"),
                   BatchInputIssueCode::MissingField, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":\"1\"}"),
                   BatchInputIssueCode::InvalidType, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1,\"extra\":true}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/extra");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1e309}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":-1}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":18446744073709551616}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    const auto literalOne = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1}");
    require(std::holds_alternative<core::PrimitiveConfig>(literalOne)
                && std::holds_alternative<core::HashConfig>(std::get<core::PrimitiveConfig>(literalOne))
                && std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(literalOne)).inputSize == 1,
            "literal one did not decode to HashConfig{1}");
    requireFailure(decode(core::PrimitiveCategory::HashXof,
                          "{\"inputSizeBytes\":184467440737095516150e0}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    const auto maximum = decode(core::PrimitiveCategory::HashXof,
                                "{\"inputSizeBytes\":18446744073709551615}");
    require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(maximum)).inputSize
                == std::numeric_limits<std::uint64_t>::max(),
            "uint64 maximum was not preserved");
    requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1e-9999}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
    requireFailure(decode(core::PrimitiveCategory::KeyEstablishment, "{\"extra\":1}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/extra");

        const auto exactZero = decode(core::PrimitiveCategory::Signature,
                      "{\"inputMode\":\"message\",\"messageSizeBytes\":0}");
        require(std::get<core::MessageInput>(std::get<core::SignatureConfig>(std::get<core::PrimitiveConfig>(exactZero)).input).messageSize == 0,
            "zero message size was not accepted");
        const auto negativeZero = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":-0}");
        require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(negativeZero)).inputSize == 0,
            "negative zero was not accepted as zero");
        const auto scientific = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":100e-2}");
        require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(scientific)).inputSize == 1,
            "exact negative scientific shift was not preserved");
            const auto positiveScientific = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1e2}");
            require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(positiveScientific)).inputSize == 100,
                "exact positive scientific shift was not preserved");
            const auto paddedScientific = decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1.00e2}");
            require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(paddedScientific)).inputSize == 100,
                "exact padded scientific shift was not preserved");
            requireFailure(decode(core::PrimitiveCategory::HashXof, "{\"inputSizeBytes\":1e-1}"),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
            const auto decimalZero = decode(core::PrimitiveCategory::HashXof,
                            "{\"inputSizeBytes\":0.0000000000000000000000000000000}");
            require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(decimalZero)).inputSize == 0,
                "long decimal zero was not accepted");
        const auto maxScientific = decode(core::PrimitiveCategory::HashXof,
                          "{\"inputSizeBytes\":184467440737095516150e-1}");
        require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(maxScientific)).inputSize
            == std::numeric_limits<std::uint64_t>::max(),
            "exact scientific uint64 maximum was not preserved");
        const auto leadingZeros = QByteArray("{\"inputSizeBytes\":0.") + QByteArray(64, '0') + "1e65}";
        const auto leadingZeroValue = decode(core::PrimitiveCategory::HashXof, leadingZeros);
        require(std::get<core::HashConfig>(std::get<core::PrimitiveConfig>(leadingZeroValue)).inputSize == 1,
            "leading-zero coefficient was not decoded exactly");

    const auto schema = decodeSchema("{\"inputSizeBytes\":1}");
    requireFailure(decodeBatchPrimitiveParameters(core::PrimitiveCategory::HashXof,
                                                  schema.entries.front().value("parameters").toObject(),
                                                  "/entries/0/parameters", {}),
                   BatchInputIssueCode::InvalidValue, "/entries/0/parameters/inputSizeBytes");
}

void testPointerEscaping()
{
    requireFailure(decode(core::PrimitiveCategory::KeyEstablishment, "{\"a/b\":1}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/a~1b");
    requireFailure(decode(core::PrimitiveCategory::KeyEstablishment, "{\"a~b\":1}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/a~0b");
    requireFailure(decode(core::PrimitiveCategory::KeyEstablishment, "{\"a~/b\":1}"),
                   BatchInputIssueCode::UnknownField, "/entries/0/parameters/a~0~1b");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testTypedAlternatives();
        cryptobench::tests::testErrorsAndExactNumbers();
        cryptobench::tests::testPointerEscaping();
        std::cout << "PASS batch primitive parameter decoding\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BatchPrimitiveParameters: " << error.what() << '\n';
        return 1;
    }
}