#include <cryptobench/application/BenchmarkConfigJson.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <QJsonObject>
#include <QJsonValue>

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

void requireString(const QJsonObject& object, const char* key, std::string_view expected)
{
    const auto value = object.value(key);
    require(value.isString() && value.toString().toStdString() == expected, "JSON string field mismatch");
}

void requireNumber(const QJsonObject& object, const char* key, double expected)
{
    const auto value = object.value(key);
    require(value.isDouble() && value.toDouble() == expected, "JSON number field mismatch");
}

void requireExactConfigFields(const QJsonObject& object)
{
    require(object.size() == 5, "config field count mismatch");
    require(object.contains("profileId"), "profileId field missing");
    require(object.contains("operation"), "operation field missing");
    require(object.contains("iterationsPerRun"), "iterationsPerRun field missing");
    require(object.contains("runs"), "runs field missing");
    require(object.contains("parameters"), "parameters field missing");
    require(object.value("parameters").isObject(), "parameters is not an object");
}

void requireParameterKeys(const QJsonObject& parameters, std::initializer_list<const char*> expected)
{
    require(parameters.size() == static_cast<int>(expected.size()), "parameter field count mismatch");
    for (const auto key : expected) {
        require(parameters.contains(key), "expected parameter field missing");
    }
}

void testOperationStrings()
{
    const std::array expected{
        std::pair{BenchmarkOperation::KeyGen, "keyGen"},
        std::pair{BenchmarkOperation::Sign, "sign"},
        std::pair{BenchmarkOperation::Verify, "verify"},
        std::pair{BenchmarkOperation::Derive, "derive"},
        std::pair{BenchmarkOperation::Encapsulate, "encapsulate"},
        std::pair{BenchmarkOperation::Decapsulate, "decapsulate"},
        std::pair{BenchmarkOperation::Encrypt, "encrypt"},
        std::pair{BenchmarkOperation::Decrypt, "decrypt"},
        std::pair{BenchmarkOperation::Hash, "hash"},
        std::pair{BenchmarkOperation::Xof, "xof"}
    };

    for (const auto& [operation, name] : expected) {
        require(toStableOperationString(operation) == name, "operation string mismatch");
        const auto parsed = parseStableOperationString(name);
        require(parsed.has_value() && *parsed == operation, "operation string did not round-trip");
    }
}

void testOperationStringRejections()
{
    const std::array invalidValues{
        std::string_view{}, std::string_view("Sign"), std::string_view("sign-extra"),
        std::string_view("pre-sign"), std::string_view("unknown")};
    for (const auto value : invalidValues) {
        require(!parseStableOperationString(value).has_value(), "invalid operation string was accepted");
    }
}

void testUnsupportedOperationRejected()
{
    bool rejected = false;
    try {
        static_cast<void>(toStableOperationString(static_cast<BenchmarkOperation>(99)));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "unsupported operation was accepted");
}

BenchmarkConfig config(AlgorithmProfileId profile, BenchmarkOperation operation, PrimitiveConfig parameters)
{
    return {profile, operation, 1000000000, 1000, std::move(parameters)};
}

void testCommonFieldsAndCanonicalProfile()
{
    const auto value = benchmarkConfigToJson(config(AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, HashConfig{4096}));
    requireExactConfigFields(value);
    requireString(value, "profileId", "sha256");
    requireString(value, "operation", "hash");
    requireNumber(value, "iterationsPerRun", 1000000000.0);
    requireNumber(value, "runs", 1000.0);
}

void testNoSignatureInput()
{
    const SignatureConfig signature{NoSignatureInput{}};
    require(!signatureInputModeToStableString(signature).has_value(),
            "no-signature input unexpectedly has a stable input mode");
    const auto value = benchmarkConfigToJson(config(
        AlgorithmProfileId::Rsa2048KeyGen, BenchmarkOperation::KeyGen, signature));
    const auto parameters = value.value("parameters").toObject();
    requireParameterKeys(parameters, {});
}

void testPrehashedInput()
{
    require(signatureInputModeToStableString(SignatureConfig{PrehashedInput{}}) == "prehashed",
            "prehashed input mode mapper mismatch");
    const auto value = benchmarkConfigToJson(config(
        AlgorithmProfileId::RsaPss2048Sha256, BenchmarkOperation::Sign, SignatureConfig{PrehashedInput{}}));
    const auto parameters = value.value("parameters").toObject();
    requireParameterKeys(parameters, {"inputMode"});
    requireString(parameters, "inputMode", "prehashed");
    require(!parameters.contains("messageSizeBytes"), "prehashed parameters contain message size");
}

void testMessageInput()
{
    require(signatureInputModeToStableString(SignatureConfig{MessageInput{777}}) == "message",
            "message input mode mapper mismatch");
    const auto value = benchmarkConfigToJson(config(
        AlgorithmProfileId::Ed25519, BenchmarkOperation::Sign, SignatureConfig{MessageInput{777}}));
    const auto parameters = value.value("parameters").toObject();
    requireParameterKeys(parameters, {"inputMode", "messageSizeBytes"});
    requireString(parameters, "inputMode", "message");
    requireNumber(parameters, "messageSizeBytes", 777.0);
}

void testKeyEstablishment()
{
    const auto value = benchmarkConfigToJson(config(
        AlgorithmProfileId::X25519, BenchmarkOperation::Derive, KeyEstablishmentConfig{}));
    requireParameterKeys(value.value("parameters").toObject(), {});
}

void testAead()
{
    const auto value = benchmarkConfigToJson(config(
        AlgorithmProfileId::Aes128Gcm, BenchmarkOperation::Encrypt, AeadConfig{2048}));
    const auto parameters = value.value("parameters").toObject();
    requireParameterKeys(parameters, {"plaintextSizeBytes"});
    requireNumber(parameters, "plaintextSizeBytes", 2048.0);
}

void testHashAndXof()
{
    const auto hash = benchmarkConfigToJson(config(AlgorithmProfileId::Sha256, BenchmarkOperation::Hash, HashConfig{512}));
    const auto xof = benchmarkConfigToJson(config(AlgorithmProfileId::Shake128_32B, BenchmarkOperation::Xof, HashConfig{1024}));
    requireParameterKeys(hash.value("parameters").toObject(), {"inputSizeBytes"});
    requireParameterKeys(xof.value("parameters").toObject(), {"inputSizeBytes"});
    requireNumber(hash.value("parameters").toObject(), "inputSizeBytes", 512.0);
    requireNumber(xof.value("parameters").toObject(), "inputSizeBytes", 1024.0);
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    try {
        cryptobench::tests::testOperationStrings();
        std::cout << "PASS operation strings\n";
        cryptobench::tests::testOperationStringRejections();
        std::cout << "PASS operation string rejection\n";
        cryptobench::tests::testUnsupportedOperationRejected();
        std::cout << "PASS unsupported operation rejection\n";
        cryptobench::tests::testCommonFieldsAndCanonicalProfile();
        std::cout << "PASS common fields and profile\n";
        cryptobench::tests::testNoSignatureInput();
        std::cout << "PASS no-signature parameters\n";
        cryptobench::tests::testPrehashedInput();
        std::cout << "PASS prehashed parameters\n";
        cryptobench::tests::testMessageInput();
        std::cout << "PASS message parameters\n";
        cryptobench::tests::testKeyEstablishment();
        std::cout << "PASS key-establishment parameters\n";
        cryptobench::tests::testAead();
        std::cout << "PASS AEAD parameters\n";
        cryptobench::tests::testHashAndXof();
        std::cout << "PASS hash and XOF parameters\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BenchmarkConfigJson: " << error.what() << '\n';
        return 1;
    }
}
