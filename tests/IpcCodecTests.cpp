#include <cryptobench/ipc/FrameCodec.h>
#include <cryptobench/ipc/JsonCodec.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

using namespace cryptobench;

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

template <typename Callable>
void requireRejected(Callable&& callable, const char* message)
{
    bool rejected = false;
    try {
        callable();
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, message);
}

QByteArray header(std::uint16_t messageType, std::uint32_t payloadLength)
{
    QByteArray value;
    value.append(static_cast<char>(messageType >> 8));
    value.append(static_cast<char>(messageType));
    for (int shift = 24; shift >= 0; shift -= 8) value.append(static_cast<char>(payloadLength >> shift));
    return value;
}

void requireConfigEqual(const core::BenchmarkConfig& actual, const core::BenchmarkConfig& expected)
{
    require(actual.profile == expected.profile, "config profile mismatch");
    require(actual.operation == expected.operation, "config operation mismatch");
    require(actual.iterationsPerRun == expected.iterationsPerRun, "config iterations mismatch");
    require(actual.runs == expected.runs, "config runs mismatch");
    require(actual.parameters.index() == expected.parameters.index(), "config parameter branch mismatch");

    std::visit([&](const auto& actualValue) {
        using T = std::decay_t<decltype(actualValue)>;
        const auto& expectedValue = std::get<T>(expected.parameters);
        if constexpr (std::is_same_v<T, core::SignatureConfig>) {
            require(actualValue.input.index() == expectedValue.input.index(), "signature input discriminator mismatch");
            std::visit([&](const auto& actualInput) {
                using I = std::decay_t<decltype(actualInput)>;
                const auto& expectedInput = std::get<I>(expectedValue.input);
                if constexpr (std::is_same_v<I, core::MessageInput>) {
                    require(actualInput.messageSize == expectedInput.messageSize, "message size mismatch");
                }
            }, actualValue.input);
        } else if constexpr (std::is_same_v<T, core::AeadConfig>) {
            require(actualValue.plaintextSize == expectedValue.plaintextSize, "plaintext size mismatch");
        } else if constexpr (std::is_same_v<T, core::HashConfig>) {
            require(actualValue.inputSize == expectedValue.inputSize, "hash input size mismatch");
        }
    }, actual.parameters);
}

void testFramingAndControlPayloads()
{
    const std::array messageTypes{
        ipc::MessageType::WorkerReady,
        ipc::MessageType::BenchmarkRequest,
        ipc::MessageType::Progress,
        ipc::MessageType::MeasurementReady,
        ipc::MessageType::StartMeasurement,
        ipc::MessageType::MeasurementFinished,
        ipc::MessageType::MemoryWindowClosed,
        ipc::MessageType::WorkerRunMeasurement,
        ipc::MessageType::WorkerOutcome
    };
    for (std::uint16_t index = 0; index < messageTypes.size(); ++index) {
        const auto frame = ipc::encodeFrame(messageTypes[index], {});
        require(frame.size() == 6, "frame header is not exactly six bytes");
        require(static_cast<unsigned char>(frame[0]) == 0 && static_cast<unsigned char>(frame[1]) == index + 1,
                "message type wire ID mismatch");
        require(frame[2] == 0 && frame[3] == 0 && frame[4] == 0 && frame[5] == 0,
                "zero payload length is not big-endian encoded");
        require(ipc::decodeFrame(frame).messageType == messageTypes[index], "message type roundtrip failed");
    }

    const std::array controlTypes{
        ipc::MessageType::MeasurementReady,
        ipc::MessageType::StartMeasurement,
        ipc::MessageType::MeasurementFinished,
        ipc::MessageType::MemoryWindowClosed
    };
    for (const auto type : controlTypes) {
        const auto frame = ipc::encodeFrame(type, ipc::encodeRunIndexPayload(0x01020304));
        require(frame.size() == 10 && frame[2] == 0 && frame[3] == 0 && frame[4] == 0 && frame[5] == 4,
                "control frame header mismatch");
        require(ipc::decodeRunIndexPayload(frame.mid(6)) == 0x01020304, "control runIndex roundtrip failed");
    }
    requireRejected([] { ipc::decodeRunIndexPayload(QByteArray(3, '\0')); }, "wrong control payload length accepted");

    const auto frame = ipc::encodeFrame(ipc::MessageType::StartMeasurement, QByteArray("payload"));
    ipc::FrameParser parser;
    require(parser.append(frame.left(3)).empty(), "partial header parsed");
    require(parser.append(frame.mid(3, 6)).empty(), "complete header with partial payload parsed");
    require(parser.append(frame.mid(9)).size() == 1, "partial payload was not completed");
    require(parser.append(frame).size() == 1, "single complete frame was not parsed");
    ipc::FrameParser twoFrameParser;
    require(twoFrameParser.append(frame + frame).size() == 2, "two complete frames were not parsed together");
    ipc::FrameParser partialNextParser;
    require(partialNextParser.append(frame + frame.left(3)).size() == 1, "complete frame plus partial next frame failed");
    require(partialNextParser.append(frame.mid(3)).size() == 1, "partial next frame was not completed");
    ipc::FrameParser unknownTypeParser;
    requireRejected([&] { unknownTypeParser.append(header(10, 0)); }, "unknown message type accepted");
    ipc::FrameParser oversizedParser;
    requireRejected([&] { oversizedParser.append(header(1, ipc::kMaxIpcPayload + 1)); }, "oversized parser header accepted");
    requireRejected([&] { ipc::decodeFrame(header(10, 0)); }, "unknown decoded message type accepted");
    requireRejected([] { ipc::encodeFrame(static_cast<ipc::MessageType>(0), {}); }, "invalid message type encoded");
    requireRejected([] { ipc::encodeFrame(ipc::MessageType::WorkerReady, QByteArray(static_cast<qsizetype>(ipc::kMaxIpcPayload) + 1, '\0')); }, "oversized encoder payload accepted");
}

void testJsonDtos()
{
    require(ipc::decodeWorkerReady(ipc::encodeWorkerReady({1})).protocolVersion == 1, "WorkerReady roundtrip failed");
    const ipc::Progress progress{core::BenchmarkPhase::Warmup, 3, 10};
    const auto progressResult = ipc::decodeProgress(ipc::encodeProgress(progress));
    require(progressResult.phase == progress.phase && progressResult.runIndex == 3 && progressResult.totalRuns == 10,
            "Progress roundtrip failed");
    requireRejected([] { ipc::encodeProgress({core::BenchmarkPhase::Measuring, std::nullopt, 1}); }, "measuring progress encoded");
    requireRejected([] { ipc::encodeProgress({static_cast<core::BenchmarkPhase>(255), std::nullopt, 1}); }, "invalid progress phase encoded");
    const auto measurement = ipc::decodeWorkerRunMeasurement(ipc::encodeWorkerRunMeasurement({2, 0xffffffffffffffffULL, 3}));
    require(measurement.runIndex == 2 && measurement.elapsedNanoseconds == 0xffffffffffffffffULL && measurement.processCpuNanoseconds == 3,
            "WorkerRunMeasurement roundtrip failed");
    const auto completed = ipc::decodeWorkerOutcome(ipc::encodeWorkerOutcome({ipc::WorkerOutcomeStatus::Completed, std::nullopt}));
    require(completed.status == ipc::WorkerOutcomeStatus::Completed && !completed.error, "completed outcome roundtrip failed");
    const core::ErrorInfo error{core::ErrorCode::CryptoOperationFailed, core::FailureStage::Measurement, 1, "failure", "detail"};
    const auto failed = ipc::decodeWorkerOutcome(ipc::encodeWorkerOutcome({ipc::WorkerOutcomeStatus::Failed, error}));
    require(failed.error && failed.error->code == error.code && failed.error->stage == error.stage && failed.error->runIndex == 1 && failed.error->technicalMessage == error.technicalMessage && failed.error->libraryDetails == error.libraryDetails,
            "failed outcome roundtrip failed");
    requireRejected([] { ipc::decodeWorkerOutcome(QByteArray("{\"status\":\"completed\",\"error\":{}}")); }, "completed outcome with error accepted");
    requireRejected([] { ipc::decodeWorkerOutcome(QByteArray("{\"status\":\"failed\"}")); }, "failed outcome without error accepted");
    requireRejected([] { ipc::encodeWorkerOutcome({ipc::WorkerOutcomeStatus::Completed, core::ErrorInfo{core::ErrorCode::InternalError, core::FailureStage::Measurement, std::nullopt, "error", std::nullopt}}); }, "completed outcome with error encoded");
    requireRejected([] { ipc::encodeWorkerOutcome({ipc::WorkerOutcomeStatus::Failed, std::nullopt}); }, "failed outcome without error encoded");
    requireRejected([] { ipc::encodeWorkerOutcome({static_cast<ipc::WorkerOutcomeStatus>(255), std::nullopt}); }, "invalid outcome status encoded");
}

void testBenchmarkConfigRoundtrips()
{
    const std::array configs{
        core::BenchmarkConfig{core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash, 3, 2, core::HashConfig{64}},
        core::BenchmarkConfig{core::AlgorithmProfileId::RsaPss2048Sha256, core::BenchmarkOperation::Sign, 7, 2, core::SignatureConfig{core::NoSignatureInput{}}},
        core::BenchmarkConfig{core::AlgorithmProfileId::RsaPss2048Sha256, core::BenchmarkOperation::Sign, 7, 2, core::SignatureConfig{core::PrehashedInput{}}},
        core::BenchmarkConfig{core::AlgorithmProfileId::RsaPss2048Sha256, core::BenchmarkOperation::Sign, 7, 2, core::SignatureConfig{core::MessageInput{123}}},
        core::BenchmarkConfig{core::AlgorithmProfileId::EcdhP256, core::BenchmarkOperation::Derive, 7, 2, core::KeyEstablishmentConfig{}},
        core::BenchmarkConfig{core::AlgorithmProfileId::Aes256Gcm, core::BenchmarkOperation::Encrypt, 7, 2, core::AeadConfig{456}}
    };
    for (const auto& expected : configs) requireConfigEqual(ipc::decodeBenchmarkRequest(ipc::encodeBenchmarkRequest({expected})).config, expected);
}

void testStrictJsonRejection()
{
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"unknown\",\"operation\":\"hash\",\"iterationsPerRun\":\"1\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "unknown profile accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"unknown\",\"iterationsPerRun\":\"1\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "unknown operation accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":\"1\",\"runs\":1,\"parameters\":{\"type\":\"unknown\"}}")); }, "unknown parameter discriminator accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":1,\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "wrong uint64 JSON type accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":\"1\",\"runs\":1,\"extra\":true,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "extra JSON field accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "missing required field accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":\"1\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}")); }, "malformed JSON accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("[]")); }, "non-object JSON accepted");
    QByteArray malformedOutcome = "{\"status\":\"failed\",\"error\":{\"code\":\"internalError\",\"stage\":\"measurement\",\"technicalMessage\":\"";
    malformedOutcome.append(static_cast<char>(0xC3));
    malformedOutcome.append(static_cast<char>(0x28));
    malformedOutcome.append("\"}}");
    requireRejected([&] { ipc::decodeWorkerOutcome(malformedOutcome); }, "malformed UTF-8 accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":\"-1\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "signed uint64 accepted");
    requireRejected([] { ipc::decodeBenchmarkRequest(QByteArray("{\"profileId\":\"sha256\",\"operation\":\"hash\",\"iterationsPerRun\":\"18446744073709551616\",\"runs\":1,\"parameters\":{\"type\":\"hash\",\"inputSize\":\"1\"}}")); }, "uint64 overflow accepted");
}

int main()
{
    try {
        testFramingAndControlPayloads();
        testJsonDtos();
        testBenchmarkConfigRoundtrips();
        testStrictJsonRejection();
        std::cout << "PASS ipc codec total=4\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
