#include "adapters/DigestAdapter.h"
#include "adapters/XofAdapter.h"

#include <cryptobench/crypto/AdapterFactory.h>

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/BenchmarkTask.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/ProcessCpuTimeSource.h>
#include <cryptobench/core/ProgressSink.h>
#include <cryptobench/core/RunMeasurementCoordinator.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptobench::tests {
namespace {

using crypto::DigestAdapter;
using crypto::XofAdapter;
using core::AlgorithmRegistry;
using core::BenchmarkOperation;
using core::BenchmarkPhase;
using core::BenchmarkRunner;
using core::BenchmarkTask;
using core::ConfigValidator;
using core::DigestAlgorithm;
using core::DigestParameters;
using core::XofAlgorithm;
using core::XofParameters;
using core::ProcessCpuTimeSource;
using core::ProgressInfo;
using core::ProgressSink;
using core::RunMeasurementCoordinator;
using core::ValidationResult;
using core::WorkerRunMeasurement;
using crypto::AdapterFactory;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string hex(std::span<const unsigned char> bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void requireDigest(DigestAdapter& adapter, std::string_view expected, std::size_t expectedLength)
{
    adapter.executeIteration();
    require(hex(adapter.output()) == expected, "digest mismatch");
    require(adapter.output().size() == expectedLength, "digest output length mismatch");
}

void testEmptyInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 0);
    adapter.prepareSeries();
    requireDigest(adapter, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
}

void testAbcInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
}

void testRepeatedIterations()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
}

void testLongerPreparedHashAndXofInput()
{
    constexpr core::WorkloadBytes inputSize = 1024;

    DigestAdapter digest(DigestParameters{DigestAlgorithm::Sha256}, inputSize);
    digest.prepareSeries();
    digest.executeIteration();
    require(digest.output().size() == 32, "longer digest output length mismatch");
    const auto digestOutput = std::vector<unsigned char>(digest.output().begin(), digest.output().end());
    digest.executeIteration();
    require(
        std::vector<unsigned char>(digest.output().begin(), digest.output().end()) == digestOutput,
        "longer digest output is not stable across iterations");

    XofAdapter xof(XofParameters{XofAlgorithm::Shake256, 64}, inputSize);
    xof.prepareSeries();
    xof.executeIteration();
    require(xof.output().size() == 64, "longer XOF output length mismatch");
    const auto xofOutput = std::vector<unsigned char>(xof.output().begin(), xof.output().end());
    xof.executeIteration();
    require(
        std::vector<unsigned char>(xof.output().begin(), xof.output().end()) == xofOutput,
        "longer XOF output is not stable across iterations");
}

void testAllCanonicalDigests()
{
    struct ExpectedDigest {
        DigestAlgorithm algorithm;
        std::size_t outputLength;
        std::string_view output;
    };
    constexpr std::array expected{
        ExpectedDigest{DigestAlgorithm::Sha224, 28, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        ExpectedDigest{DigestAlgorithm::Sha256, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        ExpectedDigest{DigestAlgorithm::Sha384, 48, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
        ExpectedDigest{DigestAlgorithm::Sha512, 64, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        ExpectedDigest{DigestAlgorithm::Sha3_224, 28, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
        ExpectedDigest{DigestAlgorithm::Sha3_256, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
        ExpectedDigest{DigestAlgorithm::Sha3_384, 48, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
        ExpectedDigest{DigestAlgorithm::Sha3_512, 64, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"}
    };

    for (const auto& vector : expected) {
        DigestAdapter adapter(DigestParameters{vector.algorithm}, 0);
        adapter.prepareSeries();
        requireDigest(adapter, vector.output, vector.outputLength);
    }
}

void testCanonicalXofVectors()
{
    constexpr std::string_view shake128 =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea";
    constexpr std::string_view shake256 =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f";
    constexpr std::array shake128Lengths{28U, 32U, 48U, 64U, 128U};
    constexpr std::array shake256Lengths{28U, 32U, 48U, 64U, 128U, 256U};

    for (const auto [algorithm, lengths, reference] : std::array{
             std::tuple{XofAlgorithm::Shake128, std::span<const unsigned int>(shake128Lengths), shake128},
             std::tuple{XofAlgorithm::Shake256, std::span<const unsigned int>(shake256Lengths), shake256}}) {
        for (const auto length : lengths) {
            XofAdapter adapter(XofParameters{algorithm, static_cast<core::ByteCount>(length)}, 0);
            adapter.prepareSeries();
            adapter.executeIteration();
            require(hex(adapter.output()) == reference.substr(0, length * 2), "XOF reference vector mismatch");
            require(adapter.output().size() == length, "XOF output length mismatch");
            adapter.executeIteration();
            require(hex(adapter.output()) == reference.substr(0, length * 2), "repeated XOF mismatch");
        }
    }
}

class NoOpProgressSink final : public ProgressSink {
public:
    void reportProgress(const ProgressInfo&) override
    {
    }
};

class RecordingMeasurementCoordinator final : public RunMeasurementCoordinator {
public:
    void beforeMeasurement(std::uint32_t) override
    {
    }

    void afterMeasurement(const WorkerRunMeasurement& measurement) override
    {
        measurements.push_back(measurement);
    }

    std::vector<WorkerRunMeasurement> measurements;
};

class DeterministicCpuTimeSource final : public ProcessCpuTimeSource {
public:
    std::uint64_t currentProcessCpuTimeNanoseconds() override
    {
        return values[nextValue++];
    }

private:
    const std::array<std::uint64_t, 4> values{1000, 1300, 2000, 2450};
    std::size_t nextValue = 0;
};

void testDigestAdapterRunsThroughBenchmarkRunner()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        3,
        2,
        core::HashConfig{64}
    };
    core::ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "SHA-256 integration config validation failed");

    const auto* profile = AlgorithmRegistry::find(config.profile);
    require(profile != nullptr && profile->id == core::AlgorithmProfileId::Sha256,
            "canonical SHA-256 profile resolution failed");
    const auto digestParameters = std::get<DigestParameters>(profile->parameters);
    const auto hashConfig = std::get<core::HashConfig>(validated->value().parameters);

    auto adapter = std::make_unique<DigestAdapter>(digestParameters, hashConfig.inputSize);
    BenchmarkTask task(std::move(*validated), *profile, std::move(adapter));
    NoOpProgressSink progress;
    RecordingMeasurementCoordinator coordinator;
    DeterministicCpuTimeSource cpuTime;
    BenchmarkRunner runner(task, progress, coordinator, cpuTime);

    runner.run();

    require(coordinator.measurements.size() == config.runs,
            "SHA-256 integration did not complete all configured runs");
    require(coordinator.measurements[0].runIndex == 0 && coordinator.measurements[1].runIndex == 1,
            "SHA-256 integration measurement indices are not ordered");
    require(coordinator.measurements[0].processCpuNanoseconds == 300,
            "SHA-256 integration run 0 CPU delta mismatch");
    require(coordinator.measurements[1].processCpuNanoseconds == 450,
            "SHA-256 integration run 1 CPU delta mismatch");
}

core::ValidatedBenchmarkConfig validateFactoryConfig(core::BenchmarkConfig config)
{
    ValidationResult validation;
    auto validated = ConfigValidator{}.validateAndCreate(config, validation);
    require(validated.has_value() && validation.isValid(), "factory test configuration validation failed");
    return std::move(*validated);
}

const core::AlgorithmProfile& canonicalFactoryProfile(core::AlgorithmProfileId id)
{
    const auto* profile = AlgorithmRegistry::find(id);
    require(profile != nullptr, "canonical factory test profile was not found");
    return *profile;
}

void testAdapterFactoryCreatesAndExecutesCanonicalSha256()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{64}
    };
    auto validated = validateFactoryConfig(config);
    const auto& profile = canonicalFactoryProfile(config.profile);

    auto adapter = AdapterFactory{}.create(profile, config.operation, validated);
    require(adapter != nullptr, "factory did not create the canonical SHA-256 adapter");
    adapter->prepareSeries();
    adapter->prepareRun();
    adapter->executeIteration();
}

void testAdapterFactoryCreatesAllCanonicalHashXofProfiles()
{
    constexpr std::array digestProfiles{
        core::AlgorithmProfileId::Sha224, core::AlgorithmProfileId::Sha256,
        core::AlgorithmProfileId::Sha384, core::AlgorithmProfileId::Sha512,
        core::AlgorithmProfileId::Sha3_224, core::AlgorithmProfileId::Sha3_256,
        core::AlgorithmProfileId::Sha3_384, core::AlgorithmProfileId::Sha3_512};
    constexpr std::array xofProfiles{
        core::AlgorithmProfileId::Shake128_28B, core::AlgorithmProfileId::Shake128_32B,
        core::AlgorithmProfileId::Shake128_48B, core::AlgorithmProfileId::Shake128_64B,
        core::AlgorithmProfileId::Shake128_128B, core::AlgorithmProfileId::Shake256_28B,
        core::AlgorithmProfileId::Shake256_32B, core::AlgorithmProfileId::Shake256_48B,
        core::AlgorithmProfileId::Shake256_64B, core::AlgorithmProfileId::Shake256_128B,
        core::AlgorithmProfileId::Shake256_256B};

    for (const auto profileId : digestProfiles) {
        const core::BenchmarkConfig config{profileId, BenchmarkOperation::Hash, 1, 1, core::HashConfig{0}};
        auto validated = validateFactoryConfig(config);
        auto adapter = AdapterFactory{}.create(canonicalFactoryProfile(profileId), config.operation, validated);
        adapter->prepareSeries();
        adapter->executeIteration();
    }
    for (const auto profileId : xofProfiles) {
        const core::BenchmarkConfig config{profileId, BenchmarkOperation::Xof, 1, 1, core::HashConfig{0}};
        auto validated = validateFactoryConfig(config);
        auto adapter = AdapterFactory{}.create(canonicalFactoryProfile(profileId), config.operation, validated);
        adapter->prepareSeries();
        adapter->executeIteration();
    }
}

void testAdapterFactoryCreatesCanonicalAead()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Aes128Gcm,
        BenchmarkOperation::Encrypt,
        1,
        1,
        core::AeadConfig{1}
    };
    auto validated = validateFactoryConfig(config);
    const auto& profile = canonicalFactoryProfile(config.profile);

    auto adapter = AdapterFactory{}.create(profile, config.operation, validated);
    require(adapter != nullptr, "factory did not create the canonical AEAD adapter");
    adapter->prepareSeries();
    adapter->executeIteration();
}

void testAdapterFactoryRejectsProfileMismatch()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{64}
    };
    auto validated = validateFactoryConfig(config);
    const auto& mismatchedProfile = canonicalFactoryProfile(core::AlgorithmProfileId::Sha224);

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, BenchmarkOperation::Hash, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory did not reject a profile identity mismatch");
}

void testAdapterFactoryRejectsOperationMismatch()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{64}
    };
    auto validated = validateFactoryConfig(config);
    const auto& profile = canonicalFactoryProfile(config.profile);

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(profile, BenchmarkOperation::Xof, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory did not reject an operation mismatch");
}

void testAdapterFactoryRejectsIncorrectParameterVariant()
{
    const core::BenchmarkConfig config{
        core::AlgorithmProfileId::Sha256,
        BenchmarkOperation::Hash,
        1,
        1,
        core::HashConfig{0}
    };
    auto validated = validateFactoryConfig(config);
    auto mismatchedProfile = canonicalFactoryProfile(config.profile);
    mismatchedProfile.parameters = XofParameters{XofAlgorithm::Shake128, 32};

    bool rejected = false;
    try {
        static_cast<void>(AdapterFactory{}.create(mismatchedProfile, config.operation, validated));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "factory did not reject an incorrect parameter variant");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"empty input", &testEmptyInput},
            std::pair{"abc input", &testAbcInput},
            std::pair{"repeated iterations", &testRepeatedIterations},
            std::pair{"longer prepared hash and XOF input", &testLongerPreparedHashAndXofInput},
            std::pair{"all canonical digest vectors", &testAllCanonicalDigests},
            std::pair{"canonical XOF vectors", &testCanonicalXofVectors},
            std::pair{"DigestAdapter through BenchmarkRunner", &testDigestAdapterRunsThroughBenchmarkRunner},
            std::pair{"AdapterFactory creates and executes canonical SHA-256", &testAdapterFactoryCreatesAndExecutesCanonicalSha256},
            std::pair{"AdapterFactory creates all canonical Hash/XOF profiles", &testAdapterFactoryCreatesAllCanonicalHashXofProfiles},
            std::pair{"AdapterFactory creates canonical AEAD", &testAdapterFactoryCreatesCanonicalAead},
            std::pair{"AdapterFactory rejects profile mismatch", &testAdapterFactoryRejectsProfileMismatch},
            std::pair{"AdapterFactory rejects operation mismatch", &testAdapterFactoryRejectsOperationMismatch},
            std::pair{"AdapterFactory rejects incorrect parameter variant", &testAdapterFactoryRejectsIncorrectParameterVariant}
        };
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS digest adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
