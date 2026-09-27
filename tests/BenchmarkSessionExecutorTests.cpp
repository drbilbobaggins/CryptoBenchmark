#include <cryptobench/application/BenchmarkController.h>
#include <cryptobench/application/BenchmarkSessionExecutor.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using namespace cryptobench;

void require(bool condition, std::string_view message)
{
    if (!condition) throw std::runtime_error(std::string(message));
}

class FakeExecutor final : public application::BenchmarkSessionExecutor {
public:
    using BenchmarkSessionExecutor::BenchmarkSessionExecutor;

    void start(const core::BenchmarkConfig&) override {}
    void requestCancel() override { cancelRequested = true; }
    bool isBusy() const noexcept override { return busy; }

    bool busy = false;
    bool cancelRequested = false;
};

core::BenchmarkConfig config()
{
    return {core::AlgorithmProfileId::Sha256, core::BenchmarkOperation::Hash, 1, 1,
            core::HashConfig{1}};
}

void testContractAndFake()
{
    static_assert(std::is_base_of_v<application::BenchmarkSessionExecutor,
                                    application::BenchmarkController>);
    FakeExecutor executor;
    bool progressReceived = false;
    bool resultReceived = false;
    QObject::connect(&executor, &application::BenchmarkSessionExecutor::progressChanged,
                     [&progressReceived](const core::ProgressInfo&) { progressReceived = true; });
    QObject::connect(&executor, &application::BenchmarkSessionExecutor::benchmarkFinished,
                     [&resultReceived](const core::BenchmarkResult&) { resultReceived = true; });

    executor.requestCancel();
    require(executor.cancelRequested, "fake executor did not implement cancellation");
    executor.progressChanged({core::BenchmarkPhase::Preparing, std::nullopt, 1});
    executor.benchmarkFinished({});
    require(progressReceived && resultReceived, "base signal contract was not usable");
}

void testRealIdleCancellation()
{
    application::BenchmarkController controller;
    controller.requestCancel();
    require(!controller.isBusy(), "idle controller cancellation changed busy state");
}

} // namespace

int main()
{
    try {
        testContractAndFake();
        testRealIdleCancellation();
        std::cout << "PASS BenchmarkSessionExecutor\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL BenchmarkSessionExecutor: " << error.what() << '\n';
        return 1;
    }
}