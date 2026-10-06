#pragma once

#include <cryptobench/core/MeasurementSettings.h>
#include <cryptobench/core/MemoryRunMeasurement.h>
#include <cryptobench/core/MemoryV2.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace cryptobench::platform::windows {

class WorkerMemorySampler final {
public:
    WorkerMemorySampler() = default;
    ~WorkerMemorySampler();

    WorkerMemorySampler(const WorkerMemorySampler&) = delete;
    WorkerMemorySampler& operator=(const WorkerMemorySampler&) = delete;

    void start(std::uint32_t processId, std::uint32_t runIndex);
    void startV2(std::uint32_t processId, const core::MeasurementSettings& settings);
    void markExecutionBoundaryV2();
    core::ParentRunMemoryMeasurement stopAndCollect();
    core::MemoryV2RawObservations stopAndCollectV2();
    void stopAndDiscard() noexcept;
    bool isActive() const noexcept;

private:
    enum class Lifecycle {
        Inactive,
        Legacy,
        V2Preparation,
        V2Execution,
        Stopping
    };

    void startInternal(
        std::uint32_t processId,
        std::uint32_t samplingIntervalMilliseconds,
        Lifecycle lifecycle,
        std::uint32_t runIndex);
    void cleanupAfterFailure(std::unique_lock<std::mutex>& lock) noexcept;
    void requestStop() noexcept;
    void joinThread() noexcept;
    void closeHandles() noexcept;
    void samplingThreadMain() noexcept;
    void recordThreadError(const std::string& message) noexcept;

    void* processHandle_ = nullptr;
    void* stopEvent_ = nullptr;
    void* timer_ = nullptr;
    std::thread samplingThread_;
    std::uint32_t runIndex_ = 0;
    std::uint64_t baselineBytes_ = 0;
    std::uint64_t peakSampledBytes_ = 0;
    core::MemoryV2RawObservations memoryV2Raw_{};
    std::string threadError_;
    bool threadErrorOccurred_ = false;
    Lifecycle lifecycle_ = Lifecycle::Inactive;
    mutable std::mutex mutex_;
};

} // namespace cryptobench::platform::windows
