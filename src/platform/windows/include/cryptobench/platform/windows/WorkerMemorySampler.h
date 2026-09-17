#pragma once

#include <cryptobench/core/MemoryRunMeasurement.h>

#include <cstdint>
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
    core::ParentRunMemoryMeasurement stopAndCollect();
    void stopAndDiscard() noexcept;
    bool isActive() const noexcept;

private:
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
    std::string threadError_;
    bool threadErrorOccurred_ = false;
    bool active_ = false;
};

} // namespace cryptobench::platform::windows
