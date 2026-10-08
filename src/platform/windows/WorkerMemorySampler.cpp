#include <cryptobench/platform/windows/WorkerMemorySampler.h>
#include "WorkerMemorySamplerAccounting.h"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

std::string errorMessage(const char* operation, DWORD errorCode)
{
    return std::string(operation) + " failed with error code "
        + std::to_string(errorCode);
}

std::uint64_t privateUsageBytes(HANDLE processHandle)
{
    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (!GetProcessMemoryInfo(
            processHandle,
            reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
            sizeof(counters))) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("GetProcessMemoryInfo", errorCode));
    }
    return static_cast<std::uint64_t>(counters.PrivateUsage);
}

} // namespace

namespace cryptobench::platform::windows {

WorkerMemorySampler::~WorkerMemorySampler()
{
    stopAndDiscard();
}

void WorkerMemorySampler::start(std::uint32_t processId, std::uint32_t runIndex)
{
    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::Inactive) {
        throw std::logic_error("WorkerMemorySampler is already active");
    }
    if (processId == 0) {
        throw std::invalid_argument("WorkerMemorySampler process ID must not be zero");
    }

    try {
        startInternal(processId, 5, Lifecycle::Legacy, runIndex);
    } catch (...) {
        cleanupAfterFailure(lock);
        throw;
    }
}

void WorkerMemorySampler::startV2(
    std::uint32_t processId,
    const core::MeasurementSettings& settings)
{
    if (!core::isValidMeasurementSettings(settings)) {
        throw std::invalid_argument("WorkerMemorySampler measurement settings are invalid");
    }

    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::Inactive) {
        throw std::logic_error("WorkerMemorySampler is already active");
    }
    if (processId == 0) {
        throw std::invalid_argument("WorkerMemorySampler process ID must not be zero");
    }

    try {
        startInternal(
            processId,
            settings.memorySamplingIntervalMilliseconds,
            Lifecycle::V2Preparation,
            0);
    } catch (...) {
        cleanupAfterFailure(lock);
        throw;
    }
}

void WorkerMemorySampler::startInternal(
    std::uint32_t processId,
    std::uint32_t samplingIntervalMilliseconds,
    Lifecycle lifecycle,
    std::uint32_t runIndex)
{
    processHandle_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle_ == nullptr) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("OpenProcess", errorCode));
    }

    baselineBytes_ = privateUsageBytes(processHandle_);
    peakSampledBytes_ = baselineBytes_;
    memoryV2Raw_ = {};
    memoryV2Raw_.baselinePrivateUsageBytes = baselineBytes_;
    runIndex_ = runIndex;

    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stopEvent_ == nullptr) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("CreateEventW", errorCode));
    }

    timer_ = CreateWaitableTimerExW(
        nullptr,
        nullptr,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
        TIMER_MODIFY_STATE | SYNCHRONIZE);
    if (timer_ == nullptr) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("CreateWaitableTimerExW", errorCode));
    }

    LARGE_INTEGER dueTime{};
    dueTime.QuadPart = -10'000LL * samplingIntervalMilliseconds;
    if (!SetWaitableTimer(
            timer_,
            &dueTime,
            static_cast<LONG>(samplingIntervalMilliseconds),
            nullptr,
            nullptr,
            FALSE)) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("SetWaitableTimer", errorCode));
    }

    threadError_.clear();
    threadErrorOccurred_ = false;
    lifecycle_ = lifecycle;
    samplingThread_ = std::thread(&WorkerMemorySampler::samplingThreadMain, this);
}

core::ParentRunMemoryMeasurement WorkerMemorySampler::stopAndCollect()
{
    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::Legacy) {
        throw std::logic_error("WorkerMemorySampler is not active");
    }

    lifecycle_ = Lifecycle::Stopping;
    requestStop();
    lock.unlock();
    joinThread();
    lock.lock();

    const auto threadErrorOccurred = threadErrorOccurred_;
    auto threadError = std::move(threadError_);
    const core::ParentRunMemoryMeasurement result{
        runIndex_,
        core::MemoryRunMeasurement{
            baselineBytes_,
            peakSampledBytes_,
            peakSampledBytes_ - baselineBytes_}};
    lifecycle_ = Lifecycle::Inactive;
    closeHandles();

    if (threadErrorOccurred) {
        if (threadError.empty()) {
            throw std::runtime_error("WorkerMemorySampler sampling thread failed");
        }
        throw std::runtime_error(threadError);
    }
    return result;
}

void WorkerMemorySampler::markExecutionBoundaryV2()
{
    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::V2Preparation) {
        throw std::logic_error("WorkerMemorySampler is not in v2 preparation");
    }

    try {
        memoryV2Raw_.readyPrivateUsageBytes = privateUsageBytes(processHandle_);
        lifecycle_ = Lifecycle::V2Execution;
    } catch (...) {
        cleanupAfterFailure(lock);
        throw;
    }
}

core::MemoryV2RawObservations WorkerMemorySampler::stopAndCollectV2()
{
    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::V2Execution) {
        throw std::logic_error("WorkerMemorySampler is not in v2 execution");
    }

    try {
        memoryV2Raw_.finalPrivateUsageBytes = privateUsageBytes(processHandle_);
    } catch (...) {
        cleanupAfterFailure(lock);
        throw;
    }

    lifecycle_ = Lifecycle::Stopping;
    requestStop();
    lock.unlock();
    joinThread();
    lock.lock();

    const auto threadErrorOccurred = threadErrorOccurred_;
    auto threadError = std::move(threadError_);
    const auto result = memoryV2Raw_;
    lifecycle_ = Lifecycle::Inactive;
    closeHandles();

    if (threadErrorOccurred) {
        if (threadError.empty()) {
            throw std::runtime_error("WorkerMemorySampler sampling thread failed");
        }
        throw std::runtime_error(threadError);
    }
    return result;
}

void WorkerMemorySampler::stopAndDiscard() noexcept
{
    std::unique_lock lock(mutex_);
    if (lifecycle_ != Lifecycle::Inactive) {
        lifecycle_ = Lifecycle::Stopping;
        requestStop();
    }
    lock.unlock();
    joinThread();
    lock.lock();
    lifecycle_ = Lifecycle::Inactive;
    closeHandles();
    threadError_.clear();
    threadErrorOccurred_ = false;
}

bool WorkerMemorySampler::isActive() const noexcept
{
    std::lock_guard lock(mutex_);
    return lifecycle_ != Lifecycle::Inactive;
}

void WorkerMemorySampler::cleanupAfterFailure(std::unique_lock<std::mutex>& lock) noexcept
{
    lifecycle_ = Lifecycle::Stopping;
    requestStop();
    lock.unlock();
    joinThread();
    lock.lock();
    lifecycle_ = Lifecycle::Inactive;
    closeHandles();
    threadError_.clear();
    threadErrorOccurred_ = false;
}

void WorkerMemorySampler::requestStop() noexcept
{
    if (stopEvent_ != nullptr) {
        SetEvent(stopEvent_);
    }
}

void WorkerMemorySampler::joinThread() noexcept
{
    if (samplingThread_.joinable()) {
        samplingThread_.join();
    }
}

void WorkerMemorySampler::closeHandles() noexcept
{
    if (timer_ != nullptr) {
        CloseHandle(timer_);
        timer_ = nullptr;
    }
    if (stopEvent_ != nullptr) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
    if (processHandle_ != nullptr) {
        CloseHandle(processHandle_);
        processHandle_ = nullptr;
    }
}

void WorkerMemorySampler::samplingThreadMain() noexcept
{
    try {
        const HANDLE waitHandles[] = {stopEvent_, timer_};
        while (true) {
            const auto waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0) {
                return;
            }
            if (waitResult == WAIT_OBJECT_0 + 1) {
                std::lock_guard lock(mutex_);
                if (lifecycle_ == Lifecycle::Stopping || lifecycle_ == Lifecycle::Inactive) {
                    return;
                }

                const auto sample = privateUsageBytes(processHandle_);
                if (lifecycle_ == Lifecycle::Legacy) {
                    peakSampledBytes_ = std::max(peakSampledBytes_, sample);
                } else if (lifecycle_ == Lifecycle::V2Preparation) {
                    recordMemoryV2Sample(
                        memoryV2Raw_, MemoryV2SamplePhase::Preparation, sample);
                } else if (lifecycle_ == Lifecycle::V2Execution) {
                    recordMemoryV2Sample(
                        memoryV2Raw_, MemoryV2SamplePhase::Execution, sample);
                }
                continue;
            }
            const auto errorCode = GetLastError();
            throw std::runtime_error(errorMessage("WaitForMultipleObjects", errorCode));
        }
    } catch (const std::exception& error) {
        recordThreadError(error.what());
    } catch (...) {
        recordThreadError("WorkerMemorySampler sampling thread failed with an unknown error");
    }
}

void WorkerMemorySampler::recordThreadError(const std::string& message) noexcept
{
    std::lock_guard lock(mutex_);
    threadErrorOccurred_ = true;
    try {
        threadError_ = message;
    } catch (...) {
    }
}

} // namespace cryptobench::platform::windows
