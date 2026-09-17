#include <cryptobench/platform/windows/WorkerMemorySampler.h>

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
    if (active_) {
        throw std::logic_error("WorkerMemorySampler is already active");
    }
    if (processId == 0) {
        throw std::invalid_argument("WorkerMemorySampler process ID must not be zero");
    }

    processHandle_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle_ == nullptr) {
        const auto errorCode = GetLastError();
        throw std::runtime_error(errorMessage("OpenProcess", errorCode));
    }

    try {
        baselineBytes_ = privateUsageBytes(processHandle_);
        peakSampledBytes_ = baselineBytes_;
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
        dueTime.QuadPart = -50'000;
        if (!SetWaitableTimer(timer_, &dueTime, 5, nullptr, nullptr, FALSE)) {
            const auto errorCode = GetLastError();
            throw std::runtime_error(errorMessage("SetWaitableTimer", errorCode));
        }

        threadError_.clear();
        threadErrorOccurred_ = false;
        active_ = true;
        try {
            samplingThread_ = std::thread(&WorkerMemorySampler::samplingThreadMain, this);
        } catch (...) {
            active_ = false;
            throw;
        }
    } catch (...) {
        requestStop();
        joinThread();
        closeHandles();
        throw;
    }
}

core::ParentRunMemoryMeasurement WorkerMemorySampler::stopAndCollect()
{
    if (!active_) {
        throw std::logic_error("WorkerMemorySampler is not active");
    }

    requestStop();
    joinThread();

    const auto threadErrorOccurred = threadErrorOccurred_;
    auto threadError = std::move(threadError_);
    const core::ParentRunMemoryMeasurement result{
        runIndex_,
        core::MemoryRunMeasurement{
            baselineBytes_,
            peakSampledBytes_,
            peakSampledBytes_ - baselineBytes_}};
    active_ = false;
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
    if (active_) {
        requestStop();
    }
    joinThread();
    active_ = false;
    closeHandles();
    threadError_.clear();
    threadErrorOccurred_ = false;
}

bool WorkerMemorySampler::isActive() const noexcept
{
    return active_;
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
                peakSampledBytes_ = std::max(peakSampledBytes_, privateUsageBytes(processHandle_));
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
    threadErrorOccurred_ = true;
    try {
        threadError_ = message;
    } catch (...) {
    }
}

} // namespace cryptobench::platform::windows
