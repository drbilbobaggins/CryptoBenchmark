#include "WorkerSession.h"

#include <cryptobench/core/AlgorithmRegistry.h>
#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/BenchmarkRunner.h>
#include <cryptobench/core/BenchmarkTask.h>
#include <cryptobench/core/ConfigValidator.h>
#include <cryptobench/core/ErrorInfo.h>
#include <cryptobench/core/RunnerFailure.h>
#include <cryptobench/crypto/AdapterFactory.h>
#include <cryptobench/ipc/WireDtos.h>
#include <cryptobench/ipc/WorkerIpcChannel.h>
#include <cryptobench/platform/windows/WindowsProcessCpuTimeSource.h>

#include <QString>

#include <cstddef>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace cryptobench::worker {
namespace {

using core::ErrorCode;
using core::ErrorInfo;
using core::FailureStage;

std::string validationMessage(const core::ValidationResult& validation)
{
    std::ostringstream message;
    for (std::size_t index = 0; index < validation.errors.size(); ++index) {
        if (index != 0) message << "; ";
        message << validation.errors[index].technicalMessage;
    }
    return message.str();
}

ErrorCode runnerErrorCode(FailureStage stage)
{
    switch (stage) {
    case FailureStage::WorkerCommunication:
        return ErrorCode::WorkerCommunicationFailed;
    case FailureStage::SeriesPreparation:
    case FailureStage::RunPreparation:
        return ErrorCode::CryptoInitializationFailed;
    case FailureStage::Warmup:
    case FailureStage::Measurement:
        return ErrorCode::CryptoOperationFailed;
    default:
        return ErrorCode::InternalError;
    }
}

ErrorInfo errorInfoFor(const core::RunnerFailure& failure)
{
    return {
        runnerErrorCode(failure.stage()),
        failure.stage(),
        failure.runIndex(),
        failure.what(),
        std::nullopt
    };
}

ErrorInfo errorInfoForTaskFailure(const std::exception& error, bool unsupportedStrategy)
{
    return {
        unsupportedStrategy ? ErrorCode::UnknownExecutionStrategy : ErrorCode::InternalError,
        FailureStage::TaskCreation,
        std::nullopt,
        error.what(),
        std::nullopt
    };
}

void trySendFailure(ipc::WorkerIpcChannel& channel, const ErrorInfo& error)
{
    try {
        channel.sendWorkerOutcome({ipc::WorkerOutcomeStatus::Failed, error});
    } catch (...) {
    }
}

} // namespace

int runWorkerSession(const QString& endpoint)
{
    ipc::WorkerIpcChannel channel;
    bool connected = false;

    try {
        channel.connectToServer(endpoint);
        connected = true;
        channel.sendWorkerReady();

        const auto request = channel.receiveBenchmarkRequest();
        core::ConfigValidator validator;
        core::ValidationResult validation;
        auto validated = validator.validateAndCreate(request.config, validation);
        if (!validated) {
            const ErrorInfo error{
                ErrorCode::InvalidConfiguration,
                FailureStage::ConfigValidation,
                std::nullopt,
                validationMessage(validation),
                std::nullopt
            };
            trySendFailure(channel, error);
            return 1;
        }

        const auto* profile = core::AlgorithmRegistry::find(validated->value().profile);
        if (profile == nullptr) {
            const std::logic_error error("validated profile is missing from AlgorithmRegistry");
            const auto info = errorInfoForTaskFailure(error, false);
            trySendFailure(channel, info);
            return 1;
        }

        std::unique_ptr<core::AlgorithmAdapter> adapter;
        try {
            adapter = crypto::AdapterFactory{}.create(*profile, validated->value().operation, *validated);
        } catch (const std::invalid_argument& error) {
            const auto info = errorInfoForTaskFailure(error, true);
            trySendFailure(channel, info);
            return 1;
        } catch (const std::exception& error) {
            const auto info = errorInfoForTaskFailure(error, false);
            trySendFailure(channel, info);
            return 1;
        }

        std::optional<core::BenchmarkTask> task;
        try {
            task.emplace(std::move(*validated), *profile, std::move(adapter));
        } catch (const std::exception& error) {
            const auto info = errorInfoForTaskFailure(error, false);
            trySendFailure(channel, info);
            return 1;
        }

        platform::windows::WindowsProcessCpuTimeSource cpuTimeSource;
        core::BenchmarkRunner runner(*task, channel, channel, cpuTimeSource);
        runner.run();

        channel.sendWorkerOutcome({ipc::WorkerOutcomeStatus::Completed, std::nullopt});
        return 0;
    } catch (const core::RunnerFailure& failure) {
        const auto error = errorInfoFor(failure);
        if (connected) trySendFailure(channel, error);
        return 1;
    } catch (const std::exception& error) {
        const ErrorInfo info{
            ErrorCode::WorkerCommunicationFailed,
            FailureStage::WorkerCommunication,
            std::nullopt,
            error.what(),
            std::nullopt
        };
        if (connected) trySendFailure(channel, info);
        return 1;
    }
}

} // namespace cryptobench::worker
