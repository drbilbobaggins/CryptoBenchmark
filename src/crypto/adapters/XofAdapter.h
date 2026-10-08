#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/CommonWorkload.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class XofAdapter final : public core::AlgorithmAdapter {
public:
    XofAdapter(core::XofParameters parameters, core::WorkloadBytes inputSize);
    XofAdapter(core::XofParameters parameters, core::CommonWorkload&& workload);

    void prepareSeries() override;
    void executeIteration() override;

    std::span<const unsigned char> output() const noexcept;
    std::span<const unsigned char> input() const noexcept;

private:
    std::span<const unsigned char> inputBytes() const noexcept;

    core::XofParameters parameters_;
    core::WorkloadBytes inputSize_;
    openssl::EvpMdPtr digest_{nullptr, &EVP_MD_free};
    openssl::EvpMdCtxPtr context_{nullptr, &EVP_MD_CTX_free};
    std::optional<core::CommonWorkload> commonWorkload_;
    std::vector<unsigned char> input_;
    std::vector<unsigned char> output_;
};

} // namespace cryptobench::crypto
