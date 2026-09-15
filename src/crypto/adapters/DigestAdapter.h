#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include <cryptobench/core/AlgorithmAdapter.h>
#include <cryptobench/core/DomainTypes.h>
#include <cryptobench/core/ProfileParameters.h>

#include "../openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

class DigestAdapter final : public core::AlgorithmAdapter {
public:
    DigestAdapter(core::DigestParameters parameters, core::WorkloadBytes inputSize);

    void prepareSeries() override;
    void executeIteration() override;

    std::span<const unsigned char> output() const noexcept;

private:
    core::DigestParameters parameters_;
    core::WorkloadBytes inputSize_;
    openssl::EvpMdPtr digest_{nullptr, &EVP_MD_free};
    openssl::EvpMdCtxPtr context_{nullptr, &EVP_MD_CTX_free};
    std::vector<unsigned char> input_;
    std::vector<unsigned char> output_;
};

} // namespace cryptobench::crypto
