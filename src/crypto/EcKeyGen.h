#pragma once

#include <string_view>

#include <cryptobench/core/ProfileParameters.h>

#include "openssl/OpenSslRaii.h"

namespace cryptobench::crypto {

std::string_view ecCurveGroupName(core::EcCurve curve);
openssl::EvpPkeyCtxPtr createEcKeyGenerationContext();
openssl::EvpPkeyPtr generateEcKey(EVP_PKEY_CTX* context, core::EcCurve curve);

} // namespace cryptobench::crypto
