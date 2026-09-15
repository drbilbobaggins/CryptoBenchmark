#pragma once

#include <string>
#include <stdexcept>
#include <string_view>

namespace cryptobench::crypto::openssl {

class OpenSslError : public std::runtime_error {
public:
    explicit OpenSslError(std::string message);
};

[[noreturn]] void throwOpenSslError(std::string_view operation);
void checkOpenSslReturn(int result, std::string_view operation);

} // namespace cryptobench::crypto::openssl
