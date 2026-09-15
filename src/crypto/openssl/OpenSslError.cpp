#include "OpenSslError.h"

#include <sstream>
#include <string>
#include <utility>

#include <openssl/err.h>

namespace cryptobench::crypto::openssl {

OpenSslError::OpenSslError(std::string message)
    : std::runtime_error(std::move(message))
{
}

[[noreturn]] void throwOpenSslError(std::string_view operation)
{
    std::ostringstream message;
    message << operation << " failed";

    bool hasDetails = false;
    for (unsigned long error = ERR_get_error(); error != 0; error = ERR_get_error()) {
        char buffer[256]{};
        ERR_error_string_n(error, buffer, sizeof(buffer));
        message << (hasDetails ? "; " : ": ") << buffer;
        hasDetails = true;
    }
    if (!hasDetails) {
        message << ": OpenSSL error queue is empty";
    }

    throw OpenSslError(message.str());
}

void checkOpenSslReturn(int result, std::string_view operation)
{
    if (result != 1) {
        throwOpenSslError(operation);
    }
}

} // namespace cryptobench::crypto::openssl
