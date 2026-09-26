#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace cryptobench::application::detail {

std::optional<std::uint64_t> parseExactUnsignedJsonInteger(std::string_view lexeme);

} // namespace cryptobench::application::detail
