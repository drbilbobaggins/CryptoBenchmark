#include "BatchJsonInteger.h"

#include <limits>
#include <string>

namespace cryptobench::application::detail {
namespace {

bool parseExponent(std::string_view lexeme, std::size_t start, bool& negative, std::uint64_t& magnitude)
{
    negative = false;
    magnitude = 0;
    if (start >= lexeme.size()) {
        return false;
    }
    if (lexeme[start] == '+' || lexeme[start] == '-') {
        negative = lexeme[start] == '-';
        ++start;
    }
    if (start == lexeme.size()) {
        return false;
    }

    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    for (; start < lexeme.size(); ++start) {
        if (lexeme[start] < '0' || lexeme[start] > '9') {
            return false;
        }
        const auto digit = static_cast<std::uint64_t>(lexeme[start] - '0');
        if (magnitude > (maximum - digit) / 10) {
            magnitude = maximum;
        } else {
            magnitude = magnitude * 10 + digit;
        }
    }
    return true;
}

bool hasOnlyZeroFraction(const std::string& digits, std::size_t first, std::size_t end)
{
    for (std::size_t index = first; index < end; ++index) {
        if (digits[index] != '0') {
            return false;
        }
    }
    return true;
}

} // namespace

std::optional<std::uint64_t> parseExactUnsignedJsonInteger(std::string_view lexeme)
{
    if (lexeme.empty()) {
        return std::nullopt;
    }

    std::size_t position = 0;
    const bool negative = lexeme[position] == '-';
    if (negative) {
        ++position;
    }
    if (position == lexeme.size()) {
        return std::nullopt;
    }

    std::string digits;
    digits.reserve(lexeme.size());
    std::size_t fractionalDigits = 0;
    bool afterDecimal = false;
    while (position < lexeme.size() && lexeme[position] != 'e' && lexeme[position] != 'E') {
        const auto character = lexeme[position++];
        if (character == '.') {
            if (afterDecimal) {
                return std::nullopt;
            }
            afterDecimal = true;
            continue;
        }
        if (character < '0' || character > '9') {
            return std::nullopt;
        }
        digits.push_back(character);
        if (afterDecimal) {
            ++fractionalDigits;
        }
    }
    if (digits.empty()) {
        return std::nullopt;
    }

    bool exponentNegative = false;
    std::uint64_t exponentMagnitude = 0;
    if (position < lexeme.size()
        && !parseExponent(lexeme, position + 1, exponentNegative, exponentMagnitude)) {
        return std::nullopt;
    }

    std::size_t firstSignificantDigit = 0;
    while (firstSignificantDigit < digits.size() && digits[firstSignificantDigit] == '0') {
        ++firstSignificantDigit;
    }
    if (firstSignificantDigit == digits.size()) {
        return 0;
    }

    std::size_t significantEnd = digits.size();
    std::size_t trailingZeros = 0;
    if (exponentNegative) {
        if (exponentMagnitude > std::numeric_limits<std::size_t>::max()
            || exponentMagnitude > std::numeric_limits<std::size_t>::max() - fractionalDigits) {
            return std::nullopt;
        }
        const auto fractionalCount = fractionalDigits + static_cast<std::size_t>(exponentMagnitude);
        if (fractionalCount > digits.size()) {
            return std::nullopt;
        }
        significantEnd = digits.size() - fractionalCount;
        if (!hasOnlyZeroFraction(digits, significantEnd, digits.size())) {
            return std::nullopt;
        }
    } else if (exponentMagnitude <= fractionalDigits) {
        const auto fractionalCount = fractionalDigits - static_cast<std::size_t>(exponentMagnitude);
        if (fractionalCount > digits.size()) {
            return std::nullopt;
        }
        significantEnd = digits.size() - fractionalCount;
        if (!hasOnlyZeroFraction(digits, significantEnd, digits.size())) {
            return std::nullopt;
        }
    } else {
        const auto shift = exponentMagnitude - fractionalDigits;
        if (shift > std::numeric_limits<std::size_t>::max() || shift > 20) {
            return std::nullopt;
        }
        trailingZeros = static_cast<std::size_t>(shift);
    }

    std::uint64_t value = 0;
    for (std::size_t index = firstSignificantDigit; index < significantEnd; ++index) {
        const auto digit = static_cast<std::uint64_t>(digits[index] - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            return std::nullopt;
        }
        value = value * 10 + digit;
    }
    for (std::size_t index = 0; index < trailingZeros; ++index) {
        if (value > std::numeric_limits<std::uint64_t>::max() / 10) {
            return std::nullopt;
        }
        value *= 10;
    }

    if (negative && value != 0) {
        return std::nullopt;
    }
    return value;
}

} // namespace cryptobench::application::detail
