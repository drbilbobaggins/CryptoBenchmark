#include "adapters/DigestAdapter.h"

#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace cryptobench::tests {
namespace {

using crypto::DigestAdapter;
using core::DigestAlgorithm;
using core::DigestParameters;

void require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::string hex(std::span<const unsigned char> bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void requireDigest(DigestAdapter& adapter, std::string_view expected)
{
    adapter.executeIteration();
    require(hex(adapter.output()) == expected, "SHA-256 digest mismatch");
}

void testEmptyInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 0);
    adapter.prepareSeries();
    requireDigest(adapter, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    require(adapter.output().size() == 32, "SHA-256 output length mismatch");
}

void testAbcInput()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void testRepeatedIterations()
{
    DigestAdapter adapter(DigestParameters{DigestAlgorithm::Sha256}, 3);
    adapter.prepareSeries();
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    requireDigest(adapter, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

} // namespace
} // namespace cryptobench::tests

int main()
{
    using namespace cryptobench::tests;
    try {
        const auto tests = std::array{
            std::pair{"empty input", &testEmptyInput},
            std::pair{"abc input", &testAbcInput},
            std::pair{"repeated iterations", &testRepeatedIterations}
        };
        for (const auto& [name, test] : tests) {
            test();
            std::cout << "PASS " << name << '\n';
        }
        std::cout << "PASS digest adapter total=" << tests.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
