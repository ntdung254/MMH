#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

// NIST SP 800-38F (Key Wrapping)
namespace SP800_38F {
    std::vector<uint8_t> key_wrap(AES& aes, const std::vector<uint8_t>& key_to_wrap);
}