#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

// NIST SP 800-38E: XTS-AES Mode (Storage/Disk Encryption)
namespace SP800_38E {
    // XTS uses 2 keys: aes1 (Key1 for data) and aes2 (Key2 for tweak)
    // Tweak is typically the sector/data-unit number (16 bytes, little-endian)
    std::vector<uint8_t> xts_encrypt(AES& aes1, AES& aes2, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& tweak);
    std::vector<uint8_t> xts_decrypt(AES& aes1, AES& aes2, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& tweak);
}