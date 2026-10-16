#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

// NIST SP 800-38D (GCM AEAD & GHASH)
namespace SP800_38D {
    std::vector<uint8_t> gcm_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& nonce);
    std::vector<uint8_t> gcm_decrypt(AES& aes, const std::vector<uint8_t>& ct_with_tag, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& nonce);
}