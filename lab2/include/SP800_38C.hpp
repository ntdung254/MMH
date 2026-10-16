#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

// NIST SP 800-38C (CCM AEAD)
namespace SP800_38C {
    std::vector<uint8_t> ccm_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& nonce, int t_len = 16);
    std::vector<uint8_t> ccm_decrypt(AES& aes, const std::vector<uint8_t>& ct_with_tag, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& nonce, int t_len = 16);
}