#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

namespace SP800_38A {
    std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& data);
    std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> cbc_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cbc_decrypt(AES& aes, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> ctr_process(AES& aes, const std::vector<uint8_t>& data, const std::vector<uint8_t>& nonce);

    // Bổ sung các mode đầy đủ theo yêu cầu:
    std::vector<uint8_t> ecb_encrypt(AES& aes, const std::vector<uint8_t>& pt);
    std::vector<uint8_t> ecb_decrypt(AES& aes, const std::vector<uint8_t>& ct);
    std::vector<uint8_t> cbc_encrypt_nopad(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cbc_decrypt_nopad(AES& aes, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cfb128_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cfb128_decrypt(AES& aes, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cfb8_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> cfb8_decrypt(AES& aes, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> ofb_encrypt(AES& aes, const std::vector<uint8_t>& pt, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> ofb_decrypt(AES& aes, const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv);
}