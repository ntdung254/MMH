#pragma once
#include <vector>
#include <cstdint>
#include "AES.hpp"

// NIST SP 800-38G: Format-Preserving Encryption (Conceptual FF1 structure)
// Simplified to encrypt/decrypt a 64-bit integer format using Feistel Network
namespace SP800_38G {
    // Encrypts a 64-bit integer, outputs a pseudo-random 64-bit integer
    uint64_t fpe_encrypt_64bit(AES& aes, uint64_t plaintext, const std::vector<uint8_t>& tweak);
    
    // Decrypts a 64-bit integer back to original
    uint64_t fpe_decrypt_64bit(AES& aes, uint64_t ciphertext, const std::vector<uint8_t>& tweak);
}