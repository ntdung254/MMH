#include "SP800_38G.hpp"

using namespace std;

namespace SP800_38G {

    // Helper: Build a 16-byte block for AES PRF from half-integer and tweak
    vector<uint8_t> build_prf_block(uint32_t half_val, const vector<uint8_t>& tweak, int round) {
        vector<uint8_t> block(16, 0);
        block[0] = round; // Round number
        for (size_t i = 0; i < tweak.size() && i < 11; ++i) block[1 + i] = tweak[i];
        
        // Put the 32-bit half into the last 4 bytes
        block[12] = (half_val >> 24) & 0xFF;
        block[13] = (half_val >> 16) & 0xFF;
        block[14] = (half_val >> 8) & 0xFF;
        block[15] = half_val & 0xFF;
        return block;
    }

    uint64_t fpe_encrypt_64bit(AES& aes, uint64_t pt, const vector<uint8_t>& tweak) {
        uint32_t L = (pt >> 32) & 0xFFFFFFFF; // Left half
        uint32_t R = pt & 0xFFFFFFFF;         // Right half
        
        // 10 Feistel Rounds (Standard for FF1 is 10 rounds)
        for (int i = 0; i < 10; ++i) {
            vector<uint8_t> prf_in = build_prf_block(R, tweak, i);
            vector<uint8_t> prf_out = aes.encrypt_block(prf_in);
            
            // Extract 32-bit pseudo-random value from AES output
            uint32_t F = (prf_out[0] << 24) | (prf_out[1] << 16) | (prf_out[2] << 8) | prf_out[3];
            
            uint32_t next_L = R;
            uint32_t next_R = L ^ F;
            
            L = next_L;
            R = next_R;
        }
        return ((uint64_t)L << 32) | R;
    }

    uint64_t fpe_decrypt_64bit(AES& aes, uint64_t ct, const vector<uint8_t>& tweak) {
        uint32_t L = (ct >> 32) & 0xFFFFFFFF;
        uint32_t R = ct & 0xFFFFFFFF;
        
        // 10 Feistel Rounds in Reverse
        for (int i = 9; i >= 0; --i) {
            uint32_t prev_R = L;
            
            vector<uint8_t> prf_in = build_prf_block(prev_R, tweak, i);
            vector<uint8_t> prf_out = aes.encrypt_block(prf_in);
            
            uint32_t F = (prf_out[0] << 24) | (prf_out[1] << 16) | (prf_out[2] << 8) | prf_out[3];
            
            uint32_t prev_L = R ^ F;
            
            L = prev_L;
            R = prev_R;
        }
        return ((uint64_t)L << 32) | R;
    }
}