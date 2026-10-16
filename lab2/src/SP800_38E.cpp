#include "SP800_38E.hpp"
#include <stdexcept>

using namespace std;

namespace SP800_38E {

    // Galois Field multiplication by x (alpha) in GF(2^128) for XTS
    // XTS uses little-endian byte ordering for this operation
    void xts_multiply_by_x(vector<uint8_t>& t) {
        uint8_t carry_in = 0;
        for (int i = 0; i < 16; ++i) {
            uint8_t carry_out = (t[i] >> 7) & 1;
            t[i] = ((t[i] << 1) | carry_in) & 0xFF;
            carry_in = carry_out;
        }
        // If carry out from the last byte is 1, XOR first byte with polynomial 0x87
        if (carry_in) t[0] ^= 0x87;
    }

    vector<uint8_t> xts_encrypt(AES& aes1, AES& aes2, const vector<uint8_t>& pt, const vector<uint8_t>& tweak) {
        if (tweak.size() != 16) throw invalid_argument("XTS tweak must be exactly 16 bytes.");
        if (pt.size() % 16 != 0) throw invalid_argument("This simplified XTS requires data to be a multiple of 16 bytes.");

        vector<uint8_t> ct = pt;
        vector<uint8_t> T = aes2.encrypt_block(tweak); // Encrypt tweak with Key2

        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> block(pt.begin() + i, pt.begin() + i + 16);
            
            // C = E_K1(P XOR T) XOR T
            for (int j = 0; j < 16; ++j) block[j] ^= T[j];
            block = aes1.encrypt_block(block);
            for (int j = 0; j < 16; ++j) block[j] ^= T[j];
            
            for (int j = 0; j < 16; ++j) ct[i + j] = block[j];
            
            // Multiply T by x in GF(2^128) for next block
            xts_multiply_by_x(T);
        }
        return ct;
    }

    vector<uint8_t> xts_decrypt(AES& aes1, AES& aes2, const vector<uint8_t>& ct, const vector<uint8_t>& tweak) {
        if (tweak.size() != 16 || ct.size() % 16 != 0) throw invalid_argument("Invalid XTS parameters.");

        vector<uint8_t> pt = ct;
        vector<uint8_t> T = aes2.encrypt_block(tweak); // Tweak is ALWAYS encrypted (even in decryption)

        for (size_t i = 0; i < ct.size(); i += 16) {
            vector<uint8_t> block(ct.begin() + i, ct.begin() + i + 16);
            
            // P = D_K1(C XOR T) XOR T
            for (int j = 0; j < 16; ++j) block[j] ^= T[j];
            block = aes1.decrypt_block(block);
            for (int j = 0; j < 16; ++j) block[j] ^= T[j];
            
            for (int j = 0; j < 16; ++j) pt[i + j] = block[j];
            
            xts_multiply_by_x(T);
        }
        return pt;
    }
}