#include "SP800_38D.hpp"

using namespace std;

namespace SP800_38D {
    // GF(2^128) Multiplication for GHASH
    void gf_mult(const vector<uint8_t>& x, const vector<uint8_t>& y, vector<uint8_t>& z) {
        z.assign(16, 0);
        vector<uint8_t> v = y;
        for (int i = 0; i < 128; ++i) {
            if (x[i / 8] & (1 << (7 - (i % 8)))) {
                for (int j = 0; j < 16; ++j) z[j] ^= v[j];
            }
            bool lsb = v[15] & 1;
            for (int j = 15; j > 0; --j) v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xE1; // Polynomial x^128 + x^7 + x^2 + x + 1
        }
    }

    vector<uint8_t> ghash(const vector<uint8_t>& h, const vector<uint8_t>& aad, const vector<uint8_t>& ct) {
        vector<uint8_t> s = aad;
        while (s.size() % 16 != 0) s.push_back(0);
        s.insert(s.end(), ct.begin(), ct.end());
        while (s.size() % 16 != 0) s.push_back(0);
        
        uint64_t aad_b = aad.size() * 8, ct_b = ct.size() * 8;
        for(int i=7; i>=0; --i) s.push_back((aad_b >> (i*8)) & 0xFF);
        for(int i=7; i>=0; --i) s.push_back((ct_b >> (i*8)) & 0xFF);

        vector<uint8_t> y(16, 0);
        for (size_t i = 0; i < s.size(); i += 16) {
            for (int j = 0; j < 16; ++j) y[j] ^= s[i + j];
            vector<uint8_t> temp = y;
            gf_mult(temp, h, y);
        }
        return y;
    }

    void inc32(vector<uint8_t>& cb) {
        for (int i = 15; i >= 12; --i) { if (++cb[i] != 0) break; }
    }

    vector<uint8_t> gcm_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& aad, const vector<uint8_t>& nonce) {
        vector<uint8_t> h = aes.encrypt_block(vector<uint8_t>(16, 0));
        vector<uint8_t> j0 = nonce; // Assume standard 12-byte nonce
        j0.insert(j0.end(), {0, 0, 0, 1});
        
        vector<uint8_t> ct, cb = j0;
        inc32(cb);
        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> st = aes.encrypt_block(cb);
            size_t len = min((size_t)16, pt.size() - i);
            for (size_t j = 0; j < len; ++j) ct.push_back(pt[i + j] ^ st[j]);
            inc32(cb);
        }
        
        vector<uint8_t> tag = ghash(h, aad, ct);
        vector<uint8_t> s0 = aes.encrypt_block(j0);
        for (int i = 0; i < 16; ++i) tag[i] ^= s0[i];
        ct.insert(ct.end(), tag.begin(), tag.end());
        return ct;
    }

    vector<uint8_t> gcm_decrypt(AES& aes, const vector<uint8_t>& ct_tag, const vector<uint8_t>& aad, const vector<uint8_t>& nonce) {
        vector<uint8_t> ct(ct_tag.begin(), ct_tag.end() - 16);
        vector<uint8_t> h = aes.encrypt_block(vector<uint8_t>(16, 0));
        vector<uint8_t> j0 = nonce; 
        j0.insert(j0.end(), {0, 0, 0, 1});
        
        vector<uint8_t> exp_tag = ghash(h, aad, ct);
        vector<uint8_t> s0 = aes.encrypt_block(j0);
        for (int i = 0; i < 16; ++i) {
            if ((exp_tag[i] ^ s0[i]) != ct_tag[ct.size() + i]) throw runtime_error("GCM Auth failed");
        }
        
        vector<uint8_t> pt, cb = j0;
        inc32(cb);
        for (size_t i = 0; i < ct.size(); i += 16) {
            vector<uint8_t> st = aes.encrypt_block(cb);
            size_t len = min((size_t)16, ct.size() - i);
            for (size_t j = 0; j < len; ++j) pt.push_back(ct[i + j] ^ st[j]);
            inc32(cb);
        }
        return pt;
    }
}