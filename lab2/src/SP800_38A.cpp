#include "SP800_38A.hpp"
#include <algorithm>

using namespace std;

namespace SP800_38A {
    // --- Padding ---
    vector<uint8_t> pkcs7_pad(const vector<uint8_t>& data) {
        size_t pad_len = 16 - (data.size() % 16);
        vector<uint8_t> out = data;
        out.insert(out.end(), pad_len, (uint8_t)pad_len);
        return out;
    }
    vector<uint8_t> pkcs7_unpad(const vector<uint8_t>& data) {
        if (data.empty() || data.size() % 16 != 0) throw invalid_argument("Bad padded length.");
        uint8_t pad_len = data.back();
        if (pad_len == 0 || pad_len > 16) throw invalid_argument("Bad padding value.");
        return vector<uint8_t>(data.begin(), data.end() - pad_len);
    }

    // --- ECB ---
    vector<uint8_t> ecb_encrypt(AES& aes, const vector<uint8_t>& pt) {
        vector<uint8_t> ct;
        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> block(pt.begin() + i, pt.begin() + i + 16);
            vector<uint8_t> enc = aes.encrypt_block(block);
            ct.insert(ct.end(), enc.begin(), enc.end());
        }
        return ct;
    }
    vector<uint8_t> ecb_decrypt(AES& aes, const vector<uint8_t>& ct) {
        vector<uint8_t> pt;
        for (size_t i = 0; i < ct.size(); i += 16) {
            vector<uint8_t> block(ct.begin() + i, ct.begin() + i + 16);
            vector<uint8_t> dec = aes.decrypt_block(block);
            pt.insert(pt.end(), dec.begin(), dec.end());
        }
        return pt;
    }

    // --- CBC ---
    vector<uint8_t> cbc_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& iv) {
        return cbc_encrypt_nopad(aes, pkcs7_pad(pt), iv);
    }
    vector<uint8_t> cbc_decrypt(AES& aes, const vector<uint8_t>& ct, const vector<uint8_t>& iv) {
        return pkcs7_unpad(cbc_decrypt_nopad(aes, ct, iv));
    }
    vector<uint8_t> cbc_encrypt_nopad(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& iv) {
        vector<uint8_t> out, prev = iv;
        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> block(pt.begin() + i, pt.begin() + i + 16);
            for (int j = 0; j < 16; ++j) block[j] ^= prev[j];
            prev = aes.encrypt_block(block);
            out.insert(out.end(), prev.begin(), prev.end());
        }
        return out;
    }
    vector<uint8_t> cbc_decrypt_nopad(AES& aes, const vector<uint8_t>& ct, const vector<uint8_t>& iv) {
        vector<uint8_t> pt, prev = iv;
        for (size_t i = 0; i < ct.size(); i += 16) {
            vector<uint8_t> block(ct.begin() + i, ct.begin() + i + 16);
            vector<uint8_t> dec = aes.decrypt_block(block);
            for (int j = 0; j < 16; ++j) dec[j] ^= prev[j];
            prev = block;
            pt.insert(pt.end(), dec.begin(), dec.end());
        }
        return pt;
    }

    // --- CFB128 ---
    vector<uint8_t> cfb128_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& iv) {
        vector<uint8_t> ct, prev = iv;
        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> stream = aes.encrypt_block(prev);
            vector<uint8_t> block(pt.begin() + i, pt.begin() + i + 16);
            for (int j = 0; j < 16; ++j) block[j] ^= stream[j];
            ct.insert(ct.end(), block.begin(), block.end());
            prev = block;
        }
        return ct;
    }
    vector<uint8_t> cfb128_decrypt(AES& aes, const vector<uint8_t>& ct, const vector<uint8_t>& iv) {
        vector<uint8_t> pt, prev = iv;
        for (size_t i = 0; i < ct.size(); i += 16) {
            vector<uint8_t> stream = aes.encrypt_block(prev);
            vector<uint8_t> block(ct.begin() + i, ct.begin() + i + 16);
            for (int j = 0; j < 16; ++j) pt.push_back(block[j] ^ stream[j]);
            prev = block;
        }
        return pt;
    }

    // --- CFB8 ---
    vector<uint8_t> cfb8_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& iv) {
        vector<uint8_t> ct;
        vector<uint8_t> I = iv;
        for (uint8_t p : pt) {
            vector<uint8_t> O = aes.encrypt_block(I);
            uint8_t c = p ^ O[0];
            ct.push_back(c);
            I.erase(I.begin());
            I.push_back(c);
        }
        return ct;
    }
    vector<uint8_t> cfb8_decrypt(AES& aes, const vector<uint8_t>& ct, const vector<uint8_t>& iv) {
        vector<uint8_t> pt;
        vector<uint8_t> I = iv;
        for (uint8_t c : ct) {
            vector<uint8_t> O = aes.encrypt_block(I);
            pt.push_back(c ^ O[0]);
            I.erase(I.begin());
            I.push_back(c);
        }
        return pt;
    }

    // --- OFB ---
    vector<uint8_t> ofb_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& iv) {
        vector<uint8_t> ct, prev = iv;
        for (size_t i = 0; i < pt.size(); i += 16) {
            prev = aes.encrypt_block(prev);
            vector<uint8_t> block(pt.begin() + i, pt.begin() + i + 16);
            for (int j = 0; j < 16; ++j) block[j] ^= prev[j];
            ct.insert(ct.end(), block.begin(), block.end());
        }
        return ct;
    }
    vector<uint8_t> ofb_decrypt(AES& aes, const vector<uint8_t>& ct, const vector<uint8_t>& iv) {
        return ofb_encrypt(aes, ct, iv); // OFB decrypt == OFB encrypt
    }

    // --- CTR ---
    vector<uint8_t> ctr_process(AES& aes, const vector<uint8_t>& data, const vector<uint8_t>& nonce) {
        vector<uint8_t> cb = nonce, out;
        for (size_t i = 0; i < data.size(); i += 16) {
            vector<uint8_t> stream = aes.encrypt_block(cb);
            size_t len = min((size_t)16, data.size() - i);
            for (size_t j = 0; j < len; ++j) out.push_back(data[i + j] ^ stream[j]);
            for (int j = 15; j >= 0; --j) { if (++cb[j] != 0) break; }
        }
        return out;
    }
}