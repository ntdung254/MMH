#include "SP800_38C.hpp"
#include <algorithm>

using namespace std;

namespace SP800_38C {
    vector<uint8_t> build_ctr(const vector<uint8_t>& nonce, uint64_t ctr) {
        int q = 15 - nonce.size();
        vector<uint8_t> b = {(uint8_t)(q - 1)};
        b.insert(b.end(), nonce.begin(), nonce.end());
        for (int i = q - 1; i >= 0; --i) b.push_back((ctr >> (i * 8)) & 0xFF);
        return b;
    }

    vector<uint8_t> cbc_mac(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& aad, const vector<uint8_t>& nonce, int t_len) {
        int q = 15 - nonce.size();
        uint8_t flags = (aad.empty() ? 0 : 0x40) | (((t_len - 2) / 2) << 3) | (q - 1);
        vector<uint8_t> b0 = {flags};
        b0.insert(b0.end(), nonce.begin(), nonce.end());
        for (int i = q - 1; i >= 0; --i) b0.push_back((pt.size() >> (i * 8)) & 0xFF);

        vector<uint8_t> stream = b0;
        if (!aad.empty()) {
            if (aad.size() < 0xFF00) { stream.push_back(aad.size() >> 8); stream.push_back(aad.size() & 0xFF); }
            stream.insert(stream.end(), aad.begin(), aad.end());
            while (stream.size() % 16 != 0) stream.push_back(0);
        }
        stream.insert(stream.end(), pt.begin(), pt.end());
        while (stream.size() % 16 != 0) stream.push_back(0);

        vector<uint8_t> x(16, 0);
        for (size_t i = 0; i < stream.size(); i += 16) {
            for (int j = 0; j < 16; ++j) x[j] ^= stream[i + j];
            x = aes.encrypt_block(x);
        }
        return vector<uint8_t>(x.begin(), x.begin() + t_len);
    }

    vector<uint8_t> ccm_encrypt(AES& aes, const vector<uint8_t>& pt, const vector<uint8_t>& aad, const vector<uint8_t>& nonce, int t_len) {
        vector<uint8_t> tag = cbc_mac(aes, pt, aad, nonce, t_len);
        vector<uint8_t> s0 = aes.encrypt_block(build_ctr(nonce, 0)), ct;
        uint64_t ctr = 1;
        for (size_t i = 0; i < pt.size(); i += 16) {
            vector<uint8_t> st = aes.encrypt_block(build_ctr(nonce, ctr++));
            size_t len = min((size_t)16, pt.size() - i);
            for (size_t j = 0; j < len; ++j) ct.push_back(pt[i + j] ^ st[j]);
        }
        for (int i = 0; i < t_len; ++i) ct.push_back(tag[i] ^ s0[i]);
        return ct;
    }

    vector<uint8_t> ccm_decrypt(AES& aes, const vector<uint8_t>& ct_tag, const vector<uint8_t>& aad, const vector<uint8_t>& nonce, int t_len) {
        size_t pt_len = ct_tag.size() - t_len;
        vector<uint8_t> pt;
        uint64_t ctr = 1;
        for (size_t i = 0; i < pt_len; i += 16) {
            vector<uint8_t> st = aes.encrypt_block(build_ctr(nonce, ctr++));
            size_t len = min((size_t)16, pt_len - i);
            for (size_t j = 0; j < len; ++j) pt.push_back(ct_tag[i + j] ^ st[j]);
        }
        vector<uint8_t> exp_tag = cbc_mac(aes, pt, aad, nonce, t_len);
        vector<uint8_t> s0 = aes.encrypt_block(build_ctr(nonce, 0));
        for (int i = 0; i < t_len; ++i) exp_tag[i] ^= s0[i];
        
        for (int i = 0; i < t_len; ++i) {
            if (ct_tag[pt_len + i] != exp_tag[i]) throw runtime_error("CCM Auth failed");
        }
        return pt;
    }
}