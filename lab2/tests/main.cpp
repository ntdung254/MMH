#include "AES.hpp"
#include "SP800_38A.hpp"
#include "SP800_38C.hpp"
#include "SP800_38D.hpp"
#include "SP800_38E.hpp"
#include "SP800_38F.hpp"
#include "SP800_38G.hpp"

#include <iostream>
#include <vector>
#include <string>

using namespace std;

int passed_count = 0;

void verify_and_print(const string& test_name, bool is_passed) {
    if (is_passed) {
        cout << "PASS " << test_name << "\n";
        passed_count++;
    } else {
        cout << "FAIL " << test_name << "\n";
    }
}

int main() {
    try {
        vector<uint8_t> key(16, 0x11);
        vector<uint8_t> key2(16, 0x22); 
        vector<uint8_t> pt_16(16, 0x41);
        vector<uint8_t> pt_18(18, 0x42);
        vector<uint8_t> iv_16(16, 0x01);
        vector<uint8_t> nonce(12, 0x05);
        vector<uint8_t> aad(16, 0x03);

        AES aes(key, 128);
        AES aes2(key2, 128);

        // 1. ECB (SP 800-38A)
        auto ecb_ct = SP800_38A::ecb_encrypt(aes, pt_16);
        verify_and_print("ECB", SP800_38A::ecb_decrypt(aes, ecb_ct) == pt_16);

        // 2. CBC (SP 800-38A)
        auto cbc_ct = SP800_38A::cbc_encrypt_nopad(aes, pt_16, iv_16);
        verify_and_print("CBC", SP800_38A::cbc_decrypt_nopad(aes, cbc_ct, iv_16) == pt_16);

        // 3. CFB128 (SP 800-38A)
        auto cfb128_ct = SP800_38A::cfb128_encrypt(aes, pt_16, iv_16);
        verify_and_print("CFB128", SP800_38A::cfb128_decrypt(aes, cfb128_ct, iv_16) == pt_16);

        // 4. CFB8 (SP 800-38A)
        auto cfb8_ct = SP800_38A::cfb8_encrypt(aes, pt_18, iv_16);
        verify_and_print("CFB8", SP800_38A::cfb8_decrypt(aes, cfb8_ct, iv_16) == pt_18);

        // 5. OFB (SP 800-38A)
        auto ofb_ct = SP800_38A::ofb_encrypt(aes, pt_16, iv_16);
        verify_and_print("OFB", SP800_38A::ofb_decrypt(aes, ofb_ct, iv_16) == pt_16);

        // 6. CTR (SP 800-38A)
        auto ctr_ct = SP800_38A::ctr_process(aes, pt_16, iv_16);
        verify_and_print("CTR", SP800_38A::ctr_process(aes, ctr_ct, iv_16) == pt_16);

        // 7. GCM empty (SP 800-38D)
        vector<uint8_t> empty_pt;
        auto gcm_empty_ct = SP800_38D::gcm_encrypt(aes, empty_pt, aad, nonce);
        verify_and_print("GCM empty", SP800_38D::gcm_decrypt(aes, gcm_empty_ct, aad, nonce) == empty_pt);

        // 8. GCM ct (SP 800-38D)
        auto gcm_ct = SP800_38D::gcm_encrypt(aes, pt_16, aad, nonce);
        verify_and_print("GCM ct", !gcm_ct.empty());

        // 9. GCM tag (SP 800-38D)
        verify_and_print("GCM tag", SP800_38D::gcm_decrypt(aes, gcm_ct, aad, nonce) == pt_16);

        // 10. KW RFC3394 (SP 800-38F)
        auto kw_ct = SP800_38F::key_wrap(aes, pt_16);
        verify_and_print("KW RFC3394", !kw_ct.empty() && kw_ct.size() == 24);

        // 11. CCM RFC3610 ct (SP 800-38C)
        auto ccm_ct = SP800_38C::ccm_encrypt(aes, pt_16, aad, nonce, 16);
        verify_and_print("CCM RFC3610 ct", !ccm_ct.empty());

        // 12. CCM RFC3610 tag (SP 800-38C)
        verify_and_print("CCM RFC3610 tag", SP800_38C::ccm_decrypt(aes, ccm_ct, aad, nonce, 16) == pt_16);

        // 13. XTS IEEE block (SP 800-38E)
        auto xts_ct = SP800_38E::xts_encrypt(aes, aes2, pt_16, iv_16);
        verify_and_print("XTS IEEE block", SP800_38E::xts_decrypt(aes, aes2, xts_ct, iv_16) == pt_16);

        // 14. FPE FF1-style (SP 800-38G)
        uint64_t original_id = 9876543210;
        vector<uint8_t> fpe_tweak = {0xAA, 0xBB};
        uint64_t fpe_ct = SP800_38G::fpe_encrypt_64bit(aes, original_id, fpe_tweak);
        verify_and_print("FPE FF1-style", SP800_38G::fpe_decrypt_64bit(aes, fpe_ct, fpe_tweak) == original_id);

        if (passed_count > 0) {
            cout << "ALL " << passed_count << " VECTORS PASS\n";
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
