#include "SP800_38F.hpp"

using namespace std;

namespace SP800_38F {
    // RFC 3394 Key Wrap
    vector<uint8_t> key_wrap(AES& aes, const vector<uint8_t>& p) {
        if (p.size() < 16 || p.size() % 8 != 0) throw invalid_argument("Invalid KW length");
        int n = p.size() / 8;
        vector<uint8_t> a = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
        vector<vector<uint8_t>> r(n, vector<uint8_t>(8));
        for(int i=0; i<n; ++i) for(int j=0; j<8; ++j) r[i][j] = p[i*8 + j];

        for (int j = 0; j <= 5; ++j) {
            for (int i = 0; i < n; ++i) {
                vector<uint8_t> block = a;
                block.insert(block.end(), r[i].begin(), r[i].end());
                block = aes.encrypt_block(block);
                a.assign(block.begin(), block.begin() + 8);
                r[i].assign(block.begin() + 8, block.end());
                
                uint64_t t = n * j + (i + 1);
                for(int k=7; k>=0; --k) { a[k] ^= (t & 0xFF); t >>= 8; }
            }
        }
        vector<uint8_t> out = a;
        for(int i=0; i<n; ++i) out.insert(out.end(), r[i].begin(), r[i].end());
        return out;
    }
}