#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

// AES Core primitive (Block Size: 16 bytes)
class AES {
public:
    static const int BLOCK_SIZE = 16;
    AES(const std::vector<uint8_t>& key, int key_length = 0);
    std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& block);
    std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& block);

private:
    std::vector<uint8_t> key;
    int key_length;
    std::vector<std::vector<uint8_t>> round_keys;
    
    void key_expansion();
    void sub_bytes(std::vector<std::vector<uint8_t>>& s);
    void shift_rows(std::vector<std::vector<uint8_t>>& s);
    void mix_columns(std::vector<std::vector<uint8_t>>& s);
    void add_round_key(std::vector<std::vector<uint8_t>>& s, int round);
    void inv_sub_bytes(std::vector<std::vector<uint8_t>>& s);
    void inv_shift_rows(std::vector<std::vector<uint8_t>>& s);
    void inv_mix_columns(std::vector<std::vector<uint8_t>>& s);
    
    std::vector<std::vector<uint8_t>> bytes_to_state(const std::vector<uint8_t>& b);
    std::vector<uint8_t> state_to_bytes(const std::vector<std::vector<uint8_t>>& s);
    int get_num_rounds() const;
    static uint8_t gmul(uint8_t a, uint8_t b);
};