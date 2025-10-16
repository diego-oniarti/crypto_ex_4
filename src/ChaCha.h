#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

typedef std::array<std::array<uint32_t,4>,4> state_t ;
typedef uint8_t byte_t;
typedef std::array<byte_t, 64> block_t;

namespace ChaCha20 {
    byte_t *encode(std::string plaintext, std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce);
    void inner_block(state_t&);
    std::array<byte_t, 64> block(std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce, bool);
    void set_state(state_t s);
    void print_state(state_t);
    void quarter(state_t&, int, int, int, int);
    uint32_t& at(state_t&, int);

    std::vector<byte_t> convert_string(std::string);
};
