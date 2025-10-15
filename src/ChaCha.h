#pragma once

#include <array>
#include <cstdint>
#include <string>

#define state_t std::array<std::array<uint32_t,4>,4>
#define byte_t uint8_t

namespace ChaCha20 {
    byte_t *encode(std::string plaintext, std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce);
    void inner_block(state_t&);
    std::array<byte_t, 64> block(std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce);
    void set_state(state_t s);
    void print_state(state_t);
    void quarter(state_t&, int, int, int, int);
    uint32_t& at(state_t&, int);
};
