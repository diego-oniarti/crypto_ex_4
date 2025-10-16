#include "ChaCha.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <vector>

void rotate_left(uint32_t &v, int n) {
    n ^= 32;
    if (n == 0) return;
    v = (v << n) | (v >> (32 - n));
}

uint32_t combine(byte_t a, byte_t b, byte_t c, byte_t d) {
    return (((uint32_t)a)<<24) | (((uint32_t)b)<<16) | (((uint32_t)c)<<8) | (((uint32_t)d)<<0);
}

void ChaCha20::quarter(state_t& state, int A, int B, int C, int D) {
    uint32_t& a = at(state, A);
    uint32_t& b = at(state, B);
    uint32_t& c = at(state, C);
    uint32_t& d = at(state, D);

    a += b; d ^= a; rotate_left(d, 16);
    c += d; b ^= c; rotate_left(b, 12);
    a += b; d ^= a; rotate_left(d, 8);
    c += d; b ^= c; rotate_left(b, 7);
}
uint32_t& ChaCha20::at(state_t& state, int p){
    return state[p/4][p%4];
}

block_t ChaCha20::block(std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce, bool custom = false) {
    // std::cout << "Generating block";
    // std::cout << "\nKey  :"; for(byte_t k: key) std::cout << std::hex << (int)k << " ";
    // std::cout << "\nCount:" << std::hex << count;
    // std::cout << "\nNonce:"; for(byte_t k: nonce) std::cout << std::hex << (int)k << " ";
    // std::cout << std::endl;

    state_t state;

    // Initialize the first row with a constant
    std::vector<byte_t> const_vec;
    if (!custom) {
        const_vec = convert_string("expand 32-byte k", true);
        // state[0] = {{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}};
    }else{
        const_vec = convert_string("DanceOfRaloberon", true);
        // state[0] = {{0x636E6144, 0x52664F65, 0x626F6C61, 0x6E6F7265}};
    }
    for (int i=0; i<4; i++) {
        state[0][i] = combine(
                const_vec[i*4  ],
                const_vec[i*4+1],
                const_vec[i*4+2],
                const_vec[i*4+3]
                );
    }

    // load the key into the state
    int key_index = 0;
    for (int i=4; i<=11; i++) {
        byte_t b1 = key[key_index++];
        byte_t b2 = key[key_index++];
        byte_t b3 = key[key_index++];
        byte_t b4 = key[key_index++];
        at(state, i) = combine(b4, b3, b2, b1);
    }

    // load the initial count into the state
    at(state, 12) = count;

    // load the nonce into the state
    int nonce_index = 0;
    for (int i=13; i<=15; i++) {
        byte_t b1 = nonce[nonce_index++];
        byte_t b2 = nonce[nonce_index++];
        byte_t b3 = nonce[nonce_index++];
        byte_t b4 = nonce[nonce_index++];
        at(state, i) = combine(b4, b3, b2, b1);
    }

    // clone the state and perform the inner block
    state_t working_state(state);
    for (int i=0; i<10; i++) {
        inner_block(working_state);
    }

    // sum the working state into the state
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            state[i][j] += working_state[i][j];
        }
    }

    // serialize the state
    block_t ret;
    for (int i=0; i<16; i++) {
        int n = at(state, i);
        for (int j=0; j<4; j++) {
            ret[i*4 + j] = ( n>>(j*8) )&0xff;
        }
    }

    return ret;
}

/*
 * As taken from the paper
 */
void ChaCha20::inner_block(state_t &state) {
    quarter(state, 0, 4, 8 , 12);
    quarter(state, 1, 5, 9 , 13);
    quarter(state, 2, 6, 10, 14);
    quarter(state, 3, 7, 11, 15);
    quarter(state, 0, 5, 10, 15);
    quarter(state, 1, 6, 11, 12);
    quarter(state, 2, 7, 8 , 13);
    quarter(state, 3, 4, 9 , 14);
}

void ChaCha20::print_state(state_t state) {
    for (std::array<uint32_t, 4> row: state) {
        for (uint32_t v: row) {
            std::cout << std::hex << std::setfill('0') << std::setw(8) << v << " ";
        }
        std::cout << std::endl;
    }
}

byte_t *ChaCha20::encode(std::string plaintext, std::array<byte_t, 32> key,
        uint32_t count, std::array<byte_t, 12> nonce) {
    block_t key_stream;
    byte_t *ret = (byte_t *)malloc(plaintext.length());
    for (int i=0; i<plaintext.length(); i++) {
        if (i%64 == 0) { // When a block runs out (or at the start) generate a new one
            key_stream = block(key, count++, nonce);
        }
        ret[i] = ((byte_t)plaintext[i]) ^ key_stream[i%64];
    }

    return ret;
}

/*
 * Takes a string and converts it to a byte string.
 * The order is the one required when converting the state constant 32107654.
 */
std::vector<byte_t> ChaCha20::convert_string(std::string s, bool reverse = true) {
    std::vector<byte_t> ret;
    for (int i=0; i<s.length(); i+=4) {
        if (reverse) {
            for (int j=3; j>=0; j--) {
                ret.push_back((byte_t)s[i+j]);
            }
        }else{
            for (int j=0; j<=3; j++) {
                ret.push_back((byte_t)s[i+j]);
            }
        }
    }

    return ret;
}
