#include "ChaCha.h"
#include <array>
#include <iomanip>
#include <iostream>

void rotate_left(uint32_t &v, int n) {
    n ^= 32;
    if (n == 0) return;
    v = (v << n) | (v >> (32 - n));
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

std::array<byte_t, 64> ChaCha20::block(std::array<byte_t, 32> key, uint32_t count, std::array<byte_t,12> nonce) {
    state_t state;

    state[0] = {{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}};

    int key_index = 0;
    for (int i=4; i<=11; i++) {
        uint32_t b1 = key[key_index++];
        uint32_t b2 = key[key_index++];
        uint32_t b3 = key[key_index++];
        uint32_t b4 = key[key_index++];
        at(state, i) = (b4<<24) | (b3<<16) | (b2<<8) | b1;
    }

    at(state, 12) = count;

    int nonce_index = 0;
    for (int i=13; i<=15; i++) {
        uint32_t b1 = nonce[nonce_index++];
        uint32_t b2 = nonce[nonce_index++];
        uint32_t b3 = nonce[nonce_index++];
        uint32_t b4 = nonce[nonce_index++];
        at(state, i) = (b4<<24) | (b3<<16) | (b2<<8) | b1;
    }

    state_t working_state(state);
    for (int i=0; i<10; i++) {
        inner_block(working_state);
    }

    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            state[i][j] += working_state[i][j];
        }
    }

    std::array<byte_t, 64> ret;
    for (int i=0; i<16; i++) {
        int n = at(state, i);
        for (int j=0; j<4; j++) {
            ret[i*4 + j] = (n&(0xff<<(8*j)))>>(8*j);
        }
    }

    return ret;
}



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
