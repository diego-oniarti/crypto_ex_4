#include "ChaCha.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>

int main (int argc, char *argv[]) {
    // Test against test vector
    std::string plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    byte_t *encoded = ChaCha20::encode(plain.c_str(),
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
            1,
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}
            );

    std::cout << "Plain            : " << plain << "\n";
    std::cout << "Encrypted        : ";
    for (int i=0; i<plain.length(); i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << ((int)encoded[i]) << " ";
    }
    std::cout << "\n";
    std::cout << "Expected encoding: 6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d\n";

    std::cout << std::endl;
    // Exercise

    // Retreive the keystream from the previous exercise by XORing plaintext and
    // cyphertext (and we pad it)
    std::string plaintext_str = "We shall attack all intruders";
    byte_t runes_str[] = {0xDD, 0xF6, 0x2A, 0xE5, 0x64, 0x1C, 0xFB, 0x52, 0xAB, 0x55, 0xDE, 0x95, 0x17, 0x1F, 0xA8, 0x6E, 0x90, 0x0C, 0xEA, 0x76, 0x39, 0xB1, 0x6A, 0xA5, 0xF0, 0xE5, 0x8E, 0x1C, 0xBB};
    std::array<byte_t, 32> key;
    for (int i=0; i<plaintext_str.length(); i++) {
        key[i] = ((byte_t)(plaintext_str[i]))^runes_str[i];
    }
    for (int i=plaintext_str.length(); i<key.size(); i++) {
        key[i] = 0;
    }
    std::cout << "Key     : ";
    for (byte_t v: key) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)v << " ";
    }
    std::cout << std::endl;

    // Convert the nonce
    std::string nonce_str = "FenceOrDance";
    std::array<byte_t, 12> nonce;
    std::vector<byte_t> nonce_vec = ChaCha20::convert_string(nonce_str, false);
    std::copy(nonce_vec.begin(), nonce_vec.end(), nonce.begin());
    std::cout << "Nonce   : ";
    for (byte_t v: nonce) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)v << " ";
    } std::cout << std::endl;

    block_t exercise = ChaCha20::block(
            key,
            0x0401,
            nonce,
            true
            );

    std::cout << "SOLUTION: ";
    for (int i=0; i<64; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)(exercise[i]) << " ";
    } std::cout << std::endl;

    free(encoded);
    return 0;
}
