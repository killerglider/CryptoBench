// ASCON-128 implementation

#include "../../include/ascon.h"
#include <stdint.h>
#include <stddef.h>

#define ASCON128_IV         0x80400c0600000000ULL
#define ASCON128_KEY_LEN    16
#define ASCON128_NONCE_LEN  16
#define ASCON128_TAG_LEN    16
#define ASCON128_RATE       8

int ascon_128_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (key_len != ASCON128_KEY_LEN || nonce_len != ASCON128_NONCE_LEN || tag_len != ASCON128_TAG_LEN) {
        return -1;
    }
    return ascon_crypto_aead_encrypt(ciphertext, plaintext, plaintext_len, aad, aad_len, nonce, key, ASCON128_IV, 12, 6, ASCON128_RATE);
}

int ascon_128_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext) {
    if (key_len != ASCON128_KEY_LEN || nonce_len != ASCON128_NONCE_LEN || tag_len != ASCON128_TAG_LEN) {
        return -1;
    }
    return ascon_crypto_aead_decrypt(plaintext, ciphertext, ciphertext_len, aad, aad_len, nonce, key, ASCON128_IV, 12, 6, ASCON128_RATE);
}