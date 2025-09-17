// ASCON-80pq implementation

#include "../../include/ascon.h"
#include <stdint.h>
#include <stddef.h>

#define ASCON80PQ_IV        0xa0400c06ULL // IV for 80pq
#define ASCON80PQ_KEY_LEN   20
#define ASCON80PQ_NONCE_LEN 16
#define ASCON80PQ_TAG_LEN   16
#define ASCON80PQ_RATE      8

int ascon_80pq_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (key_len != ASCON80PQ_KEY_LEN || nonce_len != ASCON80PQ_NONCE_LEN || tag_len != ASCON80PQ_TAG_LEN) {
        return -1;
    }
    // Pass the correct key length (20) to the core function
    return ascon_crypto_aead_encrypt(ciphertext, plaintext, plaintext_len, aad, aad_len, nonce, key, ASCON80PQ_KEY_LEN, ASCON80PQ_IV, 12, 6, ASCON80PQ_RATE);
}

int ascon_80pq_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext) {
    if (key_len != ASCON80PQ_KEY_LEN || nonce_len != ASCON80PQ_NONCE_LEN || tag_len != ASCON80PQ_TAG_LEN) {
        return -1;
    }
    // Pass the correct key length (20) to the core function
    return ascon_crypto_aead_decrypt(plaintext, ciphertext, ciphertext_len, aad, aad_len, nonce, key, ASCON80PQ_KEY_LEN, ASCON80PQ_IV, 12, 6, ASCON80PQ_RATE);
}