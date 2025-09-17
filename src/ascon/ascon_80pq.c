#include "../include/ascon.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define ASCON80pq_IV        0xa0400c0600000000ULL 
#define ASCON80pq_KEY_LEN   20
#define ASCON80pq_NONCE_LEN 16
#define ASCON80pq_TAG_LEN   16
#define ASCON80pq_RATE      8

int ascon_80pq_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (key_len != ASCON80pq_KEY_LEN || nonce_len != ASCON80pq_NONCE_LEN || tag_len != ASCON80pq_TAG_LEN) return -1;

    uint8_t* temp_c = malloc(plaintext_len + tag_len);
    if (!temp_c) return -1;

    int result = ascon_crypto_aead_encrypt(temp_c, plaintext, plaintext_len, aad, aad_len, nonce, key, ASCON80pq_KEY_LEN, ASCON80pq_IV, 12, 6, ASCON80pq_RATE);
    
    memcpy(ciphertext, temp_c, plaintext_len);
    memcpy(tag, temp_c + plaintext_len, tag_len);
    
    free(temp_c);
    return result;
}

int ascon_80pq_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext) {
    if (key_len != ASCON80pq_KEY_LEN || nonce_len != ASCON80pq_NONCE_LEN || tag_len != ASCON80pq_TAG_LEN) return -1;

    uint8_t* combined = malloc(ciphertext_len + tag_len);
    if (!combined) return -1;

    memcpy(combined, ciphertext, ciphertext_len);
    memcpy(combined + ciphertext_len, tag, tag_len);

    int result = ascon_crypto_aead_decrypt(plaintext, combined, ciphertext_len + tag_len, aad, aad_len, nonce, key, ASCON80pq_KEY_LEN, ASCON80pq_IV, 12, 6, ASCON80pq_RATE);
    
    free(combined);
    return result;
}