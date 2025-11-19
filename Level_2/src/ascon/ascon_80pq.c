/*
 * ASCON-80pq wrapper (no heap allocation)
 *
 * ASCON-80pq uses a 20-byte key; this wrapper uses the same no-malloc technique as above.
 */

#include "../include/ascon.h"
#include <string.h>
#include <stdint.h>

#define ASCON80pq_IV        0xa0400c0600000000ULL
#define ASCON80pq_KEY_LEN   20
#define ASCON80pq_NONCE_LEN 16
#define ASCON80pq_TAG_LEN   16
#define ASCON80pq_RATE      8

int ascon_80pq_encrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (key_len != ASCON80pq_KEY_LEN || nonce_len != ASCON80pq_NONCE_LEN || tag_len != ASCON80pq_TAG_LEN) return -1;

    int result = ascon_crypto_aead_encrypt(ciphertext, plaintext, plaintext_len, aad, aad_len, nonce, key, ASCON80pq_KEY_LEN, ASCON80pq_IV, 12, 6, ASCON80pq_RATE);
    if (result != 0) return result;

    memcpy(tag, ciphertext + plaintext_len, tag_len);
    /* memset(ciphertext + plaintext_len, 0, tag_len); */

    return 0;
}

int ascon_80pq_decrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* plaintext) {
    if (key_len != ASCON80pq_KEY_LEN || nonce_len != ASCON80pq_NONCE_LEN || tag_len != ASCON80pq_TAG_LEN) return -1;

    uint8_t* mutable_c = (uint8_t*)ciphertext;
    memcpy(mutable_c + ciphertext_len, tag, tag_len);

    int result = ascon_crypto_aead_decrypt(plaintext, mutable_c, ciphertext_len + tag_len, aad, aad_len, nonce, key, ASCON80pq_KEY_LEN, ASCON80pq_IV, 12, 6, ASCON80pq_RATE);

    /* memset(mutable_c + ciphertext_len, 0, tag_len); */

    return result;
}
