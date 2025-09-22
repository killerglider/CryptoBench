#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>
#include <stdalign.h>

/*
 * ASCON Level-3 header
 * Refactored for SIMD-accelerated permutation.
 *
 * Variants supported:
 *   - Ascon-128
 *   - Ascon-128a
 *   - Ascon-80pq
 *
 * Notes:
 *   - Context/state aligned to 32 bytes
 *   - No malloc inside encrypt/decrypt
 *   - Functions expect caller to allocate ciphertext buffer with +16 bytes for tag
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    alignas(32) uint64_t x[5]; /* 5x64-bit state */
} ascon_state;

/* Core permutation (12 rounds, unrolled, SIMD-optimised). */
void ascon_permutation(ascon_state *s);
void ascon_absorb(ascon_state *s, const uint8_t *data, size_t len, size_t rate);
void ascon_squeeze(const ascon_state *s, uint8_t *tag, size_t tag_len);

/* Common AEAD API signatures */
int ascon_128_encrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

int ascon_128_decrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *ciphertext, size_t ct_len,
                      const uint8_t *tag, size_t tag_len,
                      uint8_t *plaintext);

int ascon_128a_encrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

int ascon_128a_decrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *plaintext);

int ascon_80pq_encrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

int ascon_80pq_decrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif // ASCON_H
