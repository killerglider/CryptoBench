#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>

/*
 * Ascon core API (keeps the same parameterization used by the repo).
 *
 * The core AEAD functions in ascon_core.c expect a single buffer for ciphertext+tag.
 * The variant wrappers (ascon_128.c, ascon_128a.c, ascon_80pq.c) hide that detail:
 * they produce ciphertext and tag into separate buffers with no heap allocation.
 */

int ascon_crypto_aead_encrypt(
    uint8_t* c,
    const uint8_t* m, size_t mlen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k, size_t key_len,
    uint64_t iv, int num_rounds_a, int num_rounds_b, int rate);

int ascon_crypto_aead_decrypt(
    uint8_t* m,
    const uint8_t* c, size_t clen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k, size_t key_len,
    uint64_t iv, int num_rounds_a, int num_rounds_b, int rate);

/* Variant wrappers (signatures used across your repo) */
int ascon_128_encrypt(const uint8_t* key, size_t key_len,
                      const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* plaintext, size_t plaintext_len,
                      const uint8_t* aad, size_t aad_len,
                      uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

int ascon_128_decrypt(const uint8_t* key, size_t key_len,
                      const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* tag, size_t tag_len,
                      uint8_t* plaintext);

int ascon_128a_encrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

int ascon_128a_decrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* plaintext);

int ascon_80pq_encrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

int ascon_80pq_decrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* plaintext);

#endif // ASCON_H
