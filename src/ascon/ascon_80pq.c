/*
 * ascon_80pq.c
 *
 * Full AEAD implementation using SIMD permutation from ascon_core.c.
 * Variant: Ascon-80pq (rate = 8 bytes, key = 20 bytes).
 */

#include "../include/ascon.h" 
#include <string.h>
#include <stdint.h>

#define CRYPTO_KEYBYTES 20
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define RATE 8 /* Ascon-80pq absorbs 64 bits per block */

int ascon_80pq_encrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t *tag, size_t tag_len) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization */
    s.x[0] = 0xa0400c0600000000ULL ^ (uint64_t) (key_len * 8);
    memcpy(&s.x[1], key, 8);
    memcpy(&s.x[2], key + 8, 8);
    memcpy(&s.x[3], key + 16, 4); /* 20 bytes total */
    memcpy(&s.x[3] + 4, nonce, 4); /* overlap padding */
    memcpy(&s.x[4], nonce + 4, 12);
    ascon_permutation(&s);

    /* absorb full key again */
    s.x[2] ^= ((uint64_t*) key)[0];
    s.x[3] ^= ((uint64_t*) (key + 8))[0];
    s.x[4] ^= ((uint64_t*) (key + 16))[0] & 0xFFFFFFFFULL;

    /* Associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Encrypt plaintext */
    size_t i = 0;
    while (i + RATE <= pt_len) {
        uint64_t m = ((uint64_t*) (plaintext + i))[0];
        s.x[0] ^= m;
        ((uint64_t*) (ciphertext + i))[0] = s.x[0];
        ascon_permutation(&s);
        i += RATE;
    }
    /* final partial block */
    uint8_t block[RATE] = {0};
    size_t rem = pt_len - i;
    memcpy(block, plaintext + i, rem);
    block[rem] = 0x80;
    uint64_t m = ((uint64_t*) block)[0];
    s.x[0] ^= m;
    ((uint64_t*) (ciphertext + i))[0] = s.x[0];

    /* Finalization */
    s.x[1] ^= ((uint64_t*) key)[0];
    s.x[2] ^= ((uint64_t*) (key + 8))[0];
    s.x[3] ^= ((uint64_t*) (key + 16))[0] & 0xFFFFFFFFULL;
    ascon_permutation(&s);

    /* Tag */
    ascon_squeeze(&s, tag, tag_len);
    return 0;
}

int ascon_80pq_decrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *plaintext) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization */
    s.x[0] = 0xa0400c0600000000ULL ^ (uint64_t) (key_len * 8);
    memcpy(&s.x[1], key, 8);
    memcpy(&s.x[2], key + 8, 8);
    memcpy(&s.x[3], key + 16, 4);
    memcpy(&s.x[3] + 4, nonce, 4);
    memcpy(&s.x[4], nonce + 4, 12);
    ascon_permutation(&s);

    /* absorb full key again */
    s.x[2] ^= ((uint64_t*) key)[0];
    s.x[3] ^= ((uint64_t*) (key + 8))[0];
    s.x[4] ^= ((uint64_t*) (key + 16))[0] & 0xFFFFFFFFULL;

    /* Associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Decrypt ciphertext */
    size_t i = 0;
    while (i + RATE <= ct_len) {
        uint64_t c = ((uint64_t*) (ciphertext + i))[0];
        uint64_t m = s.x[0] ^ c;
        ((uint64_t*) (plaintext + i))[0] = m;
        s.x[0] = c;
        ascon_permutation(&s);
        i += RATE;
    }
    /* final partial block */
    uint8_t block[RATE] = {0};
    size_t rem = ct_len - i;
    memcpy(block, ciphertext + i, rem);
    uint64_t c = ((uint64_t*) block)[0];
    uint64_t m = s.x[0] ^ c;
    memcpy(plaintext + i, &m, rem);
    block[rem] = 0x80;
    s.x[0] = c & ~(((uint64_t) 0xFF) << (rem * 8));
    s.x[0] ^= ((uint64_t*) block)[0];

    /* Finalization */
    s.x[1] ^= ((uint64_t*) key)[0];
    s.x[2] ^= ((uint64_t*) (key + 8))[0];
    s.x[3] ^= ((uint64_t*) (key + 16))[0] & 0xFFFFFFFFULL;
    ascon_permutation(&s);

    /* Tag check */
    uint8_t computed_tag[CRYPTO_ABYTES];
    ascon_squeeze(&s, computed_tag, CRYPTO_ABYTES);
    if (memcmp(computed_tag, tag, CRYPTO_ABYTES) != 0) {
        return -1; /* authentication failed */
    }
    return 0;
}
