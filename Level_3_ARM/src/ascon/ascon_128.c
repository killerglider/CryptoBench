/*
 * ascon_128.c - Fixed version with proper bounds checking
 */

#include "../include/ascon.h"
#include <string.h>
#include <stdint.h>

#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define RATE 8 /* Ascon-128 absorbs 64 bits per block */

int ascon_128_encrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *ciphertext, uint8_t *tag, size_t tag_len) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization: IV || Key || Nonce */
    s.x[0] = 0x80400c0600000000ULL ^ (uint64_t) (key_len * 8);
    
    // Safe memory copy with proper alignment
    uint64_t key_part1, key_part2;
    memcpy(&key_part1, key, 8);
    memcpy(&key_part2, key + 8, 8);
    s.x[1] = key_part1;
    s.x[2] = key_part2;
    
    uint64_t nonce_part1, nonce_part2;
    memcpy(&nonce_part1, nonce, 8);
    memcpy(&nonce_part2, nonce + 8, 8);
    s.x[3] = nonce_part1;
    s.x[4] = nonce_part2;
    
    ascon_permutation(&s);

    /* absorb full key again */
    s.x[3] ^= key_part1;
    s.x[4] ^= key_part2;

    /* Process associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Encrypt plaintext */
    size_t i = 0;
    while (i + RATE <= pt_len) {
        uint64_t m;
        memcpy(&m, plaintext + i, 8);  // Safe copy
        s.x[0] ^= m;
        memcpy(ciphertext + i, &s.x[0], 8);  // Safe copy
        ascon_permutation(&s);
        i += RATE;
    }
    
    /* final partial block */
    if (i < pt_len) {
        uint8_t block[RATE] = {0};
        size_t rem = pt_len - i;
        memcpy(block, plaintext + i, rem);
        block[rem] = 0x80;
        uint64_t m;
        memcpy(&m, block, 8);
        s.x[0] ^= m;
        memcpy(ciphertext + i, &s.x[0], rem);  // Only copy remaining bytes
    }

    /* Finalization */
    s.x[1] ^= key_part1;
    s.x[2] ^= key_part2;
    ascon_permutation(&s);
    s.x[3] ^= key_part1;
    s.x[4] ^= key_part2;

    /* Tag */
    ascon_squeeze(&s, tag, tag_len);

    return 0;
}

int ascon_128_decrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *ciphertext, size_t ct_len,
                      const uint8_t *tag, size_t tag_len,
                      uint8_t *plaintext) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization: IV || Key || Nonce */
    s.x[0] = 0x80400c0600000000ULL ^ (uint64_t) (key_len * 8);
    
    // Safe memory copy with proper alignment
    uint64_t key_part1, key_part2;
    memcpy(&key_part1, key, 8);
    memcpy(&key_part2, key + 8, 8);
    s.x[1] = key_part1;
    s.x[2] = key_part2;
    
    uint64_t nonce_part1, nonce_part2;
    memcpy(&nonce_part1, nonce, 8);
    memcpy(&nonce_part2, nonce + 8, 8);
    s.x[3] = nonce_part1;
    s.x[4] = nonce_part2;
    
    ascon_permutation(&s);

    /* absorb full key again */
    s.x[3] ^= key_part1;
    s.x[4] ^= key_part2;

    /* Process associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Decrypt ciphertext */
    size_t i = 0;
    while (i + RATE <= ct_len) {
        uint64_t c;
        memcpy(&c, ciphertext + i, 8);  // Safe copy
        uint64_t m = s.x[0] ^ c;
        memcpy(plaintext + i, &m, 8);   // Safe copy
        s.x[0] = c;
        ascon_permutation(&s);
        i += RATE;
    }
    
    /* final partial block */
    if (i < ct_len) {
        uint8_t block[RATE] = {0};
        size_t rem = ct_len - i;
        memcpy(block, ciphertext + i, rem);
        uint64_t c;
        memcpy(&c, block, 8);
        uint64_t m = s.x[0] ^ c;
        memcpy(plaintext + i, &m, rem);  // Only copy remaining bytes
        block[rem] = 0x80;
        s.x[0] = c & (~0ULL >> (8 * (8 - rem)));  // Clear upper bits properly
        uint64_t block_val;
        memcpy(&block_val, block, 8);
        s.x[0] ^= block_val;
    }

    /* Finalization */
    s.x[1] ^= key_part1;
    s.x[2] ^= key_part2;
    ascon_permutation(&s);
    s.x[3] ^= key_part1;
    s.x[4] ^= key_part2;

    /* Tag check */
    uint8_t computed_tag[CRYPTO_ABYTES];
    ascon_squeeze(&s, computed_tag, CRYPTO_ABYTES);
    if (memcmp(computed_tag, tag, CRYPTO_ABYTES) != 0) {
        return -1; /* authentication failed */
    }

    return 0;
}