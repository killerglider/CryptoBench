/*
 * ascon_128a.c - Fixed version with proper memory handling
 */

#include "../include/ascon.h"
#include <string.h>
#include <stdint.h>

#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define RATE 16 /* Ascon-128a absorbs 128 bits per block */

int ascon_128a_encrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t *tag, size_t tag_len) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization */
    s.x[0] = 0x80800c0800000000ULL ^ (uint64_t) (key_len * 8);
    
    // Safe memory copy
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

    /* Associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Encrypt plaintext */
    size_t i = 0;
    while (i + RATE <= pt_len) {
        // Process two 64-bit words (16 bytes) at a time
        uint64_t m0, m1;
        memcpy(&m0, plaintext + i, 8);
        memcpy(&m1, plaintext + i + 8, 8);
        
        s.x[0] ^= m0;
        s.x[1] ^= m1;
        
        memcpy(ciphertext + i, &s.x[0], 8);
        memcpy(ciphertext + i + 8, &s.x[1], 8);
        
        ascon_permutation(&s);
        i += RATE;
    }
    
    /* final partial block */
    if (i < pt_len) {
        uint8_t block[RATE] = {0};
        size_t rem = pt_len - i;
        memcpy(block, plaintext + i, rem);
        block[rem] = 0x80;
        
        uint64_t m0, m1;
        memcpy(&m0, block, 8);
        memcpy(&m1, block + 8, 8);
        
        s.x[0] ^= m0;
        s.x[1] ^= m1;
        
        memcpy(ciphertext + i, &s.x[0], rem);
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

int ascon_128a_decrypt(const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *plaintext) {
    if (key_len != CRYPTO_KEYBYTES || nonce_len != CRYPTO_NPUBBYTES || tag_len != CRYPTO_ABYTES)
        return -1;

    ascon_state s = {0};

    /* Initialization */
    s.x[0] = 0x80800c0800000000ULL ^ (uint64_t) (key_len * 8);
    
    // Safe memory copy
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

    /* Associated data */
    if (ad_len > 0) {
        ascon_absorb(&s, ad, ad_len, RATE);
    }

    /* Domain separation */
    s.x[4] ^= 1ULL;

    /* Decrypt ciphertext */
    size_t i = 0;
    while (i + RATE <= ct_len) {
        uint64_t c0, c1;
        memcpy(&c0, ciphertext + i, 8);
        memcpy(&c1, ciphertext + i + 8, 8);
        
        uint64_t m0 = s.x[0] ^ c0;
        uint64_t m1 = s.x[1] ^ c1;
        
        memcpy(plaintext + i, &m0, 8);
        memcpy(plaintext + i + 8, &m1, 8);
        
        s.x[0] = c0;
        s.x[1] = c1;
        
        ascon_permutation(&s);
        i += RATE;
    }
    
    /* final partial block */
    if (i < ct_len) {
        uint8_t block[RATE] = {0};
        size_t rem = ct_len - i;
        memcpy(block, ciphertext + i, rem);
        
        uint64_t c0, c1;
        memcpy(&c0, block, 8);
        memcpy(&c1, block + 8, 8);
        
        uint64_t m0 = s.x[0] ^ c0;
        uint64_t m1 = s.x[1] ^ c1;
        
        memcpy(plaintext + i, &m0, rem);
        
        block[rem] = 0x80;
        
        // Mask out the bits we didn't use
        if (rem <= 8) {
            s.x[0] = c0 & ((1ULL << (rem * 8)) - 1);
            s.x[1] = 0;
        } else {
            s.x[0] = c0;
            s.x[1] = c1 & ((1ULL << ((rem - 8) * 8)) - 1);
        }
        
        memcpy(&c0, block, 8);
        memcpy(&c1, block + 8, 8);
        s.x[0] ^= c0;
        s.x[1] ^= c1;
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