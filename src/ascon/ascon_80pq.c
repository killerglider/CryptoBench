/*
 * ascon_80pq.c - Corrected ASCON-80pq implementation
 * 
 * ASCON-80pq specification:
 * - 160-bit (20 byte) key
 * - 128-bit (16 byte) nonce  
 * - 64-bit rate (8 bytes per block)
 * - IV = 0xa0400c0600000000 || k (first 32 bits of key)
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

    /* Initialization according to ASCON-80pq specification:
     * S = IV || K || N where:
     * - IV = 0xa0400c0600000000 || K[0..31] (first 32 bits of key)  
     * - K = 160-bit key
     * - N = 128-bit nonce
     */
    
    // Extract key parts safely
    uint32_t k0;  // First 32 bits of key
    uint64_t k1, k2; // Remaining 128 bits of key
    uint64_t n0, n1; // 128-bit nonce as two 64-bit values
    
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 8);
    memcpy(&k2, key + 12, 8);
    memcpy(&n0, nonce, 8);
    memcpy(&n1, nonce + 8, 8);
    
    // Initialize state: IV || K[0..31] || K[32..95] || K[96..159] || N[0..63] || N[64..127]
    s.x[0] = 0xa0400c0600000000ULL | ((uint64_t)k0 << 32) | (k0 >> 32); // IV || first 32 bits of K
    s.x[1] = k1;  // K[32..95]
    s.x[2] = k2;  // K[96..159] 
    s.x[3] = n0;  // N[0..63]
    s.x[4] = n1;  // N[64..127]
    
    ascon_permutation(&s);

    /* Key absorption: XOR key into state positions 1,2,3 */
    s.x[1] ^= k1;
    s.x[2] ^= k2;  
    s.x[3] ^= ((uint64_t)k0 << 32);  // Remaining key bits

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
        memcpy(&m, plaintext + i, 8);
        s.x[0] ^= m;
        memcpy(ciphertext + i, &s.x[0], 8);
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
        memcpy(ciphertext + i, &s.x[0], rem);
    }

    /* Finalization: XOR key into positions 1,2,3 again */
    s.x[1] ^= k1;
    s.x[2] ^= k2;
    s.x[3] ^= ((uint64_t)k0 << 32);
    ascon_permutation(&s);

    /* Extract authentication tag */
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

    /* Initialization - identical to encrypt */
    uint32_t k0;
    uint64_t k1, k2;
    uint64_t n0, n1;
    
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 8);
    memcpy(&k2, key + 12, 8);
    memcpy(&n0, nonce, 8);
    memcpy(&n1, nonce + 8, 8);
    
    s.x[0] = 0xa0400c0600000000ULL | ((uint64_t)k0 << 32) | (k0 >> 32);
    s.x[1] = k1;
    s.x[2] = k2;
    s.x[3] = n0;
    s.x[4] = n1;
    
    ascon_permutation(&s);

    /* Key absorption */
    s.x[1] ^= k1;
    s.x[2] ^= k2;
    s.x[3] ^= ((uint64_t)k0 << 32);

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
        memcpy(&c, ciphertext + i, 8);
        uint64_t m = s.x[0] ^ c;
        memcpy(plaintext + i, &m, 8);
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
        memcpy(plaintext + i, &m, rem);
        
        // Reconstruct the padded block for state update
        block[rem] = 0x80;
        memset(block + rem + 1, 0, RATE - rem - 1);
        
        // Update state: clear unused bits and XOR with padded block
        s.x[0] = c & ((1ULL << (rem * 8)) - 1);
        uint64_t block_val;
        memcpy(&block_val, block, 8);
        s.x[0] ^= block_val;
    }

    /* Finalization */
    s.x[1] ^= k1;
    s.x[2] ^= k2;
    s.x[3] ^= ((uint64_t)k0 << 32);
    ascon_permutation(&s);

    /* Tag verification */
    uint8_t computed_tag[CRYPTO_ABYTES];
    ascon_squeeze(&s, computed_tag, CRYPTO_ABYTES);
    if (memcmp(computed_tag, tag, CRYPTO_ABYTES) != 0) {
        return -1; /* authentication failed */
    }
    
    return 0;
}