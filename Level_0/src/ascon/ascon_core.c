// src/ascon/ascon_core.c
// Contains the core, parameterized implementation of the ASCON permutation and AEAD logic.

#include "../include/ascon.h"
#include <string.h>
#include <stdint.h>

// Helper functions to load and store 64-bit words from byte arrays (Level 0)
static uint64_t load_u64(const uint8_t *p) {
    uint64_t res = 0;
    res |= ((uint64_t)p[0]) << 56;
    res |= ((uint64_t)p[1]) << 48;
    res |= ((uint64_t)p[2]) << 40;
    res |= ((uint64_t)p[3]) << 32;
    res |= ((uint64_t)p[4]) << 24;
    res |= ((uint64_t)p[5]) << 16;
    res |= ((uint64_t)p[6]) << 8;
    res |= ((uint64_t)p[7]) << 0;
    return res;
}

static void store_u64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
}


// ROTR64: Rotates a 64-bit word to the right
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/**
 * @brief The core ASCON permutation function.
 *
 * @param s The 320-bit state, represented as an array of five 64-bit words.
 * @param rounds The number of rounds to perform (e.g., 12, 8, or 6).
 */
static void ascon_permutation(uint64_t* s, int rounds) {
    uint64_t t0, t1, t2, t3, t4;
    // Round constants for the 12 rounds of the permutation
    const uint64_t rc[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

    for (int i = 12 - rounds; i < 12; ++i) {
        // --- Add round constant ---
        s[2] ^= rc[i];
        // --- Substitution layer (S-box) ---
        s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1];
        t0 = s[0]; t1 = s[1]; t2 = s[2]; t3 = s[3]; t4 = s[4];
        s[0] = (~t0 & t1) ^ t2;
        s[1] = (~t1 & t2) ^ t3;
        s[2] = (~t2 & t3) ^ t4;
        s[3] = (~t3 & t4) ^ t0;
        s[4] = (~t4 & t0) ^ t1;
        // --- Linear diffusion layer ---
        s[0] ^= ROTR64(s[0], 19) ^ ROTR64(s[0], 28);
        s[1] ^= ROTR64(s[1], 61) ^ ROTR64(s[1], 39);
        s[2] ^= ROTR64(s[2], 1)  ^ ROTR64(s[2], 6);
        s[3] ^= ROTR64(s[3], 10) ^ ROTR64(s[3], 17);
        s[4] ^= ROTR64(s[4], 7)  ^ ROTR64(s[4], 41);
    }
}

int ascon_crypto_aead_encrypt(
    uint8_t* c,
    const uint8_t* m, size_t mlen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k, size_t key_len,
    uint64_t iv, int num_rounds_a, int num_rounds_b, int rate)
{
    uint64_t s[5];
    
    // --- Initialization ---
    if (key_len == 20) { // ASCON-80pq with 20-byte key
        s[0] = iv;
        s[1] = load_u64(k);
        s[2] = load_u64(k + 8);
        s[3] = (uint64_t)(*(uint32_t*)(k + 16)); // Load the last 4 bytes of the key
        s[3] |= load_u64(npub) << 32;
        s[4] = load_u64(npub + 4);

    } else { // ASCON-128 and 128a with 16-byte key
        s[0] = iv;
        s[1] = load_u64(k);
        s[2] = load_u64(k + 8);
        s[3] = load_u64(npub);
        s[4] = load_u64(npub + 8);
    }

    ascon_permutation(s, num_rounds_a);

    // XOR key into state after initialization permutation
    if (key_len == 20) {
        s[2] ^= load_u64(k + 4);
        s[3] ^= load_u64(k + 12);
    } else {
        s[3] ^= load_u64(k);
        s[4] ^= load_u64(k + 8);
    }

    // --- Process Associated Data ---
    if (adlen) {
        while (adlen >= (size_t)rate) {
            s[0] ^= load_u64(ad);
            if (rate == 16) s[1] ^= load_u64(ad + 8);
            ascon_permutation(s, num_rounds_b);
            ad += rate;
            adlen -= rate;
        }
        for (size_t i = 0; i < adlen; ++i) s[i / 8] ^= ((uint64_t)ad[i]) << (56 - (i % 8) * 8);
        s[adlen / 8] ^= 0x80ULL << (56 - (adlen % 8) * 8);
        ascon_permutation(s, num_rounds_b);
    }
    // Domain separation
    s[4] ^= 1;

    // --- Process Plaintext ---
    size_t clen_total = mlen;
    while (mlen >= (size_t)rate) {
        s[0] ^= load_u64(m);
        if (rate == 16) s[1] ^= load_u64(m + 8);
        store_u64(c, s[0]);
        if (rate == 16) store_u64(c + 8, s[1]);
        ascon_permutation(s, num_rounds_b);
        m += rate;
        c += rate;
        mlen -= rate;
    }
    for (size_t i = 0; i < mlen; ++i) s[i / 8] ^= ((uint64_t)m[i]) << (56 - (i % 8) * 8);
    s[mlen / 8] ^= 0x80ULL << (56 - (mlen % 8) * 8);
    for (size_t i = 0; i < mlen; ++i) c[i] = (uint8_t)(s[i / 8] >> (56 - (i % 8) * 8));

    // --- Finalization ---
    ascon_permutation(s, num_rounds_a);

    // XOR key to generate the tag
    if (key_len == 20) {
        s[3] ^= load_u64(k + 4);
        s[4] ^= load_u64(k + 12);
    } else {
        s[3] ^= load_u64(k);
        s[4] ^= load_u64(k + 8);
    }
    
    // Write tag to the end of the ciphertext
    uint8_t tag_bytes[16];
    store_u64(tag_bytes, s[3]);
    store_u64(tag_bytes + 8, s[4]);
    memcpy(c + mlen, tag_bytes, 16);

    return 0;
}

int ascon_crypto_aead_decrypt(
    uint8_t* m,
    const uint8_t* c, size_t clen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k, size_t key_len,
    uint64_t iv, int num_rounds_a, int num_rounds_b, int rate)
{
    if (clen < 16) return -1; // Ciphertext must include at least a 16-byte tag
    size_t mlen = clen - 16;
    
    uint64_t s[5];
    
    // --- Initialization (same as encryption) ---
    if (key_len == 20) {
        s[0] = iv;
        s[1] = load_u64(k);
        s[2] = load_u64(k + 8);
        s[3] = (uint64_t)(*(uint32_t*)(k + 16));
        s[3] |= load_u64(npub) << 32;
        s[4] = load_u64(npub + 4);
    } else {
        s[0] = iv;
        s[1] = load_u64(k);
        s[2] = load_u64(k + 8);
        s[3] = load_u64(npub);
        s[4] = load_u64(npub + 8);
    }

    ascon_permutation(s, num_rounds_a);

    if (key_len == 20) {
        s[2] ^= load_u64(k + 4);
        s[3] ^= load_u64(k + 12);
    } else {
        s[3] ^= load_u64(k);
        s[4] ^= load_u64(k + 8);
    }

    // --- Process Associated Data (same as encryption) ---
    if (adlen) {
        while (adlen >= (size_t)rate) {
            s[0] ^= load_u64(ad);
            if (rate == 16) s[1] ^= load_u64(ad + 8);
            ascon_permutation(s, num_rounds_b);
            ad += rate;
            adlen -= rate;
        }
        for (size_t i = 0; i < adlen; ++i) s[i / 8] ^= ((uint64_t)ad[i]) << (56 - (i % 8) * 8);
        s[adlen / 8] ^= 0x80ULL << (56 - (adlen % 8) * 8);
        ascon_permutation(s, num_rounds_b);
    }
    s[4] ^= 1;

    // --- Process Ciphertext ---
    size_t clen_without_tag = mlen;
    const uint8_t* c_orig = c; // Save original pointer
    uint8_t* m_orig = m;       // Save original pointer

    while (clen_without_tag >= (size_t)rate) {
        uint64_t c0 = load_u64(c);
        uint64_t c1 = (rate == 16) ? load_u64(c + 8) : 0;
        store_u64(m, s[0] ^ c0);
        if (rate == 16) store_u64(m + 8, s[1] ^ c1);
        s[0] = c0;
        if (rate == 16) s[1] = c1;
        ascon_permutation(s, num_rounds_b);
        m += rate;
        c += rate;
        clen_without_tag -= rate;
    }

    for (size_t i = 0; i < clen_without_tag; ++i) {
        m[i] = (uint8_t)(s[i / 8] >> (56 - (i % 8) * 8)) ^ c[i];
        s[i / 8] &= ~(0xFFULL << (56 - (i % 8) * 8));
        s[i / 8] |= ((uint64_t)c[i]) << (56 - (i % 8) * 8);
    }
    s[clen_without_tag / 8] ^= 0x80ULL << (56 - (clen_without_tag % 8) * 8);
    
    // --- Finalization and Tag Verification ---
    ascon_permutation(s, num_rounds_a);

    if (key_len == 20) {
        s[3] ^= load_u64(k + 4);
        s[4] ^= load_u64(k + 12);
    } else {
        s[3] ^= load_u64(k);
        s[4] ^= load_u64(k + 8);
    }

    // Constant-time tag comparison
    uint64_t t3 = load_u64(c_orig + mlen);
    uint64_t t4 = load_u64(c_orig + mlen + 8);
    if (((s[3] ^ t3) | (s[4] ^ t4)) != 0) {
        // Mismatch: clear the plaintext buffer to prevent using invalid data
        memset(m_orig, 0, mlen);
        return -1;
    }

    return 0;
}