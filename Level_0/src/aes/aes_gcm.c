// AES-GCM Implementation (Level 0 Baseline - No OpenSSL)
#include "../include/aes.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Helper Functions for GCM

// Performs a 128-bit XOR operation.
static void xor_128(uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; ++i) {
        a[i] ^= b[i];
    }
}

// Implements GF(2^128) multiplication for GHASH.
static void gf_mult(const uint8_t *a, const uint8_t *b, uint8_t *res) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, b, 16);

    for (int i = 0; i < 128; ++i) {
        if ((a[i / 8] >> (7 - (i % 8))) & 1) {
            xor_128(z, v);
        }
        uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; --j) {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xE1;
        }
    }
    memcpy(res, z, 16);
}

// Increments the 32-bit counter part of a GCM block.
static void increment_counter(uint8_t *counter_block) {
    for (int i = 15; i >= 12; --i) {
        if (++counter_block[i] != 0) {
            break;
        }
    }
}

// GHASH function: processes blocks of AAD or ciphertext.
static void ghash_update(uint8_t *s, const uint8_t *h, const uint8_t *data, size_t len) {
    size_t num_blocks = len / 16;
    for (size_t i = 0; i < num_blocks; ++i) {
        xor_128(s, data + i * 16);
        uint8_t temp[16];
        gf_mult(s, h, temp);
        memcpy(s, temp, 16);
    }
    if (len % 16 != 0) {
        uint8_t last_block[16] = {0};
        memcpy(last_block, data + num_blocks * 16, len % 16);
        xor_128(s, last_block);
        uint8_t temp[16];
        gf_mult(s, h, temp);
        memcpy(s, temp, 16);
    }
}


int aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,
    uint8_t *tag, size_t tag_len
) {
    if (key_len != 16 || iv_len != 12 || tag_len > 16) return -1;

    uint8_t h[16] = {0};
    aes_128_encrypt_block(key, h, h);

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    uint8_t counter[16];
    memcpy(counter, j0, 16);
    increment_counter(counter);

    // CTR mode encryption
    aes_ctr_crypt(key, 16, counter, 16, plaintext, plaintext_len, ciphertext);

    uint8_t s[16] = {0};
    ghash_update(s, h, aad, aad_len);
    ghash_update(s, h, ciphertext, plaintext_len);
    
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)plaintext_len * 8;
    for(int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(s, h, len_block, 16);

    uint8_t encrypted_j0[16];
    aes_128_encrypt_block(key, j0, encrypted_j0);
    xor_128(s, encrypted_j0);
    
    memcpy(tag, s, tag_len);

    return plaintext_len;
}

int aes_gcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *tag, size_t tag_len,
    uint8_t *plaintext
) {
    if (key_len != 16 || iv_len != 12 || tag_len > 16) return -1;

    uint8_t h[16] = {0};
    aes_128_encrypt_block(key, h, h);

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    // Calculate the tag for verification
    uint8_t s[16] = {0};
    ghash_update(s, h, aad, aad_len);
    ghash_update(s, h, ciphertext, ciphertext_len);

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ciphertext_len * 8;
    for(int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(s, h, len_block, 16);

    uint8_t encrypted_j0[16];
    aes_128_encrypt_block(key, j0, encrypted_j0);
    xor_128(s, encrypted_j0);
    
    // Constant-time tag comparison
    int diff = 0;
    for (size_t i = 0; i < tag_len; ++i) {
        diff |= s[i] ^ tag[i];
    }
    if (diff != 0) {
        // Mismatch: clear plaintext to prevent use of invalid data
        memset(plaintext, 0, ciphertext_len);
        return -1;
    }

    // If tag is valid, perform decryption
    uint8_t counter[16];
    memcpy(counter, j0, 16);
    increment_counter(counter);
    aes_ctr_crypt(key, 16, counter, 16, ciphertext, ciphertext_len, plaintext);

    return ciphertext_len;
}