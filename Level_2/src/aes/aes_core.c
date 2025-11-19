/*
 * aes_core.c
 *
 * Simple AES-128 single-block helpers using OpenSSL AES primitives.
 * Level-2 optimization (per-operation key expansion) is implemented in the mode files
 * (aes_cbc.c and aes_ctr.c) — this file provides single-block wrappers for compatibility.
 *
 * Build: link with -lcrypto
 */

#include "../include/aes.h"
#include <openssl/aes.h>
#include <string.h>
#include <stdint.h>

void aes_128_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    AES_KEY ks;
    /* Expand key once for this block (wrapper). Modes should expand once per operation. */
    if (AES_set_encrypt_key(key, 128, &ks) != 0) {
        /* On failure, produce zeroed output to avoid leaking input. */
        memset(output, 0, 16);
        return;
    }
    AES_encrypt(input, output, &ks);
    /* AES_KEY does not usually require zeroing, but could be memset(&ks, 0, sizeof(ks)) if desired */
}

void aes_128_decrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    AES_KEY ks;
    if (AES_set_decrypt_key(key, 128, &ks) != 0) {
        memset(output, 0, 16);
        return;
    }
    AES_decrypt(input, output, &ks);
}
