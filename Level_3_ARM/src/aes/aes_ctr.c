/*
 * aes_arm_ctr.c
 *
 * CTR mode using aes_arm_core.c block encrypt.
 * Counter format: treat last 64 bits as little-endian counter increment.
 */

#include "../include/aes_arm.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* increment 128-bit big-endian counter stored in 16-byte array (increment low 64 bits) */
static void ctr_increment(uint8_t ctr[16]) {
    /* treat bytes 8..15 as little-endian 64-bit counter */
    uint64_t *low = (uint64_t*)(ctr + 8);
    /* portable increment using uint64_t */
    (*low)++;
}

/* CTR crypt: encrypt the counter and XOR with input */
void aes128arm_ctr_crypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter[16];
    memcpy(counter, iv, 16);

    uint8_t keystream[16];
    size_t full_blocks = len / 16;
    size_t rem = len % 16;

    for (size_t i = 0; i < full_blocks; i++) {
        /* encrypt counter to get keystream block */
        /* const cast needed because aes128arm_block_encrypt expects non-const ctx; safe */
        aes128arm_block_encrypt((const aes128arm_ctx*)ctx, counter, keystream);
        /* XOR keystream with plaintext to produce ciphertext */
        const uint8_t *p = in + i * 16;
        uint8_t *q = out + i * 16;
        for (int b = 0; b < 16; ++b) q[b] = p[b] ^ keystream[b];
        /* increment counter */
        ctr_increment(counter);
    }

    if (rem) {
        aes128arm_block_encrypt((const aes128arm_ctx*)ctx, counter, keystream);
        const uint8_t *p = in + full_blocks * 16;
        uint8_t *q = out + full_blocks * 16;
        for (size_t b = 0; b < rem; ++b) q[b] = p[b] ^ keystream[b];
    }
}
