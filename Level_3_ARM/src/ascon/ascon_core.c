/*
 * ascon_core_arm.c
 *
 * ASCON permutation + helpers (ARMv8-A AArch64 NEON intrinsics)
 * - Replacement for ascon_core.c using x86 SIMD
 * - Operates on 5x64-bit state, kept in uint64x2_t vectors (lower lane used)
 * - Fully unrolled 12 rounds (looped here for clarity)
 */

#include "../include/ascon.h"
#include <arm_neon.h>
#include <string.h>
#include <stdint.h>

/* Round constants (12 for Ascon-128/128a/80pq) */
static const uint64_t RC[12] = {
    0xF0ULL, 0xE1ULL, 0xD2ULL, 0xC3ULL,
    0xB4ULL, 0xA5ULL, 0x96ULL, 0x87ULL,
    0x78ULL, 0x69ULL, 0x5AULL, 0x4BULL
};

/* rotate right 64 on each lane of a uint64x2_t */
#define ROTR64_U64X2(x, n) vorrq_u64(vshrq_n_u64(x, n), vshlq_n_u64(x, 64 - (n)))

void ascon_permutation(ascon_state *s) {
    /* load state into vectors, upper lane zeroed to match SSE implementation */
    uint64x2_t x0 = vsetq_lane_u64(s->x[0], vdupq_n_u64(0), 0);
    uint64x2_t x1 = vsetq_lane_u64(s->x[1], vdupq_n_u64(0), 0);
    uint64x2_t x2 = vsetq_lane_u64(s->x[2], vdupq_n_u64(0), 0);
    uint64x2_t x3 = vsetq_lane_u64(s->x[3], vdupq_n_u64(0), 0);
    uint64x2_t x4 = vsetq_lane_u64(s->x[4], vdupq_n_u64(0), 0);

    for (int r = 0; r < 12; r++) {
        /* add round constant to x2 (lower lane) */
        uint64x2_t rc = vsetq_lane_u64(RC[r], vdupq_n_u64(0), 0);
        x2 = veorq_u64(x2, rc);

        /* substitution layer
           x0 ^= ~x1 & x2
           x1 ^= ~x2 & x3
           x2 ^= ~x3 & x4
           x3 ^= ~x4 & x0_prev
           x4 ^= ~x0_prev & x1_prev
        */
        uint64x2_t t0 = x0;
        uint64x2_t t1 = x1;
        uint64x2_t t2 = x2;
        uint64x2_t t3 = x3;
        uint64x2_t t4 = x4;

        /* x0 = x0 ^ (~x1 & x2) */
        x0 = veorq_u64(x0, vbicq_u64(t2, t1));
        /* x1 = x1 ^ (~x2 & x3) */
        x1 = veorq_u64(x1, vbicq_u64(t3, t2));
        /* x2 = x2 ^ (~x3 & x4) */
        x2 = veorq_u64(x2, vbicq_u64(t4, t3));
        /* x3 = x3 ^ (~x4 & t0) */
        x3 = veorq_u64(x3, vbicq_u64(t0, t4));
        /* x4 = x4 ^ (~t0 & t1) */
        x4 = veorq_u64(x4, vbicq_u64(t1, t0));

        /* linear layer of xors */
        x1 = veorq_u64(x1, x0);
        x0 = veorq_u64(x0, x4);
        x3 = veorq_u64(x3, x2);
        /* x2 = x2 ^ (~0ULL) */
        uint64x2_t allones = vdupq_n_u64(~(uint64_t)0);
        x2 = veorq_u64(x2, allones);

        /* linear diffusion layer (rotations and xors) */
        x0 = veorq_u64(x0, ROTR64_U64X2(x0, 19));
        x0 = veorq_u64(x0, ROTR64_U64X2(x0, 28));

        x1 = veorq_u64(x1, ROTR64_U64X2(x1, 61));
        x1 = veorq_u64(x1, ROTR64_U64X2(x1, 39));

        x2 = veorq_u64(x2, ROTR64_U64X2(x2, 1));
        x2 = veorq_u64(x2, ROTR64_U64X2(x2, 6));

        x3 = veorq_u64(x3, ROTR64_U64X2(x3, 10));
        x3 = veorq_u64(x3, ROTR64_U64X2(x3, 17));

        x4 = veorq_u64(x4, ROTR64_U64X2(x4, 7));
        x4 = veorq_u64(x4, ROTR64_U64X2(x4, 41));
    }

    /* store back lower lanes */
    s->x[0] = vgetq_lane_u64(x0, 0);
    s->x[1] = vgetq_lane_u64(x1, 0);
    s->x[2] = vgetq_lane_u64(x2, 0);
    s->x[3] = vgetq_lane_u64(x3, 0);
    s->x[4] = vgetq_lane_u64(x4, 0);
}

/* === Helpers for AEAD === */

void ascon_absorb(ascon_state *s, const uint8_t *data, size_t len, size_t rate) {
    size_t i = 0;
    while (i + rate <= len) {
        for (size_t j = 0; j < rate / 8; j++) {
            s->x[j] ^= ((uint64_t*) (data + i))[j];
        }
        ascon_permutation(s);
        i += rate;
    }
    /* final partial block + padding */
    uint8_t block[16] = {0};
    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem] = 0x80;
    for (size_t j = 0; j < rate / 8; j++) {
        s->x[j] ^= ((uint64_t*) block)[j];
    }
    ascon_permutation(s);
}

void ascon_squeeze(const ascon_state *s, uint8_t *tag, size_t tag_len) {
    for (size_t j = 0; j < tag_len / 8; j++) {
        ((uint64_t*) tag)[j] = s->x[j];
    }
}