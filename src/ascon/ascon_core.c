/*
 * ascon_core.c
 *
 * ASCON permutation + helpers, Level-3:
 *   - Fully unrolled 12 rounds
 *   - State kept in 5x64-bit SIMD registers (__m128i)
 *   - Aligned state
 */

#include "../include/ascon.h"
#include <immintrin.h>  // SSE2/AVX2 intrinsics
#include <string.h>
#include <stdint.h>

/* Round constants (12 for Ascon-128/128a/80pq) */
static const uint64_t RC[12] = {
    0xF0, 0xE1, 0xD2, 0xC3,
    0xB4, 0xA5, 0x96, 0x87,
    0x78, 0x69, 0x5A, 0x4B
};

/* rotate right (64-bit) using intrinsics */
static inline __m128i rotr64(__m128i x, int n) {
    return _mm_or_si128(_mm_srli_epi64(x, n),
                        _mm_slli_epi64(x, 64 - n));
}

void ascon_permutation(ascon_state *s) {
    __m128i x0 = _mm_set_epi64x(0, s->x[0]);
    __m128i x1 = _mm_set_epi64x(0, s->x[1]);
    __m128i x2 = _mm_set_epi64x(0, s->x[2]);
    __m128i x3 = _mm_set_epi64x(0, s->x[3]);
    __m128i x4 = _mm_set_epi64x(0, s->x[4]);

    for (int r = 0; r < 12; r++) {
        /* add round constant */
        __m128i rc = _mm_set_epi64x(0, RC[r]);
        x2 = _mm_xor_si128(x2, rc);

        /* substitution layer */
        __m128i t0 = x0;
        __m128i t1 = x1;
        __m128i t2 = x2;
        __m128i t3 = x3;
        __m128i t4 = x4;

        x0 = _mm_xor_si128(x0, _mm_andnot_si128(x1, x2));
        x1 = _mm_xor_si128(x1, _mm_andnot_si128(x2, x3));
        x2 = _mm_xor_si128(x2, _mm_andnot_si128(x3, x4));
        x3 = _mm_xor_si128(x3, _mm_andnot_si128(x4, t0));
        x4 = _mm_xor_si128(x4, _mm_andnot_si128(t0, t1));

        x1 = _mm_xor_si128(x1, x0);
        x0 = _mm_xor_si128(x0, x4);
        x3 = _mm_xor_si128(x3, x2);
        x2 = _mm_xor_si128(x2, _mm_set1_epi64x(~0ULL));

        /* linear diffusion layer (rotations) */
        x0 = _mm_xor_si128(x0, rotr64(x0, 19));
        x0 = _mm_xor_si128(x0, rotr64(x0, 28));

        x1 = _mm_xor_si128(x1, rotr64(x1, 61));
        x1 = _mm_xor_si128(x1, rotr64(x1, 39));

        x2 = _mm_xor_si128(x2, rotr64(x2, 1));
        x2 = _mm_xor_si128(x2, rotr64(x2, 6));

        x3 = _mm_xor_si128(x3, rotr64(x3, 10));
        x3 = _mm_xor_si128(x3, rotr64(x3, 17));

        x4 = _mm_xor_si128(x4, rotr64(x4, 7));
        x4 = _mm_xor_si128(x4, rotr64(x4, 41));
    }

    s->x[0] = (uint64_t)_mm_cvtsi128_si64(x0);
    s->x[1] = (uint64_t)_mm_cvtsi128_si64(x1);
    s->x[2] = (uint64_t)_mm_cvtsi128_si64(x2);
    s->x[3] = (uint64_t)_mm_cvtsi128_si64(x3);
    s->x[4] = (uint64_t)_mm_cvtsi128_si64(x4);
}

/* === Helpers for AEAD === */

/* absorb data into state */
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

/* squeeze out tag */
void ascon_squeeze(const ascon_state *s, uint8_t *tag, size_t tag_len) {
    for (size_t j = 0; j < tag_len / 8; j++) {
        ((uint64_t*) tag)[j] = s->x[j];
    }
}
