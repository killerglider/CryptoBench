#include "../include/aes_ni.h"
#include <wmmintrin.h>   // AES-NI intrinsics
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void aes128ni_ctr_crypt(const aes128ni_ctx *ctx, const uint8_t iv[16],
                        const uint8_t *in, uint8_t *out, size_t len) {
    __m128i ctr = _mm_loadu_si128((const __m128i*)iv);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        __m128i tmp = ctr;
        tmp = _mm_xor_si128(tmp, ctx->round_keys[0]);
        for (int r = 1; r < 10; r++)
            tmp = _mm_aesenc_si128(tmp, ctx->round_keys[r]);
        tmp = _mm_aesenclast_si128(tmp, ctx->round_keys[10]);

        __m128i block = _mm_loadu_si128((const __m128i*)(in + i*16));
        block = _mm_xor_si128(block, tmp);
        _mm_storeu_si128((__m128i*)(out + i*16), block);

        ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1)); // increment low 64 bits
    }

    /* leftover bytes */
    size_t rem = len % 16;
    if (rem) {
        __m128i tmp = ctr;
        tmp = _mm_xor_si128(tmp, ctx->round_keys[0]);
        for (int r = 1; r < 10; r++)
            tmp = _mm_aesenc_si128(tmp, ctx->round_keys[r]);
        tmp = _mm_aesenclast_si128(tmp, ctx->round_keys[10]);

        uint8_t keystream[16];
        _mm_storeu_si128((__m128i*)keystream, tmp);
        for (size_t j = 0; j < rem; j++)
            out[blocks*16 + j] = in[blocks*16 + j] ^ keystream[j];
    }
}
