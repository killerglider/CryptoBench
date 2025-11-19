#include "../include/aes_ni.h"
#include <wmmintrin.h>   // AES-NI intrinsics
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void aes128ni_cbc_encrypt(const aes128ni_ctx *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
    __m128i prev = _mm_loadu_si128((const __m128i*)iv);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        __m128i block = _mm_loadu_si128((const __m128i*)(in + i*16));
        block = _mm_xor_si128(block, prev);

        block = _mm_xor_si128(block, ctx->round_keys[0]);
        for (int r = 1; r < 10; r++)
            block = _mm_aesenc_si128(block, ctx->round_keys[r]);
        block = _mm_aesenclast_si128(block, ctx->round_keys[10]);

        _mm_storeu_si128((__m128i*)(out + i*16), block);
        prev = block;
    }
}

void aes128ni_cbc_decrypt(const aes128ni_ctx *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
    __m128i prev = _mm_loadu_si128((const __m128i*)iv);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        __m128i block = _mm_loadu_si128((const __m128i*)(in + i*16));

        __m128i tmp = block;
        tmp = _mm_xor_si128(tmp, ctx->round_keys[10]);
        for (int r = 9; r > 0; r--)
            tmp = _mm_aesdec_si128(tmp, ctx->round_keys[r]);
        tmp = _mm_aesdeclast_si128(tmp, ctx->round_keys[0]);

        tmp = _mm_xor_si128(tmp, prev);
        _mm_storeu_si128((__m128i*)(out + i*16), tmp);

        prev = block;
    }
}
