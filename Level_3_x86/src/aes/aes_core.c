#include "../include/aes_ni.h"
#include <wmmintrin.h>   // AES-NI intrinsics
#include <stdint.h>  

/* expand one round key */
static inline __m128i aes128_keyexpand(__m128i key, int rcon) {
    __m128i temp = _mm_aeskeygenassist_si128(key, rcon);
    temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, temp);
}

void aes128ni_setkey(aes128ni_ctx *ctx, const uint8_t *key) {
    __m128i k = _mm_loadu_si128((const __m128i*)key);
    ctx->round_keys[0] = k;

    ctx->round_keys[1]  = aes128_keyexpand(ctx->round_keys[0], 0x01);
    ctx->round_keys[2]  = aes128_keyexpand(ctx->round_keys[1], 0x02);
    ctx->round_keys[3]  = aes128_keyexpand(ctx->round_keys[2], 0x04);
    ctx->round_keys[4]  = aes128_keyexpand(ctx->round_keys[3], 0x08);
    ctx->round_keys[5]  = aes128_keyexpand(ctx->round_keys[4], 0x10);
    ctx->round_keys[6]  = aes128_keyexpand(ctx->round_keys[5], 0x20);
    ctx->round_keys[7]  = aes128_keyexpand(ctx->round_keys[6], 0x40);
    ctx->round_keys[8]  = aes128_keyexpand(ctx->round_keys[7], 0x80);
    ctx->round_keys[9]  = aes128_keyexpand(ctx->round_keys[8], 0x1B);
    ctx->round_keys[10] = aes128_keyexpand(ctx->round_keys[9], 0x36);
}
