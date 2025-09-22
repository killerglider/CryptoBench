#include "../include/aes_arm.h"
#include <openssl/aes.h>
#include <string.h>
#include <assert.h>

/* We'll store both encrypt and decrypt AES_KEY structures inside the ctx buffer.
   AES_KEY size is implementation-defined but small; we reserve space for two AES_KEY instances. */
typedef struct {
    AES_KEY enc;
    AES_KEY dec;
} aes_key_storage;

/* helpers */
static aes_key_storage* key_storage_from_ctx(aes128arm_ctx *ctx) {
    return (aes_key_storage*)ctx->rk_buffer;
}
static const aes_key_storage* key_storage_from_ctx_const(const aes128arm_ctx *ctx) {
    return (const aes_key_storage*)ctx->rk_buffer;
}

/* set key (store both encrypt and decrypt expanded keys) */
void aes128arm_setkey(aes128arm_ctx *ctx, const uint8_t *key) {
    aes_key_storage *ks = key_storage_from_ctx(ctx);
    AES_set_encrypt_key(key, 128, &ks->enc);
    AES_set_decrypt_key(key, 128, &ks->dec);
}

/* block encrypt using enc key */
void aes128arm_block_encrypt(const aes128arm_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    const aes_key_storage *ks = key_storage_from_ctx_const(ctx);
    AES_encrypt(in, out, &ks->enc);
}

/* block decrypt using dec key (may be useful for CBC decrypt) */
void aes128arm_block_decrypt(const aes128arm_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    const aes_key_storage *ks = key_storage_from_ctx_const(ctx);
    AES_decrypt(in, out, &ks->dec);
}
