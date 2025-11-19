#ifndef AES_NI_H
#define AES_NI_H

#include <stdint.h>
#include <stddef.h>
#include <wmmintrin.h>   // AES-NI intrinsics
#include <immintrin.h>  // PCLMUL intrinsics
#include <string.h>

/*
 * AES-128 (AES-NI) unified header
 * Provides CTR and CBC APIs using hardware AES instructions.
 *
 * Requires: x86 CPU with AES-NI
 * Compile with: -maes -msse2 -mssse3
 *
 * Primitives:
 *   - Key expansion: aes128ni_setkey()
 *   - CTR mode: aes128ni_ctr_crypt()
 *   - CBC mode: aes128ni_cbc_encrypt(), aes128ni_cbc_decrypt()
 *
 * Note:
 *   - CTR encrypt/decrypt are the same function.
 *   - CBC requires input length to be multiple of 16 (no padding).
 */


typedef struct {
    __m128i round_keys[11]; // AES-128 has 11 round keys
} aes128ni_ctx;


/* Expand AES-128 key into round keys (encryption + decryption). */
void aes128ni_setkey(aes128ni_ctx *ctx, const uint8_t key[16]);

/* === AES-CTR ===
 * Encrypt/decrypt (same function).
 * - ctx: expanded AES-128 key
 * - iv: 16-byte initial counter (big endian incremented each block)
 * - in/out: input/output buffers
 * - length: number of bytes to process
 */
void aes128ni_ctr_crypt(const aes128ni_ctx *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);

/* === AES-CBC ===
 * Encrypt:
 * - ctx: expanded AES-128 key
 * - iv: 16-byte initialization vector
 * - in/out: input/output buffers (may overlap)
 * - length: must be multiple of 16
 *
 * Decrypt:
 * - same, requires ciphertext length multiple of 16
 *
 * Both return 0 on success, -1 on invalid args.
 */
void aes128ni_cbc_encrypt(const aes128ni_ctx *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);

void aes128ni_cbc_decrypt(const aes128ni_ctx *ctx,
                         const uint8_t iv[16],
                         const uint8_t *in, uint8_t *out,
                         size_t len);


int aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

int aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext);

#endif // AES_NI_H
