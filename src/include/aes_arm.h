#ifndef AES_ARM_H
#define AES_ARM_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    /* opaque buffer large enough for OpenSSL AES_KEY */
    unsigned char rk_buffer[240]; /* sizing - AES_KEY is small; 240 bytes enough */
} aes128arm_ctx;

/* set 128-bit key (key must be 16 bytes) */
void aes128arm_setkey(aes128arm_ctx *ctx, const uint8_t *key);

/* CTR mode (in-place allowed: input and output pointers may overlap) */
void aes128arm_ctr_crypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                         const uint8_t *in, uint8_t *out, size_t len);

/* CBC encrypt: plaintext -> ciphertext (len must be multiple of 16) */
void aes128arm_cbc_encrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len);

/* CBC decrypt: ciphertext -> plaintext (len must be multiple of 16) */
void aes128arm_cbc_decrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len);


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
