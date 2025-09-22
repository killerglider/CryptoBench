/*
 * aes_arm_cbc.c
 *
 * CBC mode wrappers (encrypt and decrypt) using aes_arm_core block encrypt.
 * Note: inputs must be a multiple of 16 bytes for CBC.
 */

#include "../include/aes_arm.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/aes.h>

/* CBC encrypt: plaintext -> ciphertext
 * len must be multiple of 16
 */
void aes128arm_cbc_encrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        uint8_t block_in[16];
        for (int j = 0; j < 16; ++j) block_in[j] = in[i*16 + j] ^ prev[j];
        uint8_t block_out[16];
        aes128arm_block_encrypt((const aes128arm_ctx*)ctx, block_in, block_out);
        memcpy(out + i*16, block_out, 16);
        memcpy(prev, block_out, 16);
    }
}

/* CBC decrypt: ciphertext -> plaintext
 * len must be multiple of 16
 */
void aes128arm_cbc_decrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    uint8_t tmp[16];
    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        const uint8_t *cblock = in + i*16;
        /* Decrypting using AES_encrypt requires an expanded decrypt key OR using AES_decrypt.
           OpenSSL provides AES_decrypt that requires AES_KEY created by AES_set_encrypt_key? No.
           So we derive decrypt by using AES_decrypt with a separate AES_KEY.
           For correctness and simplicity, we implement decrypt by calling AES_decrypt:
           But AES_decrypt requires AES_KEY initialized for decryption; we only stored the encrypt keys.
           Better approach: use AES_set_decrypt_key and store both keys. However our ctx stores only encrypt key.
           To keep interface simple we will create a temporary decrypt key on the stack per call.
        */
        AES_KEY dkey;
        /* Build decrypt key from encrypt key stored in ctx: use AES_set_decrypt_key */
        AES_set_decrypt_key((const unsigned char*)ctx->rk_buffer, 128, &dkey);
        /* Use AES_decrypt now */
        /* However AES_decrypt takes block and dkey */
        AES_decrypt(cblock, tmp, &dkey);

        /* plaintext = tmp XOR prev */
        for (int j = 0; j < 16; ++j) out[i*16 + j] = tmp[j] ^ prev[j];
        memcpy(prev, cblock, 16);
    }
}
