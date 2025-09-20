#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/*
 * Lightweight AES-128 header for this project.
 *
 * The AES core implementation uses OpenSSL AES primitives (link with -lcrypto).
 *
 * Provided API (keeps the same names used across the repo):
 *   - aes_128_encrypt_block: encrypt a single 16-byte block with a 16-byte key
 *   - aes_128_decrypt_block: decrypt a single 16-byte block with a 16-byte key
 *
 *
 * Note: Level-2 optimization is implemented in the mode files: they expand the key
 * once per operation instead of per-block.
 */

void aes_128_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output);
void aes_128_decrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output);

int aes_cbc_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext);

int aes_cbc_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext);

int aes_ctr_crypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output);

int aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

int aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext);

#endif // AES_H
