// AES-CBC Implementation

#include "../include/aes.h"
#include <string.h>
#include <stdint.h>

int aes_cbc_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext
) {
    if (key_len != 16 || iv_len != 16 || plaintext_len % 16 != 0) {
        return -1; // Invalid arguments
    }

    uint8_t previous_block[16];
    memcpy(previous_block, iv, 16);

    for (size_t i = 0; i < plaintext_len; i += 16) {
        uint8_t block_to_encrypt[16];
        for (int j = 0; j < 16; ++j) {
            block_to_encrypt[j] = plaintext[i + j] ^ previous_block[j];
        }
        aes_128_encrypt_block(key, block_to_encrypt, &ciphertext[i]);
        memcpy(previous_block, &ciphertext[i], 16);
    }

    return 0;
}

int aes_cbc_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext
) {
    if (key_len != 16 || iv_len != 16 || ciphertext_len % 16 != 0) {
        return -1; // Invalid arguments
    }

    uint8_t previous_block[16];
    memcpy(previous_block, iv, 16);

    for (size_t i = 0; i < ciphertext_len; i += 16) {
        uint8_t decrypted_block[16];
        aes_128_decrypt_block(key, &ciphertext[i], decrypted_block);
        for (int j = 0; j < 16; ++j) {
            plaintext[i + j] = decrypted_block[j] ^ previous_block[j];
        }
        memcpy(previous_block, &ciphertext[i], 16);
    }

    return 0;
}