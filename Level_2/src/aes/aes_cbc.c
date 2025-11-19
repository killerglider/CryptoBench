/*
 * AES-CBC (Level-2 optimized)
 *
 * Expands the AES key once per call (encrypt/decrypt), then processes 16-byte blocks.
 * This avoids expanding the key per-block (big win for many-block messages).
 */

#include "../include/aes.h"
#include <openssl/aes.h>
#include <string.h>
#include <stdint.h>

int aes_cbc_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext
) {
    if (key_len != 16 || iv_len != 16 || (plaintext_len % 16) != 0) {
        return -1; // Invalid args for this simple CBC (no padding)
    }

    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, 128, &enc_key) != 0) return -1;

    uint8_t previous[16];
    memcpy(previous, iv, 16);

    for (size_t off = 0; off < plaintext_len; off += 16) {
        uint8_t block[16];
        /* XOR with previous ciphertext (or IV) */
        for (int i = 0; i < 16; ++i) block[i] = plaintext[off + i] ^ previous[i];

        AES_encrypt(block, &ciphertext[off], &enc_key);

        /* update previous */
        memcpy(previous, &ciphertext[off], 16);
    }

    return 0;
}

int aes_cbc_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext
) {
    if (key_len != 16 || iv_len != 16 || (ciphertext_len % 16) != 0) {
        return -1;
    }

    AES_KEY dec_key;
    if (AES_set_decrypt_key(key, 128, &dec_key) != 0) return -1;

    uint8_t previous[16];
    memcpy(previous, iv, 16);

    for (size_t off = 0; off < ciphertext_len; off += 16) {
        uint8_t block[16];
        AES_decrypt(&ciphertext[off], block, &dec_key);

        /* plaintext = decrypted ^ previous */
        for (int i = 0; i < 16; ++i) plaintext[off + i] = block[i] ^ previous[i];

        memcpy(previous, &ciphertext[off], 16);
    }

    return 0;
}
