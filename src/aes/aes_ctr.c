/*
 * AES-CTR (Level-2 optimized)
 *
 * We treat IV as a 16-byte counter vector. The implementation encrypts successive
 * 16-byte counter blocks with AES and XORs to produce the stream.
 *
 * Behavior: aes_ctr_crypt is symmetric for encryption and decryption (same operation).
 */

#include "../include/aes.h"
#include <openssl/aes.h>
#include <string.h>
#include <stdint.h>

/* increment 128-bit counter stored in big-endian order (last byte is LSB) */
static void increment_ctr_be(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        ++counter[i];
        if (counter[i] != 0) break;
    }
}

int aes_ctr_crypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
) {
    if (key_len != 16 || iv_len != 16) return -1;

    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, 128, &enc_key) != 0) return -1;

    uint8_t counter[16];
    memcpy(counter, iv, 16);

    size_t processed = 0;
    uint8_t keystream[16];

    while (processed < input_len) {
        AES_encrypt(counter, keystream, &enc_key);

        size_t chunk = (input_len - processed) < 16 ? (input_len - processed) : 16;
        for (size_t i = 0; i < chunk; ++i) {
            output[processed + i] = input[processed + i] ^ keystream[i];
        }

        processed += chunk;
        increment_ctr_be(counter);
    }

    return 0;
}
