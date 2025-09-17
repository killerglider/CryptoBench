// AES-CTR Implementation

#include "../include/aes.h"
#include <string.h>
#include <stdint.h>
#include <string.h>

int aes_ctr_crypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
) {
    if (key_len != 16 || iv_len != 16) {
        return -1; // Invalid key or IV length
    }

    uint8_t counter_block[16];
    memcpy(counter_block, iv, 16);
    uint8_t keystream_block[16];

    for (size_t i = 0; i < input_len; ++i) {
        // Generate a new keystream block for each 16-byte chunk of data
        if (i % 16 == 0) {
            aes_128_encrypt_block(key, counter_block, keystream_block);

            // Increment the counter for the next block (simple big-endian increment)
            for (int j = 15; j >= 0; --j) {
                if (++counter_block[j] != 0) {
                    break;
                }
            }
        }
        // XOR the input byte with the corresponding keystream byte
        output[i] = input[i] ^ keystream_block[i % 16];
    }

    return 0;
}