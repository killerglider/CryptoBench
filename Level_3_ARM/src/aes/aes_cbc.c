/*
 * aes_cbc.c - Fixed CBC mode implementation
 *
 * CBC mode wrappers (encrypt and decrypt) using aes_core.c block functions.
 * Note: inputs must be a multiple of 16 bytes for CBC.
 */

#include "../include/aes_arm.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Use the decrypt function from aes_core.c instead of recreating keys
extern void aes128arm_block_decrypt(const aes128arm_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

/* CBC encrypt: plaintext -> ciphertext
 * len must be multiple of 16
 */
void aes128arm_cbc_encrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !iv || !in || !out || (len % 16) != 0) {
        return; // Invalid parameters
    }
    
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        uint8_t block_in[16];
        
        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < 16; ++j) {
            block_in[j] = in[i*16 + j] ^ prev[j];
        }
        
        // Encrypt the XORed block
        uint8_t block_out[16];
        aes128arm_block_encrypt(ctx, block_in, block_out);
        
        // Copy to output
        memcpy(out + i*16, block_out, 16);
        
        // Update prev for next iteration
        memcpy(prev, block_out, 16);
    }
}

/* CBC decrypt: ciphertext -> plaintext
 * len must be multiple of 16
 */
void aes128arm_cbc_decrypt(const aes128arm_ctx *ctx, const uint8_t iv[16],
                           const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !iv || !in || !out || (len % 16) != 0) {
        return; // Invalid parameters
    }
    
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        const uint8_t *cblock = in + i*16;
        uint8_t decrypted[16];
        
        // Decrypt the block
        aes128arm_block_decrypt(ctx, cblock, decrypted);
        
        // XOR with previous ciphertext (or IV for first block)
        for (int j = 0; j < 16; ++j) {
            out[i*16 + j] = decrypted[j] ^ prev[j];
        }
        
        // Update prev for next iteration (current ciphertext block)
        memcpy(prev, cblock, 16);
    }
}