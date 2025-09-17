#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>

// A generic, parameterized ASCON encryption/decryption function
int ascon_crypto_aead_encrypt(
    uint8_t* c,
    const uint8_t* m, size_t mlen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k,
    uint8_t iv, int num_rounds_a, int num_rounds_b, int rate);

int ascon_crypto_aead_decrypt(
    uint8_t* m,
    const uint8_t* c, size_t clen,
    const uint8_t* ad, size_t adlen,
    const uint8_t* npub,
    const uint8_t* k,
    uint8_t iv, int num_rounds_a, int num_rounds_b, int rate);

// Function stubs for specific ASCON variants
int ascon_128_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len);
int ascon_128_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext);

int ascon_128a_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len);
int ascon_128a_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext);

int ascon_80pq_encrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* plaintext, size_t plaintext_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t* tag, size_t tag_len);
int ascon_80pq_decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, size_t aad_len, const uint8_t* tag, size_t tag_len, uint8_t* plaintext);

#endif // ASCON_H