/*
 * ASCON-128 wrapper (no heap allocation)
 *
 * Uses the ascon_crypto_aead_encrypt/decrypt core functions which write ciphertext+tag
 * into a single buffer. This wrapper calls the core using the caller-provided ciphertext
 * buffer (which must have space for plaintext_len + tag_len). main.c already allocates
 * ciphertext with +16 bytes so this is safe in the benchmark harness.
 *
 * After core returns, the wrapper copies the tag portion into the tag buffer.
 */

#include "../include/ascon.h"
#include <string.h>
#include <stdint.h>

/* constants for variant */
#define ASCON128_IV         0x80400c0600000000ULL
#define ASCON128_KEY_LEN    16
#define ASCON128_NONCE_LEN  16
#define ASCON128_TAG_LEN    16
#define ASCON128_RATE       8

int ascon_128_encrypt(const uint8_t* key, size_t key_len,
                      const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* plaintext, size_t plaintext_len,
                      const uint8_t* aad, size_t aad_len,
                      uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (key_len != ASCON128_KEY_LEN || nonce_len != ASCON128_NONCE_LEN || tag_len != ASCON128_TAG_LEN) return -1;

    /* The caller's ciphertext buffer MUST be at least plaintext_len + tag_len bytes.
       main.c allocates that (max_size + 16) so it is safe for the benchmark. */
    int result = ascon_crypto_aead_encrypt(ciphertext, plaintext, plaintext_len, aad, aad_len, nonce, key, ASCON128_KEY_LEN, ASCON128_IV, 12, 6, ASCON128_RATE);
    if (result != 0) return result;

    /* core places tag at ciphertext + plaintext_len */
    memcpy(tag, ciphertext + plaintext_len, tag_len);

    /* optional: clear tag from ciphertext tail to maintain invariant that ciphertext length == plaintext_len */
    /* memset(ciphertext + plaintext_len, 0, tag_len); */

    return 0;
}

int ascon_128_decrypt(const uint8_t* key, size_t key_len,
                      const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* tag, size_t tag_len,
                      uint8_t* plaintext) {
    if (key_len != ASCON128_KEY_LEN || nonce_len != ASCON128_NONCE_LEN || tag_len != ASCON128_TAG_LEN) return -1;

    /* The core expects ciphertext+tag in one contiguous buffer. The benchmark's ciphertext
       buffer was allocated with +16 bytes, so we can safely write the tag there before calling core. */
    uint8_t* mutable_c = (uint8_t*)ciphertext; /* caller allocated buffer has extra tag space in main.c */
    memcpy(mutable_c + ciphertext_len, tag, tag_len);

    int result = ascon_crypto_aead_decrypt(plaintext, mutable_c, ciphertext_len + tag_len, aad, aad_len, nonce, key, ASCON128_KEY_LEN, ASCON128_IV, 12, 6, ASCON128_RATE);

    /* optional: clear temporary tag area */
    /* memset(mutable_c + ciphertext_len, 0, tag_len); */

    return result;
}
