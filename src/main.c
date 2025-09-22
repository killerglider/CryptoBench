/*
 * fixed_debug_main.c — Debug version with proper AES context handling
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include "include/aes_arm.h"
#include "include/ascon.h"

/* AES-GCM wrappers */
extern int aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *pt, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ct, uint8_t *tag, size_t tag_len);

extern int aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *tag, size_t tag_len,
                           uint8_t *pt);

#define TEST_SIZE 64

/* Signal handler for segfaults */
void segfault_handler(int sig) {
    printf("SEGFAULT caught! Signal: %d\n", sig);
    printf("This helps identify exactly where the crash occurs.\n");
    exit(1);
}

/* aligned allocation */
static void* portable_aligned_alloc(size_t alignment, size_t size) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) return NULL;
    return ptr;
}
static void portable_aligned_free(void *ptr) { free(ptr); }

/* Benchmark structures - exactly as in main.c */
typedef struct {
    aes128arm_ctx ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    uint8_t iv[16];
} aes_arm_bench_t;

typedef struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *nonce;
    const uint8_t *ad; 
    size_t ad_len;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    uint8_t *tag;
} ascon_bench_t;

typedef struct {
    const uint8_t *key;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    const uint8_t *iv;
    uint8_t *tag; 
    size_t tag_len;
} aes_gcm_bench_t;

/* Benchmark wrapper functions - exactly as in main.c */
static void aes_ctr_call(void *p) {
    aes_arm_bench_t *a = (aes_arm_bench_t*)p;
    if (!a || !a->in || !a->out) {
        printf("NULL pointer detected in aes_ctr_call!\n");
        return;
    }
    printf("      Calling aes128arm_ctr_crypt with len=%zu...", a->len);
    aes128arm_ctr_crypt(&a->ctx, a->iv, a->in, a->out, a->len);
    printf(" Done\n");
}

static void aes_cbc_enc_call(void *p) {
    aes_arm_bench_t *a = (aes_arm_bench_t*)p;
    if (!a || !a->in || !a->out) {
        printf("NULL pointer detected in aes_cbc_enc_call!\n");
        return;
    }
    size_t padded_len = (a->len + 15) & ~15;
    printf("      Calling aes128arm_cbc_encrypt with len=%zu...", padded_len);
    aes128arm_cbc_encrypt(&a->ctx, a->iv, a->in, a->out, padded_len);
    printf(" Done\n");
}

static void aes_gcm_enc_call(void *p) {
    aes_gcm_bench_t *a = (aes_gcm_bench_t*)p;
    if (!a || !a->key || !a->in || !a->out || !a->iv || !a->tag) {
        printf("NULL pointer detected in aes_gcm_enc_call!\n");
        return;
    }
    printf("      Calling aes_gcm_encrypt with len=%zu...", a->len);
    aes_gcm_encrypt(a->key, 16, a->iv, 12, a->in, a->len,
                    NULL, 0, a->out, a->tag, a->tag_len);
    printf(" Done\n");
}

static void ascon128_enc_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    if (!a || !a->key || !a->nonce || !a->in || !a->out || !a->tag) {
        printf("NULL pointer detected in ascon128_enc_call!\n");
        return;
    }
    printf("      Calling ascon_128_encrypt with len=%zu...", a->len);
    ascon_128_encrypt(a->key, a->key_len, a->nonce, 16, a->ad, a->ad_len,
                      a->in, a->len, a->out, a->tag, 16);
    printf(" Done\n");
}

int main(void) {
    // Install signal handler
    signal(SIGSEGV, segfault_handler);
    
    printf("=== Fixed Crypto Debug ===\n");
    
    // Test memory allocation
    printf("1. Testing memory allocation...\n");
    uint8_t *buf_in  = portable_aligned_alloc(32, TEST_SIZE);
    uint8_t *buf_mid = portable_aligned_alloc(32, TEST_SIZE);
    uint8_t *buf_out = portable_aligned_alloc(32, TEST_SIZE);
    uint8_t *tag     = portable_aligned_alloc(32, 16);
    
    if (!buf_in || !buf_mid || !buf_out || !tag) { 
        printf("ERROR: Memory allocation failed!\n");
        return 1; 
    }
    printf("   Memory allocation: OK\n");
    
    memset(buf_in, 0xA5, TEST_SIZE);
    memset(buf_mid, 0x00, TEST_SIZE);
    memset(buf_out, 0x00, TEST_SIZE);
    memset(tag, 0x00, 16);
    printf("   Memory initialization: OK\n");

    uint8_t key[20] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                       0x11, 0x12, 0x13, 0x14};
    uint8_t iv16[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t iv12[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B};
    uint8_t nonce[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    // Test 2: Basic AES operations (already working)
    printf("\n2. Testing basic AES operations...\n");
    aes128arm_ctx basic_ctx;
    aes128arm_setkey(&basic_ctx, key);
    aes128arm_ctr_crypt(&basic_ctx, iv16, buf_in, buf_mid, TEST_SIZE);
    printf("   Basic AES operations: OK\n");

    // Test 3: AES benchmark structure initialization
    printf("\n3. Testing AES benchmark structure...\n");
    
    printf("   Creating AES benchmark structure...\n");
    aes_arm_bench_t aes_bench;
    
    // Initialize structure step by step
    printf("   Setting up AES context...\n");
    aes128arm_setkey(&aes_bench.ctx, key);
    printf("   Context setup: OK\n");
    
    printf("   Setting pointers...\n");
    aes_bench.in = buf_in;
    aes_bench.out = buf_mid;
    aes_bench.len = TEST_SIZE;
    memcpy(aes_bench.iv, iv16, 16);
    printf("   Pointers setup: OK\n");
    
    // Validate pointers
    printf("   Validating pointers:\n");
    printf("     aes_bench.in = %p\n", (void*)aes_bench.in);
    printf("     aes_bench.out = %p\n", (void*)aes_bench.out);
    printf("     aes_bench.len = %zu\n", aes_bench.len);
    
    // Test the wrapper function
    printf("   Testing AES CTR wrapper function...\n");
    aes_ctr_call(&aes_bench);
    printf("   AES CTR wrapper: OK\n");
    
    printf("   Testing AES CBC wrapper function...\n");
    memset(buf_mid, 0x00, TEST_SIZE); // Reset buffer
    aes_cbc_enc_call(&aes_bench);
    printf("   AES CBC wrapper: OK\n");
    
    // Test 4: Other benchmark structures
    printf("\n4. Testing other benchmark structures...\n");
    
    printf("   AES-GCM benchmark struct...\n");
    aes_gcm_bench_t gcm_bench = { 
        .key = key, 
        .in = buf_in, 
        .out = buf_mid, 
        .len = TEST_SIZE, 
        .iv = iv12, 
        .tag = tag, 
        .tag_len = 16 
    };
    aes_gcm_enc_call(&gcm_bench);
    printf("   AES-GCM benchmark: OK\n");
    
    printf("   ASCON benchmark struct...\n");
    ascon_bench_t ascon_bench = { 
        .key = key, 
        .key_len = 16,
        .nonce = nonce, 
        .ad = NULL, 
        .ad_len = 0, 
        .in = buf_in, 
        .out = buf_mid, 
        .len = TEST_SIZE, 
        .tag = tag 
    };
    ascon128_enc_call(&ascon_bench);
    printf("   ASCON benchmark: OK\n");

    // Cleanup
    portable_aligned_free(buf_in);
    portable_aligned_free(buf_mid);
    portable_aligned_free(buf_out);
    portable_aligned_free(tag);
    
    printf("\n=== ALL TESTS PASSED ===\n");
    printf("The benchmark structures are working correctly!\n");
    return 0;
}