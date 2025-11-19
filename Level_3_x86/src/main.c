/*
 * main.c
 *
 * CryptoBench — Level-3 Benchmark Harness
 *   - AES-128 AES-NI (CTR, CBC)
 *   - AES-128-GCM (aes_gcm.c wrappers)
 *   - Ascon-128, Ascon-128a, Ascon-80pq (SIMD permutation AEAD)
 *
 * Benchmarks sizes: 16 -> 64 -> 256 -> ... -> 4 MB
 * Iterations: 10000 for <= 64KB, 1000 for >64KB
 * Results -> benchmark_results.csv (same format as Level-2)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>   // __rdtsc
#include <errno.h>

#ifdef _WIN32
#include <malloc.h>  // for _aligned_malloc / _aligned_free
#endif

#include "include/aes_ni.h"
#include "include/ascon.h"

/* AES-GCM wrappers from aes_gcm.c */
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

#define MIN_SIZE 16
#define MAX_SIZE (4 * 1024 * 1024) /* 4 MB */
#define ALIGN 32

/* portable aligned allocation */
static void* portable_aligned_alloc(size_t alignment, size_t size) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
#endif
}

static void portable_aligned_free(void *ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

/* helpers */
static inline uint64_t rdtsc(void) { return __rdtsc(); }

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* run func with iterations, return avg ns/op and cycles/op */
static void run_bench(void (*func)(void*), void *arg, size_t bytes,
                      int iterations, double *avg_ns, double *avg_cycles) {
    double total_ns = 0.0, total_cycles = 0.0;
    for (int i = 0; i < iterations; i++) {
        uint64_t c0 = rdtsc();
        uint64_t n0 = now_ns();

        func(arg);

        uint64_t n1 = now_ns();
        uint64_t c1 = rdtsc();

        total_ns += (double)(n1 - n0);
        total_cycles += (double)(c1 - c0);
    }
    *avg_ns = total_ns / (double)iterations;
    *avg_cycles = total_cycles / (double)iterations;
}

/* AES-CTR benchmark struct */
typedef struct {
    aes128ni_ctx ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    uint8_t iv[16];
} aes_bench_t;

static void aes_ctr_call(void *p) {
    aes_bench_t *a = (aes_bench_t*)p;
    aes128ni_ctr_crypt(&a->ctx, a->iv, a->in, a->out, a->len);
}

static void aes_cbc_enc_call(void *p) {
    aes_bench_t *a = (aes_bench_t*)p;
    aes128ni_cbc_encrypt(&a->ctx, a->iv, a->in, a->out, a->len);
}

static void aes_cbc_dec_call(void *p) {
    aes_bench_t *a = (aes_bench_t*)p;
    aes128ni_cbc_decrypt(&a->ctx, a->iv, a->in, a->out, a->len);
}

/* AES-GCM benchmark struct */
typedef struct {
    const uint8_t *key;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    const uint8_t *iv;
    uint8_t *tag; size_t tag_len;
} aes_gcm_bench_t;

static void aes_gcm_enc_call(void *p) {
    aes_gcm_bench_t *a = (aes_gcm_bench_t*)p;
    aes_gcm_encrypt(a->key, 16, a->iv, 12, a->in, a->len,
                    NULL, 0, a->out, a->tag, a->tag_len);
}

static void aes_gcm_dec_call(void *p) {
    aes_gcm_bench_t *a = (aes_gcm_bench_t*)p;
    aes_gcm_decrypt(a->key, 16, a->iv, 12, a->out, a->len,
                    NULL, 0, a->tag, a->tag_len, (uint8_t*)a->in);
}

/* ASCON benchmark struct */
typedef struct {
    const uint8_t *key;
    const uint8_t *nonce;
    const uint8_t *ad; size_t ad_len;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    uint8_t *tag;
} ascon_bench_t;

static void ascon128_enc_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_128_encrypt(a->key, 16, a->nonce, 16, a->ad, a->ad_len,
                      a->in, a->len, a->out, a->tag, 16);
}
static void ascon128_dec_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_128_decrypt(a->key, 16, a->nonce, 16, a->ad, a->ad_len,
                      a->in, a->len, a->tag, 16, a->out);
}

static void ascon128a_enc_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_128a_encrypt(a->key, 16, a->nonce, 16, a->ad, a->ad_len,
                       a->in, a->len, a->out, a->tag, 16);
}
static void ascon128a_dec_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_128a_decrypt(a->key, 16, a->nonce, 16, a->ad, a->ad_len,
                       a->in, a->len, a->tag, 16, a->out);
}

static void ascon80pq_enc_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_80pq_encrypt(a->key, 20, a->nonce, 16, a->ad, a->ad_len,
                       a->in, a->len, a->out, a->tag, 16);
}
static void ascon80pq_dec_call(void *p) {
    ascon_bench_t *a = (ascon_bench_t*)p;
    ascon_80pq_decrypt(a->key, 20, a->nonce, 16, a->ad, a->ad_len,
                       a->in, a->len, a->tag, 16, a->out);
}

/* write CSV row */
static void write_csv(FILE *csv, const char *alg, size_t size,
                      double enc_ns, double enc_cycles,
                      double dec_ns, double dec_cycles) {
    double enc_throughput = ((double)size / 1e6) / (enc_ns / 1e9);
    double dec_throughput = ((double)size / 1e6) / (dec_ns / 1e9);
    double mem_kb = (double)size / 1024.0;
    double enc_ns_byte = enc_ns / (double)size;
    double dec_ns_byte = dec_ns / (double)size;
    double enc_cpb = enc_cycles / (double)size;
    double dec_cpb = dec_cycles / (double)size;

    fprintf(csv, "%s,%zu,%.4f,%.2f,%.4f,%.2f,%.2f,%.6f,%.6f,%.4f,%.4f\n",
            alg, size,
            enc_ns, enc_throughput,
            dec_ns, dec_throughput,
            mem_kb,
            enc_ns_byte, dec_ns_byte,
            enc_cpb, dec_cpb);
}

/* --- main --- */
int main(void) {
    FILE *csv = fopen("benchmark_results.csv", "w");
    if (!csv) { perror("fopen"); return 1; }
    fprintf(csv, "Algorithm,Message Size (bytes),Encrypt Latency (ns/op),Encrypt Throughput (MB/s),"
                 "Decrypt Latency (ns/op),Decrypt Throughput (MB/s),Memory Footprint (KB),"
                 "Encrypt (ns/byte),Decrypt (ns/byte),Encrypt CPB,Decrypt CPB\n");

    uint8_t *buf_in, *buf_mid, *buf_out, *tag;
    buf_in  = portable_aligned_alloc(ALIGN, MAX_SIZE);
    buf_mid = portable_aligned_alloc(ALIGN, MAX_SIZE);
    buf_out = portable_aligned_alloc(ALIGN, MAX_SIZE);
    tag     = portable_aligned_alloc(ALIGN, 16);

    if (!buf_in || !buf_mid || !buf_out || !tag) {
        perror("aligned_alloc");
        return 1;
    }
    memset(buf_in, 0xA5, MAX_SIZE);

    uint8_t key[20] = {0};
    uint8_t iv16[16] = {0};
    uint8_t iv12[12] = {0};
    uint8_t nonce[16] = {0};

    for (size_t size = MIN_SIZE; size <= MAX_SIZE; size *= 4) {
        int iterations = (size <= 65536) ? 10000 : 1000;
        printf("=== %zu bytes, %d iterations ===\n", size, iterations);

        double enc_ns, enc_cycles, dec_ns, dec_cycles;

        /* AES-CTR */
        aes_bench_t actr = {0};
        aes128ni_setkey(&actr.ctx, key);
        actr.in = buf_in; actr.out = buf_mid; actr.len = size;
        memcpy(actr.iv, iv16, 16);
        run_bench(aes_ctr_call, &actr, size, iterations, &enc_ns, &enc_cycles);
        run_bench(aes_ctr_call, &actr, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-CTR", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* AES-CBC */
        memcpy(actr.iv, iv16, 16);
        run_bench(aes_cbc_enc_call, &actr, size, iterations, &enc_ns, &enc_cycles);
        aes128ni_cbc_encrypt(&actr.ctx, actr.iv, buf_in, buf_mid, size); // prepare ciphertext
        actr.in = buf_mid; actr.out = buf_out;
        run_bench(aes_cbc_dec_call, &actr, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-CBC", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* AES-GCM */
        aes_gcm_bench_t agcm = {0};
        agcm.key = key; agcm.iv = iv12; agcm.in = buf_in; agcm.out = buf_mid; agcm.len = size; agcm.tag = tag; agcm.tag_len = 16;
        run_bench(aes_gcm_enc_call, &agcm, size, iterations, &enc_ns, &enc_cycles);
        aes_gcm_enc_call(&agcm); // produce ciphertext
        run_bench(aes_gcm_dec_call, &agcm, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-GCM", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-128 */
        ascon_bench_t a128 = {0};
        a128.key = key; a128.nonce = nonce; a128.ad = NULL; a128.ad_len = 0;
        a128.in = buf_in; a128.out = buf_mid; a128.len = size; a128.tag = tag;
        run_bench(ascon128_enc_call, &a128, size, iterations, &enc_ns, &enc_cycles);
        ascon128_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon128_dec_call, &a128, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "Ascon-128", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-128a */
        a128.in = buf_in; a128.out = buf_mid; a128.len = size; a128.tag = tag;
        run_bench(ascon128a_enc_call, &a128, size, iterations, &enc_ns, &enc_cycles);
        ascon128a_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon128a_dec_call, &a128, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "Ascon-128a", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-80pq */
        a128.key = key; // first 20 bytes used
        a128.in = buf_in; a128.out = buf_mid; a128.len = size; a128.tag = tag;
        run_bench(ascon80pq_enc_call, &a128, size, iterations, &enc_ns, &enc_cycles);
        ascon80pq_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon80pq_dec_call, &a128, size, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "Ascon-80pq", size, enc_ns, enc_cycles, dec_ns, dec_cycles);
    }

    fclose(csv);
    portable_aligned_free(buf_in);
    portable_aligned_free(buf_mid);
    portable_aligned_free(buf_out);
    portable_aligned_free(tag);
    printf("Results -> benchmark_results.csv\n");
    return 0;
}
