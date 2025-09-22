/*
 * main.c — Level-3 Benchmark Harness (ARM version)
 *
 * AES-128 (CTR, CBC, GCM) using aes_arm.c
 * ASCON-128, ASCON-128a, ASCON-80pq using ascon_core_arm.c
 *
 * Benchmarks sizes: 16 → ... → 4 MB
 * Iterations: 10000 for <=64KB, 1000 for >64KB
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "include/aes_arm.h"
#include "include/ascon.h"

/* AES-GCM wrappers from aes_gcm.c (unchanged) */
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
#define MAX_SIZE (4 * 1024 * 1024)
#define ALIGN 32

/* aligned allocation */
static void* portable_aligned_alloc(size_t alignment, size_t size) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) return NULL;
    return ptr;
}
static void portable_aligned_free(void *ptr) { free(ptr); }

/* === Cycle counter for ARM === */
#if defined(__aarch64__) && defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/sysctl.h>
static inline uint64_t rdcycles(void) { return mach_absolute_time(); }
static inline uint64_t get_freq_hz(void) {
    uint64_t freq = 0; size_t sz = sizeof(freq);
    if (sysctlbyname("hw.tbfrequency", &freq, &sz, NULL, 0) == 0 && freq > 0) return freq;
    return 0;
}
#elif defined(__aarch64__)
static inline uint64_t rdcycles(void) { uint64_t v; asm volatile("mrs %0, cntvct_el0" : "=r"(v)); return v; }
static inline uint64_t get_freq_hz(void) { uint64_t v; asm volatile("mrs %0, cntfrq_el0" : "=r"(v)); return v; }
#else
#error "This main.c is ARM-only"
#endif

static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* run func with iterations, return avg ns/op and cycles/op */
static void run_bench(void (*func)(void*), void *arg, int iterations,
                      double *avg_ns, double *avg_cycles) {
    double total_ns = 0.0, total_cycles = 0.0;
    for (int i = 0; i < iterations; i++) {
        uint64_t c0 = rdcycles();
        uint64_t n0 = now_ns();
        func(arg);
        uint64_t n1 = now_ns();
        uint64_t c1 = rdcycles();
        total_ns     += (double)(n1 - n0);
        total_cycles += (double)(c1 - c0);
    }
    *avg_ns     = total_ns / (double)iterations;
    *avg_cycles = total_cycles / (double)iterations;
}

/* === AES benchmark structs/wrappers === */
typedef struct {
    aes128arm_ctx ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    uint8_t iv[16];
} aes_arm_bench_t;

static void aes_ctr_call(void *p) {
    aes_arm_bench_t *a = (aes_arm_bench_t*)p;
    aes128arm_ctr_crypt(&a->ctx, a->iv, a->in, a->out, a->len);
}
static void aes_cbc_enc_call(void *p) {
    aes_arm_bench_t *a = (aes_arm_bench_t*)p;
    aes128arm_cbc_encrypt(&a->ctx, a->iv, a->in, a->out, a->len);
}
static void aes_cbc_dec_call(void *p) {
    aes_arm_bench_t *a = (aes_arm_bench_t*)p;
    aes128arm_cbc_decrypt(&a->ctx, a->iv, a->in, a->out, a->len);
}

/* AES-GCM (unchanged, still uses OpenSSL GCM) */
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

/* === ASCON benchmark (same as before) === */
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

/* CSV writer */
static void write_csv(FILE *csv, const char *alg, size_t size,
                      double enc_ns, double enc_cycles,
                      double dec_ns, double dec_cycles) {
    double enc_throughput = ((double)size / 1e6) / (enc_ns / 1e9);
    double dec_throughput = ((double)size / 1e6) / (dec_ns / 1e9);
    double mem_kb = (double)size / 1024.0;
    double enc_ns_byte = enc_ns / (double)size;
    double dec_ns_byte = dec_ns / (double)size;
#if defined(__aarch64__) && defined(__APPLE__)
    double enc_cpb = enc_ns_byte;
    double dec_cpb = dec_ns_byte;
#else
    double enc_cpb = enc_cycles / (double)size;
    double dec_cpb = dec_cycles / (double)size;
#endif
    fprintf(csv, "%s,%zu,%.4f,%.2f,%.4f,%.2f,%.2f,%.6f,%.6f,%.6f,%.6f\n",
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

#if defined(__aarch64__) && defined(__APPLE__)
    fprintf(csv, "Algorithm,Message Size (bytes),Encrypt Latency (ns/op),Encrypt Throughput (MB/s),"
                 "Decrypt Latency (ns/op),Decrypt Throughput (MB/s),Memory Footprint (KB),"
                 "Encrypt (ns/byte),Decrypt (ns/byte),Encrypt CPB*,Decrypt CPB*\n");
#else
    fprintf(csv, "Algorithm,Message Size (bytes),Encrypt Latency (ns/op),Encrypt Throughput (MB/s),"
                 "Decrypt Latency (ns/op),Decrypt Throughput (MB/s),Memory Footprint (KB),"
                 "Encrypt (ns/byte),Decrypt (ns/byte),Encrypt CPB,Decrypt CPB\n");
#endif

    uint8_t *buf_in  = portable_aligned_alloc(ALIGN, MAX_SIZE);
    uint8_t *buf_mid = portable_aligned_alloc(ALIGN, MAX_SIZE);
    uint8_t *buf_out = portable_aligned_alloc(ALIGN, MAX_SIZE);
    uint8_t *tag     = portable_aligned_alloc(ALIGN, 16);
    if (!buf_in || !buf_mid || !buf_out || !tag) { perror("malloc"); return 1; }
    memset(buf_in, 0xA5, MAX_SIZE);

    uint8_t key[20] = {0};
    uint8_t iv16[16] = {0};
    uint8_t iv12[12] = {0};
    uint8_t nonce[16] = {0};

    uint64_t freq = get_freq_hz();
    if (freq > 0)
        printf("[INFO] cycle counter frequency = %llu Hz (~%.2f ns/tick)\n",
               (unsigned long long)freq, 1e9 / (double)freq);

    for (size_t size = MIN_SIZE; size <= MAX_SIZE; size *= 4) {
        int iterations = (size <= 65536) ? 10000 : 1000;
        printf("=== %zu bytes, %d iterations ===\n", size, iterations);

        double enc_ns, enc_cycles, dec_ns, dec_cycles;

        /* AES-CTR */
        aes_arm_bench_t actr = { .in = buf_in, .out = buf_mid, .len = size };
        memcpy(actr.iv, iv16, 16);
        aes128arm_setkey(&actr.ctx, key);
        run_bench(aes_ctr_call, &actr, iterations, &enc_ns, &enc_cycles);
        run_bench(aes_ctr_call, &actr, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-CTR", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* AES-CBC */
        aes128arm_setkey(&actr.ctx, key);
        run_bench(aes_cbc_enc_call, &actr, iterations, &enc_ns, &enc_cycles);
        aes128arm_cbc_encrypt(&actr.ctx, actr.iv, buf_in, buf_mid, size);
        actr.in = buf_mid; actr.out = buf_out;
        run_bench(aes_cbc_dec_call, &actr, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-CBC", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* AES-GCM */
        aes_gcm_bench_t agcm = { key, buf_in, buf_mid, size, iv12, tag, 16 };
        run_bench(aes_gcm_enc_call, &agcm, iterations, &enc_ns, &enc_cycles);
        aes_gcm_enc_call(&agcm);
        run_bench(aes_gcm_dec_call, &agcm, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "AES-128-GCM", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-128 */
        ascon_bench_t a128 = { key, nonce, NULL, 0, buf_in, buf_mid, size, tag };
        run_bench(ascon128_enc_call, &a128, iterations, &enc_ns, &enc_cycles);
        ascon128_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon128_dec_call, &a128, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "Ascon-128", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-128a */
        a128.in = buf_in; a128.out = buf_mid; a128.len = size;
        run_bench(ascon128a_enc_call, &a128, iterations, &enc_ns, &enc_cycles);
        ascon128a_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon128a_dec_call, &a128, iterations, &dec_ns, &dec_cycles);
        write_csv(csv, "Ascon-128a", size, enc_ns, enc_cycles, dec_ns, dec_cycles);

        /* ASCON-80pq */
        a128.key = key; // first 20 bytes used
        a128.in = buf_in; a128.out = buf_mid;
        run_bench(ascon80pq_enc_call, &a128, iterations, &enc_ns, &enc_cycles);
        ascon80pq_enc_call(&a128);
        a128.in = buf_mid; a128.out = buf_out;
        run_bench(ascon80pq_dec_call, &a128, iterations, &dec_ns, &dec_cycles);
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
