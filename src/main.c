#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>

// Include project's AES and ASCON headers
#include "include/aes.h"
#include "include/ascon.h"

// The number of iterations for each benchmark to get a stable average
#define NUM_ITERATIONS 10000

// The different message sizes to be tested
const size_t MESSAGE_SIZES[] = {
    16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304
};
const int NUM_MESSAGE_SIZES = sizeof(MESSAGE_SIZES) / sizeof(MESSAGE_SIZES[0]);

// Helper function to get the current time in nanoseconds using gettimeofday
uint64_t get_time_ns() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
}

// Function to benchmark latency
void benchmark_latency(const char* name,
                         size_t key_len,
                         size_t nonce_len) {

    printf("--- Benchmarking Latency for: %s ---\n", name);
    printf("%-15s | %-20s | %-20s\n", "Message Size", "Encrypt (ns/op)", "Decrypt (ns/op)");
    printf("----------------------------------------------------------\n");

    const size_t max_size = MESSAGE_SIZES[NUM_MESSAGE_SIZES - 1];
    uint8_t* plaintext = malloc(max_size);
    uint8_t* ciphertext = malloc(max_size + 16);
    uint8_t* decrypted_plaintext = malloc(max_size);
    uint8_t* key = malloc(key_len);
    uint8_t* nonce = malloc(nonce_len);
    uint8_t* tag = malloc(16);

    if (!plaintext || !ciphertext || !decrypted_plaintext || !key || !nonce || !tag) {
        printf("Memory allocation failed!\n");
        return;
    }

    for (size_t i = 0; i < max_size; ++i) plaintext[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < key_len; ++i) key[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < nonce_len; ++i) nonce[i] = (uint8_t)(i & 0xff);

    for (int i = 0; i < NUM_MESSAGE_SIZES; ++i) {
        size_t current_size = MESSAGE_SIZES[i];
        uint64_t start_time, end_time;
        double avg_encrypt_ns, avg_decrypt_ns;

        start_time = get_time_ns();
        for (int j = 0; j < NUM_ITERATIONS; ++j) {
            if (strcmp(name, "AES-128-GCM") == 0) {
                 aes_gcm_encrypt(key, 16, nonce, 12, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "AES-128-CBC") == 0) {
                 aes_cbc_encrypt(key, 16, nonce, 16, plaintext, current_size, ciphertext);
            } else if (strcmp(name, "AES-128-CTR") == 0) {
                 aes_ctr_crypt(key, 16, nonce, 16, plaintext, current_size, ciphertext);
            } else if (strcmp(name, "ASCON-128") == 0) {
                 ascon_128_encrypt(key, 16, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "ASCON-128a") == 0) {
                 ascon_128a_encrypt(key, 16, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "ASCON-80pq") == 0) {
                 ascon_80pq_encrypt(key, 20, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            }
        }
        end_time = get_time_ns();
        avg_encrypt_ns = (double)(end_time - start_time) / NUM_ITERATIONS;

        start_time = get_time_ns();
        for (int j = 0; j < NUM_ITERATIONS; ++j) {
            if (strcmp(name, "AES-128-GCM") == 0) {
                 aes_gcm_decrypt(key, 16, nonce, 12, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "AES-128-CBC") == 0) {
                aes_cbc_decrypt(key, 16, nonce, 16, ciphertext, current_size, decrypted_plaintext);
            } else if (strcmp(name, "AES-128-CTR") == 0) {
                aes_ctr_crypt(key, 16, nonce, 16, ciphertext, current_size, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-128") == 0) {
                ascon_128_decrypt(key, 16, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-128a") == 0) {
                ascon_128a_decrypt(key, 16, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-80pq") == 0) {
                ascon_80pq_decrypt(key, 20, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            }
        }
        end_time = get_time_ns();
        avg_decrypt_ns = (double)(end_time - start_time) / NUM_ITERATIONS;

        printf("%-15zu | %-20.2f | %-20.2f\n", current_size, avg_encrypt_ns, avg_decrypt_ns);
    }

    free(plaintext);
    free(ciphertext);
    free(decrypted_plaintext);
    free(key);
    free(nonce);
    free(tag);
    printf("\n");
}

// Function to benchmark throughput
void benchmark_throughput(const char* name,
                          size_t key_len,
                          size_t nonce_len) {

    printf("--- Benchmarking Throughput for: %s ---\n", name);
    printf("%-15s | %-20s | %-20s\n", "Message Size", "Encrypt (MB/s)", "Decrypt (MB/s)");
    printf("------------------------------------------------------------\n");

    const size_t max_size = MESSAGE_SIZES[NUM_MESSAGE_SIZES - 1];
    uint8_t* plaintext = malloc(max_size);
    uint8_t* ciphertext = malloc(max_size + 16);
    uint8_t* decrypted_plaintext = malloc(max_size);
    uint8_t* key = malloc(key_len);
    uint8_t* nonce = malloc(nonce_len);
    uint8_t* tag = malloc(16);

    if (!plaintext || !ciphertext || !decrypted_plaintext || !key || !nonce || !tag) {
        printf("Memory allocation failed!\n");
        return;
    }

    for (size_t i = 0; i < max_size; ++i) plaintext[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < key_len; ++i) key[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < nonce_len; ++i) nonce[i] = (uint8_t)(i & 0xff);

    for (int i = 0; i < NUM_MESSAGE_SIZES; ++i) {
        size_t current_size = MESSAGE_SIZES[i];
        uint64_t start_time, end_time;
        double encrypt_mb_s, decrypt_mb_s;
        double total_data_mb = (double)(NUM_ITERATIONS * current_size) / (1024 * 1024);

        start_time = get_time_ns();
        for (int j = 0; j < NUM_ITERATIONS; ++j) {
            if (strcmp(name, "AES-128-GCM") == 0) {
                 aes_gcm_encrypt(key, 16, nonce, 12, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "AES-128-CBC") == 0) {
                 aes_cbc_encrypt(key, 16, nonce, 16, plaintext, current_size, ciphertext);
            } else if (strcmp(name, "AES-128-CTR") == 0) {
                 aes_ctr_crypt(key, 16, nonce, 16, plaintext, current_size, ciphertext);
            } else if (strcmp(name, "ASCON-128") == 0) {
                 ascon_128_encrypt(key, 16, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "ASCON-128a") == 0) {
                 ascon_128a_encrypt(key, 16, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            } else if (strcmp(name, "ASCON-80pq") == 0) {
                 ascon_80pq_encrypt(key, 20, nonce, 16, plaintext, current_size, NULL, 0, ciphertext, tag, 16);
            }
        }
        end_time = get_time_ns();
        encrypt_mb_s = total_data_mb / ((double)(end_time - start_time) / 1e9);

        start_time = get_time_ns();
        for (int j = 0; j < NUM_ITERATIONS; ++j) {
            if (strcmp(name, "AES-128-GCM") == 0) {
                 aes_gcm_decrypt(key, 16, nonce, 12, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "AES-128-CBC") == 0) {
                aes_cbc_decrypt(key, 16, nonce, 16, ciphertext, current_size, decrypted_plaintext);
            } else if (strcmp(name, "AES-128-CTR") == 0) {
                aes_ctr_crypt(key, 16, nonce, 16, ciphertext, current_size, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-128") == 0) {
                ascon_128_decrypt(key, 16, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-128a") == 0) {
                ascon_128a_decrypt(key, 16, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            } else if (strcmp(name, "ASCON-80pq") == 0) {
                ascon_80pq_decrypt(key, 20, nonce, 16, ciphertext, current_size, NULL, 0, tag, 16, decrypted_plaintext);
            }
        }
        end_time = get_time_ns();
        decrypt_mb_s = total_data_mb / ((double)(end_time - start_time) / 1e9);

        printf("%-15zu | %-20.2f | %-20.2f\n", current_size, encrypt_mb_s, decrypt_mb_s);
    }

    free(plaintext);
    free(ciphertext);
    free(decrypted_plaintext);
    free(key);
    free(nonce);
    free(tag);
    printf("\n");
}


int main() {
    printf("==========================================================\n");
    printf("        Cryptographic Algorithm Performance Benchmark\n");
    printf("==========================================================\n");
    printf("Iterations per test: %d\n\n", NUM_ITERATIONS);

    // --- Latency Benchmarks ---
    benchmark_latency("AES-128-GCM", 16, 12);
    benchmark_latency("AES-128-CBC", 16, 16);
    benchmark_latency("AES-128-CTR", 16, 16);
    benchmark_latency("ASCON-128",   16, 16);
    benchmark_latency("ASCON-128a",  16, 16);
    benchmark_latency("ASCON-80pq",  20, 16);

    // --- Throughput Benchmarks ---
    benchmark_throughput("AES-128-GCM", 16, 12);
    benchmark_throughput("AES-128-CBC", 16, 16);
    benchmark_throughput("AES-128-CTR", 16, 16);
    benchmark_throughput("ASCON-128",   16, 16);
    benchmark_throughput("ASCON-128a",  16, 16);
    benchmark_throughput("ASCON-80pq",  20, 16);

    return 0;
}