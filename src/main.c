#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>

// For __rdtsc() on x86_64
#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

// Include project's AES and ASCON headers
#include "include/aes.h"
#include "include/ascon.h"

// The default number of iterations for smaller messages
#define DEFAULT_ITERATIONS 10000
// The number of iterations for larger messages
#define LARGE_MSG_ITERATIONS 1000
// The message size threshold to switch to fewer iterations
#define LARGE_MSG_THRESHOLD 65536 // 64 KB

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

// Helper function to get CPU cycles. Only works on x86_64.
static inline uint64_t get_cycles_ll() {
#if defined(__x86_64__) || defined(_M_X64)
    return __rdtsc();
#else
    // Return 0 on non-x86_64 architectures
    return 0;
#endif
}


// Unified function to benchmark performance metrics
void benchmark_algorithm(const char* name,
                         size_t key_len,
                         size_t nonce_len,
                         FILE* csv_file) {

    printf("--- Benchmarking Performance for: %s ---\n", name);
    printf("%-12s | %-15s | %-15s | %-15s | %-15s | %-12s | %-12s | %-12s\n", "Msg Size", "Enc (ns/op)", "Enc (MB/s)", "Dec (ns/op)", "Dec (MB/s)", "Mem (KB)", "Enc (cpb)", "Dec (cpb)");
    printf("------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    const size_t max_size = MESSAGE_SIZES[NUM_MESSAGE_SIZES - 1];
    uint8_t* plaintext = malloc(max_size);
    uint8_t* ciphertext = malloc(max_size + 16); // Accommodate tag
    uint8_t* decrypted_plaintext = malloc(max_size);
    uint8_t* key = malloc(key_len);
    uint8_t* nonce = malloc(nonce_len);
    uint8_t* tag = malloc(16);

    if (!plaintext || !ciphertext || !decrypted_plaintext || !key || !nonce || !tag) {
        printf("Memory allocation failed!\n");
        return;
    }

    // Pre-fill buffers with dummy data
    for (size_t i = 0; i < max_size; ++i) plaintext[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < key_len; ++i) key[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < nonce_len; ++i) nonce[i] = (uint8_t)(i & 0xff);

    for (int i = 0; i < NUM_MESSAGE_SIZES; ++i) {
        size_t current_size = MESSAGE_SIZES[i];
        uint64_t start_time, end_time, elapsed_encrypt, elapsed_decrypt;
        uint64_t start_cycles, end_cycles, elapsed_encrypt_cycles, elapsed_decrypt_cycles;

        // Dynamically set the number of iterations based on message size
        int iterations = (current_size < LARGE_MSG_THRESHOLD) ? DEFAULT_ITERATIONS : LARGE_MSG_ITERATIONS;
        
        double total_data_mb = (double)(iterations * current_size) / (1024 * 1024);
        unsigned long long total_data_bytes = (unsigned long long)iterations * current_size;

        // --- Benchmark Encryption ---
        start_time = get_time_ns();
        start_cycles = get_cycles_ll();
        for (int j = 0; j < iterations; ++j) {
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
        end_cycles = get_cycles_ll();
        end_time = get_time_ns();
        elapsed_encrypt = end_time - start_time;
        elapsed_encrypt_cycles = end_cycles - start_cycles;

        // --- Benchmark Decryption ---
        start_time = get_time_ns();
        start_cycles = get_cycles_ll();
        for (int j = 0; j < iterations; ++j) {
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
        end_cycles = get_cycles_ll();
        end_time = get_time_ns();
        elapsed_decrypt = end_time - start_time;
        elapsed_decrypt_cycles = end_cycles - start_cycles;

        // --- Calculate Metrics ---
        double avg_encrypt_ns = (double)elapsed_encrypt / iterations;
        double encrypt_mb_s = total_data_mb / ((double)elapsed_encrypt / 1e9);
        double avg_decrypt_ns = (double)elapsed_decrypt / iterations;
        double decrypt_mb_s = total_data_mb / ((double)elapsed_decrypt / 1e9);
        double encrypt_cpb = total_data_bytes > 0 ? (double)elapsed_encrypt_cycles / total_data_bytes : 0;
        double decrypt_cpb = total_data_bytes > 0 ? (double)elapsed_decrypt_cycles / total_data_bytes : 0;

        size_t total_allocated_bytes = current_size + (current_size + 16) + current_size + key_len + nonce_len + 16;
        double memory_footprint_kb = (double)total_allocated_bytes / 1024.0;

        // Print results to console
        printf("%-12zu | %-15.2f | %-15.2f | %-15.2f | %-15.2f | %-12.2f | %-12.2f | %-12.2f\n",
               current_size, avg_encrypt_ns, encrypt_mb_s, avg_decrypt_ns, decrypt_mb_s, memory_footprint_kb, encrypt_cpb, decrypt_cpb);

        // Write results to CSV file
        fprintf(csv_file, "%s,%zu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                name, current_size, avg_encrypt_ns, encrypt_mb_s, avg_decrypt_ns, decrypt_mb_s, memory_footprint_kb, encrypt_cpb, decrypt_cpb);
    }

    // Free allocated memory
    free(plaintext);
    free(ciphertext);
    free(decrypted_plaintext);
    free(key);
    free(nonce);
    free(tag);
    printf("\n");
}

int main() {
    FILE *results_file = fopen("benchmark_results.csv", "w");
    if (results_file == NULL) {
        printf("Error: Could not open benchmark_results.csv for writing.\n");
        return 1;
    }

    // Write CSV header
    fprintf(results_file, "Algorithm,Message Size (bytes),Encrypt Latency (ns/op),Encrypt Throughput (MB/s),Decrypt Latency (ns/op),Decrypt Throughput (MB/s),Memory Footprint (KB),Encrypt CPB,Decrypt CPB\n");

    printf("==================================================================================================================================================\n");
    printf("                                              Cryptographic Algorithm Performance Benchmark\n");
    printf("==================================================================================================================================================\n");
    printf("Iterations: %d (< 64KB messages), %d (>= 64KB messages)\n\n", DEFAULT_ITERATIONS, LARGE_MSG_ITERATIONS);

    benchmark_algorithm("AES-128-GCM", 16, 12, results_file);
    benchmark_algorithm("AES-128-CBC", 16, 16, results_file);
    benchmark_algorithm("AES-128-CTR", 16, 16, results_file);
    benchmark_algorithm("ASCON-128",   16, 16, results_file);
    benchmark_algorithm("ASCON-128a",  16, 16, results_file);
    benchmark_algorithm("ASCON-80pq",  20, 16, results_file);

    fclose(results_file);
    printf("Benchmark complete. Results have been saved to benchmark_results.csv\n");

    return 0;
}

