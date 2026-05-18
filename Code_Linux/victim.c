#include <stdint.h>
#include <stddef.h>

// --- VICTIM DATA ---
// Padding ensures array1_size stays out of the cache until we want it there
uint8_t padding1[64]; 
unsigned int array1_size = 16;
uint8_t padding2[64]; 

uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

// Placing the secret here usually results in a small positive offset
//char *secret = "The Magic"; 
char *secret = 
    "Modern microprocessors are designed with a primary focus on maximizing execution speed through complex layers of optimization. Speculative execution remains one of the most critical advancements in this field, allowing a CPU to predict the future path of a program's control flow and execute instructions before the branch condition is actually resolved. While this yields significant performance gains, it introduces profound security risks because the hardware does not completely revert all microarchitectural changes if a prediction is incorrect. Specifically, the state of the data cache can be modified during transient execution, leaving behind a footprint that is visible to an attacker using timing analysis. By measuring the difference between a cache hit and a cache miss, an adversary can extract sensitive data character by character. This simulation demonstrates that hardware-level isolation can be bypassed. Furthermore, the vulnerability is not limited to conditional branches; it extends to indirect branches where the Branch Target Buffer can be poisoned to misdirect the CPU to a malicious gadget. These transient instructions may only exist for a few hundred nanoseconds, but that is more than enough time to load a secret byte into the L1 cache. Even with modern software mitigations like site isolation and degraded timer resolution, the underlying architectural flaw persists in billions of devices globally.";

uint8_t array2[256 * 4096];
uint8_t temp = 0; 

/**
 * The Vulnerable Function
 * We use intptr_t to handle both positive and negative offsets safely.
 */
void victim_function(intptr_t x) {
    if (x < (intptr_t)array1_size) {
        // Speculative window: CPU waits for array1_size from DRAM
        temp &= array2[array1[x] * 4096];
    }
}
