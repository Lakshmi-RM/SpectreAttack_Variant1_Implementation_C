Spectre Attacks: Exploiting Speculative Execution
Author: Lakshmi Ramanathan
Degree: MS in Computer Engineering, University of Central Florida
This repository contains the source code, experimental data, and final report for the replication of the Spectre Variant 1 (Bounds Check Bypass implemented in C) attack. The project evaluates the efficacy of microarchitectural side-channels across two distinct hardware and software environments: Intel Xeon (Linux) and AMD Ryzen (Windows).

1. Project Structure
The submission is organized as follows:
* Code_Linux/ : Implementation for the UCF Eustis cluster environment (Linux OS). 
o attack.c: Attacker logic using clock_gettime and __rdtsc. 
o victim.c: Vulnerable code containing the secret string and padding to prevent cache interference.

* Code_Windows/: Implementation for local AMD-based Windows system. 
o attackvictim.c: Unified implementation (combined attacker/victim) using QueryPerformanceCounter.

* Report/:
o LakshmiRamanathan_ProjectReport_Spectre.pdf: Final research paper in IEEE format.
o EvaluationResults_Screenshots.pdf: Includes the screenshots of the evaluation results obtained for different strings in both Windows and Linux

2. System Specifications
Linux Environment (Eustis)
* OS: Ubuntu 24.04.4 LTS (Kernel 6.8.0). 
* Hardware: Intel(R) Xeon(R) E5430 @ 2.66 GHz. 
* Setup: Requires connection to the UCF campus network/VPN to access the Eustis cluster

Windows Environment (Local) 
* OS: Microsoft Windows 11 Home. 
* Hardware: AMD Ryzen 9 5900HS with Radeon Graphics. 
* Compiler: MSVC (Microsoft Visual C++) via VS Code. 

3. How to Reproduce Results
Linux (Eustis)
1. Navigate to the Code_Linux directory.
2. Manual compilation using Command prompt "gcc victim.c attack.c -o spectre_attack -O0"
3. Run the executable "./spectre_attack"

Windows (Local)
1. Open Code_Windows/attackvictim.c in VS Code.
2. Compile and run using the integrated C/C++ build tools.

4. Configuration Details
Microarchitectural attacks are highly environment-dependent. If the attack fails to leak data, adjust the following constants in the source code:
* CACHE_HIT_THRESHOLD:
o Linux: Set to 120 (due to shared server noise on Eustis).
o Windows: Set to 80 (local execution environment).

* Cache Stride:
o Linux uses a stride of 4096 to ensure unique cache line mapping.
o Windows implementation uses a stride of 512.

5. Experimental Observations 
* Accuracy: Achieved an average accuracy of 99.84% across both platforms. 
* Leakage Rate: Linux (Eustis) yielded a higher rate of ~817 BPS, while the Windows environment averaged ~271 BPS. 
* Mitigation Awareness: JavaScript implementation was excluded due to modern browser-level mitigations and strict project timelines. 

6. References
Paul Kocher1, Jann Horn2, Anders Fogh3, Daniel Genkin4, Daniel Gruss5, Werner Haas6, Mike Hamburg7, Moritz Lipp5, Stefan Mangard5, Thomas Prescher6, Michael Schwarz5, Yuval Yarom, "Spectre Attacks: Exploiting Speculative Execution", 2019 IEEE Symposium on Security and Privacy. [Online]. Available: https://ieeexplore.ieee.org/document/8835233 
