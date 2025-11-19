# CryptoBench
## A Comparative Performance Analysis of AES and ASCON on HPC Architectures

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue.svg)](https://isocpp.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

A major project to conduct a definitive performance comparison between key variants of the established AES and the next-generation ASCON cryptographic suites on modern high-performance architectures.

---

## 📖 Table of Contents

* [Project Overview](#-project-overview)
* [🚀 Objectives](#-objectives)
* [⚙️ Algorithms Under Test](#️-algorithms-under-test)
* [🔬 Benchmarking Methodology](#-benchmarking-methodology)
* [🛠️ Implementation Details](#️-implementation-details)
* [📂 Repository Structure](#-repository-structure)
* [🏁 Getting Started](#-getting-started)
* [📈 Expected Outcomes](#-expected-outcomes)
* [📅 Project Timeline](#-project-timeline)
* [📜 License](#-license)
* [🧑‍🏫 Supervision and Authors](#-supervision-and-authors)
* [📚 References](#-references)

---

## 🌟 Project Overview

The modern digital landscape is built on secure data communication, with cryptographic algorithms at its core. The **Advanced Encryption Standard (AES)** has been the dominant standard for years, especially with hardware acceleration like AES-NI. However, the rise of IoT and lightweight devices has led to the development of new standards, culminating in NIST's selection of the **ASCON** family for lightweight cryptography in 2023.

This project addresses the lack of a direct, apples-to-apples performance comparison between the most relevant variants of AES and ASCON on modern processor architectures. We aim to provide standardized, in-depth benchmarking data that accounts for different operational modes, hardware-specific optimizations, and the performance trade-offs associated with varying data sizes and security goals, including post-quantum resistance.

---

## 🚀 Objectives

The primary goals of this project are:

1.  **Implementation:** Develop highly optimized C/C++ implementations for all specified algorithms, leveraging hardware acceleration (AES-NI) for AES and bit-sliced, SIMD-optimized approaches for ASCON.
2.  **Benchmarking:** Design and execute a robust benchmarking suite to measure key performance metrics, including Cycles Per Byte (CPB), throughput, latency, code size, and memory footprint.
3.  **Analysis:** Analyze performance data across a spectrum of message sizes on diverse architectures (AMD64 and ARMv8) and at various optimization levels.
4.  **Reporting:** Present the findings in a formal report with detailed tables, figures, and a thorough discussion of the results and their implications.

---

## ⚙️ Algorithms Under Test

This study will directly compare three key AES modes with three strategic ASCON variants.

| Family | Variant | Description |
| :--- | :--- | :--- |
| **AES** | `AES-GCM` | Galois/Counter Mode; provides high-performance authenticated encryption. |
| | `AES-CBC` | Cipher Block Chaining; a legacy mode with sequential, non-parallelizable encryption. |
| | `AES-CTR` | Counter Mode; a highly parallelizable mode that effectively turns the block cipher into a stream cipher. |
| **ASCON** | `ASCON-128` | The primary lightweight variant selected by NIST, offering a 128-bit security level. |
| | `ASCON-128a` | A higher-throughput variant that processes more data per permutation. |
| | `ASCON-80pq` | A variant designed to offer resistance against attacks from future large-scale quantum computers. |

---

## 🔬 Benchmarking Methodology

### Architectural Diversity
To ensure comprehensive results, benchmarks are conducted across multiple modern environments:
* **CPU Architectures:**
    * **AMD64 (x86-64):** Representing high-performance desktop and server computing.
    * **ARMv8 (AArch64):** Representing mobile and embedded systems.
* **Operating Systems & Compilers:**
    * Linux (Ubuntu 22.04 LTS) with GCC/Clang.
    * Windows 11 with MSVC.
    * macOS with Clang (on ARMv8).

### Layered Code Optimization
To understand the source of performance gains, we benchmark four distinct optimization levels for each algorithm:

* **Level 0 (Baseline):** Unoptimized C implementation (`-O0`).
* **Level 1 (Compiler Optimized):** Aggressively optimized with compiler flags (`-O3 -march=native`).
* **Level 2 (Manually Optimized):** Software-level optimizations like loop unrolling.
* **Level 3 (Hardware Accelerated):** Final implementation using AES-NI or SIMD intrinsics.

### Key Performance Metrics
Tests are repeated thousands of times to ensure statistical reliability, reporting the median value for:
* **Throughput (GB/s):** Speed of bulk data processing.
* **Cycles Per Byte (CPB):** A clock-speed-independent measure of efficiency.
* **Latency (ns/op):** Time for a single, small message operation.
* **Code Size (KB):** Compiled binary size of the cryptographic functions.
* **Memory Footprint (KB):** Run-time memory usage.

---

## 🛠️ Implementation Details

The core benchmark is written in **C**, leveraging platform-specific compiler intrinsics for the highest level of optimization.

* **AES (GCM, CBC, CTR):** A common, hardware-accelerated AES core is developed using **AES-NI** intrinsics (e.g., `<wmmintrin.h>`). For GCM, Galois Field multiplication is accelerated using the `PCLMULQDQ` instruction.
* **ASCON (128, 128a, 80pq):** Implemented using a common, parameterized bit-sliced engine. This technique allows a single SIMD instruction (e.g., **AVX2** on AMD64, **NEON** on ARM) to perform a bitwise operation on 64 states simultaneously, enabling massive parallelism.

---

## 📂 Repository Structure
.\
├── 📄 .gitignore\
├── 📜 LICENSE\
├── 📖 README.md\
├── 📁 src/\
│   ├── aes/\
│   │   ├── aes_gcm.c\
│   │   └── ...\
│   ├── ascon/\
│   │   ├── ascon_128.c\
│   │   └── ...\
│   └── main.c\
├── 📁 include/\
│   ├── aes.h\
│   └── ascon.h\
├── 📁 scripts/\
│   ├── plot_results.py\
│   └── run_benchmarks.sh\
├── 📁 results/\
│   └── benchmark_data.csv\
└── Makefile

---

## 🏁 Getting Started

### Prerequisites
* A C/C++ compiler (GCC, Clang, or MSVC)
* `make` build automation tool

### Building and Running the Benchmark
1.  **Clone the repository:**
    ```sh
    git clone [the repository link]
    cd crypto-performance-analysis
    ```

2.  **Compile the source code:**
    The Makefile provides targets for different optimization levels.
    ```sh
    # Build with Level 3 (Hardware Acceleration)
    make all

    # Build a specific level
    make level0
    ```

3.  **Run the benchmark suite:**
    ```sh
    ./benchmark
    ```
    Results will be printed to the console and saved in the `/results` directory.

---

## 📈 Expected Outcomes

We hypothesize the following findings:

1.  **Peak Throughput:** AES-GCM and AES-CTR will show the highest throughput for large messages on AMD64 due to dedicated AES-NI hardware.
2.  **Small Message Latency:** ASCON-128a is expected to have lower latency for small messages due to its low setup overhead.
3.  **Legacy Performance:** AES-CBC encryption will be significantly slower than all parallelizable modes.
4.  **Post-Quantum Cost:** ASCON-80pq will be measurably slower than ASCON-128/128a, quantifying the performance penalty for post-quantum resistance.
5.  **Architectural Differences:** The performance gap between AES and ASCON may be smaller on ARMv8, where ASCON's bit-sliced SIMD implementation could be highly effective.

---

## 📅 Project Timeline

The project is executed over a 15-week period from August 25, 2025, to December 5, 2025.

* **Phase 1: Research and Setup** (Weeks 1-3: Aug 25 – Sep 12)
* **Phase 2: Implementation** (Weeks 4-7: Sep 15 – Oct 10)
* **Phase 3: Benchmarking and Data Collection** (Weeks 8-11: Oct 13 – Nov 7)
* **Phase 4: Analysis and Discussion** (Weeks 12-14: Nov 10 – Nov 28)
* **Phase 5: Finalization and Submission** (Week 15: Dec 1 – Dec 5)

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🧑‍🏫 Supervision and Authors

### Under the supervision of
* **Professor Jyotiprakash Mishra**

### Authors
* Ayush Maity - 2205545
* Ujaala Rajgariha - 22053996
* Arya Rustagi - 22053927
* Yash Saksena - 22054004
* Shreyas Chakraborty - 2205593
* Kinshuk Bhattacharya - 22053962

---

## 📚 References

[1] Daemen, Joan, and Rijmen, Vincent. The Advanced Encryption Standard (AES) Development Effort. Applied Cryptography and Network Security. 2002.

[2] NIST. Lightweight Cryptography Competition. NIST Computer Security Resource Center.

[3] Dobraunig, Christoph, et al. ASCON. Design and Analysis of Modern Cryptosystems. 2016.

[4] Intel. Intel Advanced Encryption Standard Instructions (AES-NI). Intel Developer Zone.

[5] Patterson, David A., and Hennessy, John L. Computer Architecture: A Quantitative Approach. Morgan Kaufmann. 2017.


---

## 📦 Additional Files

A compressed archive named **`RESULTS.zip`** is included separately with this submission.  
It contains all raw and processed benchmark outputs, including:

* Full CSV datasets for each optimization level  
* Architecture-specific performance logs  
* Generated plots and figures  
* Intermediate files used for the final analysis  

Please extract `RESULTS.zip` to access the complete set of performance results referenced in the report.

