# C++ DAST Security Orchestrator: Memory Safety & Heap Vulnerability Verification Suite

A high-performance Dynamic Application Security Testing (DAST) pipeline designed to automatically compile, instrument, fuzz, detect, and symbolicate runtime memory safety vulnerabilities in C and C++ source code.

Equipped with **1,000 built-in test vectors** across **133 exploit tiers** and mapped to **59 CWE identifiers**, this suite provides automated detection of Heap Buffer Overflows (CWE-122), Format String Bugs (CWE-134), Use-After-Free (CWE-416), Double Free (CWE-415), Integer Wraparounds (CWE-190/680), and related memory safety violations.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Instrumentation](#architecture--instrumentation)
- [CWE Coverage Catalog](#cwe-coverage-catalog)
- [Test Suite Breakdown (1,000 Test Cases)](#test-suite-breakdown-1000-test-cases)
- [Quick Start & Commands](#quick-start--commands)
- [Included Benchmark Target Files](#included-benchmark-target-files)
- [Understanding the Scorecard & Reports](#understanding-the-scorecard--reports)
- [Platform Safeguards & Engineering Details](#platform-safeguards--engineering-details)

---

## Overview

Traditional static analysis (SAST) often produces high false-positive rates or fails on complex runtime heap behaviors, pointer aliasing, and allocator quantum alignment. 

This DAST Orchestrator solves this by using **active compiler sanitization combined with black-box and boundary fuzzing**:
1. **Compilation & Sanitization**: Compiles the target C++ program with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).
2. **Dynamic Process Isolation**: Executes each test case in a sandboxed child process with strict timeouts (default: 5.0s per test).
3. **Real-time Detection & Tracking**: Intercepts hardware signals (SIGSEGV, SIGABRT, SIGBUS), ASan shadow memory violations, and UBSan traps.
4. **Automated Crash Symbolication**: Parses ASan stack traces and pinpoints the exact line number and function where the memory corruption happened.
5. **Auditing & Reporting**: Generates a live terminal scorecard and a comprehensive, structured JSON report (`dast_report.json`).

---

## Architecture & Instrumentation

```
  ┌────────────────────────────────────────────────────────┐
  │                 Target C++ Source Code                 │
  └──────────────────────────┬─────────────────────────────┘
                             │
            ┌────────────────▼────────────────┐
            │   Clang++ / G++ Sanitizer Build │
            │   -fsanitize=address,undefined  │
            │   -g -O1 -fno-omit-frame-pointer│
            └────────────────┬────────────────┘
                             │
            ┌────────────────▼────────────────┐
            │       Dynamic Test Engine       │
            │    1,000 Input Test Vectors     │
            │ (Subprocess isolation & timeout)│
            └──────┬──────────────────┬───────┘
                   │                  │
         ┌─────────▼────────┐  ┌──────▼──────────┐
         │ ASan Shadow Map  │  │ Exit / Signal   │
         │ & Crash Traces   │  │ Interception    │
         └─────────┬────────┘  └──────┬──────────┘
                   │                  │
            ┌──────▼──────────────────▼───────┐
            │   Vulnerability Classifier      │
            │  (CWE Mapping & CVSS Scoring)   │
            └────────────────┬────────────────┘
                             │
        ┌────────────────────┴────────────────────┐
        │                                         │
┌───────▼────────────────┐              ┌─────────▼──────────────┐
│ Real-Time Live Console │              │ Structured JSON Report │
│  Executive Scorecard   │              │   (dast_report.json)   │
└────────────────────────┘              └────────────────────────┘
```

---

## CWE Coverage Catalog

The orchestrator maps all detected violations against 59 Common Weakness Enumeration (CWE) categories, including:

| CWE ID | Vulnerability Class | CVSS v3 Base |
|---|---|---|
| **CWE-122** | Heap-based Buffer Overflow | **9.8 (Critical)** |
| **CWE-787** | Out-of-bounds Write | **9.8 (Critical)** |
| **CWE-134** | Use of Externally-Controlled Format String | **9.8 (Critical)** |
| **CWE-416** | Use After Free (UAF) | **8.8 (High)** |
| **CWE-415** | Double Free | **8.8 (High)** |
| **CWE-125** | Out-of-bounds Read | **7.5 (High)** |
| **CWE-120** | Classic Buffer Overflow (Buffer Copy without Checking Size) | **9.8 (Critical)** |
| **CWE-121** | Stack-based Buffer Overflow | **9.8 (Critical)** |
| **CWE-193** | Off-by-one Error (Poison Null Byte) | **7.5 (High)** |
| **CWE-190** | Integer Overflow or Wraparound | **7.5 (High)** |
| **CWE-680** | Integer Overflow to Buffer Overflow | **8.8 (High)** |
| **CWE-129** | Improper Validation of Array Index | **7.5 (High)** |
| **CWE-843** | Type Confusion (RTTI / Downcasting Overwrite) | **8.8 (High)** |
| **CWE-400** | Uncontrolled Resource Consumption (Denial of Service) | **7.5 (High)** |
| **CWE-476** | NULL Pointer Dereference | **6.5 (Medium)** |
| **CWE-369** | Divide By Zero | **5.3 (Medium)** |
| **CWE-170** | Improper Null Termination | **6.5 (Medium)** |
| **CWE-195** | Signed to Unsigned Conversion Error | **7.5 (High)** |
| **CWE-562** | Return of Stack Variable Address / Use-After-Scope | **7.5 (High)** |

---

## Test Suite Breakdown (1,000 Test Cases)

The 1,000 built-in test cases (`TC-HEAP-001` through `TC-HEAP-1000`) are structured into **133 Exploit Tiers**:

### 1. Allocator Chunk Boundaries & Quantums (Tiers 1–12, 46–47, 74, 84–87, 104–108)
- **Sub-64B Fine Quantums**: 8B, 12B, 16B, 20B, 24B, 28B, 32B, 36B, 40B, 44B, 48B, 52B, 56B, 60B, 64B.
- **Smallbin Quantums**: 68B, 76B, 84B, 92B, 100B, 104B, 108B, 116B, 120B, 124B, 128B, 144B, 160B, 176B, 192B, 208B, 224B, 240B, 256B.
- **Mid & Large Bins**: 288B, 320B, 384B, 448B, 512B, 576B, 640B, 704B, 768B, 832B, 896B, 960B, 1024B (1KB) up to 3584B.
- **OS Virtual Page Multiples**: Exact 4096B (1 page), 8192B (2 pages), 12288B (3 pages), 16384B (4 pages), plus $(4096 \times N) \pm 1$ boundary drifts.
- **Kernel Mmap Threshold**: 32KB, 64KB, 128KB (default glibc/jemalloc mmap threshold), 256KB, 512KB, 1MB chunks.
- **Boundary Permutations**: Tested with exact fit ($B-1$), exact boundary ($B$), off-by-one null byte ($B+1$), word overwrite ($B+2, B+8$).

### 2. Poison Null Byte & Off-by-One Overflows (Tiers 49, 75, 88, 107)
- Overwriting adjacent chunk flags (`PREV_INUSE` bit) with single null terminator byte across every allocator bin.
- Array length equal index (`arr[len]`), loop condition `<=` instead of `<`, unsigned reverse loop underflow (`i >= 0`).

### 3. C & C++ String and Stream Hazards (Tiers 76–77, 89, 91, 124)
- **Unbounded string routines**: `strcpy`, `strcat`, `stpcpy`, `sprintf`, `vsprintf`, `swprintf`, `asctime`, `realpath`.
- **C++ String/String_view**: Small String Optimization (SSO 15B/22B) heap transitions, `const_cast` `.data()` mutations, dangling `string_view` temporaries.
- **Stream Extraction**: Massive single continuous tokens (64B to 2048B) without whitespace, stressing unbounded `cin >> heap_ptr`.

### 4. Encoding, Decoding & Expansion Overflows (Tiers 50, 78, 90, 94, 98, 125, 131)
- URL percent-decoding (`%20`, partial `%2`, double `%2520`).
- Base64 & Quoted-Printable expansion exceeding destination buffers.
- Hex decoding odd-nibble misalignment.
- Wide characters: UTF-16 surrogate splitting at boundaries, UTF-32 4-byte overruns, overlong UTF-8, Unicode NFKC/NFKD expansions (ligatures, Arabic presentation forms).
- Serialization: Binary struct length prefix larger than payload, 10-byte varint shifts, TLV field overflows.

### 5. Integer Arithmetic Leading to Heap Overflow (Tiers 21–23, 72, 79, 96, 114–115)
- Integer multiplication wrapping 32-bit unsigned bounds (`count * sizeof(T) == 0` or tiny size, followed by full write).
- Signed-to-unsigned conversion: negative values passed to `malloc()` or `memcpy()` wrapping to `SIZE_MAX`.
- Numeric truncation: 64-bit `size_t` truncated to 32-bit `uint`.

### 6. Format String Exploits (Tiers 15, 36, 60, 95, 116–117)
- Stack & heap memory leak probes: `%x`, `%p`, `%s` chains.
- Direct parameter access: `%100$p`, `%999$x`.
- Arbitrary memory writes: `%n`, half-word writes (`%hn`), byte writes (`%hhn`), quad-word writes (`%lln`).
- Width and precision buffer floods: `%1000000d`, `%.10000s`.

### 7. Object Lifetime & Modern C++ Memory Flaws (Tiers 24–25, 54, 65, 82, 92–93, 109–111, 118–120)
- **Use-After-Free**: Object state transitions, virtual method table (vptr) dispatch on freed memory.
- **Double-Free**: Consecutive frees, fastbin dup cycles, corrupted interior pointer frees.
- **C++ STL & Smart Pointers**: `std::vector` `operator[]` OOB, `unique_ptr` array deleter mismatches, `shared_ptr` circular reference leaks, dereferencing `vector.end()` iterator.
- **Exception Safety**: Constructor throwing after raw `malloc()` without catch cleanup.

### 8. Structured Protocol & Parser Fuzzing (Tiers 80, 99–102, 126–130)
- Oversized HTTP request lines, headers, cookies, and multipart boundaries.
- Deeply nested JSON arrays/objects (60 levels deep) and XML Billion Laughs entity expansions.
- URI parsing overflows (scheme, authority, IPv6 literals, 50-directory paths).
- Path traversal normalization (`../` sequences, Windows volume paths).
- Decompression bomb headers (Gzip, Zip, Deflate claiming 4GB).

### 9. High-Entropy Chaos & De Bruijn Crash Offset Locators (Tiers 17, 35, 61, 63, 83, 103, 132–133)
- Unique mathematical 4-byte De Bruijn patterns from 32B up to 8192B.
- High-entropy binary mutators, alternating bit-flip patterns (`0xAA`/`0x55`), ascending/descending byte ladders.

---

## Quick Start & Commands

The main testing engine is [`dast_pipeline.py`](file:///Users/devprasad/Documents/Intern/dast_pipeline.py).

### 1. Run Complete 1,000-Test Audit on Any Target
```bash
python3 dast_pipeline.py sample_vulner.cpp
```

### 2. Run Verbose Mode (Shows Crash Frames, Signals & Exploit Vectors)
```bash
python3 dast_pipeline.py sample_vulner.cpp --verbose
```

### 3. Run a Specific Test Case (By Test ID)
```bash
python3 dast_pipeline.py sample_vulner.cpp --test-id TC-HEAP-021
```

### 4. Custom Execution Timeout (e.g., 3.0 Seconds per Test)
```bash
python3 dast_pipeline.py sample_vulner.cpp --timeout 3.0
```

### 5. Custom Output JSON Report File
```bash
python3 dast_pipeline.py sample_vulner.cpp custom_audit_report.json
```

---

## Included Benchmark Target Files

The workspace includes benchmark files to verify both detection efficacy and zero-false-positive guarantees:

| File | Type | Description | Expected Result |
|---|---|---|---|
| [`sample_vulner.cpp`](file:///Users/devprasad/Documents/Intern/sample_vulner.cpp) | **Vulnerable** | Educational multi-flaw target with clearly labeled Heap Overflow, Format String, UAF, Double Free, and Integer Wrap routines. | **Vulnerabilities Detected** (CVSS 9.8 Critical) |
| [`sample_error.cpp`](file:///Users/devprasad/Documents/Intern/sample_error.cpp) | **Vulnerable** | Unbounded `strcpy` into fixed 32-byte heap buffer and direct format string sink `printf(heap_buffer)`. | **Vulnerabilities Detected** (Pinpoints lines 35 & 40) |
| [`sample_comprehensive.cpp`](file:///Users/devprasad/Documents/Intern/sample_comprehensive.cpp) | **Vulnerable** | Multi-vulnerability suite covering heap/stack overflows, UAF, double free, and index errors. | **Vulnerabilities Detected** (Multi-CWE triggered) |
| [`Sample.cpp`](file:///Users/devprasad/Documents/Intern/Sample.cpp) | **Hardened** | Production-grade C++ memory management using bounds checking and safe allocators. | **1000 / 1000 Passed (100.0% Clean)** |
| [`Sample_secure.cpp`](file:///Users/devprasad/Documents/Intern/Sample_secure.cpp) | **Hardened** | RAII architecture using `std::make_unique` and dynamic memory validation. | **1000 / 1000 Passed (100.0% Clean)** |
| [`sample_comprehensive_secure.cpp`](file:///Users/devprasad/Documents/Intern/sample_comprehensive_secure.cpp) | **Hardened** | Enterprise defensive implementation preventing all 133 exploit tiers. | **1000 / 1000 Passed (100.0% Clean)** |

---

## Understanding the Scorecard & Reports

### Terminal Scorecard Output
At the conclusion of a test run, the orchestrator prints an executive scorecard with accuracy metrics:

```text
================================================================================
      DAST UNIVERSAL SUITE — ADVANCED MULTI-VULNERABILITY AUDIT TABLE
================================================================================
  Target Source File   : sample_vulner.cpp
  Compiler Toolchain   : Apple clang version 21.0.0 (clang-2100.3.34.2)
  Total Scan Duration  : 14.28s
--------------------------------------------------------------------------------
  CATEGORY                     TOTAL    PASSED     VULNERABLE   STATUS
--------------------------------------------------------------------------------
  Heap Bin Boundaries          92       16/92      76/92        VULN
  Format Strings               34       16/34      18/34        VULN
  Memory Lifecycle Flaws       18       8/18       10/18        VULN
  Array Indexing               22       21/22      1/22         VULN
  ...
--------------------------------------------------------------------------------
  IDENTIFIED VULNERABLE TEST CASES (528 Failures):
--------------------------------------------------------------------------------
    ✗ [TC-HEAP-021] 32-Byte Exact Probe (32B Bin + null overflow) (Heap-based Buffer Overflow) [sample_vulner.cpp:64]
    ✗ [TC-HEAP-022] 33-Byte Off-by-One Probe (32B Bin overflow) (Heap-based Buffer Overflow) [sample_vulner.cpp:64]
    ...

================================================================================
                    FINAL AUDIT RESULT & SCORECARD
================================================================================
  Target Source File   : sample_vulner.cpp
  EXECUTIVE SCORECARD & ACCURACY METRICS:
  • Overall Test Suite Execution : 1000 / 1000 (100.0% Benchmark Completeness)
  • Tests Passed (Clean Rate)    : 472 / 1000 (Passed Accuracy: 47.20%)
  • Vulnerabilities Found (Rate) : 528 / 1000 (Detection Accuracy: 52.80%)
--------------------------------------------------------------------------------
  Final Audit Verdict  : FAILED — VULNERABILITY CONFIRMED
  Max CVSS v3 Score    : 9.8 (CRITICAL)
  Vulnerabilities Found: Heap-based Buffer Overflow, Format String Crash
  CWEs Triggered       : CWE-119, CWE-121, CWE-122, CWE-134
  Primary Crash Loc    : sample_vulner.cpp:64 (in test_heap_overflow_and_format_string)
================================================================================
```

### Structured JSON Audit Report (`dast_report.json`)
The generated JSON report contains machine-parseable data suitable for CI/CD pipelines:
- `report_metadata`: Compiler version, sanitizers enabled, scan duration, overall verdict.
- `executive_summary`: 
  - `benchmark_matrix_target`: 1000
  - `overall_test_suite_accuracy_percentage`: 100.0%
  - `tests_passed_accuracy_percentage`: Percentage of tests completing cleanly without violation.
  - `vulnerability_detection_accuracy_percentage`: Percentage of tests successfully triggering and verifying vulnerabilities.
  - `all_triggered_cwes`: Array of all confirmed CWE identifiers.
- `category_breakdown`: Granular per-category totals, pass counts, vulnerability counts, and percentage rates.
- `vulnerability_locations`: Symbolicated source file and line numbers where crashes occurred.
- `detailed_test_executions`: Full execution trace for each of the 1,000 tests (exit codes, execution times, stdout/stderr previews, and ASan signals).

---

## Platform Safeguards & Engineering Details

The pipeline incorporates several low-level engineering safeguards:
- **macOS Apple Silicon Compatibility**: Automatically sets `detect_leaks=0` in `ASAN_OPTIONS` when running on Darwin/macOS, as leak detection is unsupported on macOS ARM64 and causes false initialization aborts.
- **POSIX `ARG_MAX` Command-Line Overflow Protection**: Command arguments are guarded with a 32KB ceiling. Payloads exceeding 32KB (up to 1MB) and payloads with embedded null bytes (`\x00`) are safely routed via standard input (`stdin`), preventing OS `Errno 7: Argument list too long`.
- **Surrogate Code Point Encoding Guard**: All Unicode test vectors use raw escaped byte representations (`\xed\xa0\x80`), preventing Python UTF-8 encoding crashes during terminal logging.
- **Linker Main Pre-flight Verification**: Inspects target C++ source files before compilation to confirm `main()` entry-point existence, preventing confusing link-time symbol errors.
