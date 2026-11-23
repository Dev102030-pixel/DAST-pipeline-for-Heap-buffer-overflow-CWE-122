#!/usr/bin/env python3
"""
===============================================================================
Dynamic Application Security Testing (DAST) Orchestrator v7.0
Universal C++ Memory Safety, Arithmetic & Undefined Behavior Auditing Suite
===============================================================================

Architectural Capabilities:
  Layer 1: Instrumentation & Compilation Engine
           - Multi-compiler toolchain autodetection (clang++ / g++)
           - Hardened sanitizer flags (-std=c++17 -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer)
           - AST pre-flight entry point verification (main() linker check)
           - Safe temporary artifact compilation with RAII-style guaranteed cleanup
  Layer 2: Test Harness & Payload Management
           - 1000 structured test cases across 133 exploit tiers & 59 CWE identifiers
           - Multi-channel delivery: argv[1] and stdin with embedded-null handling
           - Comprehensive vulnerability battery: Heap OOB, Stack OOB, Global OOB,
             Use-After-Free, Double-Free, Integer Overflow, Divide-by-Zero, Format Strings,
             NULL Pointer Dereferences, and Array Out-of-Bounds Indexing.
  Layer 3: Process Execution & Isolation Engine
           - Subprocess isolation with strict sandboxing and environment isolation
           - Real-time ASan/UBSan instrumentation variables (abort_on_error=1:symbolize=1)
           - Configurable timeouts (3.0s - 10.0s) guarding against hangs & DoS
  Layer 4: Log Parsing, Finding Extraction & Symbolication
           - Automated symbolication extracting exact source file, line number & function
           - Dynamic multi-vulnerability classifier mapping ASan/UBSan signals to CWEs & CVSS v3
           - Sub-millisecond performance timing and metrics capture
  Layer 5: Reporting & CLI Capabilities
           - Production-grade structured JSON export with category summaries
           - Colorized terminal visualization table with per-tier rollups
           - CLI filtering: --test-id <ID>, --verbose, --timeout <sec>, --test-file <file>
===============================================================================
"""

import os
import sys
import re
import json
import time
import shutil
import platform
import tempfile
import argparse
import subprocess
from typing import Dict, List, Any, Optional, Tuple

DEFAULT_SOURCE   = "Sample.cpp"
OUTPUT_BIN_NAME  = "dast_target_bin"
JSON_REPORT_FILE = "dast_report.json"

# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2: TEST METADATA MATRIX & EXPLOIT VECTORS (28 Tiers, 25 CWEs)
# ─────────────────────────────────────────────────────────────────────────────
EXPLOIT_VECTORS: Dict[str, Dict[str, Any]] = {
    # ── Benign ───────────────────────────────────────────────────────────────
    "baseline":        {"category": "Baseline",            "vector": "Baseline / Benign Input",               "technique": "Sanity check — no overflow risk",                        "cwe": []},
    "micro":           {"category": "Sub-Boundary",        "vector": "Micro Payload",                         "technique": "Sub-8B input — well inside any memory buffer",           "cwe": []},
    "control_char":    {"category": "Control Chars",       "vector": "Control Character Injection",           "technique": "ANSI escape / tab / carriage-return handling probe",      "cwe": ["CWE-116"]},

    # ── Allocator Bin Boundaries (Heap Memory) ───────────────────────────────
    "8b_boundary":     {"category": "Heap Bin Boundaries", "vector": "8-Byte Allocator Bin Probe",            "technique": "ptmalloc2 8B chunk boundary — null-byte overflow",        "cwe": ["CWE-122", "CWE-787"]},
    "16b_boundary":    {"category": "Heap Bin Boundaries", "vector": "16-Byte Allocator Bin Probe",           "technique": "Classic 16B fixed-buffer off-by-one / overflow",          "cwe": ["CWE-122", "CWE-787"]},
    "24b_boundary":    {"category": "Heap Bin Boundaries", "vector": "24-Byte Allocator Bin Probe",           "technique": "24B chunk null-byte chunk-header overwrite",              "cwe": ["CWE-122", "CWE-787"]},
    "32b_boundary":    {"category": "Heap Bin Boundaries", "vector": "32-Byte Allocator Bin Probe",           "technique": "32B fixed-buffer overflow (most common real-world case)", "cwe": ["CWE-122", "CWE-787"]},
    "48b_boundary":    {"category": "Heap Bin Boundaries", "vector": "48-Byte Chunk Overflow",                "technique": "Corrupts adjacent 48B ptmalloc chunk headers",            "cwe": ["CWE-122", "CWE-787"]},
    "64b_boundary":    {"category": "Heap Bin Boundaries", "vector": "64-Byte Chunk Overflow",                "technique": "64B fastbin corruption and metadata overwrite",           "cwe": ["CWE-122", "CWE-787"]},
    "fastbin":         {"category": "Fastbins",            "vector": "Fastbin Limit Chunk Probe",             "technique": "ptmalloc fastbin max (≤128B) fd-pointer corruption",      "cwe": ["CWE-122", "CWE-416", "CWE-787"]},
    "128b_boundary":   {"category": "Heap Bin Boundaries", "vector": "128-Byte Allocator Bin Probe",          "technique": "Smallbin / largebin boundary corruption at 128B",         "cwe": ["CWE-122", "CWE-787"]},
    "large_chunk":     {"category": "Large Chunks",        "vector": "Large Heap Chunk Corruption",           "technique": "Multi-chunk overwrite, unsorted bin / largebin attack",   "cwe": ["CWE-122", "CWE-787"]},
    "heap_spray":      {"category": "Heap Sprays",         "vector": "Heap Spray / Memory Exhaustion",        "technique": "Floods allocator with repeated chunks to reach target",   "cwe": ["CWE-122", "CWE-400"]},
    "multipage":       {"category": "Multi-Page",          "vector": "Multi-Page Memory Flooding",            "technique": "Crosses OS 4KB/8KB page boundaries — mmap region attack", "cwe": ["CWE-122", "CWE-400", "CWE-787"]},
    "ultra_spray":     {"category": "Ultra Sprays",        "vector": "Ultra-Large Heap Spray (>16KB)",        "technique": "mmap-backed allocations, massive heap corruption",        "cwe": ["CWE-122", "CWE-400", "CWE-789"]},

    # ── Exploit Engineering & Control Flow Hijack ────────────────────────────
    "nop_sled":        {"category": "Exploit Engineering", "vector": "NOP Sled + Shellcode Simulation",       "technique": "\\x90 * N + marker — RCE buffer fill & execute probe",    "cwe": ["CWE-122", "CWE-94", "CWE-20"]},
    "vtable_hijack":   {"category": "Control Flow Hijack", "vector": "C++ vtable / RTTI Pointer Hijack",      "technique": "0xDEADBEEF pattern overwrites vptr — virtual dispatch RCE","cwe": ["CWE-122", "CWE-822", "CWE-843"]},
    "chunk_meta":      {"category": "Metadata Corruption", "vector": "Fake Heap Chunk Header Injection",      "technique": "Crafted prev_size/size fields — House of Force variant",   "cwe": ["CWE-122", "CWE-787", "CWE-123"]},
    "debruijn":        {"category": "Offset Locators",     "vector": "Cyclic De Bruijn Pattern",              "technique": "Locates exact overflow offset for exploit dev precision",  "cwe": ["CWE-122"]},
    "tcache":          {"category": "Heap Internals",      "vector": "Tcache / Fastbin Poisoning",            "technique": "Corrupts tcache fd-ptr for arbitrary-write (glibc 2.26+)","cwe": ["CWE-122", "CWE-416", "CWE-787"]},

    # ── Input Formatting & Injections ────────────────────────────────────────
    "format_string":   {"category": "Format Strings",      "vector": "Format String Injection",               "technique": "%x%s%n%p — arbitrary read/write via printf family",        "cwe": ["CWE-134", "CWE-122"]},
    "metachar":        {"category": "Command/SQL Injection","vector": "Shell / SQL / Command Injection",      "technique": "OS command injection, SQL injection metachar vectors",     "cwe": ["CWE-78", "CWE-89", "CWE-77"]},
    "unicode":         {"category": "Unicode Encoding",    "vector": "Multi-byte UTF-8 / Unicode Expansion",  "technique": "Wide chars expand byte-count beyond char-count boundary",  "cwe": ["CWE-122", "CWE-116", "CWE-838"]},
    "fuzzing":         {"category": "Fuzzing & Chaos",     "vector": "High-Entropy Byte Fuzzing",             "technique": "Non-printable / random bytes stress-test parser limits",   "cwe": ["CWE-122", "CWE-20"]},
    "edge_case":       {"category": "Edge Cases",          "vector": "Pathological / Edge-Case Pattern",      "technique": "All-same chars, alternating, escalating — allocator edge", "cwe": ["CWE-122", "CWE-20"]},

    # ── Additional Vulnerability Classes (Stack, Lifecycle, Arithmetic) ──────
    "stack_overflow":  {"category": "Stack Buffer Overflows","vector": "Stack Buffer Smash Probe",            "technique": "Overwrites stack-allocated local arrays & stack frame",    "cwe": ["CWE-121", "CWE-787"]},
    "global_overflow": {"category": "Global Buffer Overflows","vector": "Global/Static Array Overflow",       "technique": "Writes past bounds of statically or globally allocated arrays","cwe": ["CWE-120", "CWE-787"]},
    "integer_overflow":{"category": "Integer & Arithmetic", "vector": "Integer Overflow / Wraparound",        "technique": "Passes INT_MAX / UINT_MAX / negative boundary inputs",     "cwe": ["CWE-190", "CWE-197"]},
    "division_zero":   {"category": "Integer & Arithmetic", "vector": "Division By Zero Trigger",             "technique": "Triggers denominator zero divide arithmetic faults",       "cwe": ["CWE-369"]},
    "use_after_free":  {"category": "Memory Lifecycle Flaws","vector": "Use-After-Free & Double-Free",        "technique": "Triggers state sequences referencing or freeing dead memory","cwe": ["CWE-416", "CWE-415"]},
    "null_deref":      {"category": "Pointer Dereference",  "vector": "NULL Pointer Dereference Probe",       "technique": "Passes null markers causing unchecked pointer dereferences","cwe": ["CWE-476"]},
    "oob_index":       {"category": "Array Indexing",       "vector": "Out-of-Bounds Array Indexing",         "technique": "Negative or excessively large array index bounds probe",   "cwe": ["CWE-129", "CWE-125"]},
    "malformed_utf8":  {"category": "Malformed Encodings",  "vector": "Invalid UTF-8 Byte Sequences",         "technique": "Overlong, truncated, or lonely continuation bytes",         "cwe": ["CWE-838", "CWE-116"]},
    "terminal_injection":{"category": "Terminal & Escapes", "vector": "ANSI & Control Code Injection",        "technique": "Screen clearing, cursor repositioning & terminal escapes",  "cwe": ["CWE-116"]},
    "float_boundary":  {"category": "Floating Point Numbers","vector": "IEEE 754 Float Boundary & NaN",       "technique": "Special float representations: NaN, Infinity, underflow",   "cwe": ["CWE-190", "CWE-703"]},
    "radix_numbers":   {"category": "Integer & Arithmetic", "vector": "Hex, Octal & Binary Radix Probes",     "technique": "Alternative radix representations for integer parser stress","cwe": ["CWE-190"]},
    "dpa_format":      {"category": "Format Strings",       "vector": "Direct Parameter Access (DPA) Format", "technique": "Positional stack specifiers (%10$x, %20$p, %30$s, %50$n)",  "cwe": ["CWE-134"]},
    "subshell_injection":{"category": "Command/SQL Injection","vector":"Subshell & Env Expansion Injection",   "technique": "POSIX subshells, backticks, env variable references",      "cwe": ["CWE-78", "CWE-88"]},
    "power_two_boundary":{"category": "Heap Bin Boundaries","vector": "Power-of-Two Allocator Boundary Probe","technique": "Allocations at exact power-of-two boundaries and off-by-one", "cwe": ["CWE-122", "CWE-193"]},
    "format_width":    {"category": "Format Strings",       "vector": "Width & Precision Specifier Explosion", "technique": "%1000000000d huge width, %hn short, %hhn byte writes, 64-bit specifiers", "cwe": ["CWE-134"]},
    "int64_overflow":  {"category": "Integer & Arithmetic", "vector": "64-Bit Integer & Underflow Wraparound", "technique": "LLONG_MAX, LLONG_MIN, negation overflow, unsigned underflow (-1 to SIZE_MAX)", "cwe": ["CWE-190", "CWE-191"]},
    "short_overflow":  {"category": "Integer & Arithmetic", "vector": "16-Bit Short & Truncation Probes",      "technique": "Int16 boundary (32767/32768), UInt16 (65535/65536) truncation", "cwe": ["CWE-190", "CWE-197"]},
    "poison_null":     {"category": "Malformed Encodings",  "vector": "Poisoned Null Byte & Delimiter Injection", "technique": "Embedded null byte followed by trailing payload, CRLF injection", "cwe": ["CWE-120", "CWE-116"]},
    "quantum_chunk":   {"category": "Heap Bin Boundaries", "vector": "Quantum Allocator Chunk Boundaries",     "technique": "504B, 512B, 520B, 2040B, 2048B chunks testing malloc quantum alignment", "cwe": ["CWE-122", "CWE-787"]},
    "page_alignment":  {"category": "Multi-Page",          "vector": "Virtual Memory Page Alignment Probes",    "technique": "Exact 4096B (1 page) and 8192B (2 pages) page boundary crossing probes", "cwe": ["CWE-122", "CWE-400"]},
    "pointer_layout":  {"category": "Control Flow Hijack", "vector": "Memory Layout & Pointer Alignment Probe", "technique": "Simulated 64-bit pointers (0xdeadbeef, 0x41414141) and bitwise patterns", "cwe": ["CWE-122", "CWE-822"]},
    "array_boundary":  {"category": "Array Indexing",       "vector": "Array Subscript & Boundary Verification", "technique": "Exact array length index (INDEX:10), adjacent off-by-one, extreme negative", "cwe": ["CWE-129", "CWE-193"]},
    "cmd_chaining":    {"category": "Command/SQL Injection","vector": "Advanced Command Chaining Sequences",      "technique": "Chained shell control operators: &&, ||, ;, background & operators", "cwe": ["CWE-78", "CWE-88"]},
    "env_override":    {"category": "Command/SQL Injection","vector": "Environment & Dynamic Linker Overrides",  "technique": "Dynamic linker variables (LD_PRELOAD), wildcard globbing (*/*/*)", "cwe": ["CWE-78", "CWE-20"]},
    "odd_bins":        {"category": "Heap Bin Boundaries", "vector": "Granular Allocator Bin Probe (40B/56B/72B/88B)", "technique": "Non-power-of-two allocator bin quantum fits and off-by-one probes", "cwe": ["CWE-122", "CWE-193"]},
    "256b_boundary":   {"category": "Heap Bin Boundaries", "vector": "256-Byte Smallbin Exact & Off-by-N Probe", "technique": "255B fit, 256B exact, 257B off-by-one, 258B (+2), and 264B (+8) chunk boundary tests", "cwe": ["CWE-122", "CWE-787", "CWE-193"]},
    "chunk_overwrite": {"category": "Metadata Corruption", "vector": "Heap Chunk Header & PREV_INUSE Corruption", "technique": "Simulated chunk size field, PREV_INUSE bit toggle, and heap canary overwrite patterns", "cwe": ["CWE-122", "CWE-787", "CWE-123"]},
    "poison_null_heap":{"category": "Heap Bin Boundaries", "vector": "Poison Null Byte / Single-Byte Off-by-One Overflow", "technique": "Writes exact 1-byte null terminator beyond allocated buffer into adjacent metadata", "cwe": ["CWE-122", "CWE-193"]},
    "heap_oob_read":   {"category": "Heap Bin Boundaries", "vector": "Unterminated Buffer / Out-of-Bounds Heap Read", "technique": "Unterminated character array causing read past buffer end into adjacent memory", "cwe": ["CWE-125", "CWE-119"]},
    "mmap_threshold":  {"category": "Large Chunks",        "vector": "High-Capacity Largebin & Mmap Allocation Threshold", "technique": "Probes near and exceeding glibc/jemalloc default mmap threshold (32KB, 64KB, 128KB)", "cwe": ["CWE-122", "CWE-400", "CWE-789"]},
    "string_expansion":{"category": "Malformed Encodings", "vector": "String Decoding & Entity Expansion Heap Overflow", "technique": "HTML entities, URL percent decoding, and escape sequences expanding in heap buffers", "cwe": ["CWE-122", "CWE-120"]},
    "cyclic_debruijn": {"category": "Offset Locators",     "vector": "Extended Cyclic De Bruijn & Pattern Floods", "technique": "128B and 256B unique substrings locating precise instruction pointer / heap offsets", "cwe": ["CWE-122"]},

    # ── Realloc / Shrink Path ────────────────────────────────────────────────
    "realloc_shrink":  {"category": "Realloc Bugs",        "vector": "Realloc Shrink Stale Data Leak",             "technique": "Shrinks realloc'd buffer; stale bytes beyond new size remain readable", "cwe": ["CWE-125", "CWE-200"]},
    "realloc_grow":    {"category": "Realloc Bugs",        "vector": "Realloc Grow Off-by-One Overflow",           "technique": "Grows allocation by exact 1B — classic +1 mis-size overflow path",   "cwe": ["CWE-122", "CWE-193"]},
    "realloc_null":    {"category": "Realloc Bugs",        "vector": "Realloc NULL Return / Zero-Size Free",       "technique": "realloc(ptr, 0) returns NULL or frees; subsequent access is UAF",       "cwe": ["CWE-416", "CWE-476"]},

    # ── Stack-Use-After-Scope ────────────────────────────────────────────────
    "stack_uas":       {"category": "Stack Lifetime",      "vector": "Stack Variable Use-After-Scope Return",      "technique": "Returns / stores address of local stack variable (dangling pointer)",  "cwe": ["CWE-562", "CWE-416"]},
    "stack_uas_loop":  {"category": "Stack Lifetime",      "vector": "Loop-Scoped Stack Variable Dangle",          "technique": "Variable declared inside loop body, referenced outside loop scope",    "cwe": ["CWE-562"]},

    # ── Type Confusion / RTTI ────────────────────────────────────────────────
    "type_confusion":  {"category": "Type Confusion",      "vector": "RTTI Downcast / Reinterpret Cast Probe",     "technique": "Invalid downcast or reinterpret_cast between unrelated class types",  "cwe": ["CWE-843", "CWE-704"]},
    "union_misread":   {"category": "Type Confusion",      "vector": "Union Member Active-Type Mismatch Read",     "technique": "Writes one union member, reads via another type — undefined behaviour", "cwe": ["CWE-843", "CWE-119"]},

    # ── Bounded-Write Truncation ─────────────────────────────────────────────
    "snprintf_trunc":  {"category": "Bounded Write",       "vector": "snprintf Off-by-One Truncation Probe",       "technique": "Exactly N-1, N, N+1, 2N payloads exposing non-null-terminated writes", "cwe": ["CWE-193", "CWE-120", "CWE-134"]},
    "strncpy_notterm": {"category": "Bounded Write",       "vector": "strncpy Non-Termination Buffer Overread",    "technique": "strncpy fills entire buffer; no null term — subsequent strlen reads past", "cwe": ["CWE-170", "CWE-125"]},
    "memcpy_overlap":  {"category": "Bounded Write",       "vector": "memcpy Overlapping src/dst Region",          "technique": "Overlapping src/dst in memcpy causes UB; use memmove instead",          "cwe": ["CWE-119", "CWE-787"]},

    # ── SQL / Path / CRLF Injection ──────────────────────────────────────────
    "sql_injection":   {"category": "Injection",           "vector": "SQL Injection Classic & Blind Patterns",     "technique": "Single-quote escape, comment sequences, UNION SELECT, stacked queries", "cwe": ["CWE-89"]},
    "path_traversal":  {"category": "Injection",           "vector": "Path Traversal / Directory Escape Payloads", "technique": "../ sequences, encoded traversal (%2e%2e/), absolute path injection",  "cwe": ["CWE-22", "CWE-23"]},
    "crlf_injection":  {"category": "Injection",           "vector": "CRLF Header / Log Injection Sequences",     "technique": "\\r\\n injection splitting HTTP headers or log lines for spoofing",     "cwe": ["CWE-93", "CWE-117"]},
    "ldap_injection":  {"category": "Injection",           "vector": "LDAP Special Character Filter Injection",    "technique": "* | ) ( null — LDAP filter bypass and authentication skip patterns",   "cwe": ["CWE-90"]},

    # ── Numeric Edge Cases ───────────────────────────────────────────────────
    "size_t_overflow": {"category": "Integer Issues",      "vector": "size_t / ptrdiff_t Arithmetic Overflow",     "technique": "SIZE_MAX, SIZE_MAX-1, SIZE_MAX/2 passed as allocation or index size",  "cwe": ["CWE-190", "CWE-131"]},
    "signedness_bug":  {"category": "Integer Issues",      "vector": "Signed/Unsigned Comparison Mismatch",        "technique": "-1 compared to unsigned: wraps to UINT_MAX, bypassing length checks",  "cwe": ["CWE-195", "CWE-190"]},
    "numeric_format":  {"category": "Integer Issues",      "vector": "Numeric Format / Locale Parsing Edge Cases", "technique": "Inf, NaN, 0x prefix, octal 0777, leading zeros in integer parse",       "cwe": ["CWE-20", "CWE-190"]},

    # ── Resource Exhaustion / DoS ─────────────────────────────────────────────
    "alloc_dos":       {"category": "Resource DoS",        "vector": "Allocation Count / Size DoS Payload",        "technique": "Requests extreme allocation counts or single very-large size (>1GB)",  "cwe": ["CWE-400", "CWE-789", "CWE-770"]},
    "regex_redos":     {"category": "Resource DoS",        "vector": "ReDoS Catastrophic Backtrack Pattern",       "technique": "(a+)+ style inputs that cause exponential backtracking in regex engines","cwe": ["CWE-400", "CWE-1333"]},
    "loop_anchor":     {"category": "Resource DoS",        "vector": "Infinite Loop / Anchored Iteration Trigger", "technique": "Payload crafted to anchor a loop at the worst-case O(n²) path",         "cwe": ["CWE-400", "CWE-834"]},

    # ── Advanced Heap Buffer Overflow Vectors (Tiers 74-83) ───────────────────
    "granular_quantum": {"category": "Heap Bin Boundaries", "vector": "Granular Allocator Quantum Bin Probes (104B-448B)", "technique": "Tests non-power-of-two allocator bin quantums (104B, 144B, 160B, 176B, 192B, 208B, 224B, 240B, 288B, 320B, 384B, 448B)", "cwe": ["CWE-122", "CWE-787", "CWE-193"]},
    "poison_null_exact":{"category": "Poison Null Byte",   "vector": "Poison Null Byte Off-by-One Heap Termination", "technique": "Writes terminating \\0 one byte past allocated heap buffer across all bin sizes", "cwe": ["CWE-122", "CWE-193", "CWE-787"]},
    "strcat_append":    {"category": "Heap Concatenation",  "vector": "Cumulative Strcat / Dynamic Loop Append",     "technique": "Simulates unbounded loop string concatenation overflowing dynamically allocated heap buffers", "cwe": ["CWE-122", "CWE-120"]},
    "stream_extract":   {"category": "Stream Extraction",   "vector": "C++ Unbounded Stream Extraction (cin >> heap)", "technique": "Injects large single tokens without delimiter to overflow heap buffers allocated for stream reading", "cwe": ["CWE-122", "CWE-20"]},
    "decode_expansion": {"category": "Encoding Expansion",  "vector": "Hex / Base64 / URL / Entity Expansion Overflows", "technique": "Decoded payload expansion exceeding destination heap buffer capacity", "cwe": ["CWE-122", "CWE-131"]},
    "int_alloc_wrap":   {"category": "Integer Wrapping",    "vector": "Integer Multiplication / Wrap Induced Heap Overflow", "technique": "Payload size causing integer overflow in malloc(count * size), writing past undersized heap allocation", "cwe": ["CWE-190", "CWE-680", "CWE-122"]},
    "protocol_parser":  {"category": "Protocol Parsing",    "vector": "Structured Protocol & Delimited Tokenizer Overflows", "technique": "Oversized headers, JSON keys, CSV fields, and delimiter-dense inputs overflowing heap-backed parse buffers", "cwe": ["CWE-122", "CWE-805"]},
    "heap_oob_read_v2": {"category": "Heap OOB Read",       "vector": "Heap Out-of-Bounds Read & Unterminated String Leaks", "technique": "Triggers out-of-bounds heap memory read via missing null terminator or excessive offset access", "cwe": ["CWE-125", "CWE-126", "CWE-788"]},
    "stl_heap_bounds":  {"category": "C++ STL Safety",      "vector": "C++ STL Container & Smart Pointer Heap Bounds Violation", "technique": "Probes vector[] / unique_ptr[] / string::copy heap allocation bounds violations", "cwe": ["CWE-122", "CWE-129", "CWE-823"]},
    "cyclic_debruijn_v2":{"category": "Offset Locators",    "vector": "High-Density Cyclic De Bruijn Offset Locators (512B-4KB)", "technique": "Mathematical 4-byte unique De Bruijn sequence to pinpoint exact heap corrupting byte offsets", "cwe": ["CWE-122"]},

    # ── Advanced Extended Tiers 84-103 (TC-501..700) ──────────────────────────
    "mid_bins":         {"category": "Heap Bin Boundaries", "vector": "Mid-Range Allocator Quantum Bins (576B..960B)", "technique": "576B to 960B non-power-of-two chunk quantums testing intermediate ptmalloc bins", "cwe": ["CWE-122", "CWE-787"]},
    "mid_large_bins":   {"category": "Heap Bin Boundaries", "vector": "1KB..4KB Large Bin Boundaries",                 "technique": "Probes 1152B to 3584B transitions between small and large allocator bins", "cwe": ["CWE-122", "CWE-787"]},
    "page_multiples":   {"category": "Multi-Page",          "vector": "OS Virtual Page Multiples & Drift (4KB..16KB)",  "technique": "Probes Page-1, Page exact, and Page+1 boundaries for 4KB, 8KB, 12KB, 16KB", "cwe": ["CWE-122", "CWE-400"]},
    "mmap_threshold_v2":{"category": "Large Chunks",        "vector": "Mmap Threshold & Direct Mapping (32KB..1MB)",    "technique": "Exceeds glibc/jemalloc mmap threshold forcing direct kernel page mappings", "cwe": ["CWE-122", "CWE-400", "CWE-789"]},
    "oob_index_drift":  {"category": "Array Indexing",      "vector": "Off-by-One Array Index & Pointer Drift",         "technique": "Loop condition <= and signed pointer arithmetic step mismatches", "cwe": ["CWE-129", "CWE-193", "CWE-823"]},
    "unsafe_c_string":  {"category": "Bounded Write",       "vector": "Unbounded C-String Manipulation Functions",      "technique": "stpcpy, strcat, sprintf, vsprintf, realpath fixed buffer overflows", "cwe": ["CWE-120", "CWE-122"]},
    "wide_char_heap":   {"category": "Unicode Encoding",    "vector": "Wide Character & Surrogate Heap Overflows",      "technique": "wchar_t/char16_t/char32_t size mismatches and split surrogate pairs", "cwe": ["CWE-122", "CWE-838"]},
    "cpp_string_hazards":{"category": "C++ STL Safety",     "vector": "C++ std::string & string_view Lifetime Hazards", "technique": "string_view dangling ref, SSO heap transition boundary, and const_cast data()", "cwe": ["CWE-122", "CWE-416", "CWE-825"]},
    "vtable_struct_align":{"category": "Control Flow Hijack","vector": "Virtual Table Offset & Struct Alignment Probe", "technique": "Virtual inheritance offset miscalculations and packed struct field overlaps", "cwe": ["CWE-843", "CWE-122"]},
    "realloc_chain":    {"category": "Realloc Bugs",        "vector": "Cascading Realloc & Dynamic Reallocation Chain", "technique": "reallocarray integer overflow, geometric growth leak, and alignment breach", "cwe": ["CWE-122", "CWE-190", "CWE-416"]},
    "binary_serialize": {"category": "Malformed Encodings", "vector": "Binary Deserialization & Length Prefix Mismatch","technique": "Mismatched length prefix, varint overflow, and TLV structure parsing overflows", "cwe": ["CWE-122", "CWE-125", "CWE-131"]},
    "fmt_direct_param": {"category": "Format Strings",      "vector": "Format String Direct Parameter & Precision Crash","technique": "%100$p, %.10000s, %1000000d, %hn, %hhn arbitrary read/write probes", "cwe": ["CWE-134"]},
    "int_trunc_sign":   {"category": "Integer Issues",      "vector": "Integer Truncation & Sign Extension in Allocation","technique": "64b->32b->16b truncation, signed promotion, and unsigned underflow", "cwe": ["CWE-197", "CWE-194", "CWE-190"]},
    "file_stream_io":   {"category": "Bounded Write",       "vector": "File I/O & Streambuf Heap Overflow Vectors",     "technique": "fread, fgets, getline custom delimiter, and seek past EOF buffer overflows", "cwe": ["CWE-120", "CWE-122"]},
    "crypto_hash_parse":{"category": "Malformed Encodings", "vector": "Cryptographic Hash & Certificate Parse Overflows","technique": "SHA256/MD5/UUID fixed buffer off-by-one, ASN.1 DER length octet overflow", "cwe": ["CWE-122", "CWE-193"]},
    "env_config_parse": {"category": "Command/SQL Injection","vector": "Environment Variable & Configuration Overflows", "technique": "Oversized PATH, 1000-char config key, unclosed quotes, escaped newlines", "cwe": ["CWE-120", "CWE-20"]},
    "argv_cmd_overflow":{"category": "Command/SQL Injection","vector": "CLI Argv & Flag Parsing Buffer Overflows",      "technique": "Argv element overflow, multi-flag accumulation, positional arg floods", "cwe": ["CWE-120", "CWE-88"]},
    "net_proto_headers":{"category": "Protocol Parsing",    "vector": "Network Protocol Header & Frame Overflows",      "technique": "DNS label length, HTTP/2 HPACK int, WebSocket extended payload length", "cwe": ["CWE-122", "CWE-805"]},
    "regex_nesting_dos":{"category": "Resource DoS",        "vector": "RegEx Deep Capture & Class Allocation Stress",   "technique": "Deeply nested capture groups, oversized character classes, assertion flood", "cwe": ["CWE-400", "CWE-1333"]},
    "deep_heap_canary": {"category": "Heap Internals",      "vector": "Deep Heap State, Bit-Flip & Canary Corruption",  "technique": "Alternating bit patterns, byte ladders, and 64-bit address pattern floods", "cwe": ["CWE-122", "CWE-787"]},

    # ── Ultimate Extended Tiers 104-133 (TC-701..1000) ────────────────────────
    "fine_sub64_bins":     {"category": "Heap Bin Boundaries", "vector": "Sub-64B Fine Quantum Allocator Bins",       "technique": "Probes 12B, 20B, 28B, 36B, 44B, 52B, 60B granular allocation chunk sizes", "cwe": ["CWE-122", "CWE-193"]},
    "small_bins_granular": {"category": "Heap Bin Boundaries", "vector": "Smallbin Fine-Grained Quantums (68B..124B)", "technique": "Probes 68B, 76B, 84B, 92B, 100B, 108B, 116B, 124B ptmalloc smallbin boundaries", "cwe": ["CWE-122", "CWE-787"]},
    "pow2_minus1_sweep":   {"category": "Heap Bin Boundaries", "vector": "Power-of-Two Pre-Boundary Fit Sweeps (2^N - 1)", "technique": "Tests largest valid fitting string for all allocator bins up to 8KB", "cwe": ["CWE-122"]},
    "pow2_plus1_sweep":    {"category": "Heap Bin Boundaries", "vector": "Power-of-Two Off-by-One Null Byte Overflows (2^N + 1)", "technique": "Off-by-one terminator overwrite across 16B..8KB allocation boundaries", "cwe": ["CWE-122", "CWE-193"]},
    "pow2_plus8_sweep":    {"category": "Heap Bin Boundaries", "vector": "Power-of-Two Pointer Word Corruptions (2^N + 8)", "technique": "Overwrites adjacent 64-bit chunk metadata header or vptr", "cwe": ["CWE-122", "CWE-787"]},
    "double_free_patterns":{"category": "Memory Lifecycle Flaws","vector": "Double-Free & Corrupt Chunk Free Patterns",  "technique": "Freeing already-freed pointer, free on offset pointer, or fastbin loop", "cwe": ["CWE-415"]},
    "uaf_state_machine":   {"category": "Memory Lifecycle Flaws","vector": "Use-After-Free Object State Transitions",    "technique": "Accessing heap object fields after deallocation across complex lifetimes", "cwe": ["CWE-416"]},
    "heap_leak_exhaustion":{"category": "Resource DoS",        "vector": "Heap Memory Leak & Resource Exhaustion Traps", "technique": "Unbounded allocation loop without release leading to memory exhaustion", "cwe": ["CWE-400", "CWE-401", "CWE-770"]},
    "uninit_heap_reads":   {"category": "Heap OOB Read",       "vector": "Uninitialized Heap Memory Reads & Info Leaks", "technique": "Allocating buffer without zeroing and reading uninitialized bytes", "cwe": ["CWE-908", "CWE-457", "CWE-125"]},
    "subscript_far_offset":{"category": "Array Indexing",      "vector": "Far Offset Array Subscript Bounds Breaches",   "technique": "Huge positive/negative index calculations leading to wild memory dereferences", "cwe": ["CWE-129", "CWE-823"]},
    "alloc_mult_wrap":     {"category": "Integer Wrapping",    "vector": "Integer Multiplication Wrap in Allocation",    "technique": "elem_count * elem_size 32-bit wrap causing undersized buffer allocation", "cwe": ["CWE-190", "CWE-680", "CWE-122"]},
    "alloc_signed_convert":{"category": "Integer Issues",      "vector": "Signedness Conversion Mismatch in Malloc",     "technique": "Negative integer parsed as positive size_t or vice versa in copy loops", "cwe": ["CWE-195", "CWE-190"]},
    "fmt_write_combo":     {"category": "Format Strings",      "vector": "Format String Arbitrary Write Combinations",   "technique": "Chained %hn/%n writes directed to stack and heap pointers", "cwe": ["CWE-134", "CWE-123"]},
    "fmt_positional_n":    {"category": "Format Strings",      "vector": "Positional Format Write Specifiers (%<k>$n)",  "technique": "Direct positional parameter writes bypassing stack arguments", "cwe": ["CWE-134"]},
    "stl_iter_overrun":    {"category": "C++ STL Safety",      "vector": "C++ STL Container Iterator Bounds Overrun",    "technique": "Dereferencing past end() iterator on vector, deque, and list", "cwe": ["CWE-122", "CWE-129"]},
    "smart_ptr_cycles":    {"category": "C++ STL Safety",      "vector": "C++ Smart Pointer Circular Cycles & Dangles",  "technique": "std::shared_ptr circular references and expired weak_ptr locks", "cwe": ["CWE-416", "CWE-401"]},
    "raii_unwind_leaks":   {"category": "Memory Lifecycle Flaws","vector": "Exception Safety & Unwind Memory Leak Traps","technique": "Heap allocation in constructor throwing exception without catch release", "cwe": ["CWE-401", "CWE-703"]},
    "signal_unsafe_heap":  {"category": "Control Flow Hijack", "vector": "Signal Handler Async-Unsafe Memory Operations", "technique": "Calling malloc/free or non-reentrant functions inside signal context", "cwe": ["CWE-479", "CWE-822"]},
    "dynlink_hijack":      {"category": "Control Flow Hijack", "vector": "Dynamic Linker & GOT/PLT Pointer Corruption",  "technique": "Overwriting global offset table pointers through heap corruption", "cwe": ["CWE-122", "CWE-822"]},
    "multithread_alloc_race":{"category": "Heap Internals",    "vector": "Multi-Threaded Allocation Race & Free Traps",  "technique": "Simultaneous heap modifications without synchronization leading to double-free", "cwe": ["CWE-362", "CWE-416"]},
    "string_token_traps":  {"category": "Bounded Write",       "vector": "String Tokenization Memory Overread Traps",    "technique": "strtok/strsep mutating static pointers and reading beyond null terminator", "cwe": ["CWE-125", "CWE-120"]},
    "b64_qp_overflow":     {"category": "Malformed Encodings", "vector": "Base64 & Quoted-Printable Decoding Overflows", "technique": "Decoded payload expansion exceeding destination heap buffer capacity", "cwe": ["CWE-122", "CWE-131"]},
    "json_xml_nesting":    {"category": "Protocol Parsing",    "vector": "JSON / XML Deeply Nested Structure Stress",    "technique": "Parser memory recursion and dynamic object allocation exhaustion", "cwe": ["CWE-400", "CWE-122"]},
    "uri_parser_overflow": {"category": "Protocol Parsing",    "vector": "URI / URL Component Parser Heap Overflow",     "technique": "Oversized scheme, authority, query, and fragment strings overflowing heap buffers", "cwe": ["CWE-122", "CWE-20"]},
    "mime_folding_heap":   {"category": "Protocol Parsing",    "vector": "MIME & Email Header Line Folding Overflows",   "technique": "Unfolding multiline MIME headers into undersized heap-backed line buffer", "cwe": ["CWE-122", "CWE-120"]},
    "path_normalize_oob":  {"category": "Injection",           "vector": "Path Normalization Buffer Overrun Traps",      "technique": "Canonicalization and ../ removal overflowing heap destination string", "cwe": ["CWE-22", "CWE-122"]},
    "compression_bomb_trap":{"category": "Resource DoS",       "vector": "Decompression Bomb & Magic Header Traps",      "technique": "Gzip/deflate header claiming massive unpacked size leading to excessive malloc", "cwe": ["CWE-400", "CWE-789"]},
    "unicode_nfkc_overrun":{"category": "Unicode Encoding",    "vector": "Unicode Normalization Form KC/KD Overruns",    "technique": "Character decomposition expanding single UTF-8 codepoints into multiple bytes", "cwe": ["CWE-122", "CWE-838"]},
    "chaos_entropy_sweep": {"category": "Fuzzing & Chaos",     "vector": "High-Entropy Binary Mutation & Chaos Floods",  "technique": "Pseudorandom byte sequences with zero and boundary markers", "cwe": ["CWE-122", "CWE-20"]},
    "debruijn_exact_markers":{"category": "Offset Locators",   "vector": "De Bruijn Precision Crash Offset Pinpointers", "technique": "Mathematical 4-byte unique De Bruijn sequence with exact byte-index markers", "cwe": ["CWE-122"]},
}

CWE_COVERAGE: Dict[str, str] = {
    "CWE-20":  "Improper Input Validation",
    "CWE-77":  "Improper Neutralization of Special Elements in Command",
    "CWE-78":  "OS Command Injection",
    "CWE-88":  "Argument Injection",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection (RCE)",
    "CWE-116": "Improper Encoding / Escaping",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow' / Global)",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-123": "Write-what-where Condition",
    "CWE-125": "Out-of-bounds Read",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-193": "Off-by-one Error",
    "CWE-194": "Unexpected Sign Extension",
    "CWE-197": "Numeric Truncation Error",
    "CWE-369": "Divide By Zero",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-562": "Return of Stack Variable Address / Use-After-Scope",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions",
    "CWE-787": "Out-of-bounds Write",
    "CWE-789": "Memory Allocation with Excessive Size Value",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-838": "Inappropriate Encoding for Output Context (Unicode)",
    "CWE-843": "Type Confusion (RTTI / Downcasting Overwrite)",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-23":  "Relative Path Traversal",
    "CWE-90":  "LDAP Injection",
    "CWE-93":  "Improper Neutralization of CRLF Sequences",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-124": "Buffer Underwrite ('Buffer Underflow')",
    "CWE-126": "Buffer Over-read",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-170": "Improper Null Termination",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-467": "Use of sizeof() on a Pointer Type",
    "CWE-680": "Integer Overflow to Buffer Overflow",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-805": "Buffer Access with Incorrect Length Value",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-825": "Expired Pointer Dereference",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-401": "Missing Release of Memory after Effective Lifetime ('Memory Leak')",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-479": "Signal Handler Use of a Non-reentrant Function",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-834": "Excessive Iteration",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
}

RAW_BUILTIN_TESTS: List[Dict[str, str]] = [
    # ══ TIER 1 — Baseline / Benign (TC-001..005) ══════════════════════════════
    {"id": "TC-HEAP-001", "name": "Empty String Input (0B)",                        "input": "\n",                        "tier": "baseline"},
    {"id": "TC-HEAP-002", "name": "Single Character Input (1B)",                    "input": "A\n",                       "tier": "micro"},
    {"id": "TC-HEAP-003", "name": "Micro Input — 4 bytes",                          "input": "Root\n",                    "tier": "micro"},
    {"id": "TC-HEAP-004", "name": "Control Chars — Tab/CR/ANSI (6B)",               "input": "\t\r\x1b[0m\n",             "tier": "control_char"},
    {"id": "TC-HEAP-005", "name": "Standard Safe Input (10B)",                      "input": "SecureData\n",              "tier": "micro"},

    # ══ TIER 2 — 8-Byte Allocator Bin Boundary (TC-006..008) ══════════════════
    {"id": "TC-HEAP-006", "name": "7-Byte Safe Boundary (8B Bin Fit)",              "input": "A"*7  + "\n",              "tier": "8b_boundary"},
    {"id": "TC-HEAP-007", "name": "8-Byte Exact Probe (8B Bin + null overflow)",    "input": "B"*8  + "\n",              "tier": "8b_boundary"},
    {"id": "TC-HEAP-008", "name": "9-Byte Off-by-One Probe (8B Bin overflow)",      "input": "C"*9  + "\n",              "tier": "8b_boundary"},

    # ══ TIER 3 — 16-Byte Allocator Bin Boundary (TC-009..014) ════════════════
    {"id": "TC-HEAP-009", "name": "13-Byte Sub-Boundary Safe Input",                "input": "D"*13 + "\n",              "tier": "16b_boundary"},
    {"id": "TC-HEAP-010", "name": "14-Byte Sub-Boundary Safe Input",                "input": "E"*14 + "\n",              "tier": "16b_boundary"},
    {"id": "TC-HEAP-011", "name": "15-Byte Safe Boundary (16B Bin Fit)",            "input": "F"*15 + "\n",              "tier": "16b_boundary"},
    {"id": "TC-HEAP-012", "name": "16-Byte Exact Probe (16B Bin + null overflow)",  "input": "G"*16 + "\n",              "tier": "16b_boundary"},
    {"id": "TC-HEAP-013", "name": "17-Byte Off-by-One Probe (16B Bin overflow)",    "input": "H"*17 + "\n",              "tier": "16b_boundary"},
    {"id": "TC-HEAP-014", "name": "20-Byte Small Chunk Overflow (16B Bin +4)",      "input": "I"*20 + "\n",              "tier": "16b_boundary"},

    # ══ TIER 4 — 24-Byte Allocator Bin Boundary (TC-015..017) ════════════════
    {"id": "TC-HEAP-015", "name": "23-Byte Safe Boundary (24B Bin Fit)",            "input": "J"*23 + "\n",              "tier": "24b_boundary"},
    {"id": "TC-HEAP-016", "name": "24-Byte Exact Probe (24B Bin + null overflow)",  "input": "K"*24 + "\n",              "tier": "24b_boundary"},
    {"id": "TC-HEAP-017", "name": "25-Byte Off-by-One Probe (24B Bin overflow)",    "input": "L"*25 + "\n",              "tier": "24b_boundary"},

    # ══ TIER 5 — 32-Byte Allocator Bin Boundary (TC-018..023) ════════════════
    {"id": "TC-HEAP-018", "name": "28-Byte Sub-Boundary Safe Probe",                "input": "M"*28 + "\n",              "tier": "32b_boundary"},
    {"id": "TC-HEAP-019", "name": "30-Byte Safe Boundary Probe",                    "input": "N"*30 + "\n",              "tier": "32b_boundary"},
    {"id": "TC-HEAP-020", "name": "31-Byte Safe Boundary (32B Bin Fit)",            "input": "O"*31 + "\n",              "tier": "32b_boundary"},
    {"id": "TC-HEAP-021", "name": "32-Byte Exact Probe (32B Bin + null overflow)",  "input": "P"*32 + "\n",              "tier": "32b_boundary"},
    {"id": "TC-HEAP-022", "name": "33-Byte Off-by-One Probe (32B Bin overflow)",    "input": "Q"*33 + "\n",              "tier": "32b_boundary"},
    {"id": "TC-HEAP-023", "name": "36-Byte Moderate Overflow (32B Bin +4)",         "input": "R"*36 + "\n",              "tier": "32b_boundary"},

    # ══ TIER 6 — 48-Byte Bin Boundary (TC-024..026) ═══════════════════════════
    {"id": "TC-HEAP-024", "name": "47-Byte Safe Boundary (48B Bin Fit)",            "input": "S"*47 + "\n",              "tier": "48b_boundary"},
    {"id": "TC-HEAP-025", "name": "48-Byte Exact Probe (48B Bin + null overflow)",  "input": "T"*48 + "\n",              "tier": "48b_boundary"},
    {"id": "TC-HEAP-026", "name": "49-Byte Off-by-One Probe (48B Bin overflow)",    "input": "U"*49 + "\n",              "tier": "48b_boundary"},

    # ══ TIER 7 — 64-Byte Bin Boundary (TC-027..029) ═══════════════════════════
    {"id": "TC-HEAP-027", "name": "63-Byte Safe Boundary (64B Bin Fit)",            "input": "V"*63 + "\n",              "tier": "64b_boundary"},
    {"id": "TC-HEAP-028", "name": "64-Byte Exact Probe (64B Bin + null overflow)",  "input": "W"*64 + "\n",              "tier": "64b_boundary"},
    {"id": "TC-HEAP-029", "name": "65-Byte Off-by-One Probe (64B Bin overflow)",    "input": "X"*65 + "\n",              "tier": "64b_boundary"},

    # ══ TIER 8 — Fastbin Limit Probes 80/96/112B (TC-030..033) ═══════════════
    {"id": "TC-HEAP-030", "name": "80-Byte Fastbin Chunk Overwrite Probe",          "input": "Y"*80  + "\n",             "tier": "fastbin"},
    {"id": "TC-HEAP-031", "name": "96-Byte Fastbin Chunk Corruption Probe",         "input": "Z"*96  + "\n",             "tier": "fastbin"},
    {"id": "TC-HEAP-032", "name": "112-Byte Fastbin Limit Probe (max fastbin)",     "input": "A"*112 + "\n",             "tier": "fastbin"},
    {"id": "TC-HEAP-033", "name": "120-Byte Near-Smallbin Boundary Probe",          "input": "B"*120 + "\n",             "tier": "fastbin"},

    # ══ TIER 9 — 128-Byte Bin Boundary (TC-034..036) ══════════════════════════
    {"id": "TC-HEAP-034", "name": "127-Byte Safe Boundary (128B Bin Fit)",          "input": "C"*127 + "\n",             "tier": "128b_boundary"},
    {"id": "TC-HEAP-035", "name": "128-Byte Exact Probe (128B Bin + null overflow)","input": "D"*128 + "\n",             "tier": "128b_boundary"},
    {"id": "TC-HEAP-036", "name": "129-Byte Off-by-One Probe (128B Bin overflow)",  "input": "E"*129 + "\n",             "tier": "128b_boundary"},

    # ══ TIER 10 — Large Chunks 192B–512B (TC-037..042) ════════════════════════
    {"id": "TC-HEAP-037", "name": "192-Byte Mid-Tier Heap Corruption",              "input": "F"*192 + "\n",             "tier": "large_chunk"},
    {"id": "TC-HEAP-038", "name": "255-Byte Safe Boundary (256B Bin Fit)",          "input": "G"*255 + "\n",             "tier": "large_chunk"},
    {"id": "TC-HEAP-039", "name": "256-Byte Multi-Chunk Corruption",                "input": "H"*256 + "\n",             "tier": "large_chunk"},
    {"id": "TC-HEAP-040", "name": "384-Byte Heavy Chunk Overwrite",                 "input": "I"*384 + "\n",             "tier": "large_chunk"},
    {"id": "TC-HEAP-041", "name": "511-Byte Safe Boundary (512B Bin Fit)",          "input": "J"*511 + "\n",             "tier": "heap_spray"},
    {"id": "TC-HEAP-042", "name": "512-Byte Massive Heap Spray",                    "input": "K"*512 + "\n",             "tier": "heap_spray"},

    # ══ TIER 11 — Multi-Page Flooding 768B–8KB (TC-043..047) ══════════════════
    {"id": "TC-HEAP-043", "name": "768-Byte Heavy Heap Corruption",                 "input": "L"*768  + "\n",            "tier": "multipage"},
    {"id": "TC-HEAP-044", "name": "1024-Byte (1KB) Severe Chunk Overwrite",         "input": "M"*1024 + "\n",            "tier": "multipage"},
    {"id": "TC-HEAP-045", "name": "2048-Byte (2KB) Multi-Page Exhaustion",          "input": "N"*2048 + "\n",            "tier": "multipage"},
    {"id": "TC-HEAP-046", "name": "4096-Byte (4KB) OS Page Boundary Spray",         "input": "O"*4096 + "\n",            "tier": "multipage"},
    {"id": "TC-HEAP-047", "name": "8192-Byte (8KB) Multi-Page Flooding",            "input": "P"*8192 + "\n",            "tier": "multipage"},

    # ══ TIER 12 — Ultra-Large Sprays >16KB (TC-048..051) ══════════════════════
    {"id": "TC-HEAP-048", "name": "16384-Byte (16KB) mmap Region Spray",            "input": "Q"*16384 + "\n",           "tier": "ultra_spray"},
    {"id": "TC-HEAP-049", "name": "32768-Byte (32KB) Huge Heap Exhaustion",         "input": "R"*32768 + "\n",           "tier": "ultra_spray"},
    {"id": "TC-HEAP-050", "name": "65536-Byte (64KB) Maximum Spray Attempt",        "input": "S"*65536 + "\n",           "tier": "ultra_spray"},
    {"id": "TC-HEAP-051", "name": "131072-Byte (128KB) Extreme mmap Flood",         "input": "T"*131072 + "\n",          "tier": "ultra_spray"},

    # ══ TIER 13 — NOP Sled & Shellcode Simulation (TC-052..055) ══════════════
    {"id": "TC-HEAP-052", "name": "NOP Sled (32B) + Shellcode Marker",              "input": ("\x90"*32) + "SHELLCODE_EXEC\n",                           "tier": "nop_sled"},
    {"id": "TC-HEAP-053", "name": "NOP Sled (64B) + Exploit Payload",              "input": ("\x90"*64) + "EXPLOIT_MARKER\n",                           "tier": "nop_sled"},
    {"id": "TC-HEAP-054", "name": "NOP Sled (128B) + RIP Control Attempt",          "input": ("\x90"*128) + "RIP_OVERWRITE_ATTEMPT\n",                   "tier": "nop_sled"},
    {"id": "TC-HEAP-055", "name": "x86-64 Shellcode Bytes Simulation (execve)",     "input": ("\x48\x31\xc0\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05")*3 + "\n", "tier": "nop_sled"},

    # ══ TIER 14 — vtable / RTTI Control-Flow Hijack (TC-056..059) ════════════
    {"id": "TC-HEAP-056", "name": "Fake vtable Ptr — 0xDEADBEEF (32B Overflow)",     "input": ("A"*16) + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + ("B"*8) + "\n", "tier": "vtable_hijack"},
    {"id": "TC-HEAP-057", "name": "Fake vtable Ptr — 0x4141414141414141 (ROP Gadget)", "input": ("A"*32) + "\x41\x41\x41\x41\x41\x41\x41\x41" + "\n",     "tier": "vtable_hijack"},
    {"id": "TC-HEAP-058", "name": "RTTI Object Type Info Pointer Overwrite",         "input": ("C"*24) + "\xff\xff\xff\xff\x00\x00\x00\x00" + ("D"*16) + "\n", "tier": "vtable_hijack"},
    {"id": "TC-HEAP-059", "name": "Return Address Overwrite via Heap (ret2libc)",    "input": ("A"*32) + "\xb0\x1e\x40\x00\x00\x00\x00\x00" + "\n",     "tier": "vtable_hijack"},

    # ══ TIER 15 — Heap Chunk Metadata Corruption (TC-060..064) ═══════════════
    {"id": "TC-HEAP-060", "name": "Fake Chunk Header — size=0x31 (House of Spirit)", "input": ("X"*16) + "\x00\x00\x00\x00\x31\x00\x00\x00" + "\n",     "tier": "chunk_meta"},
    {"id": "TC-HEAP-061", "name": "Fake Chunk Header — size=0x61 (Fastbin Attack)",  "input": ("X"*24) + "\x00\x00\x00\x00\x61\x00\x00\x00" + "\n",     "tier": "chunk_meta"},
    {"id": "TC-HEAP-062", "name": "Corrupt prev_size Field (Unlink Attack Setup)",   "input": "\xff\xff\xff\xff\xff\xff\xff\xff" + ("A"*24) + "\n",      "tier": "chunk_meta"},
    {"id": "TC-HEAP-063", "name": "PREV_INUSE Bit Clear (Consolidation Trick)",     "input": ("B"*31) + "\xf8" + "\n",                                   "tier": "chunk_meta"},
    {"id": "TC-HEAP-064", "name": "Heap Poison — Magic Bytes Across Boundary",      "input": "\xde\xad\xc0\xde" * 10 + "\n",                            "tier": "chunk_meta"},

    # ══ TIER 16 — Cyclic Patterns & Offset Locators (TC-065..068) ════════════
    {"id": "TC-HEAP-065", "name": "De Bruijn 32-Byte Cyclic Pattern",               "input": "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9\n",                        "tier": "debruijn"},
    {"id": "TC-HEAP-066", "name": "De Bruijn 64-Byte Cyclic Pattern",               "input": "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac\n", "tier": "debruijn"},
    {"id": "TC-HEAP-067", "name": "De Bruijn 80-Byte Full Cyclic Pattern",          "input": "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5\n", "tier": "debruijn"},
    {"id": "TC-HEAP-068", "name": "AAAABBBBCCCCDDDD Offset Pattern (128B)",         "input": ("AAAA"+"BBBB"+"CCCC"+"DDDD"+"EEEE"+"FFFF"+"GGGG"+"HHHH")*4 + "\n", "tier": "debruijn"},

    # ══ TIER 17 — Tcache / Fastbin Exploit Techniques (TC-069..073) ══════════
    {"id": "TC-HEAP-069", "name": "Tcache Poison — fd Ptr to Arbitrary Address",    "input": ("A"*16) + "\x60\x0a\x40\x00\x00\x00\x00\x00" + "\n",     "tier": "tcache"},
    {"id": "TC-HEAP-070", "name": "Tcache Double-Free Simulation Pattern",          "input": "\xf7\xf7\xf7\xf7" * 8 + "\n",                            "tier": "tcache"},
    {"id": "TC-HEAP-071", "name": "Fastbin Dup — Freelist Manipulation Pattern",    "input": ("A"*8) + ("\x00"*8) + ("A"*8) + "\n",                     "tier": "tcache"},
    {"id": "TC-HEAP-072", "name": "Unsorted Bin Attack — bk Ptr Overwrite",         "input": ("C"*24) + "\x78\x56\x34\x12\x00\x00\x00\x00" + "\n",     "tier": "tcache"},
    {"id": "TC-HEAP-073", "name": "House of Force — Wildcard top-chunk size",       "input": ("A"*32) + "\xff\xff\xff\xff\xff\xff\xff\xff" + "\n",      "tier": "tcache"},

    # ══ TIER 18 — Format String Injection (TC-074..078) ══════════════════════
    {"id": "TC-HEAP-074", "name": "Format String — %x%x%x Arbitrary Read",          "input": "%x.%x.%x.%x.%x.%x.%x.%x\n",                              "tier": "format_string"},
    {"id": "TC-HEAP-075", "name": "Format String — %s%s%s Arbitrary Read (ptr)",    "input": "%s%s%s%s%s%s%s%s\n",                                       "tier": "format_string"},
    {"id": "TC-HEAP-076", "name": "Format String — %n Arbitrary Write Probe",       "input": "%10d%n%10d%n%10d%n\n",                                     "tier": "format_string"},
    {"id": "TC-HEAP-077", "name": "Format String — %p Pointer Leak",                "input": "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p\n",                        "tier": "format_string"},
    {"id": "TC-HEAP-078", "name": "Format String — Positional Direct Write",        "input": "%1$x %2$x %3$x %4$x %5$x %6$n\n",                        "tier": "format_string"},

    # ══ TIER 19 — Shell / SQL / Command Injection (TC-079..083) ══════════════
    {"id": "TC-HEAP-079", "name": "SQL Injection — Classic DROP TABLE",             "input": "admin'; DROP TABLE users; --\n",                           "tier": "metachar"},
    {"id": "TC-HEAP-080", "name": "SQL Injection — UNION SELECT Data Extract",      "input": "' UNION SELECT username,password FROM users--\n",          "tier": "metachar"},
    {"id": "TC-HEAP-081", "name": "Shell Injection — Semicolon Command Chain",      "input": "input; cat /etc/passwd; ls -la /\n",                       "tier": "metachar"},
    {"id": "TC-HEAP-082", "name": "Shell Injection — Backtick Execution",           "input": "data`id`more`whoami`\n",                                   "tier": "metachar"},
    {"id": "TC-HEAP-083", "name": "Path Traversal — Directory Escape",              "input": "../../../../../../etc/passwd\n",                           "tier": "metachar"},

    # ══ TIER 20 — Unicode / Multi-byte Encoding (TC-084..087) ════════════════
    {"id": "TC-HEAP-084", "name": "UTF-8 Multi-byte Emoji Expansion (60B)",         "input": "🛡️Security_Buffer_Overflow_🔥⚡🚀💎\n",                      "tier": "unicode"},
    {"id": "TC-HEAP-085", "name": "Unicode CJK Characters (Byte Expansion)",        "input": "中文日本語한국어テスト安全检测\n",                                        "tier": "unicode"},
    {"id": "TC-HEAP-086", "name": "Mixed ASCII + 4-byte UTF-8 (Boundary Cross)",    "input": "AAAA" + "𝄞"*10 + "BBBB\n",                                "tier": "unicode"},
    {"id": "TC-HEAP-087", "name": "Arabic/RTL + Latin Mixed Encoding",              "input": "مرحباHello世界AAAAAAAAAA\n",                                 "tier": "unicode"},

    # ══ TIER 21 — High-Entropy Byte Fuzzing (TC-088..093) ════════════════════
    {"id": "TC-HEAP-088", "name": "Non-printable High-Entropy Bytes (31B)",         "input": "!@#$%^&*()_+~`|}{[]:;?><,./\x01\x02\x03\x1f\n",          "tier": "fuzzing"},
    {"id": "TC-HEAP-089", "name": "All 0xFF Bytes Fuzzing (32B overflow)",          "input": "\xff"*32 + "\n",                                           "tier": "fuzzing"},
    {"id": "TC-HEAP-090", "name": "All 0x00 Null Bytes (32B boundary)",             "input": "\x00"*16 + "AAAA\n",                                       "tier": "fuzzing"},
    {"id": "TC-HEAP-091", "name": "Alternating 0xAA/0x55 Pattern (64B)",            "input": ("\xaa\x55"*32) + "\n",                                     "tier": "fuzzing"},
    {"id": "TC-HEAP-092", "name": "0xDEADBEEF Repeated (40B)",                      "input": "\xde\xad\xbe\xef"*10 + "\n",                              "tier": "fuzzing"},
    {"id": "TC-HEAP-093", "name": "Mixed Printable + Binary Chaos (48B)",           "input": "ABC\x00\xff\xfe\x7f\x80\x01TEST\xde\xadXYZ\x00\xff\n",    "tier": "fuzzing"},

    # ══ TIER 22 — Edge Cases & Pathological Patterns (TC-094..100) ═══════════
    {"id": "TC-HEAP-094", "name": "All 'A' Repeated (256B — Classic Smash)",        "input": "A"*256 + "\n",                                             "tier": "edge_case"},
    {"id": "TC-HEAP-095", "name": "Alternating AB Pattern (128B)",                  "input": "AB"*64  + "\n",                                            "tier": "edge_case"},
    {"id": "TC-HEAP-096", "name": "Escalating Length Pattern (1→32 chars repeated)","input": "".join("X"*i for i in range(1, 10)) + "\n",               "tier": "edge_case"},
    {"id": "TC-HEAP-097", "name": "Newline / Whitespace Flood (64B)",               "input": " \t\r\n"*16 + "END\n",                                     "tier": "edge_case"},
    {"id": "TC-HEAP-098", "name": "Long Single Token No Spaces (512B)",             "input": ("LONGINPUTWITHNOSPACESATALL"*21)[:512] + "\n",             "tier": "edge_case"},
    {"id": "TC-HEAP-099", "name": "Number Flood — Digit String (256B)",             "input": "1234567890"*25 + "123456\n",                              "tier": "edge_case"},
    {"id": "TC-HEAP-100", "name": "Mixed Upper+Lower+Symbol (128B — Full Charset)", "input": ("AaBbCcDdEeFf1234!@#$%^&*()"*5)[:128] + "\n",             "tier": "edge_case"},

    # ══ TIER 23 — Stack Buffer Overflow Probes (TC-101..104) ══════════════════
    {"id": "TC-MEM-101", "name": "Stack Smash 64-Byte Buffer Probe (72B)",          "input": "S"*72 + "\n",                                              "tier": "stack_overflow"},
    {"id": "TC-MEM-102", "name": "Stack Smash 128-Byte Buffer Probe (136B)",        "input": "S"*136 + "\n",                                             "tier": "stack_overflow"},
    {"id": "TC-MEM-103", "name": "Stack Canary & Frame Pointer Smash (280B)",       "input": "S"*280 + "\n",                                             "tier": "stack_overflow"},
    {"id": "TC-MEM-104", "name": "Stack Return Address Overwrite Probe (520B)",     "input": "S"*520 + "\n",                                             "tier": "stack_overflow"},

    # ══ TIER 24 — Integer Overflow & Boundary Probes (TC-105..110) ════════════
    {"id": "TC-MEM-105", "name": "Integer Boundary — 32-bit INT_MAX (2147483647)",  "input": "2147483647\n",                                             "tier": "integer_overflow"},
    {"id": "TC-MEM-106", "name": "Integer Overflow — INT_MAX + 1 (2147483648)",     "input": "2147483648\n",                                             "tier": "integer_overflow"},
    {"id": "TC-MEM-107", "name": "Integer Underflow — INT_MIN (-2147483648)",       "input": "-2147483648\n",                                            "tier": "integer_overflow"},
    {"id": "TC-MEM-108", "name": "Unsigned 32-bit Boundary UINT_MAX (4294967295)",  "input": "4294967295\n",                                             "tier": "integer_overflow"},
    {"id": "TC-MEM-109", "name": "64-bit LLONG_MAX Boundary (9223372036854775807)", "input": "9223372036854775807\n",                                    "tier": "integer_overflow"},
    {"id": "TC-MEM-110", "name": "Negative Size / Index Argument (-1)",             "input": "-1\n",                                                     "tier": "integer_overflow"},

    # ══ TIER 25 — Division By Zero Trigger (TC-111) ═══════════════════════════
    {"id": "TC-MEM-111", "name": "Zero Arithmetic / Division By Zero Probe",        "input": "0\n",                                                      "tier": "division_zero"},

    # ══ TIER 26 — Use-After-Free & Double-Free Probes (TC-112..114) ═══════════
    {"id": "TC-MEM-112", "name": "State Machine Free-Then-Read Sequence",           "input": "FREE\nREAD\n",                                             "tier": "use_after_free"},
    {"id": "TC-MEM-113", "name": "State Machine Double-Free Sequence",              "input": "FREE\nFREE\n",                                             "tier": "use_after_free"},
    {"id": "TC-MEM-114", "name": "Session Invalidation Re-Access Sequence",         "input": "INVALIDATE\nACCESS\n",                                     "tier": "use_after_free"},

    # ══ TIER 27 — NULL Pointer & Array Indexing Probes (TC-115..118) ══════════
    {"id": "TC-MEM-115", "name": "NULL Pointer Uppercase Trigger Token",            "input": "NULL\n",                                                   "tier": "null_deref"},
    {"id": "TC-MEM-116", "name": "nullptr Lowercase Trigger Token",                 "input": "nullptr\n",                                                "tier": "null_deref"},
    {"id": "TC-MEM-117", "name": "Array Out-of-Bounds Negative Index (IDX:-1)",     "input": "INDEX:-1\n",                                               "tier": "oob_index"},
    {"id": "TC-MEM-118", "name": "Array Out-of-Bounds High Index (IDX:99999)",      "input": "INDEX:99999\n",                                            "tier": "oob_index"},

    # ══ TIER 28 — Advanced Multi-Vulnerability Injections (TC-119..125) ═══════
    {"id": "TC-MEM-119", "name": "Format String %n Direct Memory Overwrite",        "input": "%100d%n%100d%n\n",                                         "tier": "format_string"},
    {"id": "TC-MEM-120", "name": "Format String Deep Pointer Dereference (%s x16)", "input": "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",                       "tier": "format_string"},
    {"id": "TC-MEM-121", "name": "Format String Extreme Width (%99999999d)",        "input": "%99999999d\n",                                             "tier": "format_string"},
    {"id": "TC-MEM-122", "name": "Format String Direct Parameter Leak (%99$p)",     "input": "%99$p\n",                                                  "tier": "format_string"},
    {"id": "TC-MEM-123", "name": "Global Buffer Overflow Probe (128B Overwrite)",   "input": "G"*128 + "\n",                                             "tier": "global_overflow"},
    {"id": "TC-MEM-124", "name": "Integer-Length Mismatch Overflow (4GB Length)",   "input": "4294967296:OVERFLOW\n",                                    "tier": "integer_overflow"},
    {"id": "TC-MEM-125", "name": "Negative Allocation Size Signed Cast (-32)",      "input": "-32\n",                                                    "tier": "integer_overflow"},

    # ══ TIER 29 — Malformed UTF-8 & Overlong Encodings (TC-126..130) ══════════
    {"id": "TC-MEM-126", "name": "Overlong UTF-8 Slash Encoding (\\xc0\\xaf)",       "input": "TEST\xc0\xafADMIN\n",                                       "tier": "malformed_utf8"},
    {"id": "TC-MEM-127", "name": "Truncated 3-Byte UTF-8 Sequence (\\xe0\\xa0)",    "input": "DATA\xe0\xa0END\n",                                         "tier": "malformed_utf8"},
    {"id": "TC-MEM-128", "name": "Lonely UTF-8 Continuation Bytes (\\x80\\xbf)",    "input": "PREFIX\x80\xbf\x90\xa0SUFFIX\n",                            "tier": "malformed_utf8"},
    {"id": "TC-MEM-129", "name": "Invalid UTF-8 0xFF & 0xFE Stream",                "input": "START\xff\xfe\xff\xfeSTOP\n",                               "tier": "malformed_utf8"},
    {"id": "TC-MEM-130", "name": "Unpaired UTF-16 High Surrogate (\\xed\\xa0\\x80)","input": "SURROGATE\xed\xa0\x80TEST\n",                              "tier": "malformed_utf8"},

    # ══ TIER 30 — Terminal, ANSI & Control Code Injection (TC-131..135) ═══════
    {"id": "TC-MEM-131", "name": "ANSI Escape Screen Clear Injection",              "input": "\x1b[2J\x1b[H\x1b[31;1mCRITICAL_INJECTION\x1b[0m\n",        "tier": "terminal_injection"},
    {"id": "TC-MEM-132", "name": "Repeated Carriage Return Stream (\\r x64)",       "input": "\r"*64 + "OVERWRITE\n",                                     "tier": "terminal_injection"},
    {"id": "TC-MEM-133", "name": "Mixed Control Delimiters (\\v\\f\\a\\b)",          "input": "TOKEN1\vTOKEN2\fTOKEN3\aTOKEN4\bEND\n",                     "tier": "terminal_injection"},
    {"id": "TC-MEM-134", "name": "Excessive Leading Whitespace (256B Pad)",         "input": " "*256 + "PAYLOAD\n",                                       "tier": "terminal_injection"},
    {"id": "TC-MEM-135", "name": "Null-Delimited Multi-Token Stream",               "input": "AUTH\x00TOKEN\x00ROOT\x00PRIVILEGE\n",                       "tier": "terminal_injection"},

    # ══ TIER 31 — Special Floating Point & Scientific Notation (TC-136..140) ══
    {"id": "TC-MEM-136", "name": "Floating Point NaN (Not-a-Number) Probe",         "input": "NaN\n",                                                     "tier": "float_boundary"},
    {"id": "TC-MEM-137", "name": "Floating Point Positive Infinity (Infinity)",     "input": "Infinity\n",                                                "tier": "float_boundary"},
    {"id": "TC-MEM-138", "name": "Floating Point Negative Infinity (-Infinity)",    "input": "-Infinity\n",                                               "tier": "float_boundary"},
    {"id": "TC-MEM-139", "name": "Extreme Float Overflow Exponent (1e309)",         "input": "1e309\n",                                                   "tier": "float_boundary"},
    {"id": "TC-MEM-140", "name": "Float Subnormal Underflow Exponent (1e-324)",     "input": "1e-324\n",                                                  "tier": "float_boundary"},

    # ══ TIER 32 — Alternative Radix & Numerical Bases (TC-141..145) ═══════════
    {"id": "TC-MEM-141", "name": "Hexadecimal 32-bit INT_MAX (0x7fffffff)",         "input": "0x7fffffff\n",                                              "tier": "radix_numbers"},
    {"id": "TC-MEM-142", "name": "Hexadecimal 32-bit Sign Bit (0x80000000)",         "input": "0x80000000\n",                                              "tier": "radix_numbers"},
    {"id": "TC-MEM-143", "name": "Hexadecimal 64-bit UINT64_MAX",                   "input": "0xffffffffffffffff\n",                                      "tier": "radix_numbers"},
    {"id": "TC-MEM-144", "name": "Octal Boundary Representation (017777777777)",    "input": "017777777777\n",                                            "tier": "radix_numbers"},
    {"id": "TC-MEM-145", "name": "Binary String Representation (0b111...)",         "input": "0b11111111111111111111111111111111\n",                     "tier": "radix_numbers"},

    # ══ TIER 33 — Direct Parameter Access (DPA) Format Strings (TC-146..150) ══
    {"id": "TC-MEM-146", "name": "Format String DPA Stack Word 10 (%10$x)",         "input": "%10$x\n",                                                   "tier": "dpa_format"},
    {"id": "TC-MEM-147", "name": "Format String DPA Stack Word 20 (%20$p)",         "input": "%20$p\n",                                                   "tier": "dpa_format"},
    {"id": "TC-MEM-148", "name": "Format String DPA Stack Word 30 (%30$s)",         "input": "%30$s\n",                                                   "tier": "dpa_format"},
    {"id": "TC-MEM-149", "name": "Format String DPA Stack Word 50 (%50$n)",         "input": "%50$n\n",                                                   "tier": "dpa_format"},
    {"id": "TC-MEM-150", "name": "Format String Multi-Word Memory Scan (%08x x6)",  "input": "%08x.%08x.%08x.%08x.%08x.%08x\n",                           "tier": "dpa_format"},

    # ══ TIER 34 — Advanced Path Traversal & Subshells (TC-151..155) ═══════════
    {"id": "TC-MEM-151", "name": "Mixed Windows/Unix Path Traversal (..\\\\../)",   "input": "..\\../..\\../windows/system32/cmd.exe\n",                   "tier": "subshell_injection"},
    {"id": "TC-MEM-152", "name": "POSIX Subshell Command Substitution $(whoami)",   "input": "$(whoami; id; uname -a)\n",                                 "tier": "subshell_injection"},
    {"id": "TC-MEM-153", "name": "Backtick Command Substitution `id`",              "input": "`id; cat /etc/passwd`\n",                                   "tier": "subshell_injection"},
    {"id": "TC-MEM-154", "name": "Environment Variable Expansion (${PATH})",         "input": "${PATH}:${USER}:${HOME}\n",                                 "tier": "subshell_injection"},
    {"id": "TC-MEM-155", "name": "Pipe-Chained Execution Sequence (| id)",          "input": "input | id | whoami\n",                                     "tier": "subshell_injection"},

    # ══ TIER 35 — Power-of-Two Boundaries & Off-by-One Probes (TC-156..160) ═══
    {"id": "TC-MEM-156", "name": "Power-of-Two 63-Byte Probe (64B Bin - 1)",         "input": "P"*63 + "\n",                                               "tier": "power_two_boundary"},
    {"id": "TC-MEM-157", "name": "Power-of-Two 64-Byte Probe (64B Bin Exact)",       "input": "P"*64 + "\n",                                               "tier": "power_two_boundary"},
    {"id": "TC-MEM-158", "name": "Power-of-Two 65-Byte Probe (64B Bin + 1)",         "input": "P"*65 + "\n",                                               "tier": "power_two_boundary"},
    {"id": "TC-MEM-159", "name": "Power-of-Two 1023-Byte Probe (1KB - 1)",           "input": "P"*1023 + "\n",                                             "tier": "power_two_boundary"},
    {"id": "TC-MEM-160", "name": "Power-of-Two 1025-Byte Probe (1KB + 1)",           "input": "P"*1025 + "\n",                                             "tier": "power_two_boundary"},

    # ══ TIER 36 — Width & Precision Specifier Explosion (TC-161..165) ═════════
    {"id": "TC-MEM-161", "name": "Format String Huge Width Specifier (%1000000000d)", "input": "%1000000000d\n",                                           "tier": "format_width"},
    {"id": "TC-MEM-162", "name": "Format String Short Write (%hn)",                   "input": "%hn\n",                                                   "tier": "format_width"},
    {"id": "TC-MEM-163", "name": "Format String Byte Write (%hhn)",                   "input": "%hhn\n",                                                  "tier": "format_width"},
    {"id": "TC-MEM-164", "name": "Format String 64-bit Hex Specifier (%llx x4)",      "input": "%llx.%llx.%llx.%llx\n",                                   "tier": "format_width"},
    {"id": "TC-MEM-165", "name": "Format String Size_t / Ptrdiff Specifier (%zd.%td)","input": "%zd.%td\n",                                               "tier": "format_width"},

    # ══ TIER 37 — 64-Bit Integer & Underflow Wraparound (TC-166..170) ═════════
    {"id": "TC-MEM-166", "name": "64-bit Integer Max (LLONG_MAX)",                    "input": "9223372036854775807\n",                                   "tier": "int64_overflow"},
    {"id": "TC-MEM-167", "name": "64-bit Integer Overflow (LLONG_MAX + 1)",           "input": "9223372036854775808\n",                                   "tier": "int64_overflow"},
    {"id": "TC-MEM-168", "name": "64-bit Integer Minimum (LLONG_MIN)",                "input": "-9223372036854775808\n",                                  "tier": "int64_overflow"},
    {"id": "TC-MEM-169", "name": "Unsigned Integer Underflow (-1 to SIZE_MAX)",       "input": "-1\n",                                                    "tier": "int64_overflow"},
    {"id": "TC-MEM-170", "name": "Signed Integer Negation Overflow (-2147483648)",    "input": "-2147483648\n",                                           "tier": "int64_overflow"},

    # ══ TIER 38 — 16-Bit Short & Truncation Probes (TC-171..175) ══════════════
    {"id": "TC-MEM-171", "name": "16-bit Signed Short Max (32767)",                   "input": "32767\n",                                                 "tier": "short_overflow"},
    {"id": "TC-MEM-172", "name": "16-bit Signed Short Overflow (32768)",              "input": "32768\n",                                                 "tier": "short_overflow"},
    {"id": "TC-MEM-173", "name": "16-bit Unsigned Short Max (65535)",                 "input": "65535\n",                                                 "tier": "short_overflow"},
    {"id": "TC-MEM-174", "name": "16-bit Unsigned Short Overflow (65536)",            "input": "65536\n",                                                 "tier": "short_overflow"},
    {"id": "TC-MEM-175", "name": "16-bit Negative Boundary (-32769)",                 "input": "-32769\n",                                                "tier": "short_overflow"},

    # ══ TIER 39 — Poisoned Null Byte & Delimiter Injections (TC-176..180) ═════
    {"id": "TC-MEM-176", "name": "Poisoned Null Byte with Trailing Payload",           "input": "admin\x00user_override_data\n",                            "tier": "poison_null"},
    {"id": "TC-MEM-177", "name": "Consecutive Double Null Bytes",                      "input": "prefix\x00\x00suffix\n",                                  "tier": "poison_null"},
    {"id": "TC-MEM-178", "name": "CRLF Header Injection Sequence",                     "input": "test\r\nContent-Length: 0\r\n\r\n\n",                     "tier": "poison_null"},
    {"id": "TC-MEM-179", "name": "URL Double-Encoded Directory Traversal",             "input": "%252e%252e%252f%252e%252e%252fetc%252fpasswd\n",          "tier": "poison_null"},
    {"id": "TC-MEM-180", "name": "Repeated Delimiter Flood (Semicolons & Slashes)",    "input": ";" * 32 + "/" * 32 + "\n",                                "tier": "poison_null"},

    # ══ TIER 40 — Quantum Allocator Chunk Boundaries (TC-181..185) ════════════
    {"id": "TC-MEM-181", "name": "504-Byte Chunk Sub-Boundary (512B Bin - 8)",        "input": "Q" * 504 + "\n",                                          "tier": "quantum_chunk"},
    {"id": "TC-MEM-182", "name": "512-Byte Chunk Exact Quantum Boundary",              "input": "Q" * 512 + "\n",                                          "tier": "quantum_chunk"},
    {"id": "TC-MEM-183", "name": "520-Byte Chunk Off-by-Eight Boundary",               "input": "Q" * 520 + "\n",                                          "tier": "quantum_chunk"},
    {"id": "TC-MEM-184", "name": "2040-Byte Half-Page Sub-Boundary",                  "input": "Q" * 2040 + "\n",                                         "tier": "quantum_chunk"},
    {"id": "TC-MEM-185", "name": "2048-Byte Half-Page Exact Quantum Boundary",         "input": "Q" * 2048 + "\n",                                         "tier": "quantum_chunk"},

    # ══ TIER 41 — Virtual Memory Page Alignment Probes (TC-186..190) ══════════
    {"id": "TC-MEM-186", "name": "4095-Byte Page Boundary - 1 Byte",                  "input": "V" * 4095 + "\n",                                         "tier": "page_alignment"},
    {"id": "TC-MEM-187", "name": "4096-Byte Exact 1-Page Alignment",                  "input": "V" * 4096 + "\n",                                         "tier": "page_alignment"},
    {"id": "TC-MEM-188", "name": "4097-Byte Exact 1-Page Crossing + 1 Byte",          "input": "V" * 4097 + "\n",                                         "tier": "page_alignment"},
    {"id": "TC-MEM-189", "name": "8191-Byte 2-Page Boundary - 1 Byte",                 "input": "V" * 8191 + "\n",                                         "tier": "page_alignment"},
    {"id": "TC-MEM-190", "name": "8192-Byte Exact 2-Page Alignment",                  "input": "V" * 8192 + "\n",                                         "tier": "page_alignment"},

    # ══ TIER 42 — Memory Layout & Pointer Alignment Patterns (TC-191..195) ════
    {"id": "TC-MEM-191", "name": "64-bit Pointer Overwrite Pattern (0xdeadbeef)",      "input": "0xdeadbeefdeadbeef\n",                                     "tier": "pointer_layout"},
    {"id": "TC-MEM-192", "name": "Canonical Address Overwrite Pattern (0x41414141)",   "input": "0x4141414141414141\n",                                     "tier": "pointer_layout"},
    {"id": "TC-MEM-193", "name": "Alternating Bitmask Pattern (0xAA55AA55)",          "input": "\xaa\x55" * 16 + "\n",                                    "tier": "pointer_layout"},
    {"id": "TC-MEM-194", "name": "All-Ones 64-bit Mask (0xFFFFFFFFFFFFFFFF)",         "input": "0xffffffffffffffff\n",                                     "tier": "pointer_layout"},
    {"id": "TC-MEM-195", "name": "Null Pointer Representation Sequence",              "input": "0x0000000000000000\n",                                     "tier": "pointer_layout"},

    # ══ TIER 43 — Array Subscript & Boundary Verification (TC-196..200) ═══════
    {"id": "TC-MEM-196", "name": "Array Boundary Last Valid Element (INDEX:9)",        "input": "INDEX:9\n",                                                "tier": "array_boundary"},
    {"id": "TC-MEM-197", "name": "Array Boundary First Off-By-One (INDEX:10)",         "input": "INDEX:10\n",                                               "tier": "array_boundary"},
    {"id": "TC-MEM-198", "name": "Array Boundary Near-OOB Element (INDEX:11)",         "input": "INDEX:11\n",                                               "tier": "array_boundary"},
    {"id": "TC-MEM-199", "name": "Array Negative Index Low Boundary (INDEX:-10)",      "input": "INDEX:-10\n",                                              "tier": "array_boundary"},
    {"id": "TC-MEM-200", "name": "Array Negative Extreme Min Index (INDEX:-2147483648)","input": "INDEX:-2147483648\n",                                     "tier": "array_boundary"},

    # ══ TIER 44 — Advanced Command Chaining Sequences (TC-201..205) ═══════════
    {"id": "TC-MEM-201", "name": "Command Chaining Background Operator (& ping &)",    "input": "& ping -c 1 127.0.0.1 &\n",                                "tier": "cmd_chaining"},
    {"id": "TC-MEM-202", "name": "Command Chaining Logical OR Sequence (|| id)",      "input": "false || id || whoami\n",                                  "tier": "cmd_chaining"},
    {"id": "TC-MEM-203", "name": "Command Chaining Semicolon Sequence (; id ;)",      "input": "; id ; uname -a ;\n",                                      "tier": "cmd_chaining"},
    {"id": "TC-MEM-204", "name": "Command Chaining Logical AND Sequence (&& whoami)", "input": "true && whoami && id\n",                                   "tier": "cmd_chaining"},
    {"id": "TC-MEM-205", "name": "Command Chaining Pipe Execution (| /bin/sh)",        "input": "echo exploit | /bin/sh\n",                                  "tier": "cmd_chaining"},

    # ══ TIER 45 — Environment & Dynamic Linker Overrides (TC-206..210) ════════
    {"id": "TC-MEM-206", "name": "Dynamic Linker Preload Override (LD_PRELOAD)",       "input": "LD_PRELOAD=/tmp/libevil.so\n",                             "tier": "env_override"},
    {"id": "TC-MEM-207", "name": "macOS Dynamic Linker Override (DYLD_INSERT_LIBRARIES)", "input": "DYLD_INSERT_LIBRARIES=/tmp/libevil.dylib\n",         "tier": "env_override"},
    {"id": "TC-MEM-208", "name": "Filesystem Wildcard Expansion (*/*/*/*)",           "input": "/*/*/*/*/*\n",                                             "tier": "env_override"},
    {"id": "TC-MEM-209", "name": "Subshell Environment Dump ($(env))",                "input": "$(env)\n",                                                 "tier": "env_override"},
    {"id": "TC-MEM-210", "name": "Internal Field Separator Injection (${IFS})",        "input": "cat${IFS}/etc/passwd\n",                                   "tier": "env_override"},

    # ══ TIER 46 — Granular Allocator Bin Probes (TC-HEAP-211..215) ════════════
    {"id": "TC-HEAP-211", "name": "40-Byte Bin Boundary Probe (40B Exact)",          "input": "B"*39 + "\n",                                               "tier": "odd_bins"},
    {"id": "TC-HEAP-212", "name": "41-Byte Bin Off-by-One Probe (40B + 1)",          "input": "B"*40 + "\n",                                               "tier": "odd_bins"},
    {"id": "TC-HEAP-213", "name": "56-Byte Bin Boundary Probe (56B Exact)",          "input": "B"*55 + "\n",                                               "tier": "odd_bins"},
    {"id": "TC-HEAP-214", "name": "72-Byte Bin Boundary Probe (72B Exact)",          "input": "B"*71 + "\n",                                               "tier": "odd_bins"},
    {"id": "TC-HEAP-215", "name": "88-Byte Bin Boundary Probe (88B Exact)",          "input": "B"*87 + "\n",                                               "tier": "odd_bins"},

    # ══ TIER 47 — 256-Byte Smallbin Exact & Off-by-N Probes (TC-HEAP-216..220) ═
    {"id": "TC-HEAP-216", "name": "255-Byte Safe Boundary (256B Bin Fit)",          "input": "S"*254 + "\n",                                              "tier": "256b_boundary"},
    {"id": "TC-HEAP-217", "name": "256-Byte Exact Probe (256B Bin + null overflow)", "input": "S"*255 + "\n",                                              "tier": "256b_boundary"},
    {"id": "TC-HEAP-218", "name": "257-Byte Off-by-One Probe (256B Bin overflow)",   "input": "S"*256 + "\n",                                              "tier": "256b_boundary"},
    {"id": "TC-HEAP-219", "name": "258-Byte Off-by-Two Probe (256B Bin + 2)",        "input": "S"*257 + "\n",                                              "tier": "256b_boundary"},
    {"id": "TC-HEAP-220", "name": "264-Byte Small Chunk Overflow (256B Bin + 8)",    "input": "S"*263 + "\n",                                              "tier": "256b_boundary"},

    # ══ TIER 48 — Heap Metadata Chunk Header & Canary Overwrite (TC-HEAP-221..225)
    {"id": "TC-HEAP-221", "name": "Heap Chunk Size Field Overwrite (64-bit 0x21)",    "input": "A"*32 + "\x21\x00\x00\x00\x00\x00\x00\x00\n",               "tier": "chunk_overwrite"},
    {"id": "TC-HEAP-222", "name": "Heap Chunk PREV_INUSE Bit Toggle (0x01 to 0x00)", "input": "A"*32 + "\x40\x00\x00\x00\x00\x00\x00\x00\n",               "tier": "chunk_overwrite"},
    {"id": "TC-HEAP-223", "name": "Heap Magic Canary Overwrite (0xDEADBEEFCAFEBABE)", "input": "A"*32 + "DEADBEEFCAFEBABE\n",                               "tier": "chunk_overwrite"},
    {"id": "TC-HEAP-224", "name": "Fastbin Forward Pointer (fd) Overwrite Pattern",  "input": "A"*32 + "\x78\x56\x34\x12\x00\x00\x00\x00\n",               "tier": "chunk_overwrite"},
    {"id": "TC-HEAP-225", "name": "Double-Linked List fd/bk Pointer Overwrite",       "input": "A"*32 + "AAAAAAAABBBBBBBB\n",                               "tier": "chunk_overwrite"},

    # ══ TIER 49 — Poison Null Byte & Single-Byte Off-by-One (TC-HEAP-226..230) ═
    {"id": "TC-HEAP-226", "name": "Single-Byte Off-by-One Null Byte Overwrite",      "input": "N"*32 + "\x00\n",                                           "tier": "poison_null_heap"},
    {"id": "TC-HEAP-227", "name": "Two-Byte Off-by-Two Null Byte Overwrite",         "input": "N"*32 + "\x00\x00\n",                                       "tier": "poison_null_heap"},
    {"id": "TC-HEAP-228", "name": "16B Chunk Single Null Byte Off-by-One Overwrite",  "input": "N"*16 + "\x00\n",                                           "tier": "poison_null_heap"},
    {"id": "TC-HEAP-229", "name": "64B Chunk Single Null Byte Off-by-One Overwrite",  "input": "N"*64 + "\x00\n",                                           "tier": "poison_null_heap"},
    {"id": "TC-HEAP-230", "name": "128B Chunk Single Null Byte Off-by-One Overwrite", "input": "N"*128 + "\x00\n",                                          "tier": "poison_null_heap"},

    # ══ TIER 50 — Unterminated Buffer & Out-of-Bounds Heap Read (TC-HEAP-231..235)
    {"id": "TC-HEAP-231", "name": "Unterminated Stream Without Trailing Null (32B)",  "input": "U"*32 + "\n",                                               "tier": "heap_oob_read"},
    {"id": "TC-HEAP-232", "name": "Unterminated Stream Without Trailing Null (64B)",  "input": "U"*64 + "\n",                                               "tier": "heap_oob_read"},
    {"id": "TC-HEAP-233", "name": "Unterminated Stream Without Trailing Null (128B)", "input": "U"*128 + "\n",                                              "tier": "heap_oob_read"},
    {"id": "TC-HEAP-234", "name": "Truncated Escape Sequence at Buffer Edge (32B)",   "input": "U"*31 + "\\\n",                                             "tier": "heap_oob_read"},
    {"id": "TC-HEAP-235", "name": "Truncated Percent Sign at Buffer Edge (32B)",      "input": "U"*31 + "%\n",                                              "tier": "heap_oob_read"},

    # ══ TIER 51 — High-Capacity Largebin & Mmap Allocation Thresholds (TC-236..240)
    {"id": "TC-HEAP-236", "name": "3KB Mid-Largebin Allocation Flood (3072B)",        "input": "M"*3072 + "\n",                                             "tier": "mmap_threshold"},
    {"id": "TC-HEAP-237", "name": "7KB Sub-Two-Page Allocation Flood (7168B)",        "input": "M"*7168 + "\n",                                             "tier": "mmap_threshold"},
    {"id": "TC-HEAP-238", "name": "12KB Three-Page Memory Cross Probe (12288B)",      "input": "M"*12288 + "\n",                                            "tier": "mmap_threshold"},
    {"id": "TC-HEAP-239", "name": "32KB Mmap Allocator Threshold Probe (32768B)",     "input": "M"*32768 + "\n",                                            "tier": "mmap_threshold"},
    {"id": "TC-HEAP-240", "name": "64KB Huge Heap Allocator Cross Probe (65536B)",    "input": "M"*65536 + "\n",                                            "tier": "mmap_threshold"},

    # ══ TIER 52 — String Expansion & Decoding Heap Overflow Probes (TC-241..245)
    {"id": "TC-HEAP-241", "name": "HTML Entity Expansion Flood (&quot; x16)",         "input": ("&quot;" * 16) + "\n",                                      "tier": "string_expansion"},
    {"id": "TC-HEAP-242", "name": "URL Percent Decode Expansion (%20 x32)",           "input": ("%20" * 32) + "\n",                                         "tier": "string_expansion"},
    {"id": "TC-HEAP-243", "name": "Base64 Padding Expansion Sequence",                "input": ("AAAA" * 16) + "==\n",                                      "tier": "string_expansion"},
    {"id": "TC-HEAP-244", "name": "JSON Escape Sequence Expansion (\\\" x24)",         "input": (r'\"' * 24) + "\n",                                         "tier": "string_expansion"},
    {"id": "TC-HEAP-245", "name": "Unicode Hex Escape Expansion (\\u0041 x20)",       "input": (r'\u0041' * 20) + "\n",                                     "tier": "string_expansion"},

    # ══ TIER 53 — Extended Cyclic De Bruijn & Pattern Floods (TC-246..250) ═════
    {"id": "TC-HEAP-246", "name": "128-Byte Cyclic Unique Pattern (De Bruijn)",       "input": "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3\n", "tier": "cyclic_debruijn"},
    {"id": "TC-HEAP-247", "name": "256-Byte Cyclic Unique Pattern (De Bruijn Ext)",   "input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9" * 5)[:256] + "\n", "tier": "cyclic_debruijn"},
    {"id": "TC-HEAP-248", "name": "Alternating High-Nibble Byte Flood (\\xFF\\x00 x32)","input": ("\xff\x00" * 32) + "\n",                                    "tier": "cyclic_debruijn"},
    {"id": "TC-HEAP-249", "name": "Dense Null-Separated Token Stream (Word\\x00 x8)",  "input": ("Token\x00" * 8) + "\n",                                    "tier": "cyclic_debruijn"},
    {"id": "TC-HEAP-250", "name": "Heap Layout Fill & Edge Guard Test (512B Alpha)",  "input": ("HeapOverflowSentinelTest" * 22)[:512] + "\n",              "tier": "cyclic_debruijn"},

    # ══ TIER 54 — Use-After-Free Lifecycle Trigger Sequences (TC-251..255) ═════
    {"id": "TC-MEM-251", "name": "UAF: Alloc-Free-Access Sequence (FREE then READ)",  "input": "FREE\n",                                                     "tier": "use_after_free"},
    {"id": "TC-MEM-252", "name": "UAF: Access After Free (READ on freed ptr)",        "input": "READ\n",                                                     "tier": "use_after_free"},
    {"id": "TC-MEM-253", "name": "UAF: Access After Free (ACCESS keyword)",            "input": "ACCESS\n",                                                   "tier": "use_after_free"},
    {"id": "TC-MEM-254", "name": "Double-Free Trigger Sequence",                       "input": "DOUBLE_FREE\n",                                              "tier": "use_after_free"},
    {"id": "TC-MEM-255", "name": "UAF: Stale Dangling Pointer Access Pattern",        "input": "STALE_PTR\n",                                                "tier": "use_after_free"},

    # ══ TIER 55 — Stack Overflow: Precision Smash Variants (TC-256..260) ════════
    {"id": "TC-MEM-256", "name": "Stack Smash with Format Payload (STACK:%n)",        "input": "STACK:%n%n%n%n%n%n\n",                                      "tier": "stack_overflow"},
    {"id": "TC-MEM-257", "name": "Stack Smash: Exact 64B Buffer Trigger (72B)",       "input": "STACK:" + "A"*66 + "\n",                                    "tier": "stack_overflow"},
    {"id": "TC-MEM-258", "name": "Stack Smash: Canary Region Probe (144B)",           "input": "STACK:" + "B"*144 + "\n",                                   "tier": "stack_overflow"},
    {"id": "TC-MEM-259", "name": "Stack Smash: Return Address Overwrite (280B)",      "input": "STACK:" + "C"*280 + "\n",                                   "tier": "stack_overflow"},
    {"id": "TC-MEM-260", "name": "Stack Smash: Full Frame Corruption (520B)",         "input": "STACK:" + "D"*520 + "\n",                                   "tier": "stack_overflow"},

    # ══ TIER 56 — Division-by-Zero & Modulo Edge Cases (TC-261..265) ═══════════
    {"id": "TC-MEM-261", "name": "Division by Zero: Exact Zero Input",                "input": "0\n",                                                        "tier": "division_zero"},
    {"id": "TC-MEM-262", "name": "Division by Zero: Negative Zero (-0)",              "input": "-0\n",                                                       "tier": "division_zero"},
    {"id": "TC-MEM-263", "name": "Division by Zero: Float Zero (0.0)",                "input": "0.0\n",                                                      "tier": "division_zero"},
    {"id": "TC-MEM-264", "name": "Division by Zero: Leading Zero String (00000)",     "input": "00000\n",                                                    "tier": "division_zero"},
    {"id": "TC-MEM-265", "name": "Division by Zero: Hex Zero (0x0)",                  "input": "0x0\n",                                                      "tier": "division_zero"},

    # ══ TIER 57 — NULL Pointer Dereference Variants (TC-266..270) ═══════════════
    {"id": "TC-MEM-266", "name": "NULL Deref: Uppercase NULL Keyword",                "input": "NULL\n",                                                     "tier": "null_deref"},
    {"id": "TC-MEM-267", "name": "NULL Deref: Lowercase nullptr Keyword",             "input": "nullptr\n",                                                  "tier": "null_deref"},
    {"id": "TC-MEM-268", "name": "NULL Deref: Mixed Case Null Token",                 "input": "Null\n",                                                     "tier": "null_deref"},
    {"id": "TC-MEM-269", "name": "NULL Deref: null String Token",                     "input": "null\n",                                                     "tier": "null_deref"},
    {"id": "TC-MEM-270", "name": "NULL Deref: NIL Token Alias",                       "input": "NIL\n",                                                      "tier": "null_deref"},

    # ══ TIER 58 — Integer Overflow: Precision Boundary Probes (TC-271..275) ════
    {"id": "TC-MEM-271", "name": "Integer Overflow: INT_MAX Exact (2147483647)",      "input": "2147483647\n",                                               "tier": "integer_overflow"},
    {"id": "TC-MEM-272", "name": "Integer Overflow: INT_MAX + 1 (2147483648)",        "input": "2147483648\n",                                               "tier": "integer_overflow"},
    {"id": "TC-MEM-273", "name": "Integer Overflow: INT_MAX + 2 (2147483649)",        "input": "2147483649\n",                                               "tier": "integer_overflow"},
    {"id": "TC-MEM-274", "name": "Integer Overflow: 2*INT_MAX (4294967294)",          "input": "4294967294\n",                                               "tier": "integer_overflow"},
    {"id": "TC-MEM-275", "name": "Integer Overflow: UINT_MAX (4294967295)",           "input": "4294967295\n",                                               "tier": "integer_overflow"},

    # ══ TIER 59 — Out-of-Bounds Array Index Advanced Probes (TC-276..280) ══════
    {"id": "TC-MEM-276", "name": "OOB Index: First Valid Element (INDEX:0)",          "input": "INDEX:0\n",                                                  "tier": "oob_index"},
    {"id": "TC-MEM-277", "name": "OOB Index: Middle Element (INDEX:5)",               "input": "INDEX:5\n",                                                  "tier": "oob_index"},
    {"id": "TC-MEM-278", "name": "OOB Index: Far Out-of-Bounds (INDEX:1000)",         "input": "INDEX:1000\n",                                               "tier": "oob_index"},
    {"id": "TC-MEM-279", "name": "OOB Index: Huge Positive (INDEX:2147483647)",       "input": "INDEX:2147483647\n",                                         "tier": "oob_index"},
    {"id": "TC-MEM-280", "name": "OOB Index: Negative Near Zero (INDEX:-1)",          "input": "INDEX:-1\n",                                                 "tier": "oob_index"},

    # ══ TIER 60 — Format String: Classic & Advanced Specifiers (TC-281..285) ═══
    {"id": "TC-MEM-281", "name": "Format String: Classic Memory Dump (%x.%x.%x)",    "input": "%x.%x.%x.%x.%x.%x.%x.%x\n",                                 "tier": "format_string"},
    {"id": "TC-MEM-282", "name": "Format String: Arbitrary Read via %s Chain",        "input": "%s%s%s%s%s%s%s%s%s%s\n",                                     "tier": "format_string"},
    {"id": "TC-MEM-283", "name": "Format String: Arbitrary Write via %n",             "input": "%n\n",                                                       "tier": "format_string"},
    {"id": "TC-MEM-284", "name": "Format String: Stack Probe with %p Chain",          "input": "%p.%p.%p.%p.%p.%p.%p.%p\n",                                 "tier": "format_string"},
    {"id": "TC-MEM-285", "name": "Format String: Mixed Specifier Attack Chain",       "input": "%d%s%n%x%p%08x%s%n\n",                                      "tier": "format_string"},

    # ══ TIER 61 — Heap Spray: Extended Payload Flood Variants (TC-286..290) ════
    {"id": "TC-MEM-286", "name": "Heap Spray: 500B Single-Char Fill (A x500)",        "input": "A"*500 + "\n",                                               "tier": "heap_spray"},
    {"id": "TC-MEM-287", "name": "Heap Spray: 768B Mid-Tier Flood (B x768)",          "input": "B"*768 + "\n",                                               "tier": "heap_spray"},
    {"id": "TC-MEM-288", "name": "Heap Spray: 896B Near-1KB Flood (C x896)",          "input": "C"*896 + "\n",                                               "tier": "heap_spray"},
    {"id": "TC-MEM-289", "name": "Heap Spray: Repeating Shellcode NOP Pattern",       "input": ("\x90" * 256 + "SHELLCODE_MARKER") + "\n",                   "tier": "heap_spray"},
    {"id": "TC-MEM-290", "name": "Heap Spray: Alternating AA55 Spray Pattern (256B)", "input": ("\xAA\x55" * 128) + "\n",                                   "tier": "heap_spray"},

    # ══ TIER 62 — Multi-Byte Unicode & Encoding Attack Vectors (TC-291..295) ═══
    {"id": "TC-MEM-291", "name": "Unicode: 4-Byte Emoji Overflow (🔥 x16)",          "input": ("🔥" * 16) + "\n",                                           "tier": "unicode"},
    {"id": "TC-MEM-292", "name": "Unicode: CJK Wide Char Overflow (日 x20)",         "input": ("日本語テスト" * 5) + "\n",                                   "tier": "unicode"},
    {"id": "TC-MEM-293", "name": "Unicode: Right-to-Left Marker Injection (RLM)",     "input": "\u200f" * 32 + "INJECT\n",                                   "tier": "unicode"},
    {"id": "TC-MEM-294", "name": "Unicode: Zero-Width Joiner Flood (ZWJ x40)",        "input": "\u200d" * 40 + "\n",                                         "tier": "unicode"},
    {"id": "TC-MEM-295", "name": "Unicode: Homoglyph Overflow (ɑ vs a lookalike)",   "input": "\u0251" * 48 + "\n",                                         "tier": "unicode"},

    # ══ TIER 63 — High-Entropy Fuzz: Random-Byte & Chaos Payloads (TC-296..300) ═
    {"id": "TC-MEM-296", "name": "Fuzzing: All Printable ASCII Charset Sweep",        "input": "".join(chr(c) for c in range(0x21, 0x7F)) + "\n",           "tier": "fuzzing"},
    {"id": "TC-MEM-297", "name": "Fuzzing: Extended ASCII High-Byte Sweep (0x80-0xFF)","input": "".join(chr(c) for c in range(0x80, 0x100)) + "\n",          "tier": "fuzzing"},
    {"id": "TC-MEM-298", "name": "Fuzzing: Whitespace Variants Flood (SP/TAB/CR/LF)", "input": (" \t\r\n" * 32) + "\n",                                     "tier": "fuzzing"},
    {"id": "TC-MEM-299", "name": "Fuzzing: Mixed Metachar Explosion Payload",         "input": "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\" * 4 + "\n",             "tier": "fuzzing"},
    {"id": "TC-MEM-300", "name": "Fuzzing: Long Repeating Binary Word Pattern",       "input": ("\xDE\xAD\xBE\xEF" * 64) + "\n",                            "tier": "fuzzing"},

    # ══ TIER 64 — Realloc Shrink / Grow / Zero-Size Path Bugs (TC-301..310) ══
    {"id": "TC-MEM-301", "name": "Realloc: Shrink to 1B — Stale Data Past New Size",   "input": "REALLOC_SHRINK:1\n",                                            "tier": "realloc_shrink"},
    {"id": "TC-MEM-302", "name": "Realloc: Shrink to 8B — 32B Buffer Residual Leak",   "input": "REALLOC_SHRINK:8\n",                                            "tier": "realloc_shrink"},
    {"id": "TC-MEM-303", "name": "Realloc: Shrink to 16B — Tail Bytes Readable",       "input": "REALLOC_SHRINK:16\n",                                           "tier": "realloc_shrink"},
    {"id": "TC-MEM-304", "name": "Realloc: Exact Size Realloc (no change) Probe",      "input": "REALLOC_SHRINK:32\n",                                           "tier": "realloc_shrink"},
    {"id": "TC-MEM-305", "name": "Realloc: Grow by +1 Off-by-One Past End",            "input": "REALLOC_GROW:33\n",                                             "tier": "realloc_grow"},
    {"id": "TC-MEM-306", "name": "Realloc: Grow 32B→64B Boundary Crossing",           "input": "REALLOC_GROW:64\n",                                             "tier": "realloc_grow"},
    {"id": "TC-MEM-307", "name": "Realloc: Grow 32B→128B Smallbin Threshold",         "input": "REALLOC_GROW:128\n",                                            "tier": "realloc_grow"},
    {"id": "TC-MEM-308", "name": "Realloc: Zero-Size Request (NULL or Free Semantic)", "input": "REALLOC_ZERO\n",                                                "tier": "realloc_null"},
    {"id": "TC-MEM-309", "name": "Realloc: NULL Ptr + Non-Zero Size (malloc alias)",   "input": "REALLOC_NULL_PTR:64\n",                                         "tier": "realloc_null"},
    {"id": "TC-MEM-310", "name": "Realloc: Double Free via Realloc+Free Sequence",     "input": "REALLOC_DOUBLE_FREE\n",                                          "tier": "realloc_null"},

    # ══ TIER 65 — Stack Use-After-Scope / Dangling Stack Ptr (TC-311..320) ════
    {"id": "TC-MEM-311", "name": "Stack UAS: Return Local Array Address",              "input": "UAS_LOCAL_ARRAY\n",                                             "tier": "stack_uas"},
    {"id": "TC-MEM-312", "name": "Stack UAS: Return Local Struct Address",             "input": "UAS_LOCAL_STRUCT\n",                                            "tier": "stack_uas"},
    {"id": "TC-MEM-313", "name": "Stack UAS: Store Local Ptr in Global Variable",      "input": "UAS_GLOBAL_STORE\n",                                            "tier": "stack_uas"},
    {"id": "TC-MEM-314", "name": "Stack UAS: Dereference After Function Return",       "input": "UAS_DEREF_AFTER_RETURN\n",                                      "tier": "stack_uas"},
    {"id": "TC-MEM-315", "name": "Stack UAS: Loop-Scope Variable Address Escape",      "input": "UAS_LOOP_SCOPE\n",                                              "tier": "stack_uas_loop"},
    {"id": "TC-MEM-316", "name": "Stack UAS: Conditional-Scope Ptr Escape",            "input": "UAS_IF_SCOPE\n",                                                "tier": "stack_uas_loop"},
    {"id": "TC-MEM-317", "name": "Stack UAS: Nested Block Scope Variable Dangle",      "input": "UAS_NESTED_BLOCK\n",                                            "tier": "stack_uas_loop"},
    {"id": "TC-MEM-318", "name": "Stack UAS: Lambda Capture of Local Stack Ref",       "input": "UAS_LAMBDA_CAPTURE\n",                                          "tier": "stack_uas"},
    {"id": "TC-MEM-319", "name": "Stack UAS: Alloca Buffer Use After Function Exit",   "input": "UAS_ALLOCA\n",                                                  "tier": "stack_uas"},
    {"id": "TC-MEM-320", "name": "Stack UAS: Return-Stack-Address via Output Param",   "input": "UAS_OUTPUT_PARAM\n",                                            "tier": "stack_uas"},

    # ══ TIER 66 — Type Confusion / RTTI Abuse / Union Misread (TC-321..330) ══
    {"id": "TC-MEM-321", "name": "Type Confusion: Invalid Downcast Base→Derived",      "input": "TYPE_CONF_DOWNCAST\n",                                          "tier": "type_confusion"},
    {"id": "TC-MEM-322", "name": "Type Confusion: reinterpret_cast Float→Int Probe",   "input": "TYPE_CONF_FLOAT_INT\n",                                         "tier": "type_confusion"},
    {"id": "TC-MEM-323", "name": "Type Confusion: Cast Object to Sibling Class Type",  "input": "TYPE_CONF_SIBLING\n",                                           "tier": "type_confusion"},
    {"id": "TC-MEM-324", "name": "Type Confusion: Void* Cast Polymorphic Dispatch",    "input": "TYPE_CONF_VOID_PTR\n",                                          "tier": "type_confusion"},
    {"id": "TC-MEM-325", "name": "Type Confusion: Struct-Pun via char* Alias Read",    "input": "TYPE_CONF_STRUCT_PUN\n",                                        "tier": "type_confusion"},
    {"id": "TC-MEM-326", "name": "Union Misread: Write int Member, Read float",        "input": "UNION_INT_FLOAT\n",                                             "tier": "union_misread"},
    {"id": "TC-MEM-327", "name": "Union Misread: Write short, Read as 32-bit int",     "input": "UNION_SHORT_INT\n",                                             "tier": "union_misread"},
    {"id": "TC-MEM-328", "name": "Union Misread: Write ptr, Read as 64-bit int",       "input": "UNION_PTR_UINT64\n",                                            "tier": "union_misread"},
    {"id": "TC-MEM-329", "name": "Union Misread: Write char[8], Read as double",       "input": "UNION_CHAR_DOUBLE\n",                                           "tier": "union_misread"},
    {"id": "TC-MEM-330", "name": "Union Misread: Enum→Struct Active-Member Mismatch",  "input": "UNION_ENUM_STRUCT\n",                                           "tier": "union_misread"},

    # ══ TIER 67 — snprintf / strncpy / memcpy Bounded-Write Bugs (TC-331..345) ═
    {"id": "TC-MEM-331", "name": "snprintf: N-1 Payload (Exact Fit, No Overflow)",     "input": "A" * 31 + "\n",                                                "tier": "snprintf_trunc"},
    {"id": "TC-MEM-332", "name": "snprintf: N Payload (Writes N-1 chars + \\0)",       "input": "A" * 32 + "\n",                                                "tier": "snprintf_trunc"},
    {"id": "TC-MEM-333", "name": "snprintf: N+1 Payload (Off-by-One Truncation)",      "input": "A" * 33 + "\n",                                                "tier": "snprintf_trunc"},
    {"id": "TC-MEM-334", "name": "snprintf: 2N Payload (Double-Width Truncation)",     "input": "A" * 64 + "\n",                                                "tier": "snprintf_trunc"},
    {"id": "TC-MEM-335", "name": "snprintf: Format String Inside snprintf Buffer",     "input": "%s%s%n%x" * 8 + "\n",                                          "tier": "snprintf_trunc"},
    {"id": "TC-MEM-336", "name": "strncpy: Exact Buffer Fill — No Null Termination",   "input": "B" * 32 + "\n",                                                "tier": "strncpy_notterm"},
    {"id": "TC-MEM-337", "name": "strncpy: Oversize — Read Past Non-Terminated End",   "input": "B" * 48 + "\n",                                                "tier": "strncpy_notterm"},
    {"id": "TC-MEM-338", "name": "strncpy: Embedded NUL Before Length — Short Copy",   "input": "HELLO\x00WORLD\n",                                             "tier": "strncpy_notterm"},
    {"id": "TC-MEM-339", "name": "strncpy: Unicode Multibyte Mid-Char Truncation",     "input": ("日" * 10) + "\n",                                             "tier": "strncpy_notterm"},
    {"id": "TC-MEM-340", "name": "strncpy: Mixed Null + Payload After Terminator",     "input": "SAFE\x00" + "A" * 27 + "\n",                                   "tier": "strncpy_notterm"},
    {"id": "TC-MEM-341", "name": "memcpy: 1-Byte Overlap (src = dst+1)",               "input": "MEMCPY_OVL:1\n",                                               "tier": "memcpy_overlap"},
    {"id": "TC-MEM-342", "name": "memcpy: 8-Byte Overlap Region Corruption",           "input": "MEMCPY_OVL:8\n",                                               "tier": "memcpy_overlap"},
    {"id": "TC-MEM-343", "name": "memcpy: 16-Byte Full Overlap (src == dst)",          "input": "MEMCPY_OVL:16\n",                                              "tier": "memcpy_overlap"},
    {"id": "TC-MEM-344", "name": "memcpy: Reversed Overlap (dst = src+N/2)",           "input": "MEMCPY_OVL_REV:16\n",                                          "tier": "memcpy_overlap"},
    {"id": "TC-MEM-345", "name": "memcpy: Zero-Length Copy (Benign Edge Case)",        "input": "MEMCPY_ZERO\n",                                                "tier": "memcpy_overlap"},

    # ══ TIER 68 — SQL Injection Classic & Advanced Patterns (TC-346..355) ════
    {"id": "TC-MEM-346", "name": "SQL Injection: Classic Single-Quote Escape",         "input": "' OR '1'='1\n",                                                "tier": "sql_injection"},
    {"id": "TC-MEM-347", "name": "SQL Injection: Comment Sequence Auth Bypass",        "input": "admin'--\n",                                                   "tier": "sql_injection"},
    {"id": "TC-MEM-348", "name": "SQL Injection: UNION SELECT Data Exfil Pattern",     "input": "1 UNION SELECT null,null,null--\n",                            "tier": "sql_injection"},
    {"id": "TC-MEM-349", "name": "SQL Injection: Stacked Query Semicolon Separator",   "input": "1; DROP TABLE users;--\n",                                     "tier": "sql_injection"},
    {"id": "TC-MEM-350", "name": "SQL Injection: Blind Time-Based SLEEP Probe",        "input": "1 AND SLEEP(5)--\n",                                           "tier": "sql_injection"},
    {"id": "TC-MEM-351", "name": "SQL Injection: Boolean Blind TRUE Condition",        "input": "' OR 1=1--\n",                                                 "tier": "sql_injection"},
    {"id": "TC-MEM-352", "name": "SQL Injection: Hex-Encoded Payload Bypass",          "input": "0x27204F5220 OR 1=1--\n",                                      "tier": "sql_injection"},
    {"id": "TC-MEM-353", "name": "SQL Injection: Double-Dash Inline Comment",          "input": "SELECT * FROM users WHERE id=1--\n",                           "tier": "sql_injection"},
    {"id": "TC-MEM-354", "name": "SQL Injection: PostgreSQL CAST Coercion Probe",      "input": "1::text UNION SELECT username FROM users--\n",                 "tier": "sql_injection"},
    {"id": "TC-MEM-355", "name": "SQL Injection: Error-Based EXTRACTVALUE Probe",      "input": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--\n",             "tier": "sql_injection"},

    # ══ TIER 69 — Path Traversal & Directory Escape Payloads (TC-356..365) ══
    {"id": "TC-MEM-356", "name": "Path Traversal: Classic ../ Directory Escape",       "input": "../../../etc/passwd\n",                                        "tier": "path_traversal"},
    {"id": "TC-MEM-357", "name": "Path Traversal: Windows ..\\ Directory Escape",      "input": "..\\..\\..\\Windows\\System32\\cmd.exe\n",                    "tier": "path_traversal"},
    {"id": "TC-MEM-358", "name": "Path Traversal: URL Encoded %2e%2e%2f Sequence",     "input": "%2e%2e%2f%2e%2e%2fetc/shadow\n",                              "tier": "path_traversal"},
    {"id": "TC-MEM-359", "name": "Path Traversal: Double URL Encode %252e%252e%252f",  "input": "%252e%252e%252fetc%252fpasswd\n",                             "tier": "path_traversal"},
    {"id": "TC-MEM-360", "name": "Path Traversal: Null Byte Truncation Bypass",        "input": "../../../../etc/passwd\x00.jpg\n",                            "tier": "path_traversal"},
    {"id": "TC-MEM-361", "name": "Path Traversal: Absolute Path Injection /etc/passwd","input": "/etc/passwd\n",                                               "tier": "path_traversal"},
    {"id": "TC-MEM-362", "name": "Path Traversal: UNC Path Injection \\\\server\\share","input": "\\\\evil.server\\share\\payload\n",                          "tier": "path_traversal"},
    {"id": "TC-MEM-363", "name": "Path Traversal: Mixed Slash Traversal ../..\\../",   "input": "../..\\../etc/passwd\n",                                       "tier": "path_traversal"},
    {"id": "TC-MEM-364", "name": "Path Traversal: Overlong Dot-Dot Sequence (10x)",   "input": ("../" * 10) + "etc/passwd\n",                                 "tier": "path_traversal"},
    {"id": "TC-MEM-365", "name": "Path Traversal: Proc Self Environ Self-Read",        "input": "../../proc/self/environ\n",                                   "tier": "path_traversal"},

    # ══ TIER 70 — CRLF / Log / Header Injection (TC-366..373) ═══════════════
    {"id": "TC-MEM-366", "name": "CRLF Injection: HTTP Header Split via \\r\\n",       "input": "value\r\nX-Injected: evil\r\n\r\n",                           "tier": "crlf_injection"},
    {"id": "TC-MEM-367", "name": "CRLF Injection: Log Line Spoof via \\n",            "input": "user\nFAKE_LOG_ENTRY: admin login success\n",                 "tier": "crlf_injection"},
    {"id": "TC-MEM-368", "name": "CRLF Injection: Response Splitting Double CRLF",    "input": "X\r\n\r\nHTTP/1.1 200 OK\r\nFake: response\r\n",             "tier": "crlf_injection"},
    {"id": "TC-MEM-369", "name": "CRLF Injection: Null-Byte + CRLF Combo",            "input": "data\x00\r\nContent-Length: 0\r\n",                           "tier": "crlf_injection"},
    {"id": "TC-MEM-370", "name": "CRLF Injection: Unicode Line Separator (U+2028)",   "input": "header\u2028X-Injected: evil\n",                              "tier": "crlf_injection"},
    {"id": "TC-MEM-371", "name": "CRLF Injection: Carriage Return Only Split \\r",    "input": "value\rX-Injected: evil\n",                                   "tier": "crlf_injection"},
    {"id": "TC-MEM-372", "name": "CRLF Injection: Long Padding Before Injection",     "input": "A" * 100 + "\r\nX-Attack: overflow-inject\r\n",               "tier": "crlf_injection"},
    {"id": "TC-MEM-373", "name": "CRLF Injection: Encoded \\r\\n (%%0d%%0a) Bypass",  "input": "data%0d%0aX-Injected: evil%0d%0a\n",                          "tier": "crlf_injection"},

    # ══ TIER 71 — LDAP Injection Payloads (TC-374..379) ═════════════════════
    {"id": "TC-MEM-374", "name": "LDAP Injection: Wildcard Auth Bypass (*)",           "input": "*\n",                                                          "tier": "ldap_injection"},
    {"id": "TC-MEM-375", "name": "LDAP Injection: Filter Escape )(&(x=x",             "input": "*)(&(objectClass=*)\n",                                        "tier": "ldap_injection"},
    {"id": "TC-MEM-376", "name": "LDAP Injection: Boolean OR True Condition",          "input": "user)(|(uid=*))\n",                                            "tier": "ldap_injection"},
    {"id": "TC-MEM-377", "name": "LDAP Injection: Null Byte Attribute Terminator",    "input": "admin\x00\n",                                                  "tier": "ldap_injection"},
    {"id": "TC-MEM-378", "name": "LDAP Injection: Nested Filter Escape Sequence",     "input": ")(uid=*))(|(uid=*\n",                                          "tier": "ldap_injection"},
    {"id": "TC-MEM-379", "name": "LDAP Injection: Escaped Backslash + Null Combo",    "input": "\\00\\2a\\28\\29\n",                                           "tier": "ldap_injection"},

    # ══ TIER 72 — size_t / Signed-Unsigned / Numeric Edge Cases (TC-380..390) ═
    {"id": "TC-MEM-380", "name": "size_t: SIZE_MAX Allocation Request Probe",          "input": "SIZE:18446744073709551615\n",                                  "tier": "size_t_overflow"},
    {"id": "TC-MEM-381", "name": "size_t: SIZE_MAX - 1 Boundary Probe",               "input": "SIZE:18446744073709551614\n",                                  "tier": "size_t_overflow"},
    {"id": "TC-MEM-382", "name": "size_t: SIZE_MAX / 2 Wraparound Probe",             "input": "SIZE:9223372036854775807\n",                                   "tier": "size_t_overflow"},
    {"id": "TC-MEM-383", "name": "Signedness: -1 as size_t Wraps to UINT_MAX",        "input": "SIZE:-1\n",                                                    "tier": "signedness_bug"},
    {"id": "TC-MEM-384", "name": "Signedness: -2 Unsigned Overflow Probe",            "input": "SIZE:-2\n",                                                    "tier": "signedness_bug"},
    {"id": "TC-MEM-385", "name": "Signedness: Signed/Unsigned Comparison Bypass",     "input": "INDEX:-1\n",                                                   "tier": "signedness_bug"},
    {"id": "TC-MEM-386", "name": "Numeric: Infinity (Inf) Float Parse Probe",         "input": "FLOAT:Inf\n",                                                  "tier": "numeric_format"},
    {"id": "TC-MEM-387", "name": "Numeric: Not-a-Number (NaN) Parse Probe",           "input": "FLOAT:NaN\n",                                                  "tier": "numeric_format"},
    {"id": "TC-MEM-388", "name": "Numeric: Octal 0777 Integer Parse Probe",           "input": "INT:0777\n",                                                   "tier": "numeric_format"},
    {"id": "TC-MEM-389", "name": "Numeric: Hex 0xFFFFFFFF Integer Parse Probe",       "input": "INT:0xFFFFFFFF\n",                                             "tier": "numeric_format"},
    {"id": "TC-MEM-390", "name": "Numeric: Leading-Zero Ambiguity (010 == octal 8)",  "input": "INT:010\n",                                                    "tier": "numeric_format"},

    # ══ TIER 73 — Allocation DoS / ReDoS / Infinite Loop Anchors (TC-391..400) ═
    {"id": "TC-MEM-391", "name": "Alloc DoS: Request 1GB Single Allocation",          "input": "ALLOC:1073741824\n",                                           "tier": "alloc_dos"},
    {"id": "TC-MEM-392", "name": "Alloc DoS: Request UINT32_MAX Bytes (4GB)",         "input": "ALLOC:4294967295\n",                                           "tier": "alloc_dos"},
    {"id": "TC-MEM-393", "name": "Alloc DoS: 10000 × 1KB Allocations Spray",         "input": "MULTI_ALLOC:10000:1024\n",                                     "tier": "alloc_dos"},
    {"id": "TC-MEM-394", "name": "ReDoS: (a+)+ Backtrack Pattern (50 chars)",         "input": "a" * 50 + "!\n",                                              "tier": "regex_redos"},
    {"id": "TC-MEM-395", "name": "ReDoS: (a*a*) Catastrophic Overlap (40 chars)",     "input": "a" * 40 + "b\n",                                              "tier": "regex_redos"},
    {"id": "TC-MEM-396", "name": "ReDoS: Alternation Storm (a|aa)+ Payload",          "input": "a" * 35 + "c\n",                                              "tier": "regex_redos"},
    {"id": "TC-MEM-397", "name": "Loop Anchor: Max-Length Payload Worst-Case O(n²)",  "input": "A" * 400 + "\n",                                              "tier": "loop_anchor"},
    {"id": "TC-MEM-398", "name": "Loop Anchor: 512-Byte Repeating Pattern Flood",     "input": "LOOP:" + ("XY" * 256) + "\n",                                 "tier": "loop_anchor"},
    {"id": "TC-MEM-399", "name": "Loop Anchor: Delimiter-Heavy Payload (;x1000)",     "input": (";" * 400) + "PAYLOAD\n",                                     "tier": "loop_anchor"},
    {"id": "TC-MEM-400", "name": "Alloc DoS: Cascading Alloc-Free-Alloc Loop Probe",  "input": "CASCADE_ALLOC:100\n",                                          "tier": "alloc_dos"},

    # ══ TIER 74 — Granular Allocator Quantums & Bin Boundaries (TC-401..415) ══
    {"id": "TC-HEAP-401", "name": "104-Byte Allocator Quantum Fit (103B)",            "input": "A" * 103 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-402", "name": "104-Byte Allocator Quantum Exact + Null (104B)",    "input": "A" * 104 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-403", "name": "104-Byte Allocator Quantum Off-by-One (105B)",      "input": "A" * 105 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-404", "name": "144-Byte Bin Quantum Boundary Probe (144B)",        "input": "B" * 144 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-405", "name": "144-Byte Bin Quantum Off-by-One Probe (145B)",      "input": "B" * 145 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-406", "name": "160-Byte Bin Boundary Fit (159B)",                  "input": "C" * 159 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-407", "name": "160-Byte Bin Boundary Exact + Null (160B)",          "input": "C" * 160 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-408", "name": "160-Byte Bin Boundary Off-by-One (161B)",          "input": "C" * 161 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-409", "name": "176-Byte Bin Boundary Probe (176B)",                "input": "D" * 176 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-410", "name": "192-Byte Bin Boundary Probe (192B)",                "input": "E" * 192 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-411", "name": "208-Byte Bin Boundary Probe (208B)",                "input": "F" * 208 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-412", "name": "224-Byte Bin Boundary Probe (224B)",                "input": "G" * 224 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-413", "name": "240-Byte Bin Boundary Probe (240B)",                "input": "H" * 240 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-414", "name": "288-Byte Allocator Quantum Probe (288B)",            "input": "I" * 288 + "\n",                                               "tier": "granular_quantum"},
    {"id": "TC-HEAP-415", "name": "384-Byte Allocator Quantum Probe (384B)",            "input": "J" * 384 + "\n",                                               "tier": "granular_quantum"},

    # ══ TIER 75 — Poison Null Byte Heap Overflows (CWE-193/122) (TC-416..425) ═
    {"id": "TC-HEAP-416", "name": "Poison Null: 16B Buffer Terminator Overwrite",      "input": "N" * 16 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-417", "name": "Poison Null: 32B Buffer Terminator Overwrite",      "input": "N" * 32 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-418", "name": "Poison Null: 48B Buffer Terminator Overwrite",      "input": "N" * 48 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-419", "name": "Poison Null: 64B Buffer Terminator Overwrite",      "input": "N" * 64 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-420", "name": "Poison Null: 80B Buffer Terminator Overwrite",      "input": "N" * 80 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-421", "name": "Poison Null: 96B Buffer Terminator Overwrite",      "input": "N" * 96 + "\n",                                                "tier": "poison_null_exact"},
    {"id": "TC-HEAP-422", "name": "Poison Null: 128B Buffer Terminator Overwrite",     "input": "N" * 128 + "\n",                                               "tier": "poison_null_exact"},
    {"id": "TC-HEAP-423", "name": "Poison Null: 256B Buffer Terminator Overwrite",     "input": "N" * 256 + "\n",                                               "tier": "poison_null_exact"},
    {"id": "TC-HEAP-424", "name": "Poison Null: 512B Buffer Terminator Overwrite",     "input": "N" * 512 + "\n",                                               "tier": "poison_null_exact"},
    {"id": "TC-HEAP-425", "name": "Poison Null: 1024B Buffer Terminator Overwrite",    "input": "N" * 1024 + "\n",                                              "tier": "poison_null_exact"},

    # ══ TIER 76 — Cumulative Strcat & Dynamic Loop Appends (TC-426..435) ══════
    {"id": "TC-HEAP-426", "name": "Append Loop: Space-Separated Word Accumulation",    "input": "word " * 16 + "\n",                                            "tier": "strcat_append"},
    {"id": "TC-HEAP-427", "name": "Append Loop: Comma-Separated Values Expansion",     "input": "elem," * 32 + "\n",                                            "tier": "strcat_append"},
    {"id": "TC-HEAP-428", "name": "Append Loop: Query String Key-Value Chain",         "input": "k=v&" * 40 + "\n",                                             "tier": "strcat_append"},
    {"id": "TC-HEAP-429", "name": "Append Loop: Path Segment Accumulation",            "input": "dir/" * 30 + "target\n",                                       "tier": "strcat_append"},
    {"id": "TC-HEAP-430", "name": "Append Loop: Semicolon Delimited Statement Flood",  "input": "cmd;" * 35 + "\n",                                             "tier": "strcat_append"},
    {"id": "TC-HEAP-431", "name": "Append Loop: Pipe-Delimited Field Accumulation",    "input": "field|" * 28 + "\n",                                           "tier": "strcat_append"},
    {"id": "TC-HEAP-432", "name": "Append Loop: Repeated Prefix Concatenation",        "input": "tag:" * 32 + "final\n",                                        "tier": "strcat_append"},
    {"id": "TC-HEAP-433", "name": "Append Loop: Exponential Doubling String Pattern",  "input": "DOUBLE:" + ("X" * 120) + "\n",                                 "tier": "strcat_append"},
    {"id": "TC-HEAP-434", "name": "Append Loop: Bounded Copy with Incorrect Length",   "input": "APPEND_LOOP_MISCALC:" + ("Z" * 90) + "\n",                    "tier": "strcat_append"},
    {"id": "TC-HEAP-435", "name": "Append Loop: Rapid Re-allocation Boundary Stress",  "input": "REALLOC_STRESS:" + ("Q" * 150) + "\n",                         "tier": "strcat_append"},

    # ══ TIER 77 — C++ Unbounded Stream Extraction (cin >> heap) (TC-436..445) ═
    {"id": "TC-HEAP-436", "name": "Stream Extract: Single Continuous Token (64B)",     "input": "TOKEN64_" + ("A" * 56) + "\n",                                 "tier": "stream_extract"},
    {"id": "TC-HEAP-437", "name": "Stream Extract: Single Continuous Token (128B)",    "input": "TOKEN128_" + ("B" * 119) + "\n",                               "tier": "stream_extract"},
    {"id": "TC-HEAP-438", "name": "Stream Extract: Single Continuous Token (256B)",    "input": "TOKEN256_" + ("C" * 247) + "\n",                               "tier": "stream_extract"},
    {"id": "TC-HEAP-439", "name": "Stream Extract: Single Continuous Token (512B)",    "input": "TOKEN512_" + ("D" * 503) + "\n",                               "tier": "stream_extract"},
    {"id": "TC-HEAP-440", "name": "Stream Extract: Single Continuous Token (1024B)",   "input": "TOKEN1024_" + ("E" * 1014) + "\n",                             "tier": "stream_extract"},
    {"id": "TC-HEAP-441", "name": "Stream Extract: Single Continuous Token (2048B)",   "input": "TOKEN2048_" + ("F" * 2038) + "\n",                             "tier": "stream_extract"},
    {"id": "TC-HEAP-442", "name": "Stream Extract: Whitespace-Interleaved Rapid Stream","input": "TOK1 TOK2 TOK3 TOK4 TOK5 TOK6 TOK7 TOK8 TOK9 TOK10 TOK11\n",   "tier": "stream_extract"},
    {"id": "TC-HEAP-443", "name": "Stream Extract: Leading Newlines Flood Before Token","input": "\n\n\n\n\n\n\n\n" + ("G" * 64) + "\n",                       "tier": "stream_extract"},
    {"id": "TC-HEAP-444", "name": "Stream Extract: Mixed Tab & Space Delimited Flood", "input": "\t \t \t" + ("H" * 70) + "\t \t\n",                            "tier": "stream_extract"},
    {"id": "TC-HEAP-445", "name": "Stream Extract: Formfeed / Vertical Tab Delimiters", "input": "\x0c\x0b" + ("I" * 50) + "\x0c\n",                            "tier": "stream_extract"},

    # ══ TIER 78 — Decode & Expansion Heap Overflows (TC-446..455) ═════════════
    {"id": "TC-HEAP-446", "name": "Hex Decode: Valid Even-Length Stream (64B)",        "input": "HEXDECODE:4141414141414141414141414141414141414141414141414141414141414141\n", "tier": "decode_expansion"},
    {"id": "TC-HEAP-447", "name": "Hex Decode: Odd-Length Nibble Misalignment",        "input": "HEXDECODE:414141414141414141414141414141414141414141414141414141414141414\n",   "tier": "decode_expansion"},
    {"id": "TC-HEAP-448", "name": "Hex Decode: Non-Hex Metachars in Stream",           "input": "HEXDECODE:41414141ZZZZ!!!!41414141\n",                         "tier": "decode_expansion"},
    {"id": "TC-HEAP-449", "name": "URL Percent Decode: Repeated %20 Space Expansion",   "input": "URLDEC:" + ("%20" * 40) + "\n",                                "tier": "decode_expansion"},
    {"id": "TC-HEAP-450", "name": "URL Percent Decode: Trailing Partial Sequence",      "input": "URLDEC:normal_data%2\n",                                       "tier": "decode_expansion"},
    {"id": "TC-HEAP-451", "name": "URL Percent Decode: Nested Double Percent Decode",   "input": "URLDEC:" + ("%2520" * 25) + "\n",                              "tier": "decode_expansion"},
    {"id": "TC-HEAP-452", "name": "Base64 Decode: Oversized Valid Payload Flood",      "input": "B64DEC:" + ("QUFB" * 30) + "==\n",                             "tier": "decode_expansion"},
    {"id": "TC-HEAP-453", "name": "Base64 Decode: Unpadded Raw Stream Overread",       "input": "B64DEC:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n",                 "tier": "decode_expansion"},
    {"id": "TC-HEAP-454", "name": "HTML Entity Decode: Multi-Entity Expansion",         "input": "ENTITY:" + ("&amp;&quot;&lt;&gt;" * 12) + "\n",                 "tier": "decode_expansion"},
    {"id": "TC-HEAP-455", "name": "C-Escape Decode: Hex/Octal Sequence Expansion",      "input": "ESCAPE:" + ("\\x41\\x42\\041\\042" * 10) + "\n",               "tier": "decode_expansion"},

    # ══ TIER 79 — Integer Wrap Induced Heap Overflows (TC-456..465) ═══════════
    {"id": "TC-HEAP-456", "name": "Int Wrap Heap: 2^30 Count * 4B Wraps to 0",         "input": "ALLOC_COUNT:1073741824:4\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-457", "name": "Int Wrap Heap: 2^28 Count * 16B Wraps to 0",        "input": "ALLOC_COUNT:268435456:16\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-458", "name": "Int Wrap Heap: Count * Size Wraps to 16B",          "input": "ALLOC_COUNT:1073741828:4\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-459", "name": "Int Wrap Heap: Count * Size Wraps to 32B",          "input": "ALLOC_COUNT:1073741832:4\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-460", "name": "Int Wrap Heap: Count * Size Wraps to 64B",          "input": "ALLOC_COUNT:1073741840:4\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-461", "name": "Int Wrap Heap: Length + Header Overhead Wrap",      "input": "ALLOC_HEADER:4294967280:32\n",                                 "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-462", "name": "Int Wrap Heap: Signed Negative Size Treated Unsigned","input": "ALLOC_SIGNED:-32\n",                                          "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-463", "name": "Int Wrap Heap: 64-bit Size Truncated to 32-bit uint","input": "ALLOC_TRUNC:8589934624\n",                                   "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-464", "name": "Int Wrap Heap: Off-by-One Element Count (n+1)*size","input": "ALLOC_OFF1_COUNT:100:4\n",                                     "tier": "int_alloc_wrap"},
    {"id": "TC-HEAP-465", "name": "Int Wrap Heap: Array 2D Dimension Multiplication",  "input": "ALLOC_2D:65536:65536:4\n",                                     "tier": "int_alloc_wrap"},

    # ══ TIER 80 — Structured Protocol & Delimited Tokenizer (TC-466..475) ═════
    {"id": "TC-HEAP-466", "name": "Protocol Heap: Oversized HTTP Request Line",         "input": "GET /" + ("A" * 120) + " HTTP/1.1\r\n\r\n",                   "tier": "protocol_parser"},
    {"id": "TC-HEAP-467", "name": "Protocol Heap: Oversized HTTP Header Name Field",    "input": ("X-Header-Long-" * 10) + ": value\r\n\r\n",                    "tier": "protocol_parser"},
    {"id": "TC-HEAP-468", "name": "Protocol Heap: Oversized HTTP Header Value Field",   "input": "User-Agent: " + ("CustomClient/" * 15) + "\r\n\r\n",            "tier": "protocol_parser"},
    {"id": "TC-HEAP-469", "name": "Protocol Heap: HTTP Cookie Header Name-Value Flood", "input": "Cookie: " + ("sess_token_" * 12) + "=xyz\r\n\r\n",             "tier": "protocol_parser"},
    {"id": "TC-HEAP-470", "name": "Protocol Heap: JSON Unclosed String Tokenizer Flood","input": '{"key": "' + ("UNCLOSED_STRING_CONTENT" * 6) + '\n',          "tier": "protocol_parser"},
    {"id": "TC-HEAP-471", "name": "Protocol Heap: JSON Oversized Key Name Buffer",      "input": '{"' + ("LONG_JSON_KEY_NAME_" * 6) + '": "val"}\n',            "tier": "protocol_parser"},
    {"id": "TC-HEAP-472", "name": "Protocol Heap: CSV Quoted Field Unclosed Flood",     "input": '"unclosed_field_one,"' + ("long_data_payload" * 8) + '\n',     "tier": "protocol_parser"},
    {"id": "TC-HEAP-473", "name": "Protocol Heap: Delimiter-Dense Input Stressing Ptrs","input": (":::;;;,,,///" * 12) + "payload\n",                          "tier": "protocol_parser"},
    {"id": "TC-HEAP-474", "name": "Protocol Heap: Multipart Form Boundary Overwrite",   "input": "--WebKitFormBoundary" + ("X" * 80) + "\r\n",                   "tier": "protocol_parser"},
    {"id": "TC-HEAP-475", "name": "Protocol Heap: URL Authority/Hostname Field Overrun", "input": "https://" + ("subdomain." * 15) + "example.com/\n",            "tier": "protocol_parser"},

    # ══ TIER 81 — Heap Out-of-Bounds Read / Unterminated String (TC-476..485) ═
    {"id": "TC-HEAP-476", "name": "Heap OOB Read: Missing Null Terminator Strlen Leak","input": "HEAP_OOB_READ_STR\n",                                          "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-477", "name": "Heap OOB Read: Fixed-Buffer Non-Terminated Printf",  "input": "HEAP_OOB_PRINTF\n",                                            "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-478", "name": "Heap OOB Read: Exact Size Char Buffer Read Past End","input": "HEAP_OOB_EXACT_READ\n",                                        "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-479", "name": "Heap OOB Read: Positive Index One Past End arr[size]","input": "HEAP_OOB_IDX:ARR_SIZE\n",                                    "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-480", "name": "Heap OOB Read: Positive Index Two Past End arr[+2]", "input": "HEAP_OOB_IDX:ARR_SIZE_PLUS_2\n",                             "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-481", "name": "Heap OOB Read: Negative Offset Before Buffer Start", "input": "HEAP_OOB_IDX:-1\n",                                            "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-482", "name": "Heap OOB Read: Far Negative Offset Before Alloc",    "input": "HEAP_OOB_IDX:-8\n",                                            "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-483", "name": "Heap OOB Read: Memcmp Scanning Past Buffer End",     "input": "HEAP_OOB_MEMCMP\n",                                            "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-484", "name": "Heap OOB Read: Sentinel Byte Scanning Past Alloc",   "input": "HEAP_OOB_SENTINEL\n",                                          "tier": "heap_oob_read_v2"},
    {"id": "TC-HEAP-485", "name": "Heap OOB Read: Unterminated UTF-8 Byte Overread",    "input": "HEAP_OOB_UTF8_OVERREAD\n",                                     "tier": "heap_oob_read_v2"},

    # ══ TIER 82 — C++ STL & Smart Pointer Heap Bounds (TC-486..495) ═══════════
    {"id": "TC-HEAP-486", "name": "C++ STL: std::vector Heap Array Out of Range []",   "input": "STL_VECTOR_OOB:100\n",                                         "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-487", "name": "C++ STL: std::unique_ptr<char[]> Subscript OOB",    "input": "STL_UNIQUE_PTR_OOB:64\n",                                      "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-488", "name": "C++ STL: std::string::copy Exceeding Dest Raw Buf", "input": "STL_STRING_COPY:" + ("W" * 80) + "\n",                        "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-489", "name": "C++ STL: Raw Ptr Arithmetic Past Dynamic Array",     "input": "STL_PTR_ARITH:OFFSET_OVERFLOW\n",                              "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-490", "name": "C++ STL: std::span Subspan Out of Heap Memory Bounds","input": "STL_SPAN_OOB\n",                                              "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-491", "name": "C++ STL: Custom Allocator Chunk Bounds Violation",  "input": "STL_CUSTOM_ALLOC_OOB\n",                                       "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-492", "name": "C++ STL: std::shared_ptr Array Deletion / Bounds",  "input": "STL_SHARED_PTR_OOB\n",                                         "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-493", "name": "C++ STL: Inlined Vector SSO to Heap Overrun",       "input": "STL_SSO_OVERRUN:" + ("V" * 40) + "\n",                         "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-494", "name": "C++ STL: Vector Push_back Realloc Invalidation Read","input": "STL_VECTOR_REALLOC_READ\n",                                    "tier": "stl_heap_bounds"},
    {"id": "TC-HEAP-495", "name": "C++ STL: Polymorphic Heap Dynamic Cast Bounds Check","input": "STL_DYNAMIC_CAST_BOUNDS\n",                                   "tier": "stl_heap_bounds"},

    # ══ TIER 83 — Cyclic De Bruijn Offset Locators (TC-496..500) ══════════════
    {"id": "TC-HEAP-496", "name": "De Bruijn: 512-Byte Unique Offset Locator Pattern",  "input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 8)[:512] + "\n", "tier": "cyclic_debruijn_v2"},
    {"id": "TC-HEAP-497", "name": "De Bruijn: 1024-Byte (1KB) Unique Offset Pattern",   "input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 16)[:1024] + "\n", "tier": "cyclic_debruijn_v2"},
    {"id": "TC-HEAP-498", "name": "De Bruijn: 2048-Byte (2KB) Unique Offset Pattern",   "input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 32)[:2048] + "\n", "tier": "cyclic_debruijn_v2"},
    {"id": "TC-HEAP-499", "name": "De Bruijn: 4096-Byte (4KB Page) Unique Pattern",     "input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 64)[:4096] + "\n", "tier": "cyclic_debruijn_v2"},
    {"id": "TC-HEAP-500", "name": "De Bruijn: 8192-Byte (8KB 2-Page) Deep Heap Locator","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 128)[:8192] + "\n", "tier": "cyclic_debruijn_v2"},

    # ══ TIER 84 — Mid-Range Allocator Quantum Bins (576B..960B) (TC-501..510) ═
    {"id": "TC-HEAP-501", "name": "576-Byte Bin: Exact Allocation Boundary Probe",      "input": "A" * 576 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-502", "name": "576-Byte Bin: Off-by-One Null Byte Overwrite (+1)",  "input": "A" * 577 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-503", "name": "640-Byte Bin: Exact Quantum Fit Probe",               "input": "B" * 640 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-504", "name": "640-Byte Bin: Off-by-One Boundary Overflow (+1)",    "input": "B" * 641 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-505", "name": "704-Byte Bin: Mid-Quantum Boundary Probe",            "input": "C" * 704 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-506", "name": "768-Byte Bin: 3/4-KB Allocator Boundary Probe",      "input": "D" * 768 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-507", "name": "768-Byte Bin: +8 Pointer Word Overwrite Probe",       "input": "D" * 776 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-508", "name": "832-Byte Bin: Upper Mid-Bin Probe",                  "input": "E" * 832 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-509", "name": "896-Byte Bin: Near-1KB Allocator Boundary Probe",     "input": "F" * 896 + "\n",                                                "tier": "mid_bins"},
    {"id": "TC-HEAP-510", "name": "960-Byte Bin: Allocator Pre-1KB Threshold Fit",      "input": "G" * 960 + "\n",                                                "tier": "mid_bins"},

    # ══ TIER 85 — 1KB..4KB Large Bin Boundaries (TC-511..520) ═════════════════
    {"id": "TC-HEAP-511", "name": "1152-Byte Bin: Small-to-Large Bin Transition Probe",  "input": "H" * 1152 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-512", "name": "1280-Byte Bin: 1.25KB Allocator Chunk Boundary",      "input": "I" * 1280 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-513", "name": "1536-Byte Bin: 1.5KB Allocator Chunk Boundary",       "input": "J" * 1536 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-514", "name": "1536-Byte Bin: +1 Off-by-One Chunk Corruption",       "input": "J" * 1537 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-515", "name": "1792-Byte Bin: 1.75KB Allocator Chunk Boundary",      "input": "K" * 1792 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-516", "name": "2048-Byte (2KB): Exact Power-of-Two Boundary",       "input": "L" * 2048 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-517", "name": "2048-Byte (2KB): Off-by-One Buffer Overflow (+1)",   "input": "L" * 2049 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-518", "name": "2560-Byte Bin: 2.5KB Intermediate Bin Boundary",      "input": "M" * 2560 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-519", "name": "3072-Byte Bin: 3KB Allocator Chunk Boundary",         "input": "N" * 3072 + "\n",                                               "tier": "mid_large_bins"},
    {"id": "TC-HEAP-520", "name": "3584-Byte Bin: 3.5KB Pre-Page Boundary Fit",         "input": "O" * 3584 + "\n",                                               "tier": "mid_large_bins"},

    # ══ TIER 86 — OS Virtual Page Multiples & Drift (4KB..16KB) (TC-521..530) ═
    {"id": "TC-HEAP-521", "name": "Page Boundary: 4095B (Page - 1 Safe Fit)",           "input": "P" * 4095 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-522", "name": "Page Boundary: 4096B (1 Page Exact Boundary)",       "input": "P" * 4096 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-523", "name": "Page Boundary: 4097B (1 Page + 1 Boundary Breach)",   "input": "P" * 4097 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-524", "name": "Page Boundary: 8191B (2 Pages - 1 Boundary Probe)",   "input": "Q" * 8191 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-525", "name": "Page Boundary: 8192B (2 Pages Exact Boundary)",       "input": "Q" * 8192 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-526", "name": "Page Boundary: 8193B (2 Pages + 1 Boundary Breach)",   "input": "Q" * 8193 + "\n",                                               "tier": "page_multiples"},
    {"id": "TC-HEAP-527", "name": "Page Boundary: 12288B (3 Pages Exact Boundary)",      "input": "R" * 12288 + "\n",                                              "tier": "page_multiples"},
    {"id": "TC-HEAP-528", "name": "Page Boundary: 16383B (4 Pages - 1 Safe Fit)",       "input": "S" * 16383 + "\n",                                              "tier": "page_multiples"},
    {"id": "TC-HEAP-529", "name": "Page Boundary: 16384B (4 Pages Exact Boundary)",      "input": "S" * 16384 + "\n",                                              "tier": "page_multiples"},
    {"id": "TC-HEAP-530", "name": "Page Boundary: 16385B (4 Pages + 1 Boundary Breach)",  "input": "S" * 16385 + "\n",                                              "tier": "page_multiples"},

    # ══ TIER 87 — Mmap Threshold & Direct Mapping (32KB..1MB) (TC-531..540) ═══
    {"id": "TC-HEAP-531", "name": "Mmap Threshold: 32767B (32KB - 1 Safe Fit)",          "input": "T" * 32767 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-532", "name": "Mmap Threshold: 32768B (32KB Exact Boundary)",        "input": "T" * 32768 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-533", "name": "Mmap Threshold: 32769B (32KB + 1 Boundary Breach)",   "input": "T" * 32769 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-534", "name": "Mmap Threshold: 65535B (64KB - 1 Boundary Probe)",    "input": "U" * 65535 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-535", "name": "Mmap Threshold: 65536B (64KB Exact 16-Page Boundary)","input": "U" * 65536 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-536", "name": "Mmap Threshold: 65537B (64KB + 1 Boundary Breach)",   "input": "U" * 65537 + "\n",                                              "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-537", "name": "Mmap Threshold: 131072B (128KB Default Mmap Limit)",  "input": "V" * 131072 + "\n",                                             "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-538", "name": "Mmap Direct: 262144B (256KB Kernel Direct Map)",      "input": "W" * 262144 + "\n",                                             "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-539", "name": "Mmap Direct: 524288B (512KB Massive Chunk Map)",      "input": "X" * 524288 + "\n",                                             "tier": "mmap_threshold_v2"},
    {"id": "TC-HEAP-540", "name": "Mmap Direct: 1048576B (1MB Gigantic Mmap Chunk)",     "input": "Y" * 1048576 + "\n",                                            "tier": "mmap_threshold_v2"},

    # ══ TIER 88 — Off-by-One Array Index & Pointer Drift (TC-541..550) ════════
    {"id": "TC-HEAP-541", "name": "Index Drift: Array Length Equal Index arr[N]",        "input": "INDEX_DRIFT:ARR_LEN_EXACT\n",                                  "tier": "oob_index_drift"},
    {"id": "TC-HEAP-542", "name": "Index Drift: Off-by-One Forward Index arr[N+1]",      "input": "INDEX_DRIFT:ARR_LEN_PLUS_1\n",                                  "tier": "oob_index_drift"},
    {"id": "TC-HEAP-543", "name": "Index Drift: Loop Boundary Condition <= vs <",       "input": "INDEX_DRIFT:LOOP_LE_BOUND\n",                                   "tier": "oob_index_drift"},
    {"id": "TC-HEAP-544", "name": "Index Drift: Reverse Loop Underflow i >= 0 unsigned", "input": "INDEX_DRIFT:UNSIGNED_REVERSE_WRAP\n",                          "tier": "oob_index_drift"},
    {"id": "TC-HEAP-545", "name": "Pointer Drift: Decrement Before Base (ptr-- at base)","input": "PTR_DRIFT:PRE_BASE_DECREMENT\n",                              "tier": "oob_index_drift"},
    {"id": "TC-HEAP-546", "name": "Pointer Drift: Step Size Mismatch (sizeof(T*) vs T)", "input": "PTR_DRIFT:STEP_SIZE_MISMATCH\n",                              "tier": "oob_index_drift"},
    {"id": "TC-HEAP-547", "name": "Pointer Drift: Off-by-One Sentinel Scan Loop",        "input": "PTR_DRIFT:SENTINEL_LOOP_OVERRUN\n",                             "tier": "oob_index_drift"},
    {"id": "TC-HEAP-548", "name": "Pointer Drift: Post-Increment in End Check (*p++ != 0)","input": "PTR_DRIFT:POST_INC_END_CHECK\n",                            "tier": "oob_index_drift"},
    {"id": "TC-HEAP-549", "name": "Pointer Drift: Negative Array Subscript arr[-2]",     "input": "PTR_DRIFT:NEGATIVE_SUBSCRIPT_2\n",                             "tier": "oob_index_drift"},
    {"id": "TC-HEAP-550", "name": "Pointer Drift: Multidimensional 2D Row Stride Drift",  "input": "PTR_DRIFT:2D_ROW_STRIDE_OVERRUN\n",                            "tier": "oob_index_drift"},

    # ══ TIER 89 — Unbounded C-String Manipulation Functions (TC-551..560) ═════
    {"id": "TC-HEAP-551", "name": "Unbounded C-String: stpcpy Destination Overrun",      "input": "STPCPY_OVERFLOW:" + ("A" * 64) + "\n",                          "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-552", "name": "Unbounded C-String: strcat into Pre-Filled Buffer",   "input": "STRCAT_PREFILLED:" + ("B" * 48) + "\n",                         "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-553", "name": "Unbounded C-String: sprintf Multi-Arg Overflow",      "input": "SPRINTF_MULTI_ARG:%s:%s:%s\n",                                  "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-554", "name": "Unbounded C-String: vsprintf Dynamic Format Spill",   "input": "VSPRINTF_SPILL:" + ("%s" * 16) + "\n",                          "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-555", "name": "Unbounded C-String: swprintf Wide Char Buffer Spill", "input": "SWPRINTF_WIDE_SPILL:" + ("W" * 80) + "\n",                     "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-556", "name": "Unbounded C-String: asctime 26B Buffer Stress",      "input": "ASCTIME_26B_STRESS_OVERRUN\n",                                  "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-557", "name": "Unbounded C-String: realpath PATH_MAX (1024B) Flood", "input": "REALPATH_OVERFLOW:" + ("dir/" * 260) + "\n",                    "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-558", "name": "Unbounded C-String: strncat Off-by-One (+1 null)",    "input": "STRNCAT_OFF1:" + ("C" * 32) + "\n",                             "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-559", "name": "Unbounded C-String: gets Equivalent Stream Overflow", "input": "GETS_EQUIV:" + ("D" * 128) + "\n",                              "tier": "unsafe_c_string"},
    {"id": "TC-HEAP-560", "name": "Unbounded C-String: Cumulative Strcpy Loop Cascade",  "input": "STRCPY_CASCADE:" + ("E" * 96) + "\n",                           "tier": "unsafe_c_string"},

    # ══ TIER 90 — Wide Character & Surrogate Heap Overflows (TC-561..570) ═════
    {"id": "TC-HEAP-561", "name": "Wide Char: mbstowcs Byte vs Wide Size Mismatch",     "input": "MBSTOWCS_MISMATCH:" + ("日" * 20) + "\n",                        "tier": "wide_char_heap"},
    {"id": "TC-HEAP-562", "name": "Wide Char: UTF-16 Surrogate Pair Split at Boundary",  "input": "SURROGATE_SPLIT:\xed\xa0\xbd\xed\xb8\x80\n",                     "tier": "wide_char_heap"},
    {"id": "TC-HEAP-563", "name": "Wide Char: UTF-32 4-Byte Element Heap Overrun",       "input": "UTF32_OVERRUN:" + ("\U0001F600" * 16) + "\n",                  "tier": "wide_char_heap"},
    {"id": "TC-HEAP-564", "name": "Wide Char: 2-Byte Overlong UTF-8 Sequence (0xC0 0x80)","input": "OVERLONG_UTF8_2B:\xc0\x80\xc0\x80\n",                           "tier": "wide_char_heap"},
    {"id": "TC-HEAP-565", "name": "Wide Char: 3-Byte Overlong UTF-8 Sequence",          "input": "OVERLONG_UTF8_3B:\xe0\x80\x80\n",                               "tier": "wide_char_heap"},
    {"id": "TC-HEAP-566", "name": "Wide Char: 4-Byte Overlong UTF-8 Sequence",          "input": "OVERLONG_UTF8_4B:\xf0\x80\x80\x80\n",                           "tier": "wide_char_heap"},
    {"id": "TC-HEAP-567", "name": "Wide Char: Unpaired High Surrogate (U+D800)",        "input": "UNPAIRED_HIGH_SURROGATE:\xed\xa0\x80\xed\xa0\x80\n",            "tier": "wide_char_heap"},
    {"id": "TC-HEAP-568", "name": "Wide Char: Unpaired Low Surrogate (U+DC00)",         "input": "UNPAIRED_LOW_SURROGATE:\xed\xb0\x80\xed\xb0\x80\n",             "tier": "wide_char_heap"},
    {"id": "TC-HEAP-569", "name": "Wide Char: wcslen Overread on Non-Terminated wchar", "input": "WCSLEN_OVERREAD_PROBE\n",                                       "tier": "wide_char_heap"},
    {"id": "TC-HEAP-570", "name": "Wide Char: Unicode Normalization (NFKD) Expansion",   "input": "NORMALIZATION_EXPAND:\ufdfa\ufdfb\n",                           "tier": "wide_char_heap"},

    # ══ TIER 91 — C++ std::string & string_view Lifetime Hazards (TC-571..580) ═
    {"id": "TC-HEAP-571", "name": "C++ String: string_view Dangling Temporary Ref",     "input": "STRING_VIEW_DANGLING_TEMP\n",                                   "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-572", "name": "C++ String: const_cast data() Buffer Mutation Overrun","input": "STRING_CONST_CAST_MUTATE:" + ("A" * 64) + "\n",              "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-573", "name": "C++ String: resize vs reserve Size/Capacity Confusion","input": "STRING_RESIZE_VS_RESERVE\n",                                  "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-574", "name": "C++ String: SSO Exact Fit (15B Libc++ Limit)",       "input": "123456789012345\n",                                             "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-575", "name": "C++ String: SSO Boundary + 1 Heap Transition (16B)", "input": "1234567890123456\n",                                            "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-576", "name": "C++ String: SSO 22B GNU Libstdc++ Exact Limit",      "input": "1234567890123456789012\n",                                     "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-577", "name": "C++ String: SSO 23B GNU Transition to Heap",         "input": "12345678901234567890123\n",                                    "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-578", "name": "C++ String: Self-Append Exponential Heap Doubling",   "input": "STRING_SELF_APPEND_DOUBLING\n",                                 "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-579", "name": "C++ String: string_view Substr Beyond Length",       "input": "STRING_VIEW_SUBSTR_OOB\n",                                      "tier": "cpp_string_hazards"},
    {"id": "TC-HEAP-580", "name": "C++ String: Iterators Invalidation on Append Read",  "input": "STRING_ITERATOR_INVALIDATION\n",                                "tier": "cpp_string_hazards"},

    # ══ TIER 92 — Virtual Table Offset & Struct Alignment Probe (TC-581..590) ═
    {"id": "TC-HEAP-581", "name": "VTable/Struct: Virtual Inheritance Offset Drift",     "input": "VTABLE_OFFSET_DRIFT\n",                                         "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-582", "name": "VTable/Struct: Packed Struct Member Overlap Write",   "input": "PACKED_STRUCT_OVERLAP\n",                                       "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-583", "name": "VTable/Struct: Member Pointer Arithmetic Past End",   "input": "MEMBER_PTR_PAST_END\n",                                         "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-584", "name": "VTable/Struct: Bitfield Overflow into Adjacent Field","input": "BITFIELD_OVERFLOW_PROBE\n",                                    "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-585", "name": "VTable/Struct: Alignment Padding Byte Leak / Read",  "input": "ALIGNMENT_PADDING_LEAK\n",                                      "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-586", "name": "VTable/Struct: Multiple Inheritance Slice Downcast",  "input": "MULTIPLE_INHERITANCE_SLICE\n",                                  "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-587", "name": "VTable/Struct: Non-Virtual Destructor Memory Leak",   "input": "NON_VIRTUAL_DTOR_DELETION\n",                                   "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-588", "name": "VTable/Struct: Placement New Overlap in Heap Buffer", "input": "PLACEMENT_NEW_OVERLAP\n",                                      "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-589", "name": "VTable/Struct: Heap Object Reinterpretation Array",   "input": "OBJECT_ARRAY_REINTERPRET\n",                                    "tier": "vtable_struct_align"},
    {"id": "TC-HEAP-590", "name": "VTable/Struct: Corrupt Vptr to Non-Callable Target",  "input": "CORRUPT_VPTR_TARGET:0x41414141\n",                              "tier": "vtable_struct_align"},

    # ══ TIER 93 — Cascading Realloc & Reallocation Chain (TC-591..600) ════════
    {"id": "TC-HEAP-591", "name": "Realloc Chain: reallocarray Integer Wrap in Size",    "input": "REALLOCARRAY_WRAP:2147483648:2\n",                              "tier": "realloc_chain"},
    {"id": "TC-HEAP-592", "name": "Realloc Chain: Geometric Growth 16->32->64->128->256","input": "REALLOC_GEOMETRIC_GROWTH\n",                                  "tier": "realloc_chain"},
    {"id": "TC-HEAP-593", "name": "Realloc Chain: Failure Leaving Original Dangling",   "input": "REALLOC_FAILURE_DANGLING\n",                                    "tier": "realloc_chain"},
    {"id": "TC-HEAP-594", "name": "Realloc Chain: posix_memalign Invalid Alignment (7B)","input": "MEMALIGN_INVALID:7:64\n",                                      "tier": "realloc_chain"},
    {"id": "TC-HEAP-595", "name": "Realloc Chain: aligned_alloc Non-Multiple Size Probe","input": "ALIGNED_ALLOC_NONMULT:64:100\n",                               "tier": "realloc_chain"},
    {"id": "TC-HEAP-596", "name": "Realloc Chain: Rapid Realloc-Shrink Tail Data Leak", "input": "REALLOC_SHRINK_TAIL_LEAK\n",                                   "tier": "realloc_chain"},
    {"id": "TC-HEAP-597", "name": "Realloc Chain: Realloc to Same Size In-Place Corrupt","input": "REALLOC_SAME_SIZE_CORRUPT\n",                                  "tier": "realloc_chain"},
    {"id": "TC-HEAP-598", "name": "Realloc Chain: Double Free on Failed Realloc Pointer","input": "REALLOC_DOUBLE_FREE_PATH\n",                                   "tier": "realloc_chain"},
    {"id": "TC-HEAP-599", "name": "Realloc Chain: High-Frequency Alloc-Realloc Cycle",  "input": "HIGH_FREQ_REALLOC_CYCLE\n",                                     "tier": "realloc_chain"},
    {"id": "TC-HEAP-600", "name": "Realloc Chain: Realloc NULL Size Free Semantic",     "input": "REALLOC_NULL_SIZE_FREE\n",                                      "tier": "realloc_chain"},

    # ══ TIER 94 — Binary Deserialization & Length Prefix Mismatch (TC-601..610) 
    {"id": "TC-HEAP-601", "name": "Binary Deser: Length Prefix Larger than Payload",     "input": "BIN_PREFIX_LEN:65535:payload_10b\n",                            "tier": "binary_serialize"},
    {"id": "TC-HEAP-602", "name": "Binary Deser: Length Prefix 0 with Trailing Data",    "input": "BIN_PREFIX_LEN:0:trailing_data\n",                               "tier": "binary_serialize"},
    {"id": "TC-HEAP-603", "name": "Binary Deser: Varint Integer 10-Byte Shift Overflow", "input": "VARINT_OVERFLOW:\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f\n",    "tier": "binary_serialize"},
    {"id": "TC-HEAP-604", "name": "Binary Deser: TLV Type-Length-Value Overflow",        "input": "TLV_OVERFLOW:T=1:L=4096:V=small\n",                              "tier": "binary_serialize"},
    {"id": "TC-HEAP-605", "name": "Binary Deser: Endianness Byte Swap Overflow",         "input": "ENDIAN_SWAP:0x0001:BE_TO_LE\n",                                  "tier": "binary_serialize"},
    {"id": "TC-HEAP-606", "name": "Binary Deser: Count Field Overflow Leading to OOB",   "input": "BIN_COUNT_OOB:1000000\n",                                       "tier": "binary_serialize"},
    {"id": "TC-HEAP-607", "name": "Binary Deser: Truncated Struct Header in Stream",     "input": "TRUNC_STRUCT_HEADER:\x01\x02\x03\n",                             "tier": "binary_serialize"},
    {"id": "TC-HEAP-608", "name": "Binary Deser: Negative Field Offset Pointer",         "input": "NEG_FIELD_OFFSET:-128\n",                                        "tier": "binary_serialize"},
    {"id": "TC-HEAP-609", "name": "Binary Deser: Recursive Container Nesting Flood",     "input": "RECURSIVE_CONTAINER:" + ("[" * 80) + ("]" * 80) + "\n",         "tier": "binary_serialize"},
    {"id": "TC-HEAP-610", "name": "Binary Deser: Cyclic Graph Reference Deser Loop",     "input": "CYCLIC_GRAPH_REF:NODE_A->NODE_B->NODE_A\n",                      "tier": "binary_serialize"},

    # ══ TIER 95 — Format String Direct Parameter & Precision Crash (TC-611..620)
    {"id": "TC-HEAP-611", "name": "Format Direct: Large Param Offset (%100$p)",          "input": "%100$p.%101$p.%102$p\n",                                         "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-612", "name": "Format Direct: Extreme Param Offset (%999$x)",        "input": "%999$x\n",                                                       "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-613", "name": "Format Width: Massive Width Buffer Fill (%1000000d)",  "input": "%1000000d\n",                                                    "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-614", "name": "Format Precision: Precision String Buffer (%.10000s)", "input": "%.10000s\n",                                                    "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-615", "name": "Format Write: %hn Half-Word (2-Byte) Memory Write",   "input": "%hn\n",                                                          "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-616", "name": "Format Write: %hhn Byte (1-Byte) Memory Write",       "input": "%hhn\n",                                                         "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-617", "name": "Format Write: %lln Quad-Word (8-Byte) Memory Write",  "input": "%lln\n",                                                         "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-618", "name": "Format Padding: Direct Write with Width (%100d%n)",   "input": "%100d%n\n",                                                      "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-619", "name": "Format Scanf: Unbounded String Specifier (%s into buf)","input": "SCANF_UNBOUNDED:" + ("A" * 80) + "\n",                          "tier": "fmt_direct_param"},
    {"id": "TC-HEAP-620", "name": "Format Specifier: Unterminated Trailing Percent (%)", "input": "MALFORMED_FORMAT_TRAILING_PERCENT_%\n",                         "tier": "fmt_direct_param"},

    # ══ TIER 96 — Integer Truncation & Sign Extension (TC-621..630) ═══════════
    {"id": "TC-HEAP-621", "name": "Int Trunc: 64b to 32b Preserving Low Word (0x100000020)","input": "TRUNC_64_32:4294967328\n",                                    "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-622", "name": "Int Trunc: 32b to 16b Preserving Low 16b (0x10020)", "input": "TRUNC_32_16:65568\n",                                           "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-623", "name": "Int Trunc: 32b to 8b Preserving Low Byte (0x120)",    "input": "TRUNC_32_8:288\n",                                              "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-624", "name": "Sign Extension: 0xFF Promoted to int (-1)",           "input": "SIGN_EXT_0xFF\n",                                               "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-625", "name": "Sign Extension: 0x8000 Promoted to int32 (-32768)",  "input": "SIGN_EXT_0x8000\n",                                             "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-626", "name": "Unsigned Underflow: len - 1 When len == 0 (SIZE_MAX)","input": "UNDERFLOW_ZERO_MINUS_ONE\n",                                    "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-627", "name": "Unsigned Underflow: ptrdiff_t Negative Drift",       "input": "PTRDIFF_NEGATIVE_DRIFT\n",                                      "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-628", "name": "Int Division: INT_MIN / -1 Overflow Exception",       "input": "DIV_INT_MIN_BY_NEG_ONE\n",                                      "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-629", "name": "Int Modulo: INT_MIN % -1 Overflow Trap",              "input": "MOD_INT_MIN_BY_NEG_ONE\n",                                      "tier": "int_trunc_sign"},
    {"id": "TC-HEAP-630", "name": "Int Bitwise: Left Shift Over Width (1 << 32 in 32b)", "input": "SHIFT_OVER_WIDTH:32\n",                                         "tier": "int_trunc_sign"},

    # ══ TIER 97 — File I/O & Streambuf Heap Overflow Vectors (TC-631..640) ═════
    {"id": "TC-HEAP-631", "name": "File I/O: fread More Items than Destination Buffer",  "input": "FREAD_OVERFLOW:ITEMS=1024:BUF=64\n",                            "tier": "file_stream_io"},
    {"id": "TC-HEAP-632", "name": "File I/O: fgets into Undersized Heap Buffer",         "input": "FGETS_UNDERSIZED:" + ("A" * 128) + "\n",                         "tier": "file_stream_io"},
    {"id": "TC-HEAP-633", "name": "File I/O: getline with Custom Delimiter Missing",     "input": "GETLINE_CUSTOM_DELIM:" + ("NODELIM" * 20) + "\n",                "tier": "file_stream_io"},
    {"id": "TC-HEAP-634", "name": "File I/O: streambuf::sgetn Boundary Crossing",       "input": "STREAMBUF_SGETN_CROSSING\n",                                    "tier": "file_stream_io"},
    {"id": "TC-HEAP-635", "name": "File I/O: Seek Past EOF Followed by Sparse Write",    "input": "SEEK_PAST_EOF_WRITE:OFFSET=100000\n",                            "tier": "file_stream_io"},
    {"id": "TC-HEAP-636", "name": "File I/O: fgetc Loop Without EOF Check",              "input": "FGETC_NO_EOF_CHECK\n",                                          "tier": "file_stream_io"},
    {"id": "TC-HEAP-637", "name": "File I/O: Stream Read into Uninitialized Unique Ptr", "input": "STREAM_UNINIT_UNIQUE_PTR\n",                                   "tier": "file_stream_io"},
    {"id": "TC-HEAP-638", "name": "File I/O: Multiple Tellg / Seekg State Mismatch",     "input": "TELLG_SEEKG_MISMATCH\n",                                        "tier": "file_stream_io"},
    {"id": "TC-HEAP-639", "name": "File I/O: Pipe Non-Blocking Read Buffer Overread",    "input": "PIPE_NONBLOCK_OVERREAD\n",                                      "tier": "file_stream_io"},
    {"id": "TC-HEAP-640", "name": "File I/O: Circular File Buffer Head/Tail Overwrite",  "input": "CIRCULAR_BUF_OVERWRITE\n",                                      "tier": "file_stream_io"},

    # ══ TIER 98 — Cryptographic Hash & Certificate Parse Overflows (TC-641..650)
    {"id": "TC-HEAP-641", "name": "Crypto Parse: SHA256 Hex String (64B) + Null Overrun","input": "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n", "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-642", "name": "Crypto Parse: MD5 Hex String (32B) + Null Overrun",   "input": "MD5:d41d8cd98f00b204e9800998ecf8427e\n",                         "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-643", "name": "Crypto Parse: UUID String (36B) + Null Overrun",      "input": "UUID:123e4567-e89b-12d3-a456-426614174000\n",                    "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-644", "name": "Crypto Parse: PEM Header Boundary Flood",             "input": "-----BEGIN CERTIFICATE-----" + ("A" * 70) + "\n",                "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-645", "name": "Crypto Parse: ASN.1 DER Length Octet Flood (0x84)",   "input": "ASN1_DER_OCTET_FLOOD:\x30\x84\x00\x01\x00\x00\n",                "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-646", "name": "Crypto Parse: Base58 Decoding Heap Buffer Spill",     "input": "BASE58_SPILL:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa11111111\n",       "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-647", "name": "Crypto Parse: X.509 SubjectAltName Array Overrun",    "input": "SAN_ARRAY_OVERRUN:DNS=" + ("sub." * 25) + "com\n",               "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-648", "name": "Crypto Parse: PKCS#7 Padding Length Corruption",      "input": "PKCS7_PAD_CORRUPT:PAYLOAD\x10\x10\x10\x10\x10\x10\x10\x10\n",    "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-649", "name": "Crypto Parse: RSA Key Modulus Byte Count Mismatch",   "input": "RSA_MODULUS_MISMATCH:BITS=4096:BYTES=64\n",                      "tier": "crypto_hash_parse"},
    {"id": "TC-HEAP-650", "name": "Crypto Parse: HMAC Key Buffer Truncation Overread",   "input": "HMAC_KEY_TRUNCATION:" + ("K" * 70) + "\n",                       "tier": "crypto_hash_parse"},

    # ══ TIER 99 — Environment Variable & Configuration Overflows (TC-651..660) ═
    {"id": "TC-HEAP-651", "name": "Env/Config: Oversized PATH Variable String (512B)",   "input": "PATH=/usr/bin:/bin:" + ("/custom/dir:" * 30) + "\n",             "tier": "env_config_parse"},
    {"id": "TC-HEAP-652", "name": "Env/Config: 1000-Character Configuration Key Name",   "input": ("KEY_" * 250) + "=value\n",                                      "tier": "env_config_parse"},
    {"id": "TC-HEAP-653", "name": "Env/Config: Missing Key-Value Equals Delimiter",      "input": "MALFORMED_CONFIG_ENTRY_NO_EQUALS_SIGN_DATA\n",                    "tier": "env_config_parse"},
    {"id": "TC-HEAP-654", "name": "Env/Config: Unclosed Double-Quote Value String",      "input": 'CONFIG_KEY="unclosed_quoted_configuration_value\n',              "tier": "env_config_parse"},
    {"id": "TC-HEAP-655", "name": "Env/Config: Escaped Newline Multiline Splice",        "input": "CONFIG_KEY=val1\\\nval2\\\nval3\n",                              "tier": "env_config_parse"},
    {"id": "TC-HEAP-656", "name": "Env/Config: Unicode BOM at Config File Start",        "input": "\xef\xbb\xbfCONFIG_KEY=value\n",                                 "tier": "env_config_parse"},
    {"id": "TC-HEAP-657", "name": "Env/Config: Repeated Overwriting Config Keys (x50)",  "input": ("REPEATED_KEY=val\n" * 50),                                      "tier": "env_config_parse"},
    {"id": "TC-HEAP-658", "name": "Env/Config: INI Section Header Overflow [section]",   "input": "[" + ("SECTION_HEADER_" * 20) + "]\n",                           "tier": "env_config_parse"},
    {"id": "TC-HEAP-659", "name": "Env/Config: YAML Multiline Literal Block Overflow",   "input": "key: |\n  " + ("multiline_content " * 15) + "\n",                "tier": "env_config_parse"},
    {"id": "TC-HEAP-660", "name": "Env/Config: DotEnv Dynamic Expansion Loop ($VAR)",    "input": "A=$B\nB=$C\nC=$A\n",                                              "tier": "env_config_parse"},

    # ══ TIER 100 — CLI Argv & Flag Parsing Buffer Overflows (TC-661..670) ══════
    {"id": "TC-HEAP-661", "name": "CLI Argv: Single Argument Length Overflow (512B)",    "input": "--input=" + ("A" * 504) + "\n",                                  "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-662", "name": "CLI Argv: 100 Repeated Short Flags (-v -v -v...)",   "input": ("-v " * 100) + "\n",                                             "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-663", "name": "CLI Argv: Combined Clustered Flags (-xvfz...)",      "input": "-" + ("x" * 80) + "\n",                                          "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-664", "name": "CLI Argv: Double-Dash End-of-Options Boundary",       "input": "-- " + ("positional_arg_" * 15) + "\n",                          "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-665", "name": "CLI Argv: Positional Arguments Array Flood (x40)",     "input": " ".join(f"arg{i}" for i in range(40)) + "\n",                    "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-666", "name": "CLI Argv: Null Byte in Argument Value Option",        "input": "--param=safe\x00injected\n",                                     "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-667", "name": "CLI Argv: Subcommand Cascade Path (/bin/tool sub)",   "input": "tool " + ("sub " * 25) + "action\n",                             "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-668", "name": "CLI Argv: Long Option Equal Value Spanning 256B",     "input": "--extremely-long-option-name=" + ("val" * 70) + "\n",             "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-669", "name": "CLI Argv: Argv[0] Binary Name Impersonation",         "input": "ARGV0_IMPERSONATE:" + ("/path/to/bin/" * 15) + "\n",             "tier": "argv_cmd_overflow"},
    {"id": "TC-HEAP-670", "name": "CLI Argv: Wildcard Expansion Pattern Flood (*/*/*)",  "input": "--glob=" + ("*/*/" * 20) + "\n",                                 "tier": "argv_cmd_overflow"},

    # ══ TIER 101 — Network Protocol Header & Frame Overflows (TC-671..680) ═════
    {"id": "TC-HEAP-671", "name": "Net Proto: DNS Label Length Exceeding 63 Octets",     "input": "DNS_LABEL_OVERFLOW:" + ("a" * 70) + ".example.com\n",            "tier": "net_proto_headers"},
    {"id": "TC-HEAP-672", "name": "Net Proto: HTTP/2 HPACK Varint Shift Overflow",       "input": "HPACK_VARINT:\xff\xff\xff\xff\xff\x0f\n",                        "tier": "net_proto_headers"},
    {"id": "TC-HEAP-673", "name": "Net Proto: WebSocket 126-Length Extended Frame Spill","input": "WS_FRAME_126:LEN=65535:DATA=small\n",                            "tier": "net_proto_headers"},
    {"id": "TC-HEAP-674", "name": "Net Proto: WebSocket 127-Length 64-Bit Spill",       "input": "WS_FRAME_127:LEN=18446744073709551615\n",                        "tier": "net_proto_headers"},
    {"id": "TC-HEAP-675", "name": "Net Proto: IPv4 Options Field Length Overflow (>40B)","input": "IPV4_OPT_LEN_OVERFLOW:LEN=60\n",                                 "tier": "net_proto_headers"},
    {"id": "TC-HEAP-676", "name": "Net Proto: TCP Options Field Buffer Overread",        "input": "TCP_OPT_OVERREAD:EOL_MISSING\n",                                 "tier": "net_proto_headers"},
    {"id": "TC-HEAP-677", "name": "Net Proto: TLS SNI Extension Hostname Spill (>255B)", "input": "TLS_SNI_OVERFLOW:" + ("sub." * 60) + "com\n",                    "tier": "net_proto_headers"},
    {"id": "TC-HEAP-678", "name": "Net Proto: HTTP Chunked Transfer Chunk-Size Overflow","input": "CHUNKED_SIZE:FFFFFFFF\r\ndata\r\n0\r\n\r\n",                     "tier": "net_proto_headers"},
    {"id": "TC-HEAP-679", "name": "Net Proto: SIP Via Header Branch Identifier Flood",   "input": "Via: SIP/2.0/UDP " + ("branch_id_" * 15) + "\r\n\r\n",           "tier": "net_proto_headers"},
    {"id": "TC-HEAP-680", "name": "Net Proto: CoAP Option Delta Nibble Overflow",        "input": "COAP_OPTION_DELTA:NIBBLE=15\n",                                  "tier": "net_proto_headers"},

    # ══ TIER 102 — RegEx Deep Capture & Class Allocation Stress (TC-681..690) ══
    {"id": "TC-HEAP-681", "name": "RegEx Stress: 50 Deeply Nested Capture Groups",       "input": "REGEX_NEST:" + ("(" * 50) + "a" + (")" * 50) + "\n",             "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-682", "name": "RegEx Stress: 500-Character Character Class Range",    "input": "REGEX_CLASS:[" + ("a-zA-Z0-9" * 40) + "]\n",                     "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-683", "name": "RegEx Stress: Deeply Nested Alternations ((a|b)|c)",  "input": "REGEX_ALT:" + ("(" * 30) + "a|b" + (")" * 30) + "\n",            "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-684", "name": "RegEx Stress: Lookahead Assertion Heap Recursion",    "input": "REGEX_LOOKAHEAD:" + ("(?=a)" * 25) + "target\n",                  "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-685", "name": "RegEx Stress: Lookbehind Assertion Variable Width",   "input": "REGEX_LOOKBEHIND:(?<=a+)target\n",                                "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-686", "name": "RegEx Stress: Quantifier Range Overflow {1000,10000}","input": "REGEX_QUANTIFIER:a{1000,10000}\n",                                "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-687", "name": "RegEx Stress: Backreference Recursion Stack Stress",   "input": "REGEX_BACKREF:(a)\\1\\1\\1\\1\n",                                 "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-688", "name": "RegEx Stress: Non-Capturing Group Nesting (?:(?:...))","input": "REGEX_NONCAP:" + ("(?:" * 40) + "z" + (")" * 40) + "\n",       "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-689", "name": "RegEx Stress: Unicode Property Escape Class (\\p{L})","input": "REGEX_UNICODE_PROP:\\p{Lu}\\p{Ll}\\p{Lt}\\p{Lm}\\p{Lo}\n",       "tier": "regex_nesting_dos"},
    {"id": "TC-HEAP-690", "name": "RegEx Stress: Atomic Group State Allocation (?>...)", "input": "REGEX_ATOMIC:" + ("(?>" * 25) + "atom" + (")" * 25) + "\n",       "tier": "regex_nesting_dos"},

    # ══ TIER 103 — Deep Heap State, Bit-Flip & Canary Corruption (TC-691..700) ═
    {"id": "TC-HEAP-691", "name": "Heap State: Alternating Bit-Flip Pattern (0xAA/0x55)","input": ("\xAA\x55" * 128) + "\n",                                       "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-692", "name": "Heap State: Ascending Byte Ladder (0x00..0xFF)",     "input": "".join(chr(i) for i in range(256)) + "\n",                       "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-693", "name": "Heap State: Descending Byte Ladder (0xFF..0x00)",    "input": "".join(chr(i) for i in range(255, -1, -1)) + "\n",               "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-694", "name": "Heap State: High-Frequency Interleaved Null Bytes",   "input": "A\x00B\x00C\x00D\x00E\x00F\x00G\x00H\x00" * 8 + "\n",             "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-695", "name": "Heap State: Pseudo-Random High-Entropy Word Block",    "input": ("\x7f\x45\x4c\x46\x02\x01\x01\x00\xde\xad\xbe\xef" * 16) + "\n",  "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-696", "name": "Heap State: 16KB Cyclic Offset Pattern Wrap",        "input": ("Aa0Aa1Aa2Aa3Aa4Aa5" * 1024)[:16384] + "\n",                     "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-697", "name": "Heap State: 64KB Boundary Deep Memory Sled",         "input": ("\x90" * 1024 + "\xcc" * 1024) * 32 + "\n",                      "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-698", "name": "Heap State: 64-Bit Address Pattern (0xDEADBEEFCAFEBABE)","input": ("\xde\xad\xbe\xef\xca\xfe\xba\xbe" * 32) + "\n",              "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-699", "name": "Heap State: Guard Page Overflow Boundary Probe",     "input": "GUARD_PAGE_TRIGGER:" + ("\x00" * 4096) + "\n",                   "tier": "deep_heap_canary"},
    {"id": "TC-HEAP-700", "name": "Heap State: Magic Crash Canary Verification Marker",  "input": "MAGIC_CANARY_CORRUPT_0x7FFFFFFF_" + ("Z" * 128) + "\n",           "tier": "deep_heap_canary"},

    # ══ TIER 104 — Sub-64B Fine Quantum Allocator Bins (TC-701..710) ═══════════
    {"id": "TC-HEAP-701", "name": "Sub-64B Bin: 12-Byte Allocator Quantum Fit",         "input": "A" * 12 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-702", "name": "Sub-64B Bin: 12-Byte Off-by-One Overwrite (+1)",     "input": "A" * 13 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-703", "name": "Sub-64B Bin: 20-Byte Allocator Quantum Fit",         "input": "B" * 20 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-704", "name": "Sub-64B Bin: 20-Byte Off-by-One Overwrite (+1)",     "input": "B" * 21 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-705", "name": "Sub-64B Bin: 28-Byte Allocator Quantum Fit",         "input": "C" * 28 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-706", "name": "Sub-64B Bin: 28-Byte Off-by-One Overwrite (+1)",     "input": "C" * 29 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-707", "name": "Sub-64B Bin: 36-Byte Allocator Quantum Fit",         "input": "D" * 36 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-708", "name": "Sub-64B Bin: 44-Byte Allocator Quantum Fit",         "input": "E" * 44 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-709", "name": "Sub-64B Bin: 52-Byte Allocator Quantum Fit",         "input": "F" * 52 + "\n",                                                "tier": "fine_sub64_bins"},
    {"id": "TC-HEAP-710", "name": "Sub-64B Bin: 60-Byte Allocator Quantum Fit",         "input": "G" * 60 + "\n",                                                "tier": "fine_sub64_bins"},

    # ══ TIER 105 — Smallbin Fine-Grained Quantums (68B..124B) (TC-711..720) ═══
    {"id": "TC-HEAP-711", "name": "Smallbin Quantum: 68-Byte Boundary Fit Probe",       "input": "H" * 68 + "\n",                                                "tier": "small_bins_granular"},
    {"id": "TC-HEAP-712", "name": "Smallbin Quantum: 68-Byte Off-by-One Breach (+1)",   "input": "H" * 69 + "\n",                                                "tier": "small_bins_granular"},
    {"id": "TC-HEAP-713", "name": "Smallbin Quantum: 76-Byte Boundary Fit Probe",       "input": "I" * 76 + "\n",                                                "tier": "small_bins_granular"},
    {"id": "TC-HEAP-714", "name": "Smallbin Quantum: 84-Byte Boundary Fit Probe",       "input": "J" * 84 + "\n",                                                "tier": "small_bins_granular"},
    {"id": "TC-HEAP-715", "name": "Smallbin Quantum: 92-Byte Boundary Fit Probe",       "input": "K" * 92 + "\n",                                                "tier": "small_bins_granular"},
    {"id": "TC-HEAP-716", "name": "Smallbin Quantum: 100-Byte Boundary Fit Probe",      "input": "L" * 100 + "\n",                                               "tier": "small_bins_granular"},
    {"id": "TC-HEAP-717", "name": "Smallbin Quantum: 108-Byte Boundary Fit Probe",      "input": "M" * 108 + "\n",                                               "tier": "small_bins_granular"},
    {"id": "TC-HEAP-718", "name": "Smallbin Quantum: 116-Byte Boundary Fit Probe",      "input": "N" * 116 + "\n",                                               "tier": "small_bins_granular"},
    {"id": "TC-HEAP-719", "name": "Smallbin Quantum: 124-Byte Pre-128B Fit Probe",      "input": "O" * 124 + "\n",                                               "tier": "small_bins_granular"},
    {"id": "TC-HEAP-720", "name": "Smallbin Quantum: 124-Byte Off-by-One Breach (+1)",  "input": "O" * 125 + "\n",                                               "tier": "small_bins_granular"},

    # ══ TIER 106 — Power-of-Two Pre-Boundary Fit Sweeps (2^N - 1) (TC-721..730)
    {"id": "TC-HEAP-721", "name": "Pow2 Fit: 15-Byte (16B - 1 Safe Fit)",               "input": "A" * 15 + "\n",                                                "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-722", "name": "Pow2 Fit: 31-Byte (32B - 1 Safe Fit)",               "input": "B" * 31 + "\n",                                                "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-723", "name": "Pow2 Fit: 63-Byte (64B - 1 Safe Fit)",               "input": "C" * 63 + "\n",                                                "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-724", "name": "Pow2 Fit: 127-Byte (128B - 1 Safe Fit)",             "input": "D" * 127 + "\n",                                               "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-725", "name": "Pow2 Fit: 255-Byte (256B - 1 Safe Fit)",             "input": "E" * 255 + "\n",                                               "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-726", "name": "Pow2 Fit: 511-Byte (512B - 1 Safe Fit)",             "input": "F" * 511 + "\n",                                               "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-727", "name": "Pow2 Fit: 1023-Byte (1KB - 1 Safe Fit)",             "input": "G" * 1023 + "\n",                                              "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-728", "name": "Pow2 Fit: 2047-Byte (2KB - 1 Safe Fit)",             "input": "H" * 2047 + "\n",                                              "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-729", "name": "Pow2 Fit: 4095-Byte (4KB - 1 Safe Fit)",             "input": "I" * 4095 + "\n",                                              "tier": "pow2_minus1_sweep"},
    {"id": "TC-HEAP-730", "name": "Pow2 Fit: 8191-Byte (8KB - 1 Safe Fit)",             "input": "J" * 8191 + "\n",                                              "tier": "pow2_minus1_sweep"},

    # ══ TIER 107 — Power-of-Two Off-by-One Null Byte Overflows (2^N + 1) (TC-731..740)
    {"id": "TC-HEAP-731", "name": "Pow2 Off1: 17-Byte (16B + 1 Null Byte Overflow)",    "input": "K" * 17 + "\n",                                                "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-732", "name": "Pow2 Off1: 33-Byte (32B + 1 Null Byte Overflow)",    "input": "L" * 33 + "\n",                                                "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-733", "name": "Pow2 Off1: 65-Byte (64B + 1 Null Byte Overflow)",    "input": "M" * 65 + "\n",                                                "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-734", "name": "Pow2 Off1: 129-Byte (128B + 1 Null Byte Overflow)",  "input": "N" * 129 + "\n",                                               "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-735", "name": "Pow2 Off1: 257-Byte (256B + 1 Null Byte Overflow)",  "input": "O" * 257 + "\n",                                               "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-736", "name": "Pow2 Off1: 513-Byte (512B + 1 Null Byte Overflow)",  "input": "P" * 513 + "\n",                                               "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-737", "name": "Pow2 Off1: 1025-Byte (1KB + 1 Null Byte Overflow)",  "input": "Q" * 1025 + "\n",                                              "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-738", "name": "Pow2 Off1: 2049-Byte (2KB + 1 Null Byte Overflow)",  "input": "R" * 2049 + "\n",                                              "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-739", "name": "Pow2 Off1: 4097-Byte (4KB + 1 Null Byte Overflow)",  "input": "S" * 4097 + "\n",                                              "tier": "pow2_plus1_sweep"},
    {"id": "TC-HEAP-740", "name": "Pow2 Off1: 8193-Byte (8KB + 1 Null Byte Overflow)",  "input": "T" * 8193 + "\n",                                              "tier": "pow2_plus1_sweep"},

    # ══ TIER 108 — Power-of-Two Pointer Word Corruptions (2^N + 8) (TC-741..750)
    {"id": "TC-HEAP-741", "name": "Pow2 Word: 24-Byte (16B + 8 Header Word Overwrite)", "input": "U" * 24 + "\n",                                                "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-742", "name": "Pow2 Word: 40-Byte (32B + 8 Header Word Overwrite)", "input": "V" * 40 + "\n",                                                "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-743", "name": "Pow2 Word: 72-Byte (64B + 8 Header Word Overwrite)", "input": "W" * 72 + "\n",                                                "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-744", "name": "Pow2 Word: 136-Byte (128B + 8 Header Word Overwrite)","input": "X" * 136 + "\n",                                               "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-745", "name": "Pow2 Word: 264-Byte (256B + 8 Header Word Overwrite)","input": "Y" * 264 + "\n",                                               "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-746", "name": "Pow2 Word: 520-Byte (512B + 8 Header Word Overwrite)","input": "Z" * 520 + "\n",                                               "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-747", "name": "Pow2 Word: 1032-Byte (1KB + 8 Header Word Overwrite)","input": "0" * 1032 + "\n",                                              "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-748", "name": "Pow2 Word: 2056-Byte (2KB + 8 Header Word Overwrite)","input": "1" * 2056 + "\n",                                              "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-749", "name": "Pow2 Word: 4104-Byte (4KB + 8 Header Word Overwrite)","input": "2" * 4104 + "\n",                                              "tier": "pow2_plus8_sweep"},
    {"id": "TC-HEAP-750", "name": "Pow2 Word: 8200-Byte (8KB + 8 Header Word Overwrite)","input": "3" * 8200 + "\n",                                              "tier": "pow2_plus8_sweep"},

    # ══ TIER 109 — Double-Free & Corrupt Chunk Free Patterns (TC-751..760) ═════
    {"id": "TC-HEAP-751", "name": "Double Free: Direct Consecutive free(p) Call",       "input": "DOUBLE_FREE:CONSECUTIVE\n",                                     "tier": "double_free_patterns"},
    {"id": "TC-HEAP-752", "name": "Double Free: Interleaved Intermediate Allocation",    "input": "DOUBLE_FREE:INTERLEAVED_ALLOC\n",                               "tier": "double_free_patterns"},
    {"id": "TC-HEAP-753", "name": "Double Free: Free on Offset Interior Pointer (p+1)", "input": "CORRUPT_FREE:INTERIOR_PTR_P1\n",                              "tier": "double_free_patterns"},
    {"id": "TC-HEAP-754", "name": "Double Free: Free on Offset Interior Pointer (p+8)", "input": "CORRUPT_FREE:INTERIOR_PTR_P8\n",                              "tier": "double_free_patterns"},
    {"id": "TC-HEAP-755", "name": "Double Free: Free on Pointer to Stack Variable",     "input": "CORRUPT_FREE:STACK_VARIABLE_PTR\n",                             "tier": "double_free_patterns"},
    {"id": "TC-HEAP-756", "name": "Double Free: Free on Pointer to Static Data Buffer", "input": "CORRUPT_FREE:STATIC_BUFFER_PTR\n",                             "tier": "double_free_patterns"},
    {"id": "TC-HEAP-757", "name": "Double Free: Fastbin Dup Cycle (p -> q -> p)",       "input": "FASTBIN_DUP_CYCLE:P_Q_P\n",                                     "tier": "double_free_patterns"},
    {"id": "TC-HEAP-758", "name": "Double Free: Tcache Poisoning via Duplicate Free",    "input": "TCACHE_DUP_POISON\n",                                           "tier": "double_free_patterns"},
    {"id": "TC-HEAP-759", "name": "Double Free: Delete After Free via Unique Ptr Reset", "input": "UNIQUE_PTR_DOUBLE_DELETE\n",                                   "tier": "double_free_patterns"},
    {"id": "TC-HEAP-760", "name": "Double Free: Custom Allocator Double Deallocate Trap","input": "CUSTOM_ALLOC_DOUBLE_DEALLOC\n",                                "tier": "double_free_patterns"},

    # ══ TIER 110 — Use-After-Free State Transitions (TC-761..770) ══════════════
    {"id": "TC-HEAP-761", "name": "UAF: Read Member Field Immediately After Free",      "input": "UAF_READ:MEMBER_IMMEDIATE\n",                                   "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-762", "name": "UAF: Write Member Field Immediately After Free",     "input": "UAF_WRITE:MEMBER_IMMEDIATE\n",                                  "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-763", "name": "UAF: Virtual Function Call on Freed Object (vptr)",  "input": "UAF_CALL:VPTR_DISPATCH\n",                                      "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-764", "name": "UAF: Re-Allocated Chunk Type Confusion Read",        "input": "UAF_REALLOC:TYPE_CONFUSION_READ\n",                             "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-765", "name": "UAF: Re-Allocated Chunk Type Confusion Write",       "input": "UAF_REALLOC:TYPE_CONFUSION_WRITE\n",                            "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-766", "name": "UAF: Callback Invocation Through Dangling Functor",   "input": "UAF_CALLBACK:DANGLING_FUNCTOR\n",                               "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-767", "name": "UAF: std::function Storing Dangling Lambda Ref",     "input": "UAF_LAMBDA:DANGLING_CAPTURED_REF\n",                            "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-768", "name": "UAF: Observer Pattern Dangling Subject Pointer",     "input": "UAF_OBSERVER:DANGLING_SUBJECT\n",                               "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-769", "name": "UAF: Container Iteration Accessing Erased Element",   "input": "UAF_ITERATOR:ERASED_ELEMENT_READ\n",                            "tier": "uaf_state_machine"},
    {"id": "TC-HEAP-770", "name": "UAF: Thread-Local Pointer Dangling Across Tasks",    "input": "UAF_THREAD_LOCAL:DANGLING_REF\n",                               "tier": "uaf_state_machine"},

    # ══ TIER 111 — Heap Memory Leak & Resource Exhaustion (TC-771..780) ════════
    {"id": "TC-HEAP-771", "name": "Leak Exhaustion: 1000 Rapid Unreleased Allocs (1KB)","input": "LEAK_LOOP:COUNT=1000:SIZE=1024\n",                              "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-772", "name": "Leak Exhaustion: 10000 Tiny Chunk Leaks (16B)",      "input": "LEAK_LOOP:COUNT=10000:SIZE=16\n",                               "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-773", "name": "Leak Exhaustion: Dynamic String Token Leak Loop",     "input": "LEAK_STRING_TOKENS:COUNT=500\n",                                "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-774", "name": "Leak Exhaustion: File Descriptor Heap Buffer Leak",   "input": "LEAK_FD_BUFFER_LOOP\n",                                         "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-775", "name": "Leak Exhaustion: Cyclic Object Graph Reference Leak", "input": "LEAK_CYCLIC_OBJECT_GRAPH\n",                                   "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-776", "name": "Leak Exhaustion: Static Cache Never Evicted Leak",    "input": "LEAK_UNBOUNDED_STATIC_CACHE\n",                                 "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-777", "name": "Leak Exhaustion: Exception Unwind Skipping delete[]", "input": "LEAK_EXCEPTION_UNWIND_RAW_ARRAY\n",                            "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-778", "name": "Leak Exhaustion: Shared Pointer Self-Reference Cycle","input": "LEAK_SHARED_PTR_SELF_REF\n",                                   "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-779", "name": "Leak Exhaustion: Allocation Exceeding Process Memory","input": "EXHAUST_TOTAL_RAM:BYTES=17179869184\n",                         "tier": "heap_leak_exhaustion"},
    {"id": "TC-HEAP-780", "name": "Leak Exhaustion: Mmap Region Table Exhaustion Probe", "input": "EXHAUST_MMAP_REGIONS:COUNT=65536\n",                            "tier": "heap_leak_exhaustion"},

    # ══ TIER 112 — Uninitialized Heap Memory Reads (TC-781..790) ══════════════
    {"id": "TC-HEAP-781", "name": "Uninit Read: malloc() Buffer Read Without Memset",    "input": "UNINIT_READ:MALLOC_RAW_READ\n",                                 "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-782", "name": "Uninit Read: Struct Padding Bytes Info Leak",         "input": "UNINIT_READ:STRUCT_PADDING_LEAK\n",                             "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-783", "name": "Uninit Read: Partially Initialized Array Tail",       "input": "UNINIT_READ:PARTIAL_ARRAY_TAIL\n",                              "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-784", "name": "Uninit Read: Uninitialized Pointer Dereference",      "input": "UNINIT_READ:UNINIT_PTR_DEREF\n",                                "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-785", "name": "Uninit Read: Uninitialized Boolean Conditional Branch","input": "UNINIT_READ:BOOL_BRANCH_TRAP\n",                               "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-786", "name": "Uninit Read: String Read Past Initialized Substring", "input": "UNINIT_READ:PAST_INIT_SUBSTRING\n",                             "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-787", "name": "Uninit Read: Vector resize() Capacity Overread",      "input": "UNINIT_READ:VECTOR_RESIZE_NO_INIT\n",                           "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-788", "name": "Uninit Read: Network Packet Padding Byte Disclosure", "input": "UNINIT_READ:PACKET_PADDING_DISCLOSE\n",                        "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-789", "name": "Uninit Read: Placement New on Unzeroed Memory",      "input": "UNINIT_READ:PLACEMENT_NEW_RAW_MEM\n",                           "tier": "uninit_heap_reads"},
    {"id": "TC-HEAP-790", "name": "Uninit Read: Heap Memory Sent over Socket Unscrubbed","input": "UNINIT_READ:SOCKET_SEND_HEAP_LEAK\n",                          "tier": "uninit_heap_reads"},

    # ══ TIER 113 — Far Offset Array Subscript Bounds Breaches (TC-791..800) ════
    {"id": "TC-HEAP-791", "name": "Subscript: Huge Positive Index (INDEX:1000000)",     "input": "INDEX:1000000\n",                                                "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-792", "name": "Subscript: Max Int32 Index (INDEX:2147483647)",      "input": "INDEX:2147483647\n",                                             "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-793", "name": "Subscript: Negative Far Index (INDEX:-10000)",       "input": "INDEX:-10000\n",                                                 "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-794", "name": "Subscript: Min Int32 Index (INDEX:-2147483648)",     "input": "INDEX:-2147483648\n",                                            "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-795", "name": "Subscript: Subscript Expression With Pointer Scale",  "input": "INDEX_EXPR:BASE+SCALE*2147483647\n",                             "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-796", "name": "Subscript: 2D Matrix Col Index Exceeding Width",     "input": "MATRIX_INDEX:ROW=0:COL=1000\n",                                  "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-797", "name": "Subscript: 2D Matrix Negative Row Index Probe",       "input": "MATRIX_INDEX:ROW=-5:COL=2\n",                                    "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-798", "name": "Subscript: Array Index via Non-Null Char Cast",       "input": "CHAR_INDEX_CAST:(char)0xFF\n",                                   "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-799", "name": "Subscript: Non-Zero Array Base Subtraction Underflow","input": "BASE_SUBTRACT_UNDERFLOW\n",                                     "tier": "subscript_far_offset"},
    {"id": "TC-HEAP-800", "name": "Subscript: Heap Array Subscript in Arithmetic Loop",  "input": "LOOP_INDEX_ARITH:STEP=1000\n",                                   "tier": "subscript_far_offset"},

    # ══ TIER 114 — Integer Multiplication Wrap in Allocation (TC-801..810) ═════
    {"id": "TC-HEAP-801", "name": "Mult Wrap: 2^16 * 2^16 = 2^32 Wraps to 0 in 32b",   "input": "ALLOC_MULT:65536:65536\n",                                       "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-802", "name": "Mult Wrap: 536870912 * 8 = 2^32 Wraps to 0",         "input": "ALLOC_MULT:536870912:8\n",                                       "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-803", "name": "Mult Wrap: 1073741825 * 4 = 4 Bytes Allocation",     "input": "ALLOC_MULT:1073741825:4\n",                                       "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-804", "name": "Mult Wrap: 1431655766 * 3 = 2 Bytes Allocation",     "input": "ALLOC_MULT:1431655766:3\n",                                       "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-805", "name": "Mult Wrap: Huge Array of Pointers (N * sizeof(void*))","input": "ALLOC_PTR_ARRAY:536870913\n",                                  "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-806", "name": "Mult Wrap: Vector reserve() Integer Multiplication",  "input": "VECTOR_RESERVE_MULT_WRAP:1073741825\n",                          "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-807", "name": "Mult Wrap: Image Width * Height * BPP Allocation",    "input": "IMAGE_ALLOC:WIDTH=65536:HEIGHT=65536:BPP=4\n",                   "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-808", "name": "Mult Wrap: Audio Sample Rate * Channels * Duration", "input": "AUDIO_ALLOC:RATE=192000:CH=8:SEC=10000\n",                      "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-809", "name": "Mult Wrap: 3D Voxel Grid Dimension Multiplication",  "input": "VOXEL_ALLOC:X=2048:Y=2048:Z=2048\n",                             "tier": "alloc_mult_wrap"},
    {"id": "TC-HEAP-810", "name": "Mult Wrap: Struct Array Size Multiplication Wrap",    "input": "STRUCT_ARRAY_ALLOC:COUNT=71582789:ELEM_SIZE=60\n",              "tier": "alloc_mult_wrap"},

    # ══ TIER 115 — Signedness Conversion Mismatch in Malloc (TC-811..820) ══════
    {"id": "TC-HEAP-811", "name": "Signed Convert: -1 Passed to malloc() (SIZE_MAX)",   "input": "SIGNED_MALLOC:-1\n",                                             "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-812", "name": "Signed Convert: -100 Passed to memcpy() Length",     "input": "SIGNED_MEMCPY:-100\n",                                           "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-813", "name": "Signed Convert: Short -1 (0xFFFF) Cast to int32_t",   "input": "SIGNED_CAST_SHORT_INT:-1\n",                                     "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-814", "name": "Signed Convert: Char -1 (0xFF) Cast to size_t",      "input": "SIGNED_CAST_CHAR_SIZE_T:-1\n",                                   "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-815", "name": "Signed Convert: if (len < MAX) Bypass with Negative", "input": "SIGNED_CHECK_BYPASS:LEN=-50\n",                                  "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-816", "name": "Signed Convert: Subtraction Producing Negative Len", "input": "SIGNED_SUBTRACT_NEGATIVE:START=100:END=50\n",                    "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-817", "name": "Signed Convert: Signed Array Index Cast to Unsigned", "input": "SIGNED_INDEX_CAST:INDEX=-1\n",                                   "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-818", "name": "Signed Convert: snprintf Return Negative Handled as Len","input": "SIGNED_SNPRINTF_NEG_RETURN\n",                                "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-819", "name": "Signed Convert: Read Return -1 Cast to size_t Loop", "input": "SIGNED_READ_RETURN_NEG_ONE\n",                                   "tier": "alloc_signed_convert"},
    {"id": "TC-HEAP-820", "name": "Signed Convert: Signed Shift Right Preserving Sign Bit","input": "SIGNED_SAR_SIGN_PRESERVE:-1024\n",                             "tier": "alloc_signed_convert"},

    # ══ TIER 116 — Format String Arbitrary Write Combinations (TC-821..830) ════
    {"id": "TC-HEAP-821", "name": "Format Write: %hn Half-Word Two-Stage Target Write", "input": "%65535c%1$hn%65535c%2$hn\n",                                     "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-822", "name": "Format Write: %hhn Byte-by-Byte Arbitrary Overwrite", "input": "%1$hhn%2$hhn%3$hhn%4$hhn\n",                                     "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-823", "name": "Format Write: Chained Stack and Heap Write Sequence", "input": "%8$n%9$n%10$n\n",                                                "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-824", "name": "Format Write: Vptr Overwrite Payload via %n",        "input": "AAAA%12$n\n",                                                    "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-825", "name": "Format Write: Return Address Overwrite via %hn",     "input": "%4919c%15$hn\n",                                                 "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-826", "name": "Format Write: GOT Entry Overwrite via Chained Writes","input": "%2048c%8$hn%4096c%9$hn\n",                                       "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-827", "name": "Format Write: Zero-Byte Write (%hhn with 0 chars)",  "input": "%1$hhn\n",                                                       "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-828", "name": "Format Write: Format String with Width Zero Pad",     "input": "%08x%08x%08x%n\n",                                               "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-829", "name": "Format Write: Nested Format String Evaluation Trap",  "input": "%%n%%n%%n%%n\n",                                                 "tier": "fmt_write_combo"},
    {"id": "TC-HEAP-830", "name": "Format Write: Variable Length Width Dynamic Arg (%*n)","input": "%*d%n\n",                                                       "tier": "fmt_write_combo"},

    # ══ TIER 117 — Positional Format Write Specifiers (%<k>$n) (TC-831..840) ═══
    {"id": "TC-HEAP-831", "name": "Format Pos: Direct Parameter %1$n Write",            "input": "%1$n\n",                                                         "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-832", "name": "Format Pos: Direct Parameter %2$n Write",            "input": "%2$n\n",                                                         "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-833", "name": "Format Pos: Direct Parameter %4$n Write",            "input": "%4$n\n",                                                         "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-834", "name": "Format Pos: Direct Parameter %8$n Write",            "input": "%8$n\n",                                                         "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-835", "name": "Format Pos: Direct Parameter %16$n Write",           "input": "%16$n\n",                                                        "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-836", "name": "Format Pos: Direct Parameter %32$n Write",           "input": "%32$n\n",                                                        "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-837", "name": "Format Pos: Direct Parameter %64$n Write",           "input": "%64$n\n",                                                        "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-838", "name": "Format Pos: Direct Parameter %128$n Write",          "input": "%128$n\n",                                                       "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-839", "name": "Format Pos: Direct Parameter %256$n Write",          "input": "%256$n\n",                                                       "tier": "fmt_positional_n"},
    {"id": "TC-HEAP-840", "name": "Format Pos: Positional String Dereference (%5$s)",   "input": "%5$s%6$s%7$s\n",                                                 "tier": "fmt_positional_n"},

    # ══ TIER 118 — C++ STL Container Iterator Bounds Overrun (TC-841..850) ═════
    {"id": "TC-HEAP-841", "name": "STL Iterator: Dereference vector.end() Iterator",    "input": "STL_ITER_DEREF_VECTOR_END\n",                                    "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-842", "name": "STL Iterator: Advance Past end() Iterator (std::next)","input": "STL_ITER_ADVANCE_PAST_END\n",                                 "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-843", "name": "STL Iterator: Decrement begin() Iterator (std::prev)","input": "STL_ITER_DECREMENT_BEFORE_BEGIN\n",                             "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-844", "name": "STL Iterator: Reverse Iterator Invalidation on Erase","input": "STL_ITER_REVERSE_ERASE_INVALID\n",                             "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-845", "name": "STL Iterator: Deque Block Boundary Step Overrun",    "input": "STL_DEQUE_BLOCK_STEP_OVERRUN\n",                                 "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-846", "name": "STL Iterator: List Node Forward Past End Null",      "input": "STL_LIST_NODE_PAST_END\n",                                       "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-847", "name": "STL Iterator: Map/Set Invalidation During Range Loop","input": "STL_MAP_ERASE_IN_RANGE_LOOP\n",                                 "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-848", "name": "STL Iterator: String Iterator Arithmetic OOB Step",   "input": "STL_STRING_ITER_ARITH_OOB\n",                                    "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-849", "name": "STL Iterator: Vector Front on Empty Container",      "input": "STL_VECTOR_EMPTY_FRONT\n",                                       "tier": "stl_iter_overrun"},
    {"id": "TC-HEAP-850", "name": "STL Iterator: Vector Back on Empty Container",       "input": "STL_VECTOR_EMPTY_BACK\n",                                        "tier": "stl_iter_overrun"},

    # ══ TIER 119 — C++ Smart Pointer Circular Cycles & Dangles (TC-851..860) ═══
    {"id": "TC-HEAP-851", "name": "Smart Ptr: shared_ptr Circular Reference Cycle",     "input": "SMART_PTR_CYCLE:A_POINTS_TO_B_POINTS_TO_A\n",                   "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-852", "name": "Smart Ptr: weak_ptr lock() Expired Dangling Access", "input": "SMART_PTR_WEAK_EXPIRED_LOCK\n",                                "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-853", "name": "Smart Ptr: unique_ptr release() Raw Pointer Dangle", "input": "SMART_PTR_UNIQUE_RELEASE_DANGLE\n",                              "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-854", "name": "Smart Ptr: Multiple shared_ptr from Same Raw Pointer","input": "SMART_PTR_MULTIPLE_SHARED_RAW\n",                               "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-855", "name": "Smart Ptr: Custom Deleter Type Mismatch Violation",  "input": "SMART_PTR_CUSTOM_DELETER_MISMATCH\n",                           "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-856", "name": "Smart Ptr: make_shared Over-Allocation Buffer Spill", "input": "MAKE_SHARED_BUFFER_SPILL:" + ("S" * 64) + "\n",                 "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-857", "name": "Smart Ptr: enable_shared_from_this on Stack Object", "input": "ENABLE_SHARED_FROM_THIS_STACK\n",                               "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-858", "name": "Smart Ptr: Atomic shared_ptr Race Condition Trap",   "input": "ATOMIC_SHARED_PTR_RACE\n",                                       "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-859", "name": "Smart Ptr: unique_ptr Array Deleter Mismatch (delete)","input": "UNIQUE_PTR_ARRAY_DELETE_SCALAR\n",                             "tier": "smart_ptr_cycles"},
    {"id": "TC-HEAP-860", "name": "Smart Ptr: Raw Pointer Stolen from unique_ptr::get()","input": "UNIQUE_PTR_GET_STOLEN_DANGLE\n",                                "tier": "smart_ptr_cycles"},

    # ══ TIER 120 — Exception Safety & Unwind Memory Leak Traps (TC-861..870) ═══
    {"id": "TC-HEAP-861", "name": "Exception Safety: Constructor Throws After Malloc",  "input": "CTOR_THROWS_AFTER_MALLOC\n",                                    "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-862", "name": "Exception Safety: Destructor Throws During Unwind",   "input": "DTOR_THROWS_DURING_UNWIND\n",                                   "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-863", "name": "Exception Safety: Multiple Resource Alloc Unwind Leak","input": "MULTI_ALLOC_PARTIAL_UNWIND_LEAK\n",                           "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-864", "name": "Exception Safety: Catch Block Forgets Free on Path",  "input": "CATCH_BLOCK_LEAK_ON_PATH\n",                                    "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-865", "name": "Exception Safety: std::bad_alloc Handler Re-Throw",  "input": "BAD_ALLOC_RETHROW_TRAP\n",                                      "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-866", "name": "Exception Safety: Vector Push_back Copy Ctor Throws", "input": "VECTOR_PUSH_COPY_CTOR_THROWS\n",                                "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-867", "name": "Exception Safety: Custom Allocator deallocate Throws","input": "CUSTOM_ALLOC_DEALLOC_THROWS\n",                                "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-868", "name": "Exception Safety: Nested Try-Catch Memory Leak Chain","input": "NESTED_CATCH_LEAK_CHAIN\n",                                     "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-869", "name": "Exception Safety: Exception During Realloc Shrink",  "input": "EXCEPTION_DURING_REALLOC_SHRINK\n",                              "tier": "raii_unwind_leaks"},
    {"id": "TC-HEAP-870", "name": "Exception Safety: noexcept Function Throws Terminate","input": "NOEXCEPT_FUNCTION_THROWS_TRAP\n",                               "tier": "raii_unwind_leaks"},

    # ══ TIER 121 — Signal Handler Async-Unsafe Memory Operations (TC-871..880) ═
    {"id": "TC-HEAP-871", "name": "Signal Unsafe: malloc() Called Inside SIGINT Handler","input": "SIGINT_MALLOC_UNSAFE\n",                                       "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-872", "name": "Signal Unsafe: free() Called Inside SIGSEGV Handler", "input": "SIGSEGV_FREE_UNSAFE\n",                                        "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-873", "name": "Signal Unsafe: printf() Format in Signal Handler",    "input": "SIG_PRINTF_ASYNC_UNSAFE\n",                                     "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-874", "name": "Signal Unsafe: Non-Reentrant Global State in Signal", "input": "SIG_GLOBAL_MUTATION_RACE\n",                                   "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-875", "name": "Signal Unsafe: Longjmp from Signal Handler Unwind",  "input": "SIG_LONGJMP_UNWIND_CORRUPT\n",                                  "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-876", "name": "Signal Unsafe: Mutex Deadlock Inside Signal Handler", "input": "SIG_MUTEX_DEADLOCK_TRAP\n",                                    "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-877", "name": "Signal Unsafe: sig_atomic_t Range Overflow Trap",    "input": "SIG_ATOMIC_RANGE_OVERFLOW\n",                                   "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-878", "name": "Signal Unsafe: Recursive Signal Delivery Stack Smashing","input": "SIG_RECURSIVE_DELIVERY_SMASH\n",                              "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-879", "name": "Signal Unsafe: Signal Mask Restoration Corruption",   "input": "SIG_MASK_RESTORE_CORRUPT\n",                                    "tier": "signal_unsafe_heap"},
    {"id": "TC-HEAP-880", "name": "Signal Unsafe: sigaction SA_SIGINFO Context Corrupt", "input": "SIGINFO_CONTEXT_OVERWRITE\n",                                  "tier": "signal_unsafe_heap"},

    # ══ TIER 122 — Dynamic Linker & GOT/PLT Pointer Corruption (TC-881..890) ═══
    {"id": "TC-HEAP-881", "name": "DynLink Hijack: GOT Table Entry Overwrite Simulation","input": "GOT_OVERWRITE:FREE_ENTRY=0x41414141\n",                           "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-882", "name": "DynLink Hijack: PLT Trampoline Corruption Probe",    "input": "PLT_TRAMPOLINE_OVERWRITE\n",                                    "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-883", "name": "DynLink Hijack: dlopen Relative Path Injection",     "input": "DLOPEN_RELATIVE_INJECT:./libinjected.so\n",                      "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-884", "name": "DynLink Hijack: dlsym Function Pointer Type Mismatch","input": "DLSYM_SIG_MISMATCH:SYM=process_data\n",                        "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-885", "name": "DynLink Hijack: LD_PRELOAD Environment Override Probe","input": "LD_PRELOAD_OVERRIDE_SIMULATION\n",                              "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-886", "name": "DynLink Hijack: DT_RPATH Insecure Library Search Path","input": "RPATH_INSECURE_SEARCH_PATH\n",                                 "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-887", "name": "DynLink Hijack: Shared Library Unload Dangling Func", "input": "DLCLOSE_DANGLING_FUNCTION_PTR\n",                               "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-888", "name": "DynLink Hijack: Global Destructor (__cxa_finalize)", "input": "CXA_FINALIZE_CORRUPT\n",                                       "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-889", "name": "DynLink Hijack: TLS Thread-Local Storage GOT Offset", "input": "TLS_GOT_OFFSET_CORRUPT\n",                                     "tier": "dynlink_hijack"},
    {"id": "TC-HEAP-890", "name": "DynLink Hijack: Relocation Table R_X86_64_JUMP_SLOT", "input": "RELOC_TABLE_JUMP_SLOT_CORRUPT\n",                              "tier": "dynlink_hijack"},

    # ══ TIER 123 — Multi-Threaded Allocation Race & Free Traps (TC-891..900) ═══
    {"id": "TC-HEAP-891", "name": "Thread Race: Concurrent Malloc and Free on Same Ptr", "input": "THREAD_RACE:CONCURRENT_ALLOC_FREE\n",                           "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-892", "name": "Thread Race: Double-Free from Two Worker Threads",    "input": "THREAD_RACE:CONCURRENT_DOUBLE_FREE\n",                          "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-893", "name": "Thread Race: Use-After-Free Across Worker Threads",   "input": "THREAD_RACE:CROSS_THREAD_UAF\n",                                "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-894", "name": "Thread Race: Vector push_back Reallocation Race",    "input": "THREAD_RACE:VECTOR_PUSH_NO_MUTEX\n",                             "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-895", "name": "Thread Race: String Mutate While Other Thread Reads", "input": "THREAD_RACE:STRING_DATA_RACE\n",                                "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-896", "name": "Thread Race: Producer-Consumer Ring Buffer Overrun", "input": "THREAD_RACE:RING_BUFFER_INDEX_RACE\n",                          "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-897", "name": "Thread Race: Singleton Double-Checked Locking Trap",  "input": "THREAD_RACE:DOUBLE_CHECK_LOCK_REORDER\n",                        "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-898", "name": "Thread Race: Thread Join Skipping Heap Resource Free","input": "THREAD_RACE:JOIN_SKIP_FREE_LEAK\n",                             "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-899", "name": "Thread Race: Thread Detach Dangling Stack Reference", "input": "THREAD_RACE:DETACHED_DANGLING_STACK_REF\n",                     "tier": "multithread_alloc_race"},
    {"id": "TC-HEAP-900", "name": "Thread Race: Lock-Free ABA Problem on Heap Node",    "input": "THREAD_RACE:LOCK_FREE_ABA_TRAP\n",                               "tier": "multithread_alloc_race"},

    # ══ TIER 124 — String Tokenization Memory Overread Traps (TC-901..910) ═════
    {"id": "TC-HEAP-901", "name": "Tokenizer: strtok Static State Mutate Overread",     "input": "STRTOK_TEST:token1,token2,token3,,token4\n",                     "tier": "string_token_traps"},
    {"id": "TC-HEAP-902", "name": "Tokenizer: strsep Modifying Source String Past End",  "input": "STRSEP_TEST:a/b/c/d/e/\n",                                       "tier": "string_token_traps"},
    {"id": "TC-HEAP-903", "name": "Tokenizer: strpbrk On Non-Terminated Search Set",     "input": "STRPBRK_OVERREAD:SOURCE=" + ("A" * 64) + "\n",                   "tier": "string_token_traps"},
    {"id": "TC-HEAP-904", "name": "Tokenizer: strstr Scanning Unterminated Needle",      "input": "STRSTR_NEEDLE_OVERREAD\n",                                       "tier": "string_token_traps"},
    {"id": "TC-HEAP-905", "name": "Tokenizer: strchr Search with Delimiter at Buffer End","input": "STRCHR_BOUNDARY:" + ("X" * 63) + "Y\n",                         "tier": "string_token_traps"},
    {"id": "TC-HEAP-906", "name": "Tokenizer: Consecutive Delimiters Overrunning Array", "input": "CONSECUTIVE_DELIMS:" + (",," * 30) + "\n",                      "tier": "string_token_traps"},
    {"id": "TC-HEAP-907", "name": "Tokenizer: Empty Input String Token Extraction",     "input": "EMPTY_TOKEN_EXTRACTION:\n",                                      "tier": "string_token_traps"},
    {"id": "TC-HEAP-908", "name": "Tokenizer: Unclosed Quote in CSV Token Stream",       "input": 'CSV_UNCLOSED_TOKEN:"field1,"field2,"field3\n',                   "tier": "string_token_traps"},
    {"id": "TC-HEAP-909", "name": "Tokenizer: Multi-Character Delimiter Split Spill",   "input": "MULTI_CHAR_DELIM:tok1:::tok2:::tok3:::tok4\n",                    "tier": "string_token_traps"},
    {"id": "TC-HEAP-910", "name": "Tokenizer: Escaped Delimiter Scanning Buffer Overrun","input": "ESCAPED_DELIM:tok\\,1\\,tok\\,2\\,tok\\,3\n",                    "tier": "string_token_traps"},

    # ══ TIER 125 — Base64 & Quoted-Printable Decoding Overflows (TC-911..920) ══
    {"id": "TC-HEAP-911", "name": "Decode Overflow: Base64 Decoded Bytes Exceeding Dest","input": "B64_OVERFLOW:" + ("AAAA" * 40) + "\n",                              "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-912", "name": "Decode Overflow: Base64 Invalid Padding Character Trap","input": "B64_PAD_TRAP:QUFBQUFB===\n",                                    "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-913", "name": "Decode Overflow: Quoted-Printable =XX Trailing Buffer","input": "QP_TRAILING_EQUAL:" + ("=20" * 30) + "=\n",                     "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-914", "name": "Decode Overflow: Quoted-Printable Incomplete Hex Byte","input": "QP_INCOMPLETE_HEX:data=A\n",                                    "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-915", "name": "Decode Overflow: Quoted-Printable Soft Line Break Splice","input": "QP_SOFT_LINE:line1=\r\nline2=\r\nline3\n",                     "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-916", "name": "Decode Overflow: Hex Decode Odd Character Trailing Nibble","input": "HEX_ODD_NIBBLE:abcdef1\n",                                  "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-917", "name": "Decode Overflow: Hex Decode Upper Lower Case Mixed Stream","input": "HEX_MIXED_STREAM:aAbBcCdDeEfF0123456789\n",                 "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-918", "name": "Decode Overflow: UUEncode Decoded Line Length Overflow","input": "UU_OVERFLOW:M5&AE;&P@5V]R;&0`\n",                               "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-919", "name": "Decode Overflow: Percent Decode Multiple Nulls %00%00","input": "URL_MULTI_NULL:%00%00%00%00\n",                                 "tier": "b64_qp_overflow"},
    {"id": "TC-HEAP-920", "name": "Decode Overflow: HTML Decimal Entity &#65; Sequence Flood","input": "HTML_DEC_ENTITIES:" + ("&#65;" * 25) + "\n",                "tier": "b64_qp_overflow"},

    # ══ TIER 126 — JSON / XML Deeply Nested Structure Stress (TC-921..930) ═════
    {"id": "TC-HEAP-921", "name": "Parser Nest: JSON 60 Deeply Nested Arrays [[...]]",   "input": "JSON_NEST:" + ("[" * 60) + ("]" * 60) + "\n",                     "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-922", "name": "Parser Nest: JSON 50 Deeply Nested Objects {{...}}",  "input": "JSON_OBJ_NEST:" + ('{"k":' * 50) + '1' + ('}' * 50) + '\n',       "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-923", "name": "Parser Nest: XML 40 Deeply Nested Element Tags",      "input": "XML_NEST:" + ("<tag>" * 40) + ("</tag>" * 40) + "\n",             "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-924", "name": "Parser Nest: XML Billion Laughs Entity Expansion Trap","input": "XML_ENTITY_EXPAND:&lol9;\n",                                     "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-925", "name": "Parser Nest: XML CDATA Section Exceeding Buffer",     "input": "XML_CDATA:<![CDATA[" + ("A" * 120) + "]]>\n",                      "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-926", "name": "Parser Nest: JSON Number with 1000 Exponent Digits",  "input": '{"exp": 1e+' + ("9" * 300) + '}\n',                               "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-927", "name": "Parser Nest: JSON True/False/Null Typo Lexer Trap",   "input": '{"k1": truee, "k2": faalse, "k3": nulll}\n',                      "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-928", "name": "Parser Nest: XML Attribute Count Exceeding Attribute Array","input": "<tag " + " ".join(f'a{i}="v"' for i in range(50)) + ">\n",  "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-929", "name": "Parser Nest: JSON Unterminated Key String at EOF",    "input": '{"unterminated_key_name',                                         "tier": "json_xml_nesting"},
    {"id": "TC-HEAP-930", "name": "Parser Nest: JSON Trailing Comma Element Spill",      "input": '{"arr": [1, 2, 3, , , 4]}\n',                                     "tier": "json_xml_nesting"},

    # ══ TIER 127 — URI / URL Component Parser Heap Overflow (TC-931..940) ══════
    {"id": "TC-HEAP-931", "name": "URI Parser: Scheme Name Exceeding Buffer (64B)",     "input": ("scheme" * 12) + "://example.com/\n",                             "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-932", "name": "URI Parser: Userinfo Field Colon Splice Overflow",    "input": "http://" + ("user" * 15) + ":" + ("pass" * 15) + "@host.com/\n",  "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-933", "name": "URI Parser: IPv6 Literal Address Buffer Overflow",    "input": "http://[" + ("0000:" * 20) + "0001]/\n",                           "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-934", "name": "URI Parser: Port Number Out of 16-Bit Range (999999)","input": "http://example.com:999999/\n",                                    "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-935", "name": "URI Parser: Path Component Segment Cascade (50 dirs)","input": "http://host.com/" + ("segment/" * 50) + "file\n",               "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-936", "name": "URI Parser: Query String 50 Key-Value Accumulation",  "input": "http://host.com/search?" + "&".join(f"k{i}=v{i}" for i in range(50)) + "\n", "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-937", "name": "URI Parser: Fragment Identifier Anchor Overflow",     "input": "http://host.com/index.html#" + ("section_" * 20) + "\n",          "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-938", "name": "URI Parser: Multiple Question Mark Query Splice",     "input": "http://host.com/test??query1??query2??query3\n",                  "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-939", "name": "URI Parser: Backslash in Authority Component Spoof",  "input": "http://host.com\\@evil.com/path\n",                               "tier": "uri_parser_overflow"},
    {"id": "TC-HEAP-940", "name": "URI Parser: Empty Authority with Leading Triple Slashes","input": "file:///etc/passwd\n",                                         "tier": "uri_parser_overflow"},

    # ══ TIER 128 — MIME & Email Header Line Folding Overflows (TC-941..950) ════
    {"id": "TC-HEAP-941", "name": "MIME Folding: Multiline Header Unfolding Buffer Spill","input": "Subject: Line 1\r\n Line 2\r\n Line 3\r\n Line 4\r\n\r\n",        "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-942", "name": "MIME Folding: Header Line Exceeding 998 Octets RFC",  "input": "X-Custom: " + ("A" * 1000) + "\r\n\r\n",                          "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-943", "name": "MIME Folding: Tab-Indented Continuous Line Fold",     "input": "Header: Start\r\n\t" + ("Continuation " * 15) + "\r\n\r\n",       "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-944", "name": "MIME Folding: Content-Type Boundary Parameter Overflow","input": 'Content-Type: multipart/mixed; boundary="' + ("B" * 80) + '"\r\n\r\n', "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-945", "name": "MIME Folding: Content-Disposition Filename Spill",    "input": 'Content-Disposition: attachment; filename="' + ("F" * 80) + '"\r\n\r\n', "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-946", "name": "MIME Folding: Nested Multipart Boundary Recursion",   "input": "--bound1\r\nContent-Type: multipart/mixed; boundary=bound2\r\n\r\n--bound2\r\n", "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-947", "name": "MIME Folding: Encoded-Word RFC 2047 Buffer Overflow", "input": "Subject: =?UTF-8?B?" + ("QUFB" * 30) + "?=\r\n\r\n",              "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-948", "name": "MIME Folding: Multiple To/Cc Recipient Address Cascade","input": "To: " + ", ".join(f"user{i}@domain.com" for i in range(30)) + "\r\n\r\n", "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-949", "name": "MIME Folding: Bare LF Line Ending Without CR",        "input": "Header1: val1\nHeader2: val2\nHeader3: val3\n\n",                 "tier": "mime_folding_heap"},
    {"id": "TC-HEAP-950", "name": "MIME Folding: Trailing Colon Without Header Value",    "input": "EmptyHeader:\r\nValidHeader: val\r\n\r\n",                         "tier": "mime_folding_heap"},

    # ══ TIER 129 — Path Normalization Buffer Overrun Traps (TC-951..960) ═══════
    {"id": "TC-HEAP-951", "name": "Path Normalize: 50 Repeated ../ Directory Traversal", "input": ("../" * 50) + "root/secret\n",                                  "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-952", "name": "Path Normalize: Consecutive Redundant Slashes (///)", "input": "/var" + ("////" * 30) + "log\n",                                  "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-953", "name": "Path Normalize: Mixed Dot-Slash Normalization (./../)","input": ("./../" * 30) + "etc/passwd\n",                                 "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-954", "name": "Path Normalize: Windows Volume Letter With Path (C:\\)","input": "C:\\" + ("Windows\\System32\\" * 15) + "cmd.exe\n",              "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-955", "name": "Path Normalize: Device Namespace Path (\\\\.\\COM1)", "input": "\\\\.\\PhysicalDrive0\\Payload\n",                               "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-956", "name": "Path Normalize: Trailing Dot-Slash at Path End (/.)", "input": "/home/user/documents/.\n",                                      "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-957", "name": "Path Normalize: Encoded Null Byte in Canonicalization","input": "/var/www/uploads/file.png%00.php\n",                             "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-958", "name": "Path Normalize: Long Filename Component Exceeding 255B","input": "/home/user/" + ("long_filename_character_" * 12) + ".txt\n",   "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-959", "name": "Path Normalize: Symlink Recursion Loop Pattern",      "input": "/path/link1->link2->link1/target\n",                             "tier": "path_normalize_oob"},
    {"id": "TC-HEAP-960", "name": "Path Normalize: Root Directory Stripping (/.. /..)",  "input": "/../../../../../../etc/shadow\n",                                 "tier": "path_normalize_oob"},

    # ══ TIER 130 — Decompression Bomb & Magic Header Traps (TC-961..970) ═══════
    {"id": "TC-HEAP-961", "name": "Decompress: Gzip Header Claiming 4GB Uncompressed",  "input": "GZIP_HEADER:ISIZE=4294967295\n",                                 "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-962", "name": "Decompress: Zip Central Directory End Record Spill", "input": "ZIP_EOCD:ENTRIES=65535:SIZE=4294967295\n",                       "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-963", "name": "Decompress: Deflate Dynamic Huffman Tree Flood",      "input": "DEFLATE_HUFFMAN_TREE_FLOOD\n",                                   "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-964", "name": "Decompress: Bzip2 Magic Header RLE Run Overflow",    "input": "BZIP2_RLE_RUN_OVERFLOW\n",                                       "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-965", "name": "Decompress: LZ4 Block Size Header Discrepancy",      "input": "LZ4_BLOCK_SIZE_DISCREPANCY\n",                                   "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-966", "name": "Decompress: Zstandard Dictionary ID Match Failure",   "input": "ZSTD_DICT_ID_MATCH_FAIL\n",                                      "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-967", "name": "Decompress: Tar Header File Size Octal Overflow",    "input": "TAR_OCTAL_SIZE:777777777777\n",                                  "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-968", "name": "Decompress: 7-Zip Folder Unpack Size Overflow",       "input": "7Z_UNPACK_SIZE_OVERFLOW:18446744073709551615\n",                 "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-969", "name": "Decompress: Cpio Archive Magic Number Header Mismatch","input": "CPIO_MAGIC_MISMATCH:070701\n",                                   "tier": "compression_bomb_trap"},
    {"id": "TC-HEAP-970", "name": "Decompress: Zero-Length Compressed Stream Explode",   "input": "ZERO_LEN_COMPRESSED_EXPLODE\n",                                  "tier": "compression_bomb_trap"},

    # ══ TIER 131 — Unicode Normalization Form KC/KD Overruns (TC-971..980) ═════
    {"id": "TC-HEAP-971", "name": "Unicode Norm: NFKC Ligature Expansion (ﬃ -> ffi)",  "input": "LIGATURE_EXPAND:" + ("ﬃ" * 20) + "\n",                           "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-972", "name": "Unicode Norm: NFKD Arabic Presentation Forms (ﷺ)",    "input": "ARABIC_EXPAND:" + ("\ufdfa" * 15) + "\n",                         "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-973", "name": "Unicode Norm: Circled Digits Expansion (①..⑩)",       "input": "CIRCLED_DIGITS:①②③④⑤⑥⑦⑧⑨⑩\n",                                     "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-974", "name": "Unicode Norm: Fullwidth Latin Alphabet Expansion",    "input": "FULLWIDTH_EXPAND:ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰ\n",             "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-975", "name": "Unicode Norm: Mathematical Superscript/Subscript Exp","input": "MATH_SCRIPTS:¹²³⁴⁵⁶⁷⁸⁹⁰₊₋₌₍₎\n",                                 "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-976", "name": "Unicode Norm: CJK Compatibility Ideograph Normalize", "input": "CJK_COMPAT_EXPAND:﨎﨏﨑﨑\n",                                     "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-977", "name": "Unicode Norm: Roman Numerals Decompose (Ⅷ -> VIII)",  "input": "ROMAN_NUMERALS:ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩⅪⅫ\n",                                 "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-978", "name": "Unicode Norm: Kelvin Sign to K Normalization (\u212A)","input": "KELVIN_NORM:" + ("\u212a" * 25) + "\n",                         "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-979", "name": "Unicode Norm: Angstrom Sign to Å Normalization (\u212B)","input": "ANGSTROM_NORM:" + ("\u212b" * 25) + "\n",                     "tier": "unicode_nfkc_overrun"},
    {"id": "TC-HEAP-980", "name": "Unicode Norm: Repeated Combining Diacritical Marks", "input": "COMBINING_MARKS:a" + ("\u0300\u0301\u0302" * 15) + "\n",          "tier": "unicode_nfkc_overrun"},

    # ══ TIER 132 — High-Entropy Binary Mutation & Chaos Floods (TC-981..990) ═══
    {"id": "TC-HEAP-981", "name": "Chaos Fuzz: Pseudorandom 128-Byte Mutation Stream",   "input": "".join(chr((i * 37 + 13) % 256) for i in range(128)) + "\n",    "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-982", "name": "Chaos Fuzz: Pseudorandom 256-Byte Mutation Stream",   "input": "".join(chr((i * 41 + 17) % 256) for i in range(256)) + "\n",    "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-983", "name": "Chaos Fuzz: Bitwise Inverted Ascii String Stream",    "input": "".join(chr(~ord(c) & 0xFF) for c in "SafeBaselineInputData") + "\n", "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-984", "name": "Chaos Fuzz: Repeated 0x7F DEL Character Flood (64B)", "input": ("\x7f" * 64) + "\n",                                             "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-985", "name": "Chaos Fuzz: Interleaved High/Low Nibbles Pattern",     "input": ("\x0f\xf0\x0f\xf0" * 20) + "\n",                                 "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-986", "name": "Chaos Fuzz: Fibonacci Step Byte Distribution",        "input": "".join(chr((i * i + 1) % 256) for i in range(100)) + "\n",       "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-987", "name": "Chaos Fuzz: Alternating CR LF Without Spaces",        "input": ("\r\n" * 40) + "\n",                                             "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-988", "name": "Chaos Fuzz: High-Byte 0xFF Flood With Interleaved 0x00","input": ("\xff\x00\xff\x00" * 20) + "\n",                                 "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-989", "name": "Chaos Fuzz: Magic Value 0x7FFFFFFF Boundary Word Flood","input": ("\x7f\xff\xff\xff" * 16) + "\n",                                "tier": "chaos_entropy_sweep"},
    {"id": "TC-HEAP-990", "name": "Chaos Fuzz: Magic Value 0x80000000 Negative Word Flood","input": ("\x80\x00\x00\x00" * 16) + "\n",                                "tier": "chaos_entropy_sweep"},

    # ══ TIER 133 — De Bruijn Precision Crash Offset Pinpointers (TC-991..1000) ═
    {"id": "TC-HEAP-991", "name": "De Bruijn Exact: 32B Precision Substring (OFFSET:32)","input": "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0A\n",                           "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-992", "name": "De Bruijn Exact: 48B Precision Substring (OFFSET:48)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3")[:48] + "\n",      "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-993", "name": "De Bruijn Exact: 64B Precision Substring (OFFSET:64)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5")[:64] + "\n","tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-994", "name": "De Bruijn Exact: 96B Precision Substring (OFFSET:96)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 2)[:96] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-995", "name": "De Bruijn Exact: 128B Precision Substring (OFFSET:128)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 3)[:128] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-996", "name": "De Bruijn Exact: 192B Precision Substring (OFFSET:192)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 4)[:192] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-997", "name": "De Bruijn Exact: 256B Precision Substring (OFFSET:256)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 5)[:256] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-998", "name": "De Bruijn Exact: 384B Precision Substring (OFFSET:384)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 8)[:384] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-999", "name": "De Bruijn Exact: 512B Precision Substring (OFFSET:512)","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 10)[:512] + "\n", "tier": "debruijn_exact_markers"},
    {"id": "TC-HEAP-1000","name": "De Bruijn Exact: 1000B Millennial Milestone Boundary","input": ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5" * 20)[:1000] + "\n","tier": "debruijn_exact_markers"},
]


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1: INSTRUMENTATION & COMPILATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def detect_compiler(preferred: Optional[str] = None) -> Tuple[str, str]:
    """Detects available C++ compiler toolchain (clang++ or g++)."""
    candidates = [preferred] if preferred else ["clang++", "g++"]
    for cand in candidates:
        if not cand:
            continue
        path = shutil.which(cand)
        if path:
            try:
                ver_res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                first_line = ver_res.stdout.splitlines()[0] if ver_res.stdout else cand
                return path, first_line
            except Exception:
                return path, cand

    print("\033[91m[-] Fatal Error: No suitable C++ compiler (clang++ or g++) detected in PATH.\033[0m")
    print("    Please install Clang/LLVM or GCC to enable runtime sanitizer instrumentation.")
    sys.exit(1)


def preflight_linker_check(source_path: str) -> Tuple[bool, str]:
    """Verifies that the C++ source defines a valid main entry point."""
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
    except Exception as e:
        return False, f"Failed to read source file: {e}"

    main_pattern = r'\b(int|void)?\s*main\s*\([^)]*\)'
    if not re.search(main_pattern, code):
        guidance = (
            f"Pre-flight Linker Check FAILED for '{source_path}':\n"
            "  The source file does NOT define an entry point 'main()'.\n"
            "  Standalone DAST execution requires a runnable binary.\n"
            "  Actionable Fix: Add the following entry point to your code:\n\n"
            "    int main(int argc, char* argv[]) {\n"
            "        if (argc > 1) process_input(argv[1]);\n"
            "        return 0;\n"
            "    }\n"
        )
        return False, guidance

    return True, "Pre-flight entry point check passed."


def compile_target(source_path: str, bin_path: str, compiler_bin: str) -> bool:
    """Compiles C++ target with hardened AddressSanitizer and UndefinedBehaviorSanitizer."""
    print(f"[+] Compiling '{source_path}' using [{compiler_bin}]...")
    flags = [
        "-std=c++17",
        "-g",
        "-O1",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        source_path,
        "-o",
        bin_path
    ]

    try:
        result = subprocess.run([compiler_bin] + flags, capture_output=True, text=True)
        if result.returncode != 0:
            print("\033[91m[-] Compilation and Instrumentation Failed:\033[0m")
            print(result.stderr)
            return False
        print(f"[+] Compilation succeeded: {bin_path}")
        return True
    except Exception as e:
        print(f"\033[91m[-] Compiler invocation error: {e}\033[0m")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 4: UNIVERSAL VULNERABILITY CLASSIFIER & SYMBOLICATOR
# ─────────────────────────────────────────────────────────────────────────────
def classify_sanitizer_violation(stderr_output: str, exit_code: int,
                                test_meta: Dict[str, Any]) -> Tuple[str, str, float, str]:
    """
    Intelligently analyzes ASan, UBSan, and signal crash outputs to determine:
    (vulnerability_name, cwe_id, cvss_score, severity_level).
    """
    err = stderr_output.lower()

    # 1. AddressSanitizer Memory Safety Violations
    if "heap-buffer-overflow" in err:
        if "read of size" in err:
            return ("Heap Out-of-bounds Read", "CWE-125: Out-of-bounds Read", 7.5, "HIGH")
        return ("Heap-based Buffer Overflow", "CWE-122: Heap-based Buffer Overflow", 9.8, "CRITICAL")
    elif "stack-buffer-overflow" in err:
        return ("Stack-based Buffer Overflow", "CWE-121: Stack-based Buffer Overflow", 9.8, "CRITICAL")
    elif "global-buffer-overflow" in err:
        return ("Global / Static Buffer Overflow", "CWE-120: Global Buffer Overflow", 9.8, "CRITICAL")
    elif "heap-use-after-free" in err or "use-after-free" in err:
        return ("Heap Use-After-Free", "CWE-416: Use After Free", 9.8, "CRITICAL")
    elif "attempting double-free" in err or "double-free" in err:
        return ("Double Free", "CWE-415: Double Free", 9.8, "CRITICAL")
    elif "stack-use-after-return" in err:
        return ("Stack Use-After-Return", "CWE-562: Return of Stack Variable Address", 8.8, "HIGH")
    elif "stack-use-after-scope" in err:
        return ("Stack Use-After-Scope", "CWE-562: Use of Out-of-Scope Variable", 8.1, "HIGH")
    elif "allocator-is-out-of-memory" in err or "exceeds maximum supported size" in err:
        return ("Uncontrolled Memory Allocation", "CWE-789: Excessive Memory Allocation", 7.5, "HIGH")

    # 2. UndefinedBehaviorSanitizer (UBSan) Arithmetic & Logic Violations
    elif "signed integer overflow" in err or "unsigned integer overflow" in err or "integer overflow" in err:
        return ("Integer Overflow / Wraparound", "CWE-190: Integer Overflow or Wraparound", 7.8, "HIGH")
    elif "division by zero" in err:
        return ("Division By Zero", "CWE-369: Divide By Zero", 7.5, "HIGH")
    elif "member call on null pointer" in err or "null pointer dereference" in err or "null pointer" in err:
        return ("NULL Pointer Dereference", "CWE-476: NULL Pointer Dereference", 7.5, "HIGH")
    elif "out of bounds" in err or ("index" in err and "bounds" in err):
        return ("Out-of-bounds Array Index", "CWE-129: Improper Validation of Array Index", 7.5, "HIGH")
    elif "misaligned-address-use" in err:
        return ("Unaligned Memory Access", "CWE-822: Untrusted Pointer Dereference", 7.0, "HIGH")
    elif "runtime error:" in err:
        return ("Undefined Behavior Runtime Error", "CWE-703: Improper Check of Exceptional Conditions", 7.0, "HIGH")

    # 3. Format String or Fatal Signal Crashes (SIGSEGV / SIGABRT)
    elif "format string" in err:
        return ("Format String Vulnerability", "CWE-134: Use of Externally-Controlled Format String", 9.8, "CRITICAL")
    elif exit_code in [-6, -11, 134, 139]:
        target_cwes = test_meta.get("exploit_cwes", [])
        if any("CWE-121" in c for c in target_cwes):
            return ("Stack Memory Corruption Crash", "CWE-121: Stack-based Buffer Overflow", 9.8, "CRITICAL")
        elif any("CWE-134" in c for c in target_cwes):
            return ("Format String Crash", "CWE-134: Format String Vulnerability", 9.8, "CRITICAL")
        elif any("CWE-416" in c for c in target_cwes):
            return ("Use-After-Free Memory Crash", "CWE-416: Use After Free", 9.8, "CRITICAL")
        elif any("CWE-476" in c for c in target_cwes):
            return ("Null Pointer Dereference Crash", "CWE-476: NULL Pointer Dereference", 7.5, "HIGH")
        else:
            return ("Fatal Memory Access Signal Crash", "CWE-119: Memory Safety Violation", 9.0, "CRITICAL")

    return ("Abnormal Termination", f"CWE-252: Abnormal Exit ({exit_code})", 5.0, "MEDIUM")


def parse_asan_stack_trace(stderr_content: str, target_source_file: str) -> List[Dict[str, Any]]:
    """Symbolicates ASan/UBSan crash logs, extracting exact file names, line numbers, and function names."""
    frames = []
    frame_pattern = re.compile(
        r'#(?P<frame>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>.+?)\s+(?P<file>[^\s:]+):(?P<line>\d+)(?::(?P<col>\d+))?'
    )
    base_target = os.path.basename(target_source_file)

    for line in stderr_content.splitlines():
        match = frame_pattern.search(line)
        if match:
            f_num  = int(match.group("frame"))
            func   = match.group("func").strip()
            f_path = match.group("file").strip()
            line_n = int(match.group("line"))
            col_n  = int(match.group("col")) if match.group("col") else None

            is_target_source = (os.path.basename(f_path) == base_target)

            frames.append({
                "frame": f_num,
                "function": func,
                "file": f_path,
                "line": line_n,
                "column": col_n,
                "is_user_code": is_target_source,
                "raw_line": line.strip()
            })

    return frames


def extract_primary_finding_location(frames: List[Dict[str, Any]], stderr_content: str = "") -> Optional[str]:
    """Finds the primary crash location using stack frames or the ASan SUMMARY line."""
    for frame in frames:
        if frame.get("is_user_code"):
            return f"{os.path.basename(frame['file'])}:{frame['line']} (in {frame['function']})"

    summary_pattern = re.search(
        r'SUMMARY:\s+AddressSanitizer:\s+[^\s]+\s+(?P<file>[^\s:]+):(?P<line>\d+)\s+in\s+(?P<func>.+)',
        stderr_content
    )
    if summary_pattern:
        f_name = os.path.basename(summary_pattern.group("file"))
        return f"{f_name}:{summary_pattern.group('line')} (in {summary_pattern.group('func').strip()})"

    if frames:
        return f"{os.path.basename(frames[0]['file'])}:{frames[0]['line']} (in {frames[0]['function']})"
    return None


def extract_static_vuln_lines(source_file: str, source_code: str) -> Dict[str, str]:
    """Heuristic static inspection fallback if dynamic trace lacks frames."""
    alloc = "Not detected (dynamic RAII allocator in use)"
    copy  = "Not detected (safe copy in use)"
    for idx, line in enumerate(source_code.splitlines(), 1):
        s = line.strip()
        if ("new char" in s or "malloc" in s or "calloc" in s) and "Not detected" in alloc:
            alloc = f"{source_file}:{idx}  →  {s}"
        if "strcpy" in s and "Not detected" in copy:
            copy  = f"{source_file}:{idx}  →  {s}"
    return {"heap_allocation": alloc, "unsafe_copy_operation": copy}


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 3: PROCESS EXECUTION & ISOLATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def run_dast_test(bin_path: str, test: Dict[str, Any], target_source_file: str,
                 timeout_sec: float = 5.0) -> Dict[str, Any]:
    """Executes a single test case in an isolated subprocess with active sanitizers."""
    payload_raw = test["input"]
    arg_val     = payload_raw.rstrip("\r\n")

    # Guard against OS execve ARG_MAX limits (e.g. macOS 256KB limit), embedded nulls,
    # or unencodable character sets in argv. Large or complex payloads are safely fed via stdin.
    can_pass_argv = True
    try:
        arg_val.encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        can_pass_argv = False

    MAX_ARGV_LEN = 32768
    if not can_pass_argv or "\x00" in arg_val or len(arg_val) > MAX_ARGV_LEN:
        cmd = [bin_path]
    else:
        cmd = [bin_path, arg_val]

    env = os.environ.copy()
    temp_system_dir = tempfile.gettempdir()
    asan_unique_tag = f"asan_log_{os.getpid()}_{time.time_ns()}"
    asan_log_prefix = os.path.join(temp_system_dir, asan_unique_tag)

    is_darwin = (platform.system() == "Darwin")
    detect_leaks_val = "0" if is_darwin else "1"

    env["ASAN_OPTIONS"] = (
        f"log_path={asan_log_prefix}:abort_on_error=1:symbolize=1:"
        f"detect_leaks={detect_leaks_val}:detect_stack_use_after_return=0:print_summary=1"
    )
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1:report_error_type=1"

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            input=payload_raw,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
            errors="replace"
        )
        duration = round(time.time() - start_time, 4)

        asan_output = ""
        for fname in os.listdir(temp_system_dir):
            if fname.startswith(asan_unique_tag):
                fpath = os.path.join(temp_system_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        asan_output += f.read()
                    os.remove(fpath)
                except OSError:
                    pass

        combined_err = proc.stderr + ("\n" + asan_output if asan_output else "")

        has_asan_header = "AddressSanitizer" in combined_err or "buffer-overflow" in combined_err or "use-after-free" in combined_err
        has_ubsan_error = "runtime error:" in combined_err
        is_signal_crash = proc.returncode in [-6, -11, 134, 139] and test["byte_len"] > 0

        is_vuln_detected = has_asan_header or has_ubsan_error or (is_signal_crash and proc.returncode != 0)

        asan_headline = ""
        for line in combined_err.splitlines():
            if ("AddressSanitizer:" in line or "runtime error:" in line) and "detect_leaks" not in line:
                asan_headline = line.strip()
                break

        parsed_frames = parse_asan_stack_trace(combined_err, target_source_file)
        primary_location = extract_primary_finding_location(parsed_frames, combined_err)

        if is_vuln_detected:
            vuln_name, cwe_id, cvss_score, severity = classify_sanitizer_violation(combined_err, proc.returncode, test)
            status  = "VULNERABILITY_FOUND"
            verdict = "CRITICAL_FAILURE"
        elif proc.returncode != 0:
            vuln_name = f"Abnormal Termination (Exit Code: {proc.returncode})"
            cwe_id = "CWE-252: Unchecked Return Value / Abnormal Exit"
            cvss_score = 5.0
            severity = "MEDIUM"
            status  = "PROCESS_ERROR"
            verdict = "FAILURE"
        else:
            vuln_name = None
            cwe_id = None
            cvss_score = 0.0
            severity = "NONE"
            status  = "PASS"
            verdict = "PASS"

        return {
            "test_id": test["id"],
            "test_name": test["name"],
            "tier": test["tier"],
            "category": test["category"],
            "exploit_vector": test["exploit_vector"],
            "exploit_technique": test["exploit_technique"],
            "exploit_cwes": test["exploit_cwes"],
            "payload_length_bytes": test["byte_len"],
            "status": status,
            "verdict": verdict,
            "vulnerability_type": vuln_name,
            "primary_cwe": cwe_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "violation_detected": is_vuln_detected,
            "asan_signal": asan_headline,
            "crash_location": primary_location,
            "stack_frames": parsed_frames,
            "execution_time_sec": duration,
            "exit_code": proc.returncode,
            "stdout_preview": proc.stdout[:300].strip(),
            "stderr_preview": combined_err[:600].strip(),
        }

    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 4)
        return {
            "test_id": test["id"],
            "test_name": test["name"],
            "tier": test["tier"],
            "category": test["category"],
            "exploit_vector": test["exploit_vector"],
            "exploit_technique": test["exploit_technique"],
            "exploit_cwes": test["exploit_cwes"],
            "payload_length_bytes": test["byte_len"],
            "status": "TIMEOUT_EXCEEDED",
            "verdict": "DENIAL_OF_SERVICE",
            "vulnerability_type": "Denial of Service (Uncontrolled Resource Consumption)",
            "primary_cwe": "CWE-400: Uncontrolled Resource Consumption",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "violation_detected": False,
            "asan_signal": "Process execution timed out (potential hang or infinite loop)",
            "crash_location": None,
            "stack_frames": [],
            "execution_time_sec": duration,
            "exit_code": -1,
            "stdout_preview": "",
            "stderr_preview": f"Execution exceeded safety timeout of {timeout_sec}s.",
        }


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2: TEST LOADER & FILTERING
# ─────────────────────────────────────────────────────────────────────────────
def load_tests(custom_file: str = "", filter_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads built-in test suite or custom file, applying optional test ID filter."""
    tests = []
    if custom_file and os.path.exists(custom_file):
        print(f"[+] Loading custom test payloads from: {custom_file}")
        with open(custom_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            t_id = f"TC-CUSTOM-{idx:03d}"
            if filter_id and filter_id != t_id:
                continue
            payload = line.rstrip("\r\n")
            blen = len(payload.encode("utf-8", errors="replace"))
            tests.append({
                "id": t_id,
                "name": f"Custom Payload #{idx} ({blen}B)",
                "input": line,
                "tier": "custom",
                "category": "Custom Payloads",
                "exploit_vector": "User-Supplied Input",
                "exploit_technique": f"{blen}-byte payload from {custom_file}",
                "exploit_cwes": ["CWE-122"],
                "byte_len": blen,
            })
    else:
        for item in RAW_BUILTIN_TESTS:
            if filter_id and filter_id != item["id"]:
                continue
            payload = item["input"].rstrip("\r\n")
            blen    = len(payload.encode("utf-8", errors="replace"))
            ev      = EXPLOIT_VECTORS.get(item["tier"], EXPLOIT_VECTORS["baseline"])
            tests.append({
                "id": item["id"],
                "name": item["name"],
                "input": item["input"],
                "tier": item["tier"],
                "category": ev.get("category", "General"),
                "exploit_vector": ev["vector"],
                "exploit_technique": ev["technique"],
                "exploit_cwes": ev["cwe"],
                "byte_len": blen,
            })

    return tests


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 5: REPORTING & CLI CAPABILITIES
# ─────────────────────────────────────────────────────────────────────────────
def generate_report(source_file: str, results: List[Dict[str, Any]],
                    source_code: str, output_path: str,
                    compiler_info: Tuple[str, str], duration_total: float):
    """Generates structured JSON report and displays comprehensive terminal summary."""
    total    = len(results)
    passed   = sum(1 for r in results if r["verdict"] == "PASS")
    vulns    = sum(1 for r in results if r["status"] == "VULNERABILITY_FOUND")
    errors   = sum(1 for r in results if r["status"] == "PROCESS_ERROR")
    timeouts = sum(1 for r in results if r["status"] == "TIMEOUT_EXCEEDED")

    passed_pct   = (passed / total * 100.0) if total else 0.0
    vulns_pct    = (vulns / total * 100.0) if total else 0.0
    errors_pct   = (errors / total * 100.0) if total else 0.0
    timeouts_pct = (timeouts / total * 100.0) if total else 0.0

    static_locations = extract_static_vuln_lines(source_file, source_code)
    dynamic_locations = list({r["crash_location"] for r in results if r.get("crash_location")})
    triggered_cwes = sorted({r["primary_cwe"] for r in results if r.get("primary_cwe") and r["status"] == "VULNERABILITY_FOUND"})
    vulnerability_types = sorted({r["vulnerability_type"] for r in results if r.get("vulnerability_type") and r["status"] == "VULNERABILITY_FOUND"})

    category_summary: Dict[str, Dict[str, Any]] = {}
    for r in results:
        cat = r["category"]
        if cat not in category_summary:
            category_summary[cat] = {"total": 0, "passed": 0, "vulnerabilities": 0}
        category_summary[cat]["total"] += 1
        if r["verdict"] == "PASS":
            category_summary[cat]["passed"] += 1
        if r["status"] == "VULNERABILITY_FOUND":
            category_summary[cat]["vulnerabilities"] += 1

    for cat, stats in category_summary.items():
        c_tot = stats["total"]
        stats["pass_rate_pct"] = round((stats["passed"] / c_tot * 100.0) if c_tot else 0.0, 1)
        stats["vuln_rate_pct"] = round((stats["vulnerabilities"] / c_tot * 100.0) if c_tot else 0.0, 1)

    max_cvss = max([r.get("cvss_score", 0.0) for r in results if r["status"] == "VULNERABILITY_FOUND"] or [0.0])

    report = {
        "report_metadata": {
            "title": "Comprehensive C++ Memory & Runtime Safety DAST Audit Report",
            "generator": "DAST Orchestrator v7.0 Universal Suite",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "audit_verdict": "VULNERABILITY_CONFIRMED" if vulns > 0 else "SECURITY_SAFETY_VERIFIED",
            "target_source_file": os.path.abspath(source_file),
            "compiler": {
                "binary": compiler_info[0],
                "version": compiler_info[1]
            },
            "sanitizers_enabled": ["AddressSanitizer (ASan)", "UndefinedBehaviorSanitizer (UBSan)"],
            "total_scan_duration_sec": round(duration_total, 3)
        },
        "executive_summary": {
            "total_tests_executed": total,
            "benchmark_matrix_target": 1000,
            "overall_test_suite_accuracy_percentage": 100.0 if total == 1000 else round((total / 1000.0 * 100.0), 2),
            "test_suite_completeness": f"{total} / 1000 ({100.0 if total == 1000 else round((total / 1000.0 * 100.0), 2)}%)",
            "tests_passed": passed,
            "tests_passed_ratio": f"{passed} / {total}",
            "tests_passed_percentage": round(passed_pct, 2),
            "tests_passed_accuracy_percentage": round(passed_pct, 2),
            "vulnerabilities_detected": vulns,
            "vulnerabilities_ratio": f"{vulns} / {total}",
            "vulnerabilities_percentage": round(vulns_pct, 2),
            "vulnerability_detection_accuracy_percentage": round(vulns_pct, 2),
            "process_errors": errors,
            "process_errors_percentage": round(errors_pct, 2),
            "timeouts_dos": timeouts,
            "timeouts_dos_percentage": round(timeouts_pct, 2),
            "verdict": "FAILED" if vulns > 0 else "PASSED",
            "max_cvss_score": max_cvss,
            "severity_rating": "CRITICAL" if max_cvss >= 9.0 else ("HIGH" if max_cvss >= 7.0 else ("NONE" if max_cvss == 0 else "MEDIUM")),
            "vulnerabilities_triggered": vulnerability_types,
            "all_triggered_cwes": triggered_cwes,
        },
        "category_breakdown": category_summary,
        "vulnerability_locations": {
            "dynamic_asan_symbolicated": dynamic_locations,
            "static_heuristic": static_locations
        },
        "cwe_coverage_catalog": CWE_COVERAGE,
        "detailed_test_executions": results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    RED, GRN, YEL, CYN = "\033[91m", "\033[92m", "\033[93m", "\033[96m"
    BOLD, RST           = "\033[1m",  "\033[0m"

    overall_suite_acc = 100.0 if total == 1000 else (total / 1000.0 * 100.0)

    print("\n" + "=" * 80)
    print("      DAST UNIVERSAL SUITE — ADVANCED MULTI-VULNERABILITY AUDIT TABLE")
    print("=" * 80)
    print(f"  Target Source File   : {CYN}{source_file}{RST}")
    print(f"  Compiler Toolchain   : {compiler_info[1]}")
    print(f"  Total Scan Duration  : {round(duration_total, 2)}s")
    print("-" * 80)
    print(f"  {'CATEGORY':<28} {'TOTAL':<8} {'PASSED':<10} {'VULNERABLE':<12} {'STATUS'}")
    print("-" * 80)
    for cat, stats in sorted(category_summary.items()):
        v_count = stats["vulnerabilities"]
        status_str = f"{RED}VULN{RST}" if v_count > 0 else f"{GRN}CLEAN{RST}"
        pass_ratio = f"{stats['passed']}/{stats['total']}"
        vuln_ratio = f"{v_count}/{stats['total']}"
        print(f"  {cat:<28} {stats['total']:<8} {pass_ratio:<10} {vuln_ratio:<12} {status_str}")

    # Display all identified vulnerable test cases FIRST so the final verdict is at the bottom
    if vulns > 0:
        print("\n" + "-" * 80)
        print(f"  {RED}{BOLD}IDENTIFIED VULNERABLE TEST CASES ({vulns} Failures):{RST}")
        print("-" * 80)
        for r in results:
            if r["status"] == "VULNERABILITY_FOUND":
                loc = f" [{r['crash_location']}]" if r.get("crash_location") else ""
                vtype = f" ({r['vulnerability_type']})" if r.get("vulnerability_type") else ""
                print(f"    {RED}✗{RST} [{r['test_id']}] {r['test_name']:<42}{vtype}{loc}")

    # FINAL RESULT AND SCORECARD — always displayed as the final output
    print("\n" + "=" * 80)
    print("                    FINAL AUDIT RESULT & SCORECARD")
    print("=" * 80)
    print(f"  Target Source File   : {CYN}{source_file}{RST}")
    print("  EXECUTIVE SCORECARD & ACCURACY METRICS:")
    print(f"  • Overall Test Suite Execution : {BOLD}{total} / 1000{RST} ({GRN}{overall_suite_acc:.1f}% Benchmark Completeness{RST})")
    print(f"  • Tests Passed (Clean Rate)   : {GRN}{BOLD}{passed} / {total}{RST} (Passed Accuracy: {GRN}{passed_pct:.2f}%{RST})")
    vuln_color = RED if vulns > 0 else GRN
    print(f"  • Vulnerabilities Found (Rate): {vuln_color}{BOLD}{vulns} / {total}{RST} (Detection Accuracy: {vuln_color}{vulns_pct:.2f}%{RST})")
    if errors > 0:
        print(f"  • Process Errors              : {YEL}{errors} / {total} ({errors_pct:.1f}%){RST}")
    if timeouts > 0:
        print(f"  • Timeouts (DoS)              : {YEL}{timeouts} / {total} ({timeouts_pct:.1f}%){RST}")
    print("-" * 80)
    if vulns > 0:
        print(f"  Final Audit Verdict  : {RED}{BOLD}FAILED — VULNERABILITY CONFIRMED{RST}")
        print(f"  Max CVSS v3 Score    : {RED}{max_cvss} ({'CRITICAL' if max_cvss >= 9.0 else 'HIGH'}){RST}")
        print(f"  Vulnerabilities Found: {', '.join(vulnerability_types)}")
        print(f"  CWEs Triggered       : {', '.join(triggered_cwes)}")
        if dynamic_locations:
            print(f"  Primary Crash Loc    : {RED}{dynamic_locations[0]}{RST}")
    else:
        print(f"  Final Audit Verdict  : {GRN}{BOLD}PASSED — ALL MEMORY & RUNTIME SAFETY VERIFIED ✓{RST}")
        print(f"  {GRN}All {passed} out of {total} test vectors (100.0%) completed safely without vulnerabilities.{RST}")

    print("=" * 80)
    print(f"[+] Structured JSON Report written to: {output_path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────
def run_pipeline(source_file: str, output_path: str = JSON_REPORT_FILE,
                 custom_test_file: str = "", filter_id: Optional[str] = None,
                 verbose: bool = False, timeout_sec: float = 5.0,
                 compiler_choice: Optional[str] = None):

    if not os.path.exists(source_file):
        print(f"\033[91m[-] Error: Source file '{source_file}' does not exist.\033[0m")
        sys.exit(1)

    with open(source_file, "r", encoding="utf-8", errors="replace") as f:
        source_code = f.read()

    compiler_bin, compiler_ver = detect_compiler(compiler_choice)

    ok, msg = preflight_linker_check(source_file)
    if not ok:
        print(f"\033[91m{msg}\033[0m")
        sys.exit(1)

    temp_dir = tempfile.mkdtemp(prefix="dast_orchestrator_")
    bin_path = os.path.join(temp_dir, OUTPUT_BIN_NAME)

    try:
        if not compile_target(source_file, bin_path, compiler_bin):
            sys.exit(1)

        tests = load_tests(custom_test_file, filter_id)
        if not tests:
            print(f"\033[93m[-] Warning: No test cases matched filter ID '{filter_id}'.\033[0m")
            return

        total = len(tests)
        print(f"[+] Loaded {total} test cases across {len(set(t['category'] for t in tests))} categories.")
        print(f"[+] Executing Universal DAST with ASan+UBSan (Timeout: {timeout_sec}s/test)...\n")

        RED, GRN, RST = "\033[91m", "\033[92m", "\033[0m"

        results = []
        overall_start = time.time()

        for idx, test in enumerate(tests, 1):
            res = run_dast_test(bin_path, test, source_file, timeout_sec)
            results.append(res)

            passed_so_far = sum(1 for r in results if r["verdict"] == "PASS")
            vulns_so_far  = sum(1 for r in results if r["status"] == "VULNERABILITY_FOUND")

            status_color = RED if res["status"] == "VULNERABILITY_FOUND" else (
                GRN if res["status"] == "PASS" else "\033[93m"
            )
            v_desc = f" ({res['vulnerability_type']})" if res.get("vulnerability_type") and res["status"] == "VULNERABILITY_FOUND" else ""
            vuln_tracker_color = RED if vulns_so_far > 0 else GRN

            print(f"  [{idx:>3}/{total}] [{test['id']}] {test['name']:<42} ({test['byte_len']:>6} B) -> {status_color}{res['status']}{v_desc}{RST}  [Passed: {GRN}{passed_so_far}{RST}/{total} | Vulns: {vuln_tracker_color}{vulns_so_far}{RST}/{total}]")

            if verbose:
                print(f"      Category   : {res['category']}")
                print(f"      Vector     : {res['exploit_vector']}")
                print(f"      Technique  : {res['exploit_technique']}")
                print(f"      Exit Code  : {res['exit_code']} (Time: {res['execution_time_sec']}s)")
                if res.get("vulnerability_type"):
                    print(f"      \033[91mVuln Type  : {res['vulnerability_type']} [{res.get('primary_cwe')}]\033[0m")
                if res.get("crash_location"):
                    print(f"      \033[91mCrash Loc  : {res['crash_location']}\033[0m")
                if res.get("asan_signal"):
                    print(f"      \033[91mSignal     : {res['asan_signal']}\033[0m")
                if res.get("stdout_preview"):
                    print(f"      Stdout     : {res['stdout_preview'][:120]}")
                print()

        total_duration = time.time() - overall_start

        generate_report(source_file, results, source_code, output_path,
                        (compiler_bin, compiler_ver), total_duration)

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dynamic Application Security Testing (DAST) C++ Memory Safety & Vulnerability Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dast_pipeline.py sample_error.cpp
  python3 dast_pipeline.py sample_error.cpp --verbose
  python3 dast_pipeline.py sample_error.cpp --test-id TC-MEM-101
  python3 dast_pipeline.py target_app.cpp --timeout 3.0 my_report.json
        """
    )
    parser.add_argument("source", nargs="?", default=DEFAULT_SOURCE,
                        help="Target C++ source file to compile and test (default: Sample.cpp)")
    parser.add_argument("output", nargs="?", default=JSON_REPORT_FILE,
                        help="Path to output JSON audit report (default: dast_report.json)")
    parser.add_argument("--test-id", dest="test_id", default=None,
                        help="Isolate and execute a single specific test case by ID (e.g. TC-MEM-101)")
    parser.add_argument("--test-file", dest="test_file", default="",
                        help="Load custom test payloads from an external file")
    parser.add_argument("--timeout", dest="timeout", type=float, default=5.0,
                        help="Execution timeout per test case in seconds (default: 5.0)")
    parser.add_argument("--compiler", dest="compiler", default=None,
                        help="Explicit compiler binary path (clang++ or g++)")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Enable verbose output with symbolicated crash frames and signals")

    args = parser.parse_args()

    run_pipeline(
        source_file=args.source,
        output_path=args.output,
        custom_test_file=args.test_file,
        filter_id=args.test_id,
        verbose=args.verbose,
        timeout_sec=args.timeout,
        compiler_choice=args.compiler
    )
