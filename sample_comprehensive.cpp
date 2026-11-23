/*
 * sample_comprehensive.cpp
 * ============================================================================
 * Comprehensive Multi-Vulnerability Benchmark Target for C++ DAST Orchestrator
 * ============================================================================
 * Contains intentional vulnerability triggers for:
 *   1. Heap Buffer Overflow (CWE-122)
 *   2. Stack Buffer Overflow (CWE-121)
 *   3. Format String Flaw (CWE-134)
 *   4. Use-After-Free (CWE-416) & Double-Free (CWE-415)
 *   5. Integer Overflow / Wraparound (CWE-190)
 *   6. Division By Zero (CWE-369)
 *   7. NULL Pointer Dereference (CWE-476)
 *   8. Out-of-Bounds Array Indexing (CWE-129)
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>

// Global session pointer for Use-After-Free & Double-Free simulation
struct SessionData {
    char username[32];
    int access_token;
};
static SessionData* g_session = nullptr;

// 1. Stack Buffer Overflow Trigger (CWE-121)
void test_stack_overflow(const char* input) {
    if (std::strncmp(input, "STACK:", 6) == 0) {
        char local_stack_buf[64];
        // UNSAFE: Unbounded copy into 64-byte stack buffer
        std::strcpy(local_stack_buf, input + 6);
        std::cout << "[STACK] Processed: " << local_stack_buf << std::endl;
    }
}

// 2. Format String Vulnerability Trigger (CWE-134)
void test_format_string(const char* input) {
    if (std::strchr(input, '%') != nullptr) {
        // UNSAFE: Passing user input directly as format string
        std::printf(input);
        std::printf("\n");
    }
}

// 3. Integer Overflow & Divide-by-Zero Trigger (CWE-190 / CWE-369)
void test_integer_and_arithmetic(const char* input) {
    // Check if input is integer numeric
    char* endptr = nullptr;
    long val = std::strtol(input, &endptr, 10);
    if (endptr != input && (*endptr == '\0' || *endptr == '\n')) {
        // Divide by zero check (CWE-369)
        if (val == 0) {
            volatile int denom = 0;
            volatile int div_res = 1000 / denom; // Triggers UBSan division by zero
            (void)div_res;
        }

        // Signed Integer Overflow check (CWE-190)
        if (val > 2000000000L) {
            int max_int = 2147483647;
            volatile int overflow = max_int + static_cast<int>(val - 2000000000L); // Triggers UBSan integer overflow
            (void)overflow;
        }
    }
}

// 4. Use-After-Free & Double-Free Trigger (CWE-416 / CWE-415)
void test_lifecycle_uaf_double_free(const char* input) {
    if (std::strcmp(input, "FREE") == 0) {
        if (!g_session) {
            g_session = new SessionData();
            std::strcpy(g_session->username, "admin_user");
            g_session->access_token = 1337;
        }
        // First delete
        delete g_session;
        // Do NOT null out pointer to simulate dangling pointer
    } else if (std::strcmp(input, "READ") == 0 || std::strcmp(input, "ACCESS") == 0) {
        if (g_session) {
            // UNSAFE: Use-After-Free (CWE-416)
            std::cout << "[UAF] Token: " << g_session->access_token << std::endl;
        }
    } else if (std::strcmp(input, "DOUBLE_FREE") == 0) {
        delete g_session;
        // UNSAFE: Double Free (CWE-415)
        delete g_session;
    }
}

// 5. NULL Pointer Dereference Trigger (CWE-476)
void test_null_pointer_deref(const char* input) {
    if (std::strcmp(input, "NULL") == 0 || std::strcmp(input, "nullptr") == 0) {
        int* null_ptr = nullptr;
        // UNSAFE: Dereferencing null pointer
        std::cout << *null_ptr << std::endl;
    }
}

// 6. Out-of-Bounds Array Indexing Trigger (CWE-129)
void test_oob_array_index(const char* input) {
    if (std::strncmp(input, "INDEX:", 6) == 0) {
        int safe_array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        int idx = std::atoi(input + 6);
        // UNSAFE: Out-of-bounds array access
        std::cout << "[OOB] Value at " << idx << " = " << safe_array[idx] << std::endl;
    }
}

// 7. Heap Buffer Overflow Trigger (CWE-122)
void test_heap_buffer_overflow(const char* input) {
    // Fixed 32-byte heap buffer
    char* heap_buffer = new char[32];
    std::memset(heap_buffer, 0, 32);

    // UNSAFE: Unbounded strcpy into 32-byte heap buffer (CWE-122)
    std::strcpy(heap_buffer, input);

    std::cout << "[HEAP] Stored: " << heap_buffer << std::endl;
    delete[] heap_buffer;
}

// Main Entry Point: Dispatches input across all vulnerability subroutines
int main(int argc, char* argv[]) {
    std::string input;
    const char* payload = nullptr;

    if (argc > 1) {
        payload = argv[1];
    } else if (std::getline(std::cin, input)) {
        payload = input.c_str();
    }

    if (!payload) {
        std::cout << "Usage: " << argv[0] << " <payload>" << std::endl;
        return 0;
    }

    // Strip trailing newline if present for clean token matching
    std::string clean_str = payload;
    while (!clean_str.empty() && (clean_str.back() == '\n' || clean_str.back() == '\r')) {
        clean_str.pop_back();
    }
    const char* clean_payload = clean_str.c_str();

    // 1. Check specialized lifecycle & logic triggers
    test_null_pointer_deref(clean_payload);
    test_integer_and_arithmetic(clean_payload);
    test_oob_array_index(clean_payload);
    test_lifecycle_uaf_double_free(clean_payload);
    test_stack_overflow(clean_payload);
    test_format_string(clean_payload);

    // 2. Default to general heap buffer processing
    test_heap_buffer_overflow(clean_payload);

    return 0;
}

