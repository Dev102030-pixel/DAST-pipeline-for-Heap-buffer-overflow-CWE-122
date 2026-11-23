/**
 * ==============================================================================
 * Security Vulnerability Target Benchmark: sample_vulner.cpp
 * ==============================================================================
 * This program contains intentional, clearly documented memory and runtime
 * vulnerabilities designed to be detected and classified by the Universal
 * Dynamic Application Security Testing (DAST) pipeline with ASan & UBSan.
 *
 * Included Vulnerabilities:
 *   [1] CWE-122: Heap-Based Buffer Overflow (unbounded strcpy to 24-byte heap chunk)
 *   [2] CWE-134: Format String Vulnerability (printf on raw user heap memory)
 *   [3] CWE-416: Use-After-Free (UAF) (dereferencing deleted heap object)
 *   [4] CWE-415: Double Free (deallocating the same heap pointer twice)
 *   [5] CWE-129: Array Index Out-of-Bounds (unvalidated heap subscript access)
 *   [6] CWE-190/680: Integer Overflow to Undersized Heap Allocation
 * ==============================================================================
 */

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Structure for testing Use-After-Free and vtable integrity
class VulnerableSession {
public:
    int session_id;
    char session_tag[16];

    VulnerableSession(int id, const char* tag) : session_id(id) {
        std::strncpy(session_tag, tag, sizeof(session_tag) - 1);
        session_tag[sizeof(session_tag) - 1] = '\0';
    }

    virtual void print_status() {
        std::cout << "[+] Active Session ID: " << session_id 
                  << " (Tag: " << session_tag << ")" << std::endl;
    }

    virtual ~VulnerableSession() = default;
};

// ------------------------------------------------------------------------------
// VULNERABILITY 1 & 2: Heap Buffer Overflow (CWE-122) & Format String (CWE-134)
// ------------------------------------------------------------------------------
void test_heap_overflow_and_format_string(const char* input_data) {
    if (!input_data) return;

    size_t len = std::strlen(input_data);
    std::cout << "[Target] Received payload (" << len << " bytes)" << std::endl;

    // Fixed 24-byte heap chunk (typical 24B/32B allocator quantum bin)
    char* heap_buf = new char[24];
    std::memset(heap_buf, 0, 24);

    std::cout << "[Target] Allocated 24-byte heap buffer at address: " 
              << static_cast<void*>(heap_buf) << std::endl;

    // --- VULNERABILITY 1: Unbounded strcpy (Heap Buffer Overflow) ---
    // If input_data is 24 bytes or larger, strcpy writes past the 24-byte boundary,
    // corrupting adjacent heap chunk headers and triggering ASan heap-buffer-overflow.
    std::strcpy(heap_buf, input_data);

    // --- VULNERABILITY 2: Format String Vulnerability ---
    // If the input contains format specifiers (%s, %x, %n, %p), passing heap_buf
    // directly as the format string leaks stack/heap or crashes process.
    if (std::strchr(heap_buf, '%') != nullptr) {
        std::cout << "[!] Executing format string sink: ";
        std::printf(heap_buf);
        std::printf("\n");
    }

    std::cout << "[Target] Processed buffer output: " << heap_buf << std::endl;
    delete[] heap_buf;
}

// ------------------------------------------------------------------------------
// VULNERABILITY 3: Use-After-Free (CWE-416)
// ------------------------------------------------------------------------------
void test_use_after_free() {
    std::cout << "[!] Triggering Use-After-Free (CWE-416)..." << std::endl;
    VulnerableSession* session = new VulnerableSession(42, "ADMIN_SESSION");
    
    // Free the heap object
    delete session;

    // VULNERABILITY: Dereferencing pointer after it has been freed!
    session->print_status();
}

// ------------------------------------------------------------------------------
// VULNERABILITY 4: Double Free (CWE-415)
// ------------------------------------------------------------------------------
void test_double_free() {
    std::cout << "[!] Triggering Double Free (CWE-415)..." << std::endl;
    char* double_buf = new char[32];
    std::strcpy(double_buf, "DOUBLE_FREE_TARGET");

    // First legal deallocation
    delete[] double_buf;

    // VULNERABILITY: Freeing the same memory pointer a second time!
    delete[] double_buf;
}

// ------------------------------------------------------------------------------
// VULNERABILITY 5: Array Index Out-of-Bounds (CWE-129)
// ------------------------------------------------------------------------------
void test_array_out_of_bounds(int index) {
    std::cout << "[!] Testing Heap Array Index: " << index << std::endl;
    int* heap_array = new int[10]; // Valid elements: index 0 to 9
    for (int i = 0; i < 10; ++i) heap_array[i] = (i + 1) * 10;

    // VULNERABILITY: Unchecked array subscript on heap allocated memory
    std::cout << "[!] Value at heap_array[" << index << "] = " 
              << heap_array[index] << std::endl;

    delete[] heap_array;
}

// ------------------------------------------------------------------------------
// VULNERABILITY 6: Integer Overflow leading to Undersized Allocation (CWE-190/680)
// ------------------------------------------------------------------------------
void test_integer_overflow_allocation(unsigned int count) {
    std::cout << "[!] Testing Integer Multiplication Wrap with count: " << count << std::endl;
    
    // VULNERABILITY: 32-bit unsigned multiplication wraps around zero!
    // Example: count = 1073741825 * 4 = 4294967300 = 4 bytes allocated
    unsigned int total_bytes = count * sizeof(int);
    std::cout << "[!] Calculated allocation size: " << total_bytes << " bytes" << std::endl;

    char* tiny_buf = new char[total_bytes];
    // Write 32 bytes into tiny_buf (which may only be 4 bytes due to wrap!)
    std::memset(tiny_buf, 'A', 32);

    delete[] tiny_buf;
}

// ------------------------------------------------------------------------------
// MAIN ENTRY POINT (Accepts input via argv[1] or standard input stdin)
// ------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    std::string user_input;
    const char* payload = nullptr;

    if (argc > 1) {
        payload = argv[1];
    } else if (std::getline(std::cin, user_input)) {
        payload = user_input.c_str();
    }

    if (!payload || std::strlen(payload) == 0) {
        std::cout << "[+] No input provided. Program exiting cleanly." << std::endl;
        return 0;
    }

    // Check for specific exploit simulation command triggers
    if (std::strstr(payload, "UAF") != nullptr || std::strstr(payload, "FREE_ACCESS") != nullptr) {
        test_use_after_free();
        return 0;
    }

    if (std::strstr(payload, "DOUBLE_FREE") != nullptr) {
        test_double_free();
        return 0;
    }

    if (std::strncmp(payload, "INDEX:", 6) == 0) {
        int idx = std::atoi(payload + 6);
        test_array_out_of_bounds(idx);
        return 0;
    }

    if (std::strncmp(payload, "ALLOC_COUNT:", 12) == 0) {
        unsigned int cnt = static_cast<unsigned int>(std::strtoul(payload + 12, nullptr, 10));
        test_integer_overflow_allocation(cnt);
        return 0;
    }

    // Default primary test routine: 24-byte Heap Buffer Overflow & Format String sink
    test_heap_overflow_and_format_string(payload);

    return 0;
}
