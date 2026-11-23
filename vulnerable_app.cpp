/*
 * vulnerable_app.cpp
 * ─────────────────────────────────────────────────────────────
 * INTENTIONALLY VULNERABLE C++ PROGRAM — FOR DAST TESTING ONLY
 * CWE-122: Heap-based Buffer Overflow
 * CWE-787: Out-of-bounds Write
 *
 * Root Cause:
 *   1. Fixed-size heap allocation: `new char[32]` — only 32 bytes allocated.
 *   2. Unbounded `strcpy()` copies user input with NO length check.
 *   3. Any input longer than 31 characters (32 - 1 for null) overflows the heap.
 *
 * Impact:
 *   - Adjacent heap metadata corruption
 *   - Potential control-flow hijacking via vtable or return-address overwrite
 *   - Exploitable by: heap spray, De Bruijn pattern, fake chunk injection
 *
 * DO NOT use this code in production. This exists only for DAST pipeline testing.
 * ─────────────────────────────────────────────────────────────
 */

#include <iostream>
#include <cstring>

#define HEAP_BUFFER_SIZE 32   // Fixed-size heap buffer — the vulnerable constant

void process_heap_data(const char* user_data) {
    // VULNERABILITY: Fixed 32-byte allocation. Any input > 31 chars WILL overflow.
    char* heap_buffer = new char[HEAP_BUFFER_SIZE];

    std::cout << "[INFO] Allocated " << HEAP_BUFFER_SIZE
              << " bytes on Heap at: " << static_cast<void*>(heap_buffer) << std::endl;

    // UNSAFE: strcpy performs NO bounds check — classic CWE-122 trigger
    strcpy(heap_buffer, user_data);

    std::cout << "[INFO] Successfully processed heap data: " << heap_buffer << std::endl;

    delete[] heap_buffer;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        // Input from command-line argument (argv[1])
        process_heap_data(argv[1]);
    } else {
        // Input from stdin (for pipeline stdin-based delivery)
        std::string input;
        if (std::getline(std::cin, input)) {
            process_heap_data(input.c_str());
        }
    }
    return 0;
}

