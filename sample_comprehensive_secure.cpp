/*
 * sample_comprehensive_secure.cpp
 * ============================================================================
 * Hardened C++ Implementation: Fully Defended Against All Vulnerability Classes
 * ============================================================================
 * Defends against:
 *   1. Heap Buffer Overflow (CWE-122) -> RAII std::make_unique & dynamic sizing
 *   2. Stack Buffer Overflow (CWE-121) -> Safe std::string & bounds validation
 *   3. Format String Flaw (CWE-134)   -> Standard type-safe streams (std::cout)
 *   4. Use-After-Free & Double-Free   -> std::unique_ptr with strict reset()
 *   5. Integer Overflow (CWE-190)     -> Pre-computation range checking
 *   6. Division By Zero (CWE-369)     -> Explicit denominator validation
 *   7. NULL Pointer Deref (CWE-476)   -> Strict null checking prior to access
 *   8. Out-of-Bounds Index (CWE-129)  -> Bounds-checked std::array::at()
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <string_view>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <array>
#include <limits>

struct SessionData {
    std::string username;
    int access_token = 0;
};
static std::unique_ptr<SessionData> g_session = nullptr;

// 1. Defended Stack Processing: Enforces strict length limits (CWE-121 fix)
void test_stack_overflow_secure(std::string_view input) {
    if (input.rfind("STACK:", 0) == 0) {
        std::string_view content = input.substr(6);
        // Truncate safely or process via dynamic string
        std::string safe_stack_buf(content.substr(0, 63));
        std::cout << "[SECURE STACK] Processed " << safe_stack_buf.size() << " bytes\n";
    }
}

// 2. Defended Output: Eliminates format string vulnerabilities (CWE-134 fix)
void test_format_string_secure(std::string_view input) {
    // Type-safe stream output guarantees user data is never parsed as a format specifier
    std::cout << "[SECURE PRINT] " << input << "\n";
}

// 3. Defended Integer & Arithmetic: Checked arithmetic prevents wrap & div-zero (CWE-190/369 fix)
void test_integer_and_arithmetic_secure(const std::string& input) {
    char* endptr = nullptr;
    errno = 0;
    long long val = std::strtoll(input.c_str(), &endptr, 10);
    if (endptr != input.c_str() && (*endptr == '\0' || *endptr == '\n') && errno == 0) {
        // Prevent Divide by Zero
        if (val == 0) {
            std::cout << "[SECURE MATH] Ignored division by zero trigger.\n";
            return;
        }

        // Prevent Integer Overflow
        constexpr int max_int = std::numeric_limits<int>::max();
        if (val > 0 && val < max_int) {
            int a = 100;
            int b = static_cast<int>(val);
            if (a <= max_int - b) {
                int sum = a + b;
                std::cout << "[SECURE MATH] Safe addition result: " << sum << "\n";
            }
        }
    }
}

// 4. Defended Lifecycle: RAII Smart Pointers eliminate UAF and Double-Free (CWE-416/415 fix)
void test_lifecycle_secure(std::string_view input) {
    if (input == "FREE") {
        g_session.reset(); // Safely destroys session and sets pointer to nullptr
        std::cout << "[SECURE LIFECYCLE] Session safely freed.\n";
    } else if (input == "READ" || input == "ACCESS") {
        if (g_session != nullptr) {
            std::cout << "[SECURE LIFECYCLE] Token: " << g_session->access_token << "\n";
        } else {
            std::cout << "[SECURE LIFECYCLE] Session inactive, access safely denied.\n";
        }
    } else if (input == "DOUBLE_FREE") {
        g_session.reset();
        g_session.reset(); // Safe no-op on nullptr
        std::cout << "[SECURE LIFECYCLE] Double-free prevented.\n";
    }
}

// 5. Defended Pointer Access: Explicit null verification (CWE-476 fix)
void test_null_pointer_secure(std::string_view input) {
    if (input == "NULL" || input == "nullptr") {
        int* null_ptr = nullptr;
        if (null_ptr != nullptr) {
            std::cout << *null_ptr << "\n";
        } else {
            std::cout << "[SECURE POINTER] Null pointer check succeeded.\n";
        }
    }
}

// 6. Defended Array Indexing: Bounds verification prevents out-of-bounds access (CWE-129 fix)
void test_oob_array_index_secure(std::string_view input) {
    if (input.rfind("INDEX:", 0) == 0) {
        std::array<int, 10> safe_array = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        try {
            int idx = std::stoi(std::string(input.substr(6)));
            if (idx >= 0 && idx < static_cast<int>(safe_array.size())) {
                std::cout << "[SECURE ARRAY] Element: " << safe_array.at(idx) << "\n";
            } else {
                std::cout << "[SECURE ARRAY] Index out of bounds rejected.\n";
            }
        } catch (...) {
            std::cout << "[SECURE ARRAY] Invalid index format rejected.\n";
        }
    }
}

// 7. Defended Heap Allocation: Dynamic sizing & RAII prevent Heap Buffer Overflows (CWE-122 fix)
void test_heap_buffer_overflow_secure(const char* input) {
    if (!input) return;
    size_t input_len = std::strlen(input);

    // Dynamically allocate exact required memory (input_len + 1 for null terminator)
    auto safe_buffer = std::make_unique<char[]>(input_len + 1);
    std::memcpy(safe_buffer.get(), input, input_len);
    safe_buffer[input_len] = '\0';

    std::cout << "[SECURE HEAP] Allocated " << (input_len + 1) << " bytes safely.\n";
}

int main(int argc, char* argv[]) {
    std::string input;
    const char* payload = nullptr;

    if (argc > 1) {
        payload = argv[1];
    } else if (std::getline(std::cin, input)) {
        payload = input.c_str();
    }

    if (!payload) {
        std::cout << "Usage: " << argv[0] << " <payload>\n";
        return 0;
    }

    // Clean whitespace
    std::string clean_str = payload;
    while (!clean_str.empty() && (clean_str.back() == '\n' || clean_str.back() == '\r')) {
        clean_str.pop_back();
    }

    // Run all hardened routines
    test_null_pointer_secure(clean_str);
    test_integer_and_arithmetic_secure(clean_str);
    test_oob_array_index_secure(clean_str);
    test_lifecycle_secure(clean_str);
    test_stack_overflow_secure(clean_str);
    test_format_string_secure(clean_str);
    test_heap_buffer_overflow_secure(clean_str.c_str());

    return 0;
}

