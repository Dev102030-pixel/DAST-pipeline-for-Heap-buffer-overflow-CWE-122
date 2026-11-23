#include <iostream>
#include <string>
#include <memory>

// Secure Function: Prevents Heap Buffer Overflow
void process_heap_data_secure() {
    std::string user_input;

    std::cout << "Enter input for heap processing: ";
    if (std::getline(std::cin, user_input)) {
        constexpr size_t MAX_CAPACITY = 32;

        // Remediation 1: Enforce strict bounds check before any heap operation
        if (user_input.length() >= MAX_CAPACITY) {
            std::cerr << "[ERROR] Input length (" << user_input.length() 
                      << ") exceeds maximum allowed heap capacity (" << (MAX_CAPACITY - 1) 
                      << " chars + null terminator). Operation rejected.\n";
            return;
        }

        // Remediation 2: Use smart pointer to manage heap memory safely (prevents memory leaks)
        auto safe_heap_buffer = std::make_unique<char[]>(MAX_CAPACITY);

        // Copy bounded data safely (snprintf ensures null termination and no overflow)
        snprintf(safe_heap_buffer.get(), MAX_CAPACITY, "%s", user_input.c_str());

        std::cout << "[INFO] Safely stored in heap buffer: " << safe_heap_buffer.get() << std::endl;
        // Memory is automatically released when safe_heap_buffer goes out of scope (RAII)
    }
}

int main() {
    process_heap_data_secure();
    return 0;
}
