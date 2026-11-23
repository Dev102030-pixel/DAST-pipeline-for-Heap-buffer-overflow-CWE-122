#include <iostream>
#include <string>
#include <memory>
#include <cstring>

// Secure Function: Dynamically allocates the exact size needed on the heap
// using RAII smart pointers, preventing any heap buffer overflow or memory leak.
void process_input_secure(const char* user_data) {
    if (!user_data) {
        return;
    }

    // Step 1: Calculate the exact byte length needed
    size_t data_len = strlen(user_data);

    // Step 2: Dynamically allocate exact required bytes (data + 1 for null terminator)
    // std::make_unique ensures automatic cleanup when leaving scope (RAII)
    auto safe_heap_buffer = std::make_unique<char[]>(data_len + 1);

    // Step 3: Bounds-checked copy (never exceeds allocated boundary)
    memcpy(safe_heap_buffer.get(), user_data, data_len);
    safe_heap_buffer[data_len] = '\0'; // Guarantee null termination

    std::cout << "[+] Heap memory allocated safely: " << (data_len + 1) << " bytes at address: " 
              << static_cast<void*>(safe_heap_buffer.get()) << std::endl;
    std::cout << "[+] Successfully and safely copied: " << safe_heap_buffer.get() << std::endl;
}

int main(int argc, char* argv[]) {
    // Universal input: Supports both command-line arguments (argv[1]) and standard input (cin)
    if (argc > 1) {
        process_input_secure(argv[1]);
    } else {
        std::string input;
        if (std::getline(std::cin, input)) {
            process_input_secure(input.c_str());
        }
    }
    return 0;
}

