#include <iostream>
#include <string>
#include <cstring>

// Target Function: Allocates memory on the heap and performs an unconstrained copy
void process_heap_data() {
    std::string user_input;

    std::cout << "Enter input for heap processing: ";
    if (std::getline(std::cin, user_input)) {
        // Allocate a fixed 32-byte buffer in dynamic memory (the Heap)
        constexpr size_t ALLOCATED_SIZE = 32;
        char* heap_buffer = new char[ALLOCATED_SIZE];

        std::cout << "[INFO] Allocated " << ALLOCATED_SIZE << " bytes on Heap at: " 
                  << static_cast<void*>(heap_buffer) << std::endl;

        // Vulnerability: Heap-based Buffer Overflow (CWE-122 / CWE-787)
        // 'strcpy' does not verify that user_input fits within ALLOCATED_SIZE.
        // If user_input exceeds 31 characters, it writes out-of-bounds into adjacent heap memory.
        strcpy(heap_buffer, user_input.c_str());

        std::cout << "[INFO] Successfully processed heap data: " << heap_buffer << std::endl;

        // Clean up heap allocation
        delete[] heap_buffer;
    }
}

int main() {
    process_heap_data();
    return 0;
}
