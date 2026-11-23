#include <cstring>
#include <iostream>
#include <memory>
#include <string>

// Secure Heap Processing: Dynamically calculates required memory,
// allocates using RAII smart pointers, and prevents all buffer overflows.
void process_heap_data_secure(const char *user_data) {
  if (!user_data) {
    return;
  }

  // Step 1: Calculate exact input length (handles 0B up to multi-KB payloads)
  size_t data_len = strlen(user_data);

  // Step 2: Dynamically allocate exact required bytes (data + 1 for
  // null-terminator) std::make_unique guarantees automatic deallocation when
  // leaving scope (RAII)
  auto safe_heap_buffer = std::make_unique<char[]>(data_len + 1);

  // Step 3: Bounds-checked memory copy
  memcpy(safe_heap_buffer.get(), user_data, data_len);
  safe_heap_buffer[data_len] = '\0'; // Guarantee null termination

  std::cout << "[INFO] Heap allocated safely: " << (data_len + 1)
            << " bytes at: " << static_cast<void *>(safe_heap_buffer.get())
            << std::endl;
  std::cout << "[INFO] Successfully processed heap data: "
            << safe_heap_buffer.get() << std::endl;
}

int main(int argc, char *argv[]) {
  // Universal input: Supports both CLI arguments (argv[1]) and standard input
  // (cin)
  if (argc > 1) {
    process_heap_data_secure(argv[1]);
  } else {
    std::string input;
    if (std::getline(std::cin, input)) {
      process_heap_data_secure(input.c_str());
    }
  }
  return 0;
}