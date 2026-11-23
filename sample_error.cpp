#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

// Class structure for heap boundary and vtable layout testing
class UserSession {
public:
  char role[16];
  virtual void display_access_level() {
    std::cout << "[+] Access Level: Standard User" << std::endl;
  }
  virtual ~UserSession() = default;
};

// Target input processor containing vulnerable memory routines
void process_input_vulnerable(const char *user_data) {
  if (!user_data)
    return;

  size_t input_len = std::strlen(user_data);
  std::cout << "[+] Received input byte length: " << input_len << std::endl;

  // 1. Heap Allocation (Fixed 32-Byte Allocation)
  char *heap_buffer = new char[32];
  std::memset(heap_buffer, 0, 32);

  std::cout << "[+] Heap buffer allocated at: " << (void *)heap_buffer
            << std::endl;

  // VULNERABILITY 1: Unbounded string copy (CWE-122 / CWE-787)
  // Inputs > 31 bytes force strcpy to write past the 32-byte boundary,
  // overwriting adjacent heap chunk headers and triggering ASan.
  strcpy(heap_buffer, user_data);

  // VULNERABILITY 2: Format String Flaw (CWE-134)
  // Passing unvalidated heap memory directly to printf
  if (input_len < 32) {
    std::printf(heap_buffer);
    std::printf("\n");
  }

  std::cout << "[+] Output: " << heap_buffer << std::endl;

  // Clean up allocated buffer
  delete[] heap_buffer;
}

// Adjacent heap allocation test function
void process_adjacent_heap(const char *user_data) {
  // Sequential heap allocations
  char *buffer = new char[16];
  UserSession *session = new UserSession();

  // VULNERABILITY 3: Adjacent object corruption (CWE-822)
  // Writing past the 16-byte buffer spills into the session object,
  // corrupting its virtual method table (vtable) pointer.
  strcpy(buffer, user_data);

  session->display_access_level();

  delete session;
  delete[] buffer;
}

// Mandatory entry point for Clang++ linker (ARM64 macOS compatibility)
int main(int argc, char *argv[]) {
  std::string input;
  const char *payload = nullptr;

  if (argc > 1) {
    // Input provided via command-line argument
    payload = argv[1];
  } else if (std::getline(std::cin, input)) {
    // Input provided via standard input (stdin)
    payload = input.c_str();
  }

  if (payload) {
    // 1. Fixed 32-byte heap buffer & format string routine
    process_input_vulnerable(payload);

    // 2. Adjacent heap allocation & vtable dispatch routine (16-byte buffer)
    process_adjacent_heap(payload);
  } else {
    std::cout << "Usage: " << argv[0] << " <input_payload>" << std::endl;
  }
  return 0;
}