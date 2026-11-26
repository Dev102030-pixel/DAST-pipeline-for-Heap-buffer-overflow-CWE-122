#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <string>

void process_vulnerable(const char *user_data) {
  if (!user_data)
    return;

  size_t len = std::strlen(user_data);

  // Fixed 32-byte heap allocation
  // Inputs <= 31 bytes fit safely; inputs >= 32 bytes overflow
  char *heap_buffer = new char[32];
  std::memset(heap_buffer, 0, 32);

  // VULNERABILITY 1 (CWE-122 / CWE-787): Unbounded copy into 32-byte heap chunk
  std::strcpy(heap_buffer, user_data);

  // VULNERABILITY 2 (CWE-134): Uncontrolled format string on short payloads
  if (len > 0 && len < 32) {
    std::printf(heap_buffer);
    std::printf("\n");
  }

  std::cout << "[+] Buffer processed (" << len << " bytes)\n";

  delete[] heap_buffer;
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    process_vulnerable(argv[1]);
  } else {
    // Supports stdin test vectors as well
    std::string stdin_data((std::istreambuf_iterator<char>(std::cin)),
                           std::istreambuf_iterator<char>());
    if (!stdin_data.empty()) {
      process_vulnerable(stdin_data.c_str());
    }
  }
  return 0;
}