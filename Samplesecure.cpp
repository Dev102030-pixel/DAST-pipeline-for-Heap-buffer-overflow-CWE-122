#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

class SecureProcessor {
public:
  static void process_payload(std::string_view input) {
    // 1. Dynamic RAII allocation: automatically sizes to exact input length
    std::string safe_buffer(input);

    // 2. Safe format-string output: never pass user input as the format string
    std::cout << "[+] Processed byte length: " << safe_buffer.size() << '\n';

    // 3. Safe byte-level transformation using bounded std::vector
    std::vector<uint8_t> byte_copy(safe_buffer.begin(), safe_buffer.end());

    if (!byte_copy.empty()) {
      // Bounded read/write check on first and last bytes
      uint8_t first = byte_copy.front();
      uint8_t last = byte_copy.back();
      std::cout << "[+] Checksum preview: " << static_cast<int>(first ^ last)
                << '\n';
    }
    // Automatic cleanup via RAII destructors (zero memory leaks)
  }
};

int main(int argc, char *argv[]) {
  if (argc > 1) {
    SecureProcessor::process_payload(argv[1]);
  } else {
    // Fallback: read from stdin if no argv[1] is supplied
    std::string stdin_data((std::istreambuf_iterator<char>(std::cin)),
                           std::istreambuf_iterator<char>());
    if (!stdin_data.empty()) {
      SecureProcessor::process_payload(stdin_data);
    }
  }
  return 0;
}