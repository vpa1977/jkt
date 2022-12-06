#include "util.h"

#include <span>
#include <vector>
#include <string>

namespace jks{
    namespace util {
        // password and digest functions
        std::vector<uint8_t> create_digest(std::span<uint8_t> data, const char* password);
        std::vector<uint8_t> convert_to_bytes(const char* data);

        // read/write utilitities for aliases
        std::wstring read_utf(std::span<uint8_t> data);
        std::vector<uint8_t> write_utf(std::wstring& data);
    }
}

