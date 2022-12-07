#pragma once
#include <concepts>
#include <span>
#include <vector>
#include <string>

namespace jks
{
namespace util
{
// password and digest functions
std::vector<uint8_t> create_jks_digest(std::span<uint8_t> data,
				       const char16_t *password);

std::vector<uint8_t> convert_to_bytes(const char16_t *data);

// read/write utilities for aliases
std::u16string read_utf(std::span<uint8_t> data);
std::vector<uint8_t> write_utf(std::u16string &data);

}
}