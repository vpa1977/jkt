#pragma once
#include <concepts>
#include <istream>
#include <span>
#include <string>
#include <vector>

namespace jks
{
namespace util
{
// password and digest functions
std::vector<uint8_t> create_jks_digest(std::span<uint8_t> data,
				       const std::u16string &password);

std::vector<uint8_t> convert_to_bytes(const char16_t *data);

// read/write utilities for aliases
std::u16string read_utf(std::istream &);
std::u16string read_utf(std::span<uint8_t> byteArr);

void write_utf(std::ostream &os, const std::u16string &data);
std::vector<uint8_t> convert_utf(const std::u16string &data);

}
}