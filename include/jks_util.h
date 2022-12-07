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
std::vector<uint8_t> create_jks_digest(std::span<uint8_t> data,
				       const std::u16string &password);

std::u16string read_utf(std::istream &);
void write_utf(std::ostream &os, const std::u16string &data);

}
}