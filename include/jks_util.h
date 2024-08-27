#pragma once
#include <cstdint>
#include <concepts>
#include <istream>
#include <span>
#include <string>
#include <vector>

namespace jks
{
namespace util
{
std::vector<uint8_t> JKSCreateDigest(std::span<uint8_t> data,
				     const std::u16string &password);

std::u16string ReadUTF(std::istream &);
void WriteUTF(std::ostream &os, const std::u16string &data);

}
}
