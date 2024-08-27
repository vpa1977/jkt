#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace jks
{
namespace util
{

std::vector<uint8_t> ReadDER(const std::string &file);

}
}
