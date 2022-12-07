#pragma once

#include <string>
#include <vector>

namespace jks
{
namespace util
{

std::vector<uint8_t> ReadDER(const std::string &file);

}
}