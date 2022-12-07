#include <codecvt>
#include <locale>
#include <string>

#include "gtest/gtest.h"

#include "jks_util.h"

using namespace jks::util;

namespace jks
{
namespace util
{
std::vector<uint8_t> convert_utf(const std::u16string &data);
std::vector<uint8_t> convert_to_bytes(const char16_t *data);
std::u16string ReadUTF(std::span<uint8_t> byteArr);
}
}

TEST(jks_util, jks_digest)
{
	// GIVEN an arbitrary bytestring
	std::vector<uint8_t> data = { 1, 2, 3, 4, 5, 6, 7 };
	// WHEN a JKS digest is created
	auto digest = JKSCreateDigest(data, u"password");
	// THEN an arbitrary bytestring is produced
	std::vector<uint8_t> expected{ 206, 57,	 245, 184, 174, 197, 65,
				       35,  147, 191, 231, 130, 238, 77,
				       221, 201, 119, 6,   144, 168 };
}

TEST(jks_util, read_WriteUTF_ascii)
{
	// GIVEN an arbitrary U16 string with ASCII symbols
	auto str = u"123";
	// WHEN string is converted to bytes
	auto ret = convert_utf(str);
	// AND back
	auto converted = ReadUTF(ret);
	// THEN string matches the original
	ASSERT_EQ(str, converted);
}

TEST(jks_util, read_WriteUTF)
{
	// GIVEN an arbitrary U16 string with 3 byte symbols
	auto str = u"這是一個中文短語";
	// WHEN string is converted to bytes
	auto ret = convert_utf(str);
	// AND back
	auto converted = ReadUTF(ret);
	// THEN string matches the original
	ASSERT_EQ(str, converted);
}