#include <codecvt>
#include <locale>
#include <string>

#include "gtest/gtest.h"

#include "jks_util.h"

using namespace jks::util;

TEST(jks_util, jks_digest)
{
	std::vector<uint8_t> data = { 1, 2, 3, 4, 5, 6, 7 };
	auto digest = create_jks_digest(data, u"password");
	std::vector<uint8_t> expected{ 206, 57,	 245, 184, 174, 197, 65,
				       35,  147, 191, 231, 130, 238, 77,
				       221, 201, 119, 6,   144, 168 };
}

TEST(jks_util, read_write_utf_ascii)
{
	auto str = u"123";
	auto ret = convert_utf(str);
	auto converted = read_utf(ret);
	ASSERT_EQ(str, converted);
}

TEST(jks_util, read_write_utf)
{
	// using chineese to test unicode conversion
	auto str = u"這是一個中文短語";
	auto ret = convert_utf(str);
	auto converted = read_utf(ret);
	ASSERT_EQ(str, converted);
}