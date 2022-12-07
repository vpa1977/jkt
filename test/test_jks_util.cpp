#include <string>
#include <locale>
#include <codecvt>

#include "gtest/gtest.h"

#include "jks_util.h"

using namespace jks::util;

TEST(jks_util, jks_digest)
{
	std::vector<uint8_t> data = { 1, 2, 3, 4, 5, 6, 7 };
	// Linux formatter does not like u"" literals. Since it is a test,
	// just converting from a normal string
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		utf16conv;
	auto digest = create_jks_digest(
		data, utf16conv.from_bytes("password").data());
	std::vector<uint8_t> expected{ 206, 57,	 245, 184, 174, 197, 65,
				       35,  147, 191, 231, 130, 238, 77,
				       221, 201, 119, 6,   144, 168 };
}

TEST(jks_util, read_write_utf_ascii)
{
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		utf16conv;
	auto str = utf16conv.from_bytes("123");
	auto ret = write_utf(str);
	auto converted = read_utf(ret);
	ASSERT_EQ(str, converted);
}

TEST(jks_util, read_write_utf)
{
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		utf16conv;
	// using chineese to test unicode conversion
	auto str = utf16conv.from_bytes("這是一個中文短語");
	auto ret = write_utf(str);
	auto converted = read_utf(ret);
	ASSERT_EQ(str, converted);
}