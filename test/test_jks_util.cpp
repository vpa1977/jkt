#include <string>
#include <locale>
#include <codecvt>

#include "gtest/gtest.h"

#include "jks_util.h"

using namespace jks::util;

TEST(jks_util, jks_digest)
{
	std::vector<uint8_t> data = { 1, 2, 3, 4, 5, 6, 7 };
	std::wstring_convert<std::codecvt_utf16<char16_t>, char16_t> utf16conv;
	auto digest = create_jks_digest(
		data, utf16conv.from_bytes("password").data());
	std::vector<uint8_t> expected{ 187, 64,	 134, 109, 230, 125, 253,
				       129, 166, 147, 151, 207, 232, 236,
				       62,  87,	 95,  161, 179, 91 };
	ASSERT_EQ(expected, digest);
}