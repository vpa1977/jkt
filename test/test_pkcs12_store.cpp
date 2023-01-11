#include "gtest/gtest.h"

#include "pkcs12.h"

TEST(PKCS12_store, replace_alias)
{
	std::string pass("123123");
	std::string store("test/files/pfxstore");

	PCKS12Store::Replace("test/files/pfxstore", "123123", "afriendlybag",
			     nullptr);
}