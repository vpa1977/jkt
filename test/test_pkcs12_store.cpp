#include "gtest/gtest.h"

#include "pkcs12.h"

TEST(PKCS12_store, replace_alias)
{
	// GIVEN a store with 3 certificates
	// AND alias "afriendlybag" exits
	// WHEN "afriendlybag" alias is removed
	ASSERT_TRUE(PKCS12Store::Replace("test/files/pfxstore", "123123",
					 "afriendlybag", "",
					 "test/files/pfxstore.new"));
	// THEN "afriendlybag" certificate is no longer found
	ASSERT_FALSE(PKCS12Store::Replace("test/files/pfxstore.new", "123123",
					  "afriendlybag", "",
					  "test/files/pfxstore.new"));
}

TEST(PKCS12_store, add_alias)
{
	// GIVEN a store with 3 certificates
	// WHEN a new certificate is added
	ASSERT_TRUE(PKCS12Store::Replace(
		"test/files/pfxstore", "123123", "add_new_cert",
		"test/files/globaltrust.pem", "test/files/pfxstore.new"));
	// THEN "afriendlybag" certificate is no longer found
	ASSERT_TRUE(PKCS12Store::Replace("test/files/pfxstore.new", "123123",
					 "add_new_cert", "",
					 "test/files/pfxstore.new"));
}

TEST(PKCS12_store, empty_store)
{
	// GIVEN a store with 1 certificate
	// WHEN last certificate is removed
	ASSERT_TRUE(PKCS12Store::Replace("test/files/singlepfx", "123123",
					 "afriendlybag", "",
					 "test/files/pfxstore.new"));
	// THEN "afriendlybag" certificate can be added
	ASSERT_TRUE(PKCS12Store::Replace(
		"test/files/pfxstore.new", "123123", "afriendlybag",
		"test/files/globaltrust.pem", "test/files/pfxstore.new"));
}
