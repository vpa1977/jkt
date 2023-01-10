#include "jks.h"
#include "x509.h"
#include <fstream>
#include <gtest/gtest.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace jks::util;
using namespace jks;

TEST(jks_cert_data, store_contains_der)
{
	// GIVEN a JKS store with a single certificate is loaded
	JKSStore store(u"123123");
	std::ifstream storeStream("test/files/singlecert",
				  std::ios::in | std::ios::binary);
	storeStream >> store;

	// WHEN data of the raw certificate is queried
	auto data = store.GetTrustedCertificate(u"globaltrust 2020");
	X509 *pCert = X509_new();
	const auto *start = data.data();
	// THEN the data is in DER format
	auto *ret = d2i_X509(&pCert, &start, data.size());
	ASSERT_NE(nullptr, ret);
	// AND the subject name matches the expected one
	std::string subj =
		X509_NAME_oneline(X509_get_subject_name(ret), NULL, 0);
	ASSERT_EQ("/C=AT/O=e-commerce monitoring GmbH/CN=GLOBALTRUST 2020",
		  subj);
	X509_free(pCert);
}

TEST(jks_cert_data, pem_file_can_be_read)
{
	// WHEN der is read from the PEM file
	auto data = ReadDER("test/files/globaltrust.pem");
	// THEN a valid certificate is read
	X509 *pCert = X509_new();
	const auto *start = data.data();
	// THEN the data is in DER format
	auto *ret = d2i_X509(&pCert, &start, data.size());
	ASSERT_NE(nullptr, ret);
	// AND the subject name matches the expected one
	std::string subj =
		X509_NAME_oneline(X509_get_subject_name(ret), NULL, 0);
	ASSERT_EQ("/C=AT/O=e-commerce monitoring GmbH/CN=GLOBALTRUST 2020",
		  subj);
	X509_free(pCert);
}

TEST(jks_cert_data, certificate_can_be_imported)
{
	// GIVEN a trust store is loaded
	JKSStore store(u"123123");
	{
		std::ifstream storeStream("test/files/singlecert",
					  std::ios::in | std::ios::binary);
		storeStream >> store;
	}
	// WHEN certificate is imported
	auto data = ReadDER("test/files/globaltrust.pem");
	store.EmplaceTrustedCertificate(u"newcertificate", data);
	// AND store is saved
	{
		std::ofstream output("test/files/newstore",
				     std::ios::out | std::ios::binary);

		output << store;
	}
	// THEN a new store contains imported certificate
	JKSStore newStore(u"123123");
	{
		std::ifstream storeStream("test/files/newstore",
					  std::ios::in | std::ios::binary);
		storeStream >> newStore;
	}
	auto newCertData = newStore.GetTrustedCertificate(u"newcertificate");
	ASSERT_EQ(data, newCertData);
}