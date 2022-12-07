#include "x509.h"
#include "safehandle.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>

namespace jks
{

namespace util
{

std::vector<uint8_t> ReadDER(const std::string &filename)
{
	FileHandle fp(fopen(filename.c_str(), "r"));
	if (fp == nullptr)
		throw std::runtime_error("Unable to open file");

	X509Handle x509(PEM_read_X509(fp, NULL, NULL, NULL));
	if (x509 == nullptr)
		throw std::runtime_error("Unable to parse certificate");

	const auto len = i2d_X509(x509, nullptr);
	if (len == 0)
		return {};
	std::vector<unsigned char> ret(len);
	auto *pData = ret.data();
	i2d_X509(x509, &pData);
	return ret;
}

}

}
