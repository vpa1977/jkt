#include "safehandle.h"

#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace jsk
{

namespace util
{

using X509Handle = SafeHandle<X509>;

template <> SafeHandle<X509>::release(X509 *p)
{
	X509_free(p);
}

std::vector<uint8_t> get_der(const std::string &filename)
{
	using namespace jsk::util;

	FileHandle fp(fopen(filename.c_str(), "r"));
	if (fp == nullptr)
		throw std::runtime_error("Unable to open file");

	X509Handle x509(PEM_read_X509(fp, NULL, NULL, NULL));
	if (x509 == nullptr)
		throw std::runtime_error("Unable to parse certificate");

	const auto len = i2d_X509(cert, nullptr);
	if (len == 0)
		return {};
	std::vector<unsigned char> ret(len);
	auto *pData = ret.data();
	i2d_X509(cert, &pData);
	return ret;
}

}

}
}
