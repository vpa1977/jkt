#include "jks.h"

#include "jks_util.h"

#include <iostream>
#include <vector>
#include <span>

#include <byteswap.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

constexpr uint32_t VERSION1 = 0x01;
constexpr uint32_t VERSION2 = 0x02;

/*
* KEYSTORE FORMAT:
*
* Magic number (big-endian integer),
* Version of this file format (big-endian integer),
*
* Count (big-endian integer),
* followed by "count" instances of either:
*
*     {
*      tag=1 (big-endian integer),
*      alias (UTF string)
*      timestamp
*      encrypted private-key info according to PKCS #8
*          (integer length followed by encoding)
*      cert chain (integer count, then certs; for each cert,
*          integer length followed by encoding)
*     }
*
* or:
*
*     {
*      tag=2 (big-endian integer)
*      alias (UTF string)
*      timestamp
*      cert (integer length followed by encoding)
*     }
*
* ended by a keyed SHA1 hash (bytes only) of
*     { password + extra data + preceding body }
*/
namespace
{
template <typename T> T read(std::istream &is)
{
	T buf;
	is >> buf;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if constexpr (sizeof(T) == 2)
		return bswap_16(buf);
	else if constexpr (sizeof(T) == 4)
		return bswap_32(buf);
	else if constexpr (sizeof(T) == 8)
		return bswap_64(buf);
	else
		static_assert(sizeof(T) == 0,
			      "Unsupported template parameter size");
#else
	return buf;
#endif
}

}

namespace jks
{

void JKSStore::TrustedCertificate::Read(std::istream &is, uint32_t version)
{
	m_alias = util::read_utf(is);

	// timestamp is in milliseconds
	m_timestampMs = read<uint64_t>(is);
	if (version == 2) {
		m_certificate.m_type = util::read_utf(is);
	}
	auto certLen = read<uint32_t>(is);
	m_certificate.m_data.resize(certLen);
	is.read(reinterpret_cast<char *>(m_certificate.m_data.data()),
		m_certificate.m_data.size());
}

void JKSStore::KeyEntry::Read(std::istream &is, uint32_t version)
{
	m_alias = util::read_utf(is);

	// timestamp is in milliseconds
	m_timestampMs = read<uint64_t>(is);

	auto privateKeyLen = read<uint32_t>(is);
	m_encryptedKey.resize(privateKeyLen);
	is.read(reinterpret_cast<char *>(m_encryptedKey.data()),
		m_encryptedKey.size());
	m_certificateChain.clear();
	uint32_t nCertificates = read<uint32_t>(is);
	for (auto i = 0; i < nCertificates; ++i) {
		Certificate cert;
		if (version == 2) {
			cert.m_type = util::read_utf(is);
		}
		auto certLen = read<uint32_t>(is);
		cert.m_data.resize(certLen);
		is.read(reinterpret_cast<char *>(cert.m_data.data()),
			cert.m_data.size());
		m_certificateChain.emplace_back(cert);
	}
}

std::istream &operator>>(std::istream &is, JKSStore &store)
{
	uint32_t magic = read<uint32_t>(is);

	if (magic != jks::MAGIC) {
		throw std::runtime_error("Not a JKS store");
	}
	uint32_t version = read<uint32_t>(is);
	store.m_version = version;

	uint32_t entries = read<uint32_t>(is);

	for (int entry = 0; entry < entries; ++entry) {
		uint32_t tag = read<uint32_t>(is);
		switch (tag) {
		case 1: {
			JKSStore::KeyEntry keyEntry;
			keyEntry.Read(is, version);
			store.m_keys.emplace(keyEntry.m_alias, keyEntry);
		} break;
		case 2: {
			JKSStore::TrustedCertificate tc;
			tc.Read(is, version);
			store.m_certificates.emplace(tc.m_alias, tc);
		} break;
		default:
			throw std::runtime_error("Unexpected tag");
		}
	}

	// re-read stream to compute digest
	// not efficient, but easier than implementing digesting stream
	auto pos = is.tellg();
	is.seekg(0, is.beg);
	std::vector<uint8_t> toDigest(pos);

	// not checking return value, as failure to obtain correct digest
	// will result in runtime exception
	is.read(reinterpret_cast<char *>(toDigest.data()), toDigest.size());

	auto digest =
		util::create_jks_digest(toDigest, store.m_password.data());
	std::vector<uint8_t> expected(digest.size());
	is.read(reinterpret_cast<char *>(expected.data()), expected.size());

	if (expected != digest)
		throw std::runtime_error("digest mismatch");
	return is;
}

std::ostream &operator<<(std::ostream &os, const JKSStore &store)
{
	return os;
}

}

// release X509 structure with X509_free()
X509 *read_certificate(const char *pem)
{
	X509 *ret = NULL;
	FILE *fp = fopen(pem, "r");
	if (!fp)
		return ret;

	ret = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	return ret;
}

X509 *read_certificate_from_data(std::span<unsigned char> data)
{
	const auto *pStart = data.data();
	return d2i_X509(NULL, &pStart, data.size());
}

std::vector<uint8_t> get_der(X509 *cert)
{
	const auto len = i2d_X509(cert, nullptr);
	if (len == 0)
		return {};
	std::vector<unsigned char> ret(len);
	auto *pData = ret.data();
	i2d_X509(cert, &pData);
	return ret;
}
