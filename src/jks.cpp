#include "jks.h"

#include "jks_util.h"

#include <chrono>
#include <iostream>
#include <span>
#include <sstream>
#include <vector>

#include <byteswap.h>

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
	is.read(reinterpret_cast<char *>(&buf), sizeof(T));
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

template <typename T> void write(std::ostream &os, const T buf)
{
	T ret;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if constexpr (sizeof(T) == 2)
		ret = bswap_16(buf);
	else if constexpr (sizeof(T) == 4)
		ret = bswap_32(buf);
	else if constexpr (sizeof(T) == 8)
		ret = bswap_64(buf);
	else
		static_assert(sizeof(T) == 0,
			      "Unsupported template parameter size");
#else
	ret = buf;
#endif
	os.write(reinterpret_cast<char *>(&ret), sizeof(T));
}

}

namespace jks
{

void JKSStore::TrustedCertificate::Read(std::istream &is, uint32_t version)
{
	m_alias = util::ReadUTF(is);

	// timestamp is in milliseconds
	m_timestampMs = read<uint64_t>(is);
	if (version == 2) {
		m_certificate.m_type = util::ReadUTF(is);
	}
	auto certLen = read<uint32_t>(is);
	m_certificate.m_data.resize(certLen);
	is.read(reinterpret_cast<char *>(m_certificate.m_data.data()),
		m_certificate.m_data.size());
}

void JKSStore::TrustedCertificate::Write(std::ostream &os,
					 uint32_t version) const
{
	util::WriteUTF(os, m_alias);
	write(os, m_timestampMs);

	// timestamp is in milliseconds
	if (version == 2) {
		util::WriteUTF(os, m_certificate.m_type);
	}
	write<uint32_t>(os, m_certificate.m_data.size());
	os.write(reinterpret_cast<const char *>(m_certificate.m_data.data()),
		 m_certificate.m_data.size());
}

void JKSStore::KeyEntry::Read(std::istream &is, uint32_t version)
{
	m_alias = util::ReadUTF(is);

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
			cert.m_type = util::ReadUTF(is);
		}
		auto certLen = read<uint32_t>(is);
		cert.m_data.resize(certLen);
		is.read(reinterpret_cast<char *>(cert.m_data.data()),
			cert.m_data.size());
		m_certificateChain.emplace_back(cert);
	}
}

void JKSStore::KeyEntry::Write(std::ostream &os, uint32_t version) const
{
	util::WriteUTF(os, m_alias);

	// timestamp is in milliseconds
	write(os, m_timestampMs);

	write<uint32_t>(os, m_encryptedKey.size());
	os.write(reinterpret_cast<const char *>(m_encryptedKey.data()),
		 m_encryptedKey.size());

	write<uint32_t>(os, m_certificateChain.size());
	for (const auto &cert : m_certificateChain) {
		if (version == 2) {
			util::WriteUTF(os, cert.m_type);
		}
		write<uint32_t>(os, cert.m_data.size());
		os.write(reinterpret_cast<const char *>(cert.m_data.data()),
			 cert.m_data.size());
	}
}

std::istream &operator>>(std::istream &is, JKSStore &store)
{
	uint32_t magic = read<uint32_t>(is);

	if (magic != jks::MAGIC) {
		throw NotJKSStore();
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

	auto digest = util::JKSCreateDigest(toDigest, store.m_password.data());
	std::vector<uint8_t> expected(digest.size());
	is.read(reinterpret_cast<char *>(expected.data()), expected.size());

	if (expected != digest)
		throw std::runtime_error("digest mismatch");
	return is;
}

std::ostream &operator<<(std::ostream &output, const JKSStore &store)
{
	std::ostringstream os;
	write(os, MAGIC);
	write(os, store.m_version);
	auto recordCount = store.m_keys.size() + store.m_certificates.size();
	write<uint32_t>(os, recordCount);

	for (const auto &[_, value] : store.m_keys) {
		write<uint32_t>(os, 1);
		value.Write(os, store.m_version);
	}

	for (const auto &[_, value] : store.m_certificates) {
		write<uint32_t>(os, 2);
		value.Write(os, store.m_version);
	}

	auto toDigest = os.str();
	uint8_t *digestStart = reinterpret_cast<uint8_t *>(toDigest.data());
	auto digest = util::JKSCreateDigest({ digestStart, toDigest.size() },
					    store.m_password);

	output.write(toDigest.data(), toDigest.size());
	output.write(reinterpret_cast<char *>(digest.data()), digest.size());

	return output;
}

void JKSStore::EmplaceTrustedCertificate(const std::u16string &alias,
					 std::vector<uint8_t> &data)
{
	using namespace std::chrono;
	milliseconds ms = duration_cast<milliseconds>(
		system_clock::now().time_since_epoch());
	TrustedCertificate cert{ alias,
				 static_cast<uint64_t>(ms.count()),
				 { DEFAULT_CERTIFICATE_TYPE, data } };
	m_certificates.emplace(alias, cert);
}

}
