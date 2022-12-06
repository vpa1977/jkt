#include "jks.h"

#include <iostream>
#include <vector>
#include <span>

#include <byteswap.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

constexpr uint32_t MAGIC = 0xfeedfeed;
constexpr uint32_t VERSION1 = 0x01;
constexpr uint32_t VERSION2 = 0x02;
//constexpr auto PASSWORD_SALT =                       "M    i    g   h     t    y       A    p    h    r    o    d    i    t    e";
constexpr std::initializer_list<uint8_t> PASSWORD_SALT{ 77,  105, 103, 104,
							116, 121, 32,  65,
							112, 104, 114, 111,
							100, 105, 116, 101 };

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

std::wstring readUtf(FILE *fp)
{
	uint16_t utfLen{};
	fread(&utfLen, sizeof(utfLen), 1, fp);
	utfLen = bswap_16(utfLen);
	std::vector<uint8_t> byteArr(utfLen);
	std::wstring charArr;
	charArr.resize(utfLen);

	int c, char2, char3;
	int count = 0;
	int chararr_count = 0;

	fread(byteArr.data(), byteArr.size(), 1, fp);
	while (count < utfLen) {
		c = (int)byteArr[count] & 0xff;
		if (c > 127)
			break;
		count++;
		charArr[chararr_count++] = (char)c;
	}

	while (count < utfLen) {
		c = (int)byteArr[count] & 0xff;
		switch (c >> 4) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7: {
			/* 0xxxxxxx*/
			count++;
			charArr[chararr_count++] = (char)c;
		} break;

		case 12:
		case 13: {
			/* 110x xxxx   10xx xxxx*/
			count += 2;
			if (count > utfLen)
				throw std::runtime_error(
					"malformed input: partial character at end");
			char2 = byteArr[count - 1];
			if ((char2 & 0xC0) != 0x80)
				throw std::runtime_error(
					"malformed input around byte ");
			charArr[chararr_count++] =
				(char)(((c & 0x1F) << 6) | (char2 & 0x3F));
		} break;
		case 14: {
			/* 1110 xxxx  10xx xxxx  10xx xxxx */
			count += 3;
			if (count > utfLen)
				std::runtime_error(
					"malformed input: partial character at end");
			char2 = byteArr[count - 2];
			char3 = byteArr[count - 1];
			if (((char2 & 0xC0) != 0x80) ||
			    ((char3 & 0xC0) != 0x80))
				throw std::runtime_error(
					"malformed input around byte ");
			charArr[chararr_count++] =
				(char)(((c & 0x0F) << 12) |
				       ((char2 & 0x3F) << 6) |
				       ((char3 & 0x3F) << 0));
		} break;
		default:
			/* 10xx xxxx,  1111 xxxx */
			throw std::runtime_error(
				"malformed input around byte " + count);
		}
	}
	// The number of chars produced may be less than utfLen
	return charArr;
}

template <typename T> T read(FILE *fp)
{
	T buf;
	fread(&buf, sizeof(T), 1, fp);
	if constexpr (sizeof(T) == 2)
		return bswap_16(buf);
	else if constexpr (sizeof(T) == 4)
		return bswap_32(buf);
	else if constexpr (sizeof(T) == 8)
		return bswap_64(buf);
	else
		static_assert(sizeof(T) == 0,
			      "Unsupported template parameter size");
}

void parse_kv_pair(FILE *fp, int version)
{
	auto alias = readUtf(fp);

	// timestamp is in milliseconds
	auto timestamp = read<uint64_t>(fp);

	std::wcout << alias << std::endl;
	std::wcout << timestamp << std::endl;

	auto privateKeyLen = read<uint32_t>(fp);
	std::cout << "Private key len is " << privateKeyLen << std::endl;
	std::vector<uint8_t> privateKey(privateKeyLen);
	fread(privateKey.data(), sizeof(uint8_t), privateKey.size(), fp);

	uint32_t nCertificates = read<uint32_t>(fp);
	std::cout << "I have " << nCertificates << std::endl;
	for (auto i = 0; i < nCertificates; ++i) {
		if (version == 2) {
			auto certType = readUtf(fp);
			std::wcout << "The cert type is " << certType
				   << std::endl;
		}

		auto certLen = read<uint32_t>(fp);
		std::vector<uint8_t> cert(certLen);
		fread(cert.data(), sizeof(uint8_t), cert.size(), fp);
	}
}

void parse_cert_entry(FILE *fp, uint32_t version)
{
	auto alias = readUtf(fp);
	auto timestamp = read<uint64_t>(fp);
	if (version == 2) {
		auto certType = readUtf(fp);
		std::wcout << "The cert type is " << certType << std::endl;
	}
	auto certLen = read<uint32_t>(fp);
	std::vector<uint8_t> cert(certLen);
	fread(cert.data(), sizeof(uint8_t), cert.size(), fp);
}

std::vector<uint8_t> convertToBytes(const char *password)
{
	int i, j;
	std::vector<uint8_t> passwdBytes(strlen(password) * 2);
	for (i = 0, j = 0; j < passwdBytes.size(); i++) {
		passwdBytes[j++] = password[i] >> 8;
		passwdBytes[j++] = password[i];
	}
	return passwdBytes;
}

void read_digest(FILE *fp, size_t offset, const char *password)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	if (!EVP_DigestInit(ctx, EVP_sha1())) {
		std::cout << "Unable to init digest!!!";
	}

	if (password) {
		auto passwordBytes = convertToBytes(password);
		EVP_DigestUpdate(ctx, passwordBytes.data(),
				 passwordBytes.size());
		EVP_DigestUpdate(ctx, std::data(PASSWORD_SALT),
				 PASSWORD_SALT.size());
	}

	std::vector<uint8_t> toDigest(offset);
	fseek(fp, 0, SEEK_SET);
	fread(toDigest.data(), sizeof(uint8_t), toDigest.size(), fp);

	EVP_DigestUpdate(ctx, toDigest.data(), toDigest.size());

	EVP_DigestFinal(ctx, md_value, &md_len);

	EVP_MD_CTX_free(ctx);

	std::vector<uint8_t> storedDigest(md_len);
	fread(storedDigest.data(), sizeof(uint8_t), md_len, fp);

	if (memcmp(storedDigest.data(), md_value, md_len)) {
		std::cout << "store was tampered" << std::endl;
	} else {
		std::cout << "perfectly good store" << std::endl;
	}
}

void read_jks(const char *storeLocation, const char *password)
{
	FILE *fp = fopen(storeLocation, "rb");
	uint32_t magic = read<uint32_t>(fp);

	if (magic != MAGIC) {
		std::cout << "Cannot read the magic " << magic << std::endl;
		return;
	}
	uint32_t version = read<uint32_t>(fp);

	std::cout << "Store version is " << version << std::endl;

	uint32_t entries = read<uint32_t>(fp);
	std::cout << "Store entries is " << entries << std::endl;

	for (int entry = 0; entry < entries; ++entry) {
		uint32_t tag = read<uint32_t>(fp);
		switch (tag) {
		case 1:
			parse_kv_pair(fp, version);
			break;
		case 2:
			parse_cert_entry(fp, version);
			break;
		default:
			std::cout << "Bad tag" << std::endl;
			goto exit;
		}
	}

	read_digest(fp, ftell(fp), password);
//
//ended by a keyed SHA1 hash (bytes only) of
// { password + extra data + preceding body }
exit:
	fclose(fp);
}