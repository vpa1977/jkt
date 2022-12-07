#include "jks_util.h"

#include <stdexcept>

#include "safehandle.h"

#include "jks.h" // for JKS defines

namespace jks
{
namespace util
{

std::vector<uint8_t> convert_to_bytes(const char16_t *data)
{
	const auto size = std::char_traits<char16_t>::length(data);
	std::vector<uint8_t> passwdBytes(size * sizeof(char16_t));
	const uint8_t *pStart = reinterpret_cast<const uint8_t *>(data);
	std::copy(pStart, pStart + passwdBytes.size(), passwdBytes.begin());
	return passwdBytes;
}

std::vector<uint8_t> create_jks_digest(std::span<uint8_t> data,
				       const char16_t *password)
{
	std::string PASSWORD_SALT = "Mighty Aphrodite";

	EvpMdCtxHandle ctx(EVP_MD_CTX_new());

	if (!EVP_DigestInit(ctx, EVP_sha1()))
		throw std::runtime_error("Unable to init sha1 digest");

	if (password) {
		auto passwordBytes = convert_to_bytes(password);
		if (!EVP_DigestUpdate(ctx, passwordBytes.data(),
				      passwordBytes.size()))
			throw std::runtime_error("Unable to hash password");
		if (!EVP_DigestUpdate(ctx, PASSWORD_SALT.data(),
				      PASSWORD_SALT.size()))
			throw std::runtime_error(
				"Unable to hash password salt");
	}

	if (!EVP_DigestUpdate(ctx, std::data(data), data.size()))
		throw std::runtime_error("Unable to hash data");

	std::vector<uint8_t> ret(EVP_MAX_MD_SIZE);
	unsigned int len;

	if (!EVP_DigestFinal(ctx, ret.data(), &len))
		throw std::runtime_error("Unable to create sha1 hash");

	ret.resize(len);
	return ret;
}
}
}
