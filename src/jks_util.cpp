#include "jks_util.h"
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
	constexpr auto PASSWORD_SALT = "Mighty Aphrodite";
	std::vector<uint8_t> digest;

	return digest;
}
}
}
