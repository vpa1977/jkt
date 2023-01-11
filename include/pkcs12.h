#pragma once

#include <string>

namespace PKCS12Store
{
bool Replace(const std::string &file, const std::string &password,
	     const std::string &alias, const std::string &pem,
	     const std::string &output);
}
