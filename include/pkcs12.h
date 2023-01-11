#pragma once

#include <string>

namespace PCKS12Store
{
void Replace(const char *file, const std::string &password,
	     const std::string &alias, const char *pem);
}
