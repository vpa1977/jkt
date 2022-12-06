#pragma once

#include <string>

void read_jks(const char *storeLocation, const char *password);

namespace jks
{

struct KeyEntry {};

/**
 * Represent java key store structure
*/
class JKSStore {
    public:
	JKSStore(const char *fileName, const char *password);

    private:
	std::string m_name;
};

}
