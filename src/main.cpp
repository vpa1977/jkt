
#include "jks.h"
#include "jks_util.h"
#include "safehandle.h"
#include "x509.h"

#include <codecvt>
#include <fstream>
#include <iostream>
#include <locale>

using namespace jks;

// todo proper usage
void Usage()
{
	std::cout << "jkt <store-file> <store-password> <alias> <pem>"
		  << std::endl;
}

void ReadStore(jks::JKSStore &store, const char *from)
{
	std::ifstream storeStream(from, std::ios::in | std::ios::binary);
	if (!storeStream)
		throw std::runtime_error("unable to open a file");
	storeStream >> store;
}

int main(int argc, char **argv)
{
	// todo: argument parsing
	if (argc < 5) {
		Usage();
		return 255;
	}

	auto *storeFile = argv[1];
	auto *storePassword = argv[2];
	auto *alias = argv[3];
	auto *pemToImport = argv[4];

	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		convert;
	auto password = convert.from_bytes(storePassword);

	JKSStore store(password);

	ReadStore(store, storeFile);

	auto certificate = jks::util::ReadDER(pemToImport);

	store.EmplaceTrustedCertificate(convert.from_bytes(alias), certificate);

	// write the store
	std::ofstream otherStoreStream(storeFile,
				       std::ios::out | std::ios::binary);
	otherStoreStream << store;

	return 0;
}
