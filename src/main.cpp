#include "jks.h"
#include "jks_util.h"
#include "safehandle.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <locale>
#include <codecvt>

int main(int argc, char **argv)
{
	// convert utf8 -> utf16

	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		convert;
	auto password = convert.from_bytes("123123");

	std::cout << "jkt - manage java keystore\n" << std::endl;
	using namespace jks;

	std::ifstream storeStream(
		"/home/vladimirp/personal-projects/jkt/store/here",
		std::ios::binary);

	JKSStore store(password);
	storeStream >> store;
}
