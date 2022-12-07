#include "jks.h"
#include "jks_util.h"
#include "safehandle.h"
#include <stdlib.h>
#include <stdio.h>
#include <locale>
#include <codecvt>

int main(int argc, char **argv)
{
	// convert utf8 -> utf16
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		convert;
	auto ret = convert.from_bytes(argv[1]);

	printf("jkt - manage java keystore\n");

	using namespace jks::util;

	FileHandle file(fopen(
		"/home/vladimirp/personal-projects/jkt/store/here", "rb"));

	fread(nullptr, 1, 1, file);

	read_jks("/home/vladimirp/personal-projects/jkt/store/here", "123123");
}
