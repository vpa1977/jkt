#include "jks.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("jkt - manage java keystore\n");

	using namespace jks::util;

	FileHandle file(fopen(
		"/home/vladimirp/personal-projects/jkt/store/here", "rb"));

	fread(nullptr, 1, 1, file);

	read_jks("/home/vladimirp/personal-projects/jkt/store/here", "123123");
}
