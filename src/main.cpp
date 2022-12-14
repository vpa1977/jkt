
#include "jks.h"
#include "jks_util.h"
#include "pkcs12.h"
#include "safehandle.h"
#include "x509.h"

#include <argp.h>

#include <codecvt>
#include <fstream>
#include <iostream>
#include <locale>

using namespace jks;

void ReadStore(jks::JKSStore &store, const char *from)
{
	std::ifstream storeStream(from, std::ios::in | std::ios::binary);
	if (!storeStream)
		throw std::runtime_error("unable to open a file");
	storeStream >> store;
}

std::u16string ConvertU16(const char *text)
{
	if (text == nullptr)
		return {};
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
		convert;
	return convert.from_bytes(text);
}

// arguments
const char *argp_program_version = "jkt 1.0";
const char *argp_program_bug_address = "<vpa1977@gmail.com>";

static char doc[] =
	"jkt -- Java Keystore certificate Tool. Add or update certificate in Java keystore";

static struct argp_option options[] = { { "password", 'p', "PASSWORD", 0,
					  "Java keystore password" },
					{ 0 } };

struct arguments {
	char *args[3];
	char *password;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	arguments *args = static_cast<arguments *>(state->input);
	switch (key) {
	case ARGP_KEY_ARG:
		if (state->arg_num >= 3)
			argp_usage(state);
		else
			args->args[state->arg_num] = arg;
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 3)
			argp_usage(state);
		break;
	case 'p':
		args->password = arg;
		break;
	default:
		break;
	}
	return 0;
}

static char args_doc[] = "KEYSTORE ALIAS PEM-CERTIFICATE";
static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv)
{
	struct arguments args {};
	auto ret = argp_parse(&argp, argc, argv, 0, 0, &args);
	if (ret != 0)
		return ret;

	auto *storeFile = args.args[0];
	auto *alias = args.args[1];
	auto *pemToImport = args.args[2];
	auto *storePassword = args.password;
	try {
		JKSStore store(ConvertU16(storePassword));

		try {
			ReadStore(store, storeFile);
			auto certificate = jks::util::ReadDER(pemToImport);
			store.EmplaceTrustedCertificate(ConvertU16(alias),
							certificate);
			// write the store
			std::ofstream otherStoreStream(
				storeFile, std::ios::out | std::ios::binary);
			otherStoreStream << store;
			return 0;
		} catch (const NotJKSStore &) {
		}

		std::cout << "Not Java keystore format, trying pkcs12"
			  << std::endl;
		PKCS12Store::Replace(storeFile, storePassword, alias,
				     pemToImport, storeFile);

	} catch (const std::exception &e) {
		std::cerr << e.what() << '\n';
		return 1;
	}

	return 0;
}
