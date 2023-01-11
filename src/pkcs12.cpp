#include "pkcs12.h"
#include "safehandle.h"
#include "x509.h"

#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <stdexcept>

using namespace jks::util;

namespace PCKS12Store
{
STACK_OF(PKCS12_SAFEBAG) * ReadBags(PKCS7 *safe, const std::string &password)
{
	auto bagnid = OBJ_obj2nid(safe->type);
	if (bagnid == NID_pkcs7_data) {
		return PKCS12_unpack_p7data(safe);
	} else if (bagnid == NID_pkcs7_encrypted) {
		return PKCS12_unpack_p7encdata(safe, password.c_str(),
					       password.size());
	}
	return nullptr;
}

void Replace(const char *file, const std::string &password,
	     const std::string &alias, const char *pem)
{
	FileHandle fp(fopen(file, "rb"));
	PKCS12Handle p12(d2i_PKCS12_fp(fp, nullptr));
	SafeHandle<STACK_OF(PKCS7) *> safes(PKCS12_unpack_authsafes(p12));
	bool validPassword = true;
	bool macPresent = PKCS12_mac_present(p12);
	if (macPresent) {
		if (!PKCS12_verify_mac(p12, password.c_str(), -1)) {
			throw std::runtime_error("Invalid password");
		}
	}
	std::vector<PKCS12_SAFEBAG *> toDelete;
	for (int i = 0; i < sk_PKCS7_num(safes); ++i) {
		auto *p7 = sk_PKCS7_value(safes, i);
		SafeHandle<STACK_OF(PKCS12_SAFEBAG) *> bags(
			ReadBags(p7, password));
		if (bags == nullptr)
			continue;
		int replace = -1;
		int numBags = sk_PKCS12_SAFEBAG_num(bags);
		for (int j = 0; j < numBags; j++) {
			auto *value = sk_PKCS12_SAFEBAG_value(bags, j);
			auto bagNid = PKCS12_SAFEBAG_get_bag_nid(value);
			if (bagNid == NID_x509Certificate &&
			    (alias == PKCS12_get_friendlyname(value))) {
				replace = j;
				break;
			}
		}
		if (replace >= 0) {
			sk_PKCS12_SAFEBAG_delete(bags, replace);
			if (numBags == 1)
				toDelete.emplace_back(p7);
		}
	}
	for (auto *p7 : toDelete)
		sk_PKCS7_delete_ptr(safes, p7);

	if (pem == nullptr)
		return;
}
}
