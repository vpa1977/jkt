#include "pkcs12.h"
#include "safehandle.h"
#include "x509.h"

#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <stdexcept>

using namespace jks::util;

namespace PKCS12Store
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

void AddCertificate(STACK_OF(PKCS7) * safes, const std::string &password,
		    const std::string &alias, const std::string &pem)
{
	const auto der = jks::util::ReadDER(pem);
	auto ptr = der.data();
	X509Handle handle(d2i_X509(nullptr, &ptr, der.size()));

	SafeHandle<PKCS12_SAFEBAG *> bag(PKCS12_SAFEBAG_create_cert(handle));
	// add attribute 2.5.29.37.0
	if (!PKCS12_add_friendlyname_asc(bag, alias.c_str(), alias.size()))
		throw std::runtime_error("unable to set friendly name");

	//     2.16.840.1.113894.746875.1.1: Any Extended Key Usage (2.5.29.37.0)
	SafeHandle<ASN1_OBJECT *> asnObjValue(OBJ_txt2obj("2.5.29.37.0", 0));
	if (!PKCS12_add1_attr_by_txt(
		    bag, "2.16.840.1.113894.746875.1.1", V_ASN1_OBJECT,
		    (const unsigned char *)asnObjValue.raw(), -1))
		throw std::runtime_error("unable to add extended key usage");

	STACK_OF(PKCS12_SAFEBAG) *safebags = sk_PKCS12_SAFEBAG_new_null();
	if (!sk_PKCS12_SAFEBAG_push(safebags, bag))
		throw std::runtime_error("unable to add bag");

	if (!PKCS12_add_safe(&safes, safebags, NID_aes_256_cbc, 10000,
			     password.c_str()))
		throw std::runtime_error("unable to package asafes");
}

void WriteOutput(STACK_OF(PKCS7) * safes, const std::string &password,
		 const std::string &alias, const std::string &output)
{
	SafeHandle<PKCS12 *> newP12(PKCS12_add_safes(safes, 0));
	if (!PKCS12_set_mac(newP12, password.c_str(), -1, nullptr, 0, 0,
			    nullptr))
		throw std::runtime_error("unable to set mac");
	FileHandle fp(fopen(output.c_str(), "wb"));
	i2d_PKCS12_fp(fp, newP12);
}

bool Replace(const std::string &file, const std::string &password,
	     const std::string &alias, const std::string &pem,
	     const std::string &output)
{
	FileHandle fp(fopen(file.c_str(), "rb"));
	PKCS12Handle p12(d2i_PKCS12_fp(fp, nullptr));
	SafeHandle<STACK_OF(PKCS7) *> safes(PKCS12_unpack_authsafes(p12));
	bool validPassword = true;
	bool macPresent = PKCS12_mac_present(p12);
	if (macPresent) {
		if (!PKCS12_verify_mac(p12, password.c_str(), -1)) {
			throw std::runtime_error("Invalid password");
		}
	}
	bool updated = false;
	std::vector<PKCS7 *> toDelete;
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
			updated = true;
			SafeHandle<PKCS12_SAFEBAG *> removedBag(
				sk_PKCS12_SAFEBAG_delete(bags, replace));
			if (removedBag == nullptr)
				throw std::runtime_error(
					"unable to remove entry from the bag stack");
			auto *rawSafe = safes.raw();
			if (!PKCS12_add_safe(&rawSafe, bags, NID_aes_256_cbc,
					     10000, password.c_str()))
				throw std::runtime_error(
					"unable to package asafes");

			toDelete.emplace_back(p7);
			break;
		}
	}
	for (auto *p7 : toDelete) {
		SafeHandle<PKCS7 *> removedP7(sk_PKCS7_delete_ptr(safes, p7));
	}

	if (!pem.empty()) {
		AddCertificate(safes, password, alias, pem);
		updated = true;
	}

	if (updated) {
		WriteOutput(safes, password, alias, output);
	}

	return updated;
}
}
