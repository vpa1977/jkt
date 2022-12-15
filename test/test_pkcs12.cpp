#include "gtest/gtest.h"
#include "safehandle.h"
#include "x509.h"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>

using namespace jks;
using namespace jks::util;

/* Generalised attribute print: handle PKCS#8 and bag attributes */
void print_attribute(BIO *out, const ASN1_TYPE *av);
void hex_prin(BIO *out, unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		BIO_printf(out, "%02X ", buf[i]);
}

int print_attribs(BIO *out, const STACK_OF(X509_ATTRIBUTE) * attrlst,
		  const char *name)
{
	X509_ATTRIBUTE *attr;
	ASN1_TYPE *av;
	int i, j, attr_nid;
	if (!attrlst) {
		BIO_printf(out, "%s: <No Attributes>\n", name);
		return 1;
	}
	if (!sk_X509_ATTRIBUTE_num(attrlst)) {
		BIO_printf(out, "%s: <Empty Attributes>\n", name);
		return 1;
	}
	BIO_printf(out, "%s\n", name);
	for (i = 0; i < sk_X509_ATTRIBUTE_num(attrlst); i++) {
		ASN1_OBJECT *attr_obj;
		attr = sk_X509_ATTRIBUTE_value(attrlst, i);
		attr_obj = X509_ATTRIBUTE_get0_object(attr);
		attr_nid = OBJ_obj2nid(attr_obj);
		BIO_printf(out, "    ");
		if (attr_nid == NID_undef) {
			i2a_ASN1_OBJECT(out, attr_obj);
			BIO_printf(out, ": ");
		} else {
			BIO_printf(out, "%s: ", OBJ_nid2ln(attr_nid));
		}

		if (X509_ATTRIBUTE_count(attr)) {
			for (j = 0; j < X509_ATTRIBUTE_count(attr); j++) {
				av = X509_ATTRIBUTE_get0_type(attr, j);
				print_attribute(out, av);
			}
		} else {
			BIO_printf(out, "<No Values>\n");
		}
	}
	return 1;
}

void print_attribute(BIO *out, const ASN1_TYPE *av)
{
	char *value;
	const char *ln;
	char objbuf[80];

	switch (av->type) {
	case V_ASN1_BMPSTRING:
		value = OPENSSL_uni2asc(av->value.bmpstring->data,
					av->value.bmpstring->length);
		BIO_printf(out, "%s\n", value);
		OPENSSL_free(value);
		break;

	case V_ASN1_UTF8STRING:
		BIO_printf(out, "%.*s\n", av->value.utf8string->length,
			   av->value.utf8string->data);
		break;

	case V_ASN1_OCTET_STRING:
		hex_prin(out, av->value.octet_string->data,
			 av->value.octet_string->length);
		BIO_printf(out, "\n");
		break;

	case V_ASN1_BIT_STRING:
		hex_prin(out, av->value.bit_string->data,
			 av->value.bit_string->length);
		BIO_printf(out, "\n");
		break;

	case V_ASN1_OBJECT:
		ln = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
		if (!ln)
			ln = "";
		OBJ_obj2txt(objbuf, sizeof(objbuf), av->value.object, 1);
		BIO_printf(out, "%s (%s)", ln, objbuf);
		BIO_printf(out, "\n");
		break;

	default:
		BIO_printf(out, "<Unsupported tag %d>\n", av->type);
		break;
	}
}

static int alg_print(const X509_ALGOR *alg)
{
	int pbenid, aparamtype;
	const ASN1_OBJECT *aoid;
	const void *aparam;
	PBEPARAM *pbe = NULL;

	X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);

	pbenid = OBJ_obj2nid(aoid);

	fprintf(stderr, "%s", OBJ_nid2ln(pbenid));

	/*
     * If PBE algorithm is PBES2 decode algorithm parameters
     * for additional details.
     */
	if (pbenid == NID_pbes2) {
		PBE2PARAM *pbe2 = NULL;
		int encnid;
		if (aparamtype == V_ASN1_SEQUENCE)
			pbe2 = (PBE2PARAM *)ASN1_item_unpack(
				(const ASN1_STRING *)aparam,
				ASN1_ITEM_rptr(PBE2PARAM));
		if (pbe2 == NULL) {
			fprintf(stderr, ", <unsupported parameters>");
			goto done;
		}
		X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
		pbenid = OBJ_obj2nid(aoid);
		X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
		encnid = OBJ_obj2nid(aoid);
		fprintf(stderr, ", %s, %s", OBJ_nid2ln(pbenid),
			OBJ_nid2sn(encnid));
		/* If KDF is PBKDF2 decode parameters */
		if (pbenid == NID_id_pbkdf2) {
			PBKDF2PARAM *kdf = NULL;
			int prfnid;
			if (aparamtype == V_ASN1_SEQUENCE)
				kdf = (PBKDF2PARAM *)ASN1_item_unpack(
					(const ASN1_STRING *)aparam,
					ASN1_ITEM_rptr(PBKDF2PARAM));
			if (kdf == NULL) {
				fprintf(stderr, ", <unsupported parameters>");
				goto done;
			}

			if (kdf->prf == NULL) {
				prfnid = NID_hmacWithSHA1;
			} else {
				X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
				prfnid = OBJ_obj2nid(aoid);
			}
			fprintf(stderr, ", Iteration %ld, PRF %s",
				ASN1_INTEGER_get(kdf->iter),
				OBJ_nid2sn(prfnid));
			PBKDF2PARAM_free(kdf);
#ifndef OPENSSL_NO_SCRYPT
		} else if (pbenid == NID_id_scrypt) {
			SCRYPT_PARAMS *kdf = NULL;

			if (aparamtype == V_ASN1_SEQUENCE)
				kdf = (SCRYPT_PARAMS *)ASN1_item_unpack(
					(const ASN1_STRING *)aparam,
					ASN1_ITEM_rptr(SCRYPT_PARAMS));
			if (kdf == NULL) {
				fprintf(stderr, ", <unsupported parameters>");
				goto done;
			}
			fprintf(stderr,
				", Salt length: %d, Cost(N): %ld, "
				"Block size(r): %ld, Parallelism(p): %ld",
				ASN1_STRING_length(kdf->salt),
				ASN1_INTEGER_get(kdf->costParameter),
				ASN1_INTEGER_get(kdf->blockSize),
				ASN1_INTEGER_get(
					kdf->parallelizationParameter));
			SCRYPT_PARAMS_free(kdf);
#endif
		}
		PBE2PARAM_free(pbe2);
	} else {
		if (aparamtype == V_ASN1_SEQUENCE)
			pbe = (PBEPARAM *)ASN1_item_unpack(
				(const ASN1_STRING *)aparam,
				ASN1_ITEM_rptr(PBEPARAM));
		if (pbe == NULL) {
			fprintf(stderr, ", <unsupported parameters>");
			goto done;
		}
		fprintf(stderr, ", Iteration %ld", ASN1_INTEGER_get(pbe->iter));
		PBEPARAM_free(pbe);
	}
done:
	fprintf(stderr, "\n");
	return 1;
}

int PKCS12_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
			   ASN1_TYPE *param, const EVP_CIPHER *cipher,
			   const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx,
			   const char *propq)
{
	PBEPARAM *pbe;
	int saltlen, iter, ret;
	unsigned char *salt;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned char *piv = iv;

	if (cipher == NULL)
		return 0;

	/* Extract useful info from parameter */

	pbe = (PBEPARAM *)ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM),
						    param);
	if (pbe == NULL) {
		//ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
		return 0;
	}

	if (pbe->iter == NULL)
		iter = 1;
	else
		iter = ASN1_INTEGER_get(pbe->iter);
	salt = pbe->salt->data;
	saltlen = pbe->salt->length;
	if (!PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, PKCS12_KEY_ID,
				    iter, EVP_CIPHER_get_key_length(cipher),
				    key, md, libctx, propq)) {
		//ERR_raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR);
		PBEPARAM_free(pbe);
		return 0;
	}
	auto piv_len = EVP_CIPHER_get_iv_length(cipher);
	if (piv_len > 0) {
		if (!PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen,
					    PKCS12_IV_ID, iter,
					    EVP_CIPHER_get_iv_length(cipher),
					    iv, md, libctx, propq)) {
			//ERR_raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR);
			PBEPARAM_free(pbe);
			return 0;
		}
	} else {
		piv = NULL;
	}
	PBEPARAM_free(pbe);

	const char *name = EVP_CIPHER_get0_name(cipher);
	ret = EVP_CipherInit(ctx, cipher, nullptr, nullptr, 1);

	ret = EVP_CipherInit(ctx, cipher, key, piv, en_de);
	OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
	OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
	return ret;
}

int EVP_PBE_CipherInit_ex(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
			  ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de,
			  OSSL_LIB_CTX *libctx, const char *propq)
{
	const EVP_CIPHER *cipher = NULL;
	EVP_CIPHER *cipher_fetch = NULL;
	const EVP_MD *md = NULL;
	EVP_MD *md_fetch = NULL;
	int ret = 0, cipher_nid, md_nid;
	EVP_PBE_KEYGEN_EX *keygen_ex;
	EVP_PBE_KEYGEN *keygen;

	if (!EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj),
			     &cipher_nid, &md_nid, &keygen, &keygen_ex)) {
		char obj_tmp[80];

		if (pbe_obj == NULL)
			OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
		else
			i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
		//        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
		//                       "TYPE=%s", obj_tmp);
		goto err;
	}

	if (pass == NULL)
		passlen = 0;
	else if (passlen == -1)
		passlen = strlen(pass);

	if (cipher_nid != -1) {
		// (void)ERR_set_mark();
		cipher = cipher_fetch =
			EVP_CIPHER_fetch(libctx, OBJ_nid2sn(cipher_nid), propq);
		/* Fallback to legacy method */
		if (cipher == NULL)
			cipher = EVP_get_cipherbynid(cipher_nid);
		if (cipher == NULL) {
			//       (void)ERR_clear_last_mark();
			//        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER,
			//                      OBJ_nid2sn(cipher_nid));
			goto err;
		}
		//(void)ERR_pop_to_mark();
	}

	if (md_nid != -1) {
		//(void)ERR_set_mark();
		md = md_fetch = EVP_MD_fetch(libctx, OBJ_nid2sn(md_nid), propq);
		/* Fallback to legacy method */
		if (md == NULL)
			EVP_get_digestbynid(md_nid);

		if (md == NULL) {
			//(void)ERR_clear_last_mark();
			//          ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
			goto err;
		}
		//        (void)ERR_pop_to_mark();
	}

	/* Try extended keygen with libctx/propq first, fall back to legacy keygen */
	if (keygen_ex != NULL)
		ret = PKCS12_PBE_keyivgen_ex(ctx, pass, passlen, param, cipher,
					     md, en_de, libctx, propq);
	else
		ret = keygen(ctx, pass, passlen, param, cipher, md, en_de);

err:
	EVP_CIPHER_free(cipher_fetch);
	EVP_MD_free(md_fetch);

	return ret;
}

/*
 * Encrypt/Decrypt a buffer based on password and algor, result in a
 * OPENSSL_malloc'ed buffer
 */
unsigned char *PKCS12_pbe_crypt_ex(const X509_ALGOR *algor, const char *pass,
				   int passlen, const unsigned char *in,
				   int inlen, unsigned char **data,
				   int *datalen, int en_de,
				   OSSL_LIB_CTX *libctx, const char *propq)
{
	unsigned char *out = NULL;
	int outlen, i;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int max_out_len, mac_len = 0;

	if (ctx == NULL) {
		//ERR_raise(ERR_LIB_PKCS12, ERR_R_EVP_LIB);
		goto err;
	}

	/* Process data */
	if (!EVP_PBE_CipherInit_ex(algor->algorithm, pass, passlen,
				   algor->parameter, ctx, en_de, libctx, propq))
		goto err;

	/*
     * GOST algorithm specifics:
     * OMAC algorithm calculate and encrypt MAC of the encrypted objects
     * It's appended to encrypted text on encrypting
     * MAC should be processed on decrypting separately from plain text
     */
	max_out_len = inlen + EVP_CIPHER_CTX_get_block_size(ctx);
	if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) &
	     EVP_CIPH_FLAG_CIPHER_WITH_MAC) != 0) {
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 0,
					&mac_len) < 0) {
			//	ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
			goto err;
		}

		if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
			max_out_len += mac_len;
		} else {
			if (inlen < mac_len) {
				//	ERR_raise(ERR_LIB_PKCS12,
				//		  PKCS12_R_UNSUPPORTED_PKCS12_MODE);
				goto err;
			}
			inlen -= mac_len;
			if (EVP_CIPHER_CTX_ctrl(
				    ctx, EVP_CTRL_AEAD_SET_TAG, (int)mac_len,
				    (unsigned char *)in + inlen) < 0) {
				//		ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
				goto err;
			}
		}
	}

	if ((out = (unsigned char *)OPENSSL_malloc(max_out_len)) == NULL)
		goto err;

	if (!EVP_CipherUpdate(ctx, out, &i, in, inlen)) {
		OPENSSL_free(out);
		out = NULL;
		//	ERR_raise(ERR_LIB_PKCS12, ERR_R_EVP_LIB);
		goto err;
	}

	outlen = i;
	if (!EVP_CipherFinal_ex(ctx, out + i, &i)) {
		OPENSSL_free(out);
		out = NULL;
		//	ERR_raise_data(ERR_LIB_PKCS12,
		//		       PKCS12_R_PKCS12_CIPHERFINAL_ERROR,
		//		       passlen == 0 ? "empty password" :
		//				      "maybe wrong password");
		goto err;
	}
	outlen += i;
	if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) &
	     EVP_CIPH_FLAG_CIPHER_WITH_MAC) != 0) {
		if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
			if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
						(int)mac_len,
						out + outlen) < 0) {
				OPENSSL_free(out);
				out = NULL;
				//	ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
				goto err;
			}
			outlen += mac_len;
		}
	}
	if (datalen)
		*datalen = outlen;
	if (data)
		*data = out;
err:
	EVP_CIPHER_CTX_free(ctx);
	return out;
}

/*
 * Encode ASN1 structure and encrypt, return OCTET STRING if zbuf set zero
 * encoding.
 */

ASN1_OCTET_STRING *item_i2d_encrypt_ex(X509_ALGOR *algor, const ASN1_ITEM *it,
				       const char *pass, int passlen, void *obj,
				       int zbuf, OSSL_LIB_CTX *ctx,
				       const char *propq)
{
	ASN1_OCTET_STRING *oct = NULL;
	unsigned char *in = NULL;
	int inlen;

	if ((oct = ASN1_OCTET_STRING_new()) == NULL) {
		//ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
		goto err;
	}
	inlen = ASN1_item_i2d((const ASN1_VALUE *)obj, &in, it);
	if (!in) {
		//ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCODE_ERROR);
		goto err;
	}
	if (!PKCS12_pbe_crypt_ex(algor, pass, passlen, in, inlen, &oct->data,
				 &oct->length, 1, ctx, propq)) {
		//ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR);
		OPENSSL_free(in);
		goto err;
	}
	if (zbuf)
		OPENSSL_cleanse(in, inlen);
	OPENSSL_free(in);
	return oct;
err:
	ASN1_OCTET_STRING_free(oct);
	return NULL;
}

PKCS7 *p7encdata_ex(int pbe_nid, const char *pass, int passlen,
		    unsigned char *salt, int saltlen, int iter,
		    STACK_OF(PKCS12_SAFEBAG) * bags)
{
	PKCS7 *p7;
	X509_ALGOR *pbe;
	const EVP_CIPHER *pbe_ciph = NULL;
	EVP_CIPHER *pbe_ciph_fetch = NULL;

	if ((p7 = PKCS7_new_ex(nullptr, nullptr)) == NULL) {
		//ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
		return NULL;
	}
	if (!PKCS7_set_type(p7, NID_pkcs7_encrypted)) {
		//ERR_raise(ERR_LIB_PKCS12,
		//	  PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE);
		goto err;
	}

	//ERR_set_mark();
	pbe_ciph = pbe_ciph_fetch =
		EVP_CIPHER_fetch(nullptr, OBJ_nid2sn(pbe_nid), nullptr);
	if (pbe_ciph == NULL)
		pbe_ciph = EVP_get_cipherbynid(pbe_nid);
	//ERR_pop_to_mark();

	if (pbe_ciph != NULL) {
		pbe = PKCS5_pbe2_set_iv_ex(pbe_ciph, iter, salt, saltlen, NULL,
					   -1, nullptr);
	} else {
		pbe = PKCS5_pbe_set_ex(pbe_nid, iter, salt, saltlen, nullptr);
	}

	if (pbe == NULL) {
		//	ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
		goto err;
	}
	X509_ALGOR_free(p7->d.encrypted->enc_data->algorithm);
	p7->d.encrypted->enc_data->algorithm = pbe;
	ASN1_OCTET_STRING_free(p7->d.encrypted->enc_data->enc_data);
	if (!(p7->d.encrypted->enc_data->enc_data = item_i2d_encrypt_ex(
		      pbe, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), pass, passlen, bags,
		      1, nullptr, nullptr))) {
		//	ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR);
		goto err;
	}

	EVP_CIPHER_free(pbe_ciph_fetch);
	return p7;

err:
	PKCS7_free(p7);
	EVP_CIPHER_free(pbe_ciph_fetch);
	return NULL;
}

TEST(prototype, prototype_PKCS12_loader)
{
	OPENSSL_init();
	auto *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	const char *pass = "123123";
	auto passlen = strlen(pass);
	FileHandle fp(fopen("test/files/pfxstore", "rb"));
	PKCS12Handle p12(d2i_PKCS12_fp(fp, nullptr));
	ASSERT_NE(nullptr, p12.raw());

	STACK_OF(X509) *ocerts = NULL;
	X509 *x = NULL;

	// todo: distinguish between empty password and no password
	bool validPassword = true;
	bool macPresent = PKCS12_mac_present(p12);
	if (macPresent) {
		validPassword = PKCS12_verify_mac(p12, pass, -1);
	}

	ASSERT_TRUE(macPresent);
	ASSERT_TRUE(validPassword);

	// todo: safehandle
	STACK_OF(PKCS7) *asafes = PKCS12_unpack_authsafes(p12);
	ASSERT_NE(nullptr, asafes);
	STACK_OF(PKCS12_SAFEBAG) * bags;

	for (int i = 0; i < sk_PKCS7_num(asafes); i++) {
		PKCS7 *p7 = sk_PKCS7_value(asafes, i);
		int bagnid = OBJ_obj2nid(p7->type);
		std::cout << bagnid << std::endl;
		if (bagnid == NID_pkcs7_data) {
			bags = PKCS12_unpack_p7data(p7);
		} else if (bagnid == NID_pkcs7_encrypted) {
			alg_print(p7->d.encrypted->enc_data->algorithm);
			bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
		} else
			continue;
		if (!bags) {
			sk_PKCS7_pop_free(asafes, PKCS7_free);
		}

		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++) {
			auto *value = sk_PKCS12_SAFEBAG_value(bags, j);
			auto nid = PKCS12_SAFEBAG_get_nid(value);
			std::cout << "NID " << nid << std::endl;
			auto bagNid = PKCS12_SAFEBAG_get_bag_nid(value);
			if (bagNid == NID_x509Certificate) {
				// this is a cert. But what's the alias?
				auto *alias = PKCS12_get_friendlyname(value);
				std::cout << alias << std::endl;
				auto *attrs = (STACK_OF(X509_ATTRIBUTE) *)
					PKCS12_SAFEBAG_get0_attrs(value);

				print_attribs(bio_out, attrs, "test");
			}
		}

		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}

	/// append a certificate
	const auto der = jks::util::ReadDER("test/files/globaltrust.pem");
	auto ptr = der.data();
	X509Handle handle(d2i_X509(nullptr, &ptr, der.size()));

	auto *bag = PKCS12_SAFEBAG_create_cert(handle);
	// add attribute 2.5.29.37.0
	if (!PKCS12_add_friendlyname_asc(bag, "anotherfriendlybag",
					 strlen("anotherfriendlybag")))
		throw std::runtime_error("no friendly name");

	//     2.16.840.1.113894.746875.1.1: Any Extended Key Usage (2.5.29.37.0)
	auto *asnObjValue = OBJ_txt2obj("2.5.29.37.0", 0);
	auto *asnObjTag = OBJ_txt2obj("2.16.840.1.113894.746875.1.1", 0);

	struct temp_asn1_object_st {
		const char *sn, *ln;
		int nid;
		int length;
		const unsigned char *data; /* data remains const after init */
		int flags; /* Should we free this one */
	};

	auto *a1 = (temp_asn1_object_st *)asnObjTag;
	auto *a2 = (temp_asn1_object_st *)asnObjValue;

	if (!PKCS12_add1_attr_by_txt(bag, "2.16.840.1.113894.746875.1.1",
				     V_ASN1_OBJECT,
				     (const unsigned char *)asnObjValue, -1))
		throw std::runtime_error("attribute not added");

	STACK_OF(PKCS12_SAFEBAG) *safebags = sk_PKCS12_SAFEBAG_new_null();
	if (!sk_PKCS12_SAFEBAG_push(safebags, bag))
		throw std::runtime_error("cannot push bag");

	//STACK_OF(PKCS7) *asafes2 = sk_PKCS7_new_null();

	if (!PKCS12_add_safe(&asafes, safebags, NID_aes_256_cbc, 10000, pass))
		throw std::runtime_error("Unable to pack authsafes");

	//
	auto *newP12 = PKCS12_add_safes(asafes, 0);

	if (!PKCS12_set_mac(newP12, pass, -1, nullptr, 0, 0, nullptr))
		throw std::runtime_error("unable to set mac");
	FileHandle fp2(fopen("test/files/pfxstore.new", "wb"));
	i2d_PKCS12_fp(fp2, newP12);

	sk_PKCS7_pop_free(asafes, PKCS7_free);
}
