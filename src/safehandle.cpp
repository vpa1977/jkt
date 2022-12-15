#include "safehandle.h"

namespace jks
{
namespace util
{

/// safehandle specializations
template <> void SafeHandle<FILE *>::release(FILE *fp)
{
	if (fp != nullptr)
		fclose(fp);
}

template <> void SafeHandle<EVP_MD_CTX *>::release(EVP_MD_CTX *ctx)
{
	if (ctx != nullptr)
		EVP_MD_CTX_free(ctx);
}

template <> void SafeHandle<x509_st *>::release(x509_st *x)
{
	if (x != nullptr)
		X509_free(x);
}

template <> void SafeHandle<PKCS12 *>::release(PKCS12 *x)
{
	if (x != nullptr)
		PKCS12_free(x);
}

}
}
