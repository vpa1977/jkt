#include "safehandle.h"

namespace jks
{
namespace util
{

/// safehandle specializations
template <> void SafeHandle<FILE *>::release(FILE *fp)
{
	fclose(fp);
}

template <> void SafeHandle<EVP_MD_CTX *>::release(EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_free(ctx);
}

template <> void SafeHandle<x509_st *>::release(x509_st *x)
{
	X509_free(x);
}

}
}
