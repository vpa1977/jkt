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

}
}
