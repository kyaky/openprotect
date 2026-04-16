/* Wrapper header for bindgen — pulls in the public openconnect API.
 *
 * On Windows, openconnect.h references the SOCKET type. We forward-declare
 * it so bindgen doesn't need to chase into the full Windows SDK headers
 * (which conflict with MinGW headers when using LLVM clang). */
#ifdef _WIN32
typedef unsigned long long SOCKET;
#endif
#include <openconnect.h>
