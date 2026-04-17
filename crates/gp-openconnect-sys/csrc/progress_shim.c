/* Variadic trampoline for libopenconnect's progress callback.
 *
 * Rust (stable) can't implement C variadic functions, but libopenconnect
 * unconditionally calls the progress callback with a printf-style format
 * + varargs. We format the message into a stack buffer and forward it to
 * a plain, non-variadic Rust callback.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Plain, non-variadic sink implemented in Rust. Takes the already-
 * formatted message as a NUL-terminated C string. */
extern void openprotect_progress_sink(void *privdata, int level, const char *msg);

void openprotect_progress_trampoline(void *privdata, int level, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) {
        buf[0] = '\0';
    }
    /* Strip a trailing newline — openconnect always sends one. */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    openprotect_progress_sink(privdata, level, buf);
}
