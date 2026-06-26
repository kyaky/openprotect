# Vendored libopenconnect patches

These patches are applied to the upstream
[openconnect](https://gitlab.com/openconnect/openconnect) source tree at
**build time** by the Windows release job (`.github/workflows/release.yml`,
"Build libopenconnect" step). The clone is pinned to a tag (`v9.21`) so the
patch context stays stable; bumping the tag means re-checking each patch.

To apply manually against a fresh checkout:

```sh
git clone --depth 1 --branch v9.21 https://gitlab.com/openconnect/openconnect.git
cd openconnect
git apply /path/to/openprotect/patches/<patch>.patch
```

## `openconnect-esp-win32-send-errno.patch`

**Symptom:** on Windows the log floods with
`ERROR openconnect: Failed to send ESP packet: No error`, many per
millisecond, while the VPN still works.

**Cause:** `esp.c`'s ESP *send* path classifies `send()` failures with
POSIX `errno` (`errno == ENOBUFS || EAGAIN || EWOULDBLOCK`) and formats the
message with `strerror(errno)`. On Windows, Winsock reports socket errors
via `WSAGetLastError()`, **not** `errno` — so `errno` stays `0`, the
transient-error filter never matches, every non-fatal send failure is
logged at `PRG_ERR`, and `strerror(0)` renders as `"No error"`. The same
file's ESP *receive* path already does this correctly with
`WSAGetLastError()` + `openconnect__win32_strerror()`; the send path was
simply never made Windows-aware.

**Fix:** wrap the send-error classification in `#ifdef _WIN32`, mirroring
the receive path — treat `WSAEWOULDBLOCK`/`WSAENOBUFS` as the transient
requeue case and format genuine errors with `openconnect__win32_strerror()`.
The `#else` branch is the unchanged upstream POSIX code. This both silences
the spurious spam and surfaces the *real* Windows error string when a send
truly fails (e.g. UDP 4501 blocked), instead of masking it as "No error".

Upstreamable; intended to be offered to openconnect.
