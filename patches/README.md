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

## `openconnect-mainloop-reset-dpd-on-entry.patch`

**Symptom:** on every `opc connect`, immediately after `tunnel running`,
openconnect logs `ERROR ... GPST Dead Peer Detection detected dead peer!`
~0.1 ms after the mainloop starts, then does one needless reconnect
(re-POST getconfig, re-SSL, re-submit HIP) before stabilising.

**Cause:** GPST's `gpst_connect()` stamps `ssl_times.last_rx = last_tx =
now` when the CSTP connection comes up. opc then spends ~2 s installing
split routes + DNS (the Windows NRPT registry write + `DnsCache`
`SERVICE_CONTROL_PARAMCHANGE` dominates) *before* it enters
`openconnect_mainloop()`. `openconnect_mainloop()` does not re-stamp those
timers on entry, so the first `keepalive_action()` sees `last_rx` as older
than `2 * dpd` and returns `KA_DPD_DEAD` → spurious dead peer → reconnect.
There is no public API to reset the DPD timer from the Rust wrapper.

**Fix:** re-stamp `vpninfo->ssl_times.last_rx = last_tx = now` ONCE at
`openconnect_mainloop()` entry (guarded by `ssl_fd >= 0`), so DPD is
measured from when the loop actually starts pumping the socket. Done once
per mainloop entry only — never per iteration (that would disable DPD
entirely). Tradeoff: a peer that dies *during* route/DNS setup is detected
up to one DPD window later — acceptable.

Upstreamable; intended to be offered to openconnect.
