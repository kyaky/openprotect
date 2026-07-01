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

## `openconnect-mainloop-reset-dpd-on-entry.patch` — REVERTED, do not re-add

There used to be a patch here that re-stamped `ssl_times.last_rx = last_tx
= now` at `openconnect_mainloop()` entry to suppress the startup
`GPST Dead Peer Detection detected dead peer!` log line (which fires ~0.1 ms
after `tunnel running`). **It was shipped in v0.2.0-alpha.19 and it broke
GlobalProtect connect entirely (reproducible HTTP 400 → rc=-5).**

Why: that startup "dead peer" is **not** spurious — it is load-bearing. On
Windows libopenconnect's csd/HIP hook is a no-op, so opc submits the HIP
report out-of-band (`submit_hip_from_rust`) *after* the first CSTP
tunnel-connect. The gateway rejects that first (not-yet-HIP-credited)
tunnel with an HTTP 400, which libopenconnect reads as an "Unknown packet"
and treats as a **fatal** quit. In the unpatched build the stale `last_rx`
(aged by the ~2 s route/DNS install) trips `KA_DPD_DEAD` on the first
mainloop iteration → an in-mainloop `ssl_reconnect` that re-establishes the
tunnel *after* HIP has landed → stable. Suppressing that DPD removed the
only thing repairing the HIP-after-tunnel race, so the 400 became fatal.

The "obvious" alternative — submit HIP *before* the tunnel-connect — does
**not** work on this gateway: UNSW Prisma Access rotates `client_ip` per
`getconfig`, so a pre-tunnel HIP lands under the wrong session key (see
`crates/gp-tunnel/src/openconnect.rs` `setup_csd` docs, 2026-04-14 capture).

Resolution (v0.2.0-alpha.20): keep the functional DPD reconnect; just stop
it looking scary by downgrading the `GPST Dead Peer Detection` line from
`error` to `warn` in `is_benign_error` (`crates/gp-openconnect-sys/src/lib.rs`).
