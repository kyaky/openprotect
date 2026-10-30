# macOS Status

OpenProtect now has a working macOS CLI path built around Homebrew's `libopenconnect`.

## What works

- `opc` builds on stable Rust against Homebrew `openconnect`
- Headless SAML paste auth in the terminal
- Long Prisma callback URLs on macOS terminals
- HIP report submission through libopenconnect's CSD wrapper
- Native split-route setup for `--only` via `ifconfig` + `route`
- DNS updates via `networksetup`
- Per-instance IPC sockets under `/tmp/openprotect-<uid>/<instance>.sock`
- Homebrew `vpnc-script` autodiscovery at `/opt/homebrew/etc/vpnc/vpnc-script`

## Build

```bash
brew install pkgconf openconnect
cargo build --release --bin opc
```

## Run

`opc connect` must currently run with elevated privileges on macOS so libopenconnect can create the `utun` device:

```bash
sudo -E target/release/opc connect vpn.example.com --only 10.0.0.0/8
```

If the session was started with `sudo`, use the same privilege context for control commands too:

```bash
sudo -E target/release/opc status
sudo -E target/release/opc disconnect
```

## Notable fixes in this branch

- SAML paste input no longer stalls on long JWT callbacks from macOS terminals
- Bracketed-paste wrappers and `\r`-terminated Enter are accepted
- CLI callback capture prints a masked success message instead of echoing the token
- GUI callback paste now masks the captured URL as `****` and can submit with Enter
- macOS IPC no longer tries to bind `/run/openprotect/*.sock`
- HIP wrapper execution now uses the current effective uid when not launched under `sudo`

## Current limitations

- Release tarballs are raw unsigned binaries, not notarized `.app` bundles
- The bundled CLI ships with its dependent `libopenconnect` dylibs, but `opc connect` still needs `sudo`
- The DNS backend writes per-zone scoped resolvers to `/etc/resolver/<zone>` for split-DNS connects
  (`--dns-zone` / `--only`); full-tunnel connects (no split zones) swap the active service's DNS
  globally via `networksetup`. Stale resolver files left by a killed session are swept and reclaimed
  on the next `opc connect` before the portal prelogin runs, and a global swap leaves a journal that
  `opc recover` (or the next reconnect) restores — so the common crash shapes no longer wedge the
  first connection. Pre-journal releases and service switches between crash and recovery still
  require the manual `networksetup` recipe in `opc recover`'s nothing-found output
- `opc connect` without `sudo` is rejected up front because `utun` creation fails with `EPERM`
- Root-owned sessions use `/tmp/openprotect-0/<instance>.sock`, so non-root `status` / `disconnect` will not see them

## Troubleshooting

- `openprotect: callback paste captured as **** — continuing...`
  means the terminal SAML callback was accepted
- `starting ipc server: binding control socket at /run/openprotect/...`
  means you are using an old binary
- `Failed to connect utun unit: Operation not permitted`
  means the command was not run with sufficient privileges; rerun with `sudo`
