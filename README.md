# Pangolin

> A modern, headless-friendly GlobalProtect VPN client for Linux
> and Windows, written in Rust.

`pangolin` (CLI binary `pgn`) connects to Palo Alto Networks
GlobalProtect VPN portals — including modern **Prisma Access**
deployments that use cloud authentication — without needing a desktop
environment, a graphical browser, or `vpn-slice`.

> **Status:** Phases 1-2 complete and live-verified against UNSW
> Prisma Access. **Windows support landed** — SAML + Wintun + ESP
> tunnel tested end-to-end on Windows 11. macOS support is the
> main remaining platform target. See [Roadmap](#roadmap) below.

---

## Why another GlobalProtect client?

There are two main open-source options today:

| | openconnect + vpnc-script + gp-saml-gui | yuezk/GlobalProtect-openconnect | **pangolin** |
|---|---|---|---|
| Tunnel | Native ESP/HTTPS | Native (via libopenconnect) | Native (via libopenconnect) |
| Single binary, no sidecar helpers, no GUI runtime | ❌ (`openconnect` + `vpnc-script` + `gp-saml-gui` Python) | ❌ (`gpclient` + `gpauth` helper + webkit2gtk runtime) | ✅ one `pgn` binary |
| Gateway-aware split tunnel out of the box | ❌ needs `vpn-slice` add-on, otherwise `--only <gw-subnet>` sends ESP probes into the tunnel and the session dies in ~20s | ❌ same, needs `vpn-slice` | ✅ **`gp-route` installs a gateway `/32` pin automatically** (ports vpn-slice's `VPNGATEWAY` trick into Rust so the gateway always stays on the physical interface regardless of split-route coverage) |
| Prisma Access cloud-auth (`globalprotectcallback:`) | ✅ via gp-saml-gui | ✅ via `gpauth` webview window | ✅ **two headless modes**: `--auth-mode paste` (browser-of-your-choice callback) and `--auth-mode okta` (direct Okta API, no browser at all) |
| Multi-instance parallel tunnels | ❌ | ❌ | ✅ `pgn connect -i work` + `pgn connect -i client-a` run side-by-side |
| HIP report (Windows / macOS / Linux) | partial (Windows only via script) | partial (Windows only, fixed template) | ✅ `gp-hip` — **OS-aware**, emits the category set each platform is expected to report |
| Prometheus metrics endpoint | ❌ | ❌ | ✅ `--metrics-port 9100` |
| systemd integration out of the box | ❌ | partial (user-level GUI) | ✅ `pangolin@.service` template, one unit per saved profile |
| Written in | C + shell + Python | Rust + C | Rust |

### The four things that make it worth switching

1. **Headless from the bottom up, by design.** pangolin has no
   embedded browser. `pgn connect --auth-mode paste` starts a
   tiny local HTTP server on `127.0.0.1:29999`, prints a URL,
   and waits for you to complete SAML in whatever browser you
   already have open — your usual Firefox/Chrome, or a browser
   on a different machine reached via `ssh -L 29999:localhost:29999`.
   Copy the final `globalprotectcallback:` URL out of the
   address bar, paste it back into the terminal, done. No
   webkit2gtk, no GTK, no X11, no Wayland. `pgn --auth-mode
   okta` goes one step further and drives an Okta tenant's
   `/api/v1/authn` directly, so even the browser step drops
   out. The `gpauth` helper from `yuezk/GlobalProtect-openconnect`
   cannot do this: its auth window hard-links libwebkit2gtk and
   needs a display.

2. **Split tunnel that doesn't die at 20 seconds.** If you tell
   `openconnect` or `yuezk/gpclient` to only route `129.94.0.0/16`
   through the VPN, and the gateway's own IP lives inside that
   `/16`, the tunnel comes up cleanly and then dies 20 seconds later
   with `GPST Dead Peer Detection detected dead peer!`. The classic
   fix is the third-party `vpn-slice` script, which reads
   `VPNGATEWAY` from openconnect's environment and pins the gateway
   IP to the pre-tunnel default route before the split routes land.
   **pangolin does that step natively** — `gp-route::apply()` runs
   `ip -4 route get <gw>` to resolve the pre-tunnel path, installs
   a `/32` host-route for the gateway, and restores whatever was
   there (or deletes the pin) on disconnect. `--only` with any
   subnet that contains the gateway Just Works, no extra packages.

3. **Multi-instance tunnels in parallel.** Each `pgn connect` is
   scoped by an `--instance <name>` flag and gets its own control
   socket, TUN device, route set, and DNS state. A consultant with
   three clients can hold three tunnels open at once; no other
   open-source GlobalProtect client supports that today. Combine
   with the systemd template unit for one-per-profile services.

4. **OS-consistent HIP.** `gp-hip` ships plausible HIP profiles
   for Windows, macOS, and Linux, picked from the session's
   `clientos` identity so the HTTP header and the HIP XML never
   disagree. The Windows profile is structurally identical to
   openconnect's reference `trojans/hipreport.sh`; the Linux
   profile omits the categories that make no sense on Linux
   (antivirus, anti-spyware, DLP) and reports iptables + nftables
   + cryptsetup instead.

### Why no embedded browser?

pangolin used to ship a GTK+WebKit SAML window behind a feature
flag. It was removed during the headless-first architecture
cleanup for three reasons:

1. **The dep chain was an ongoing maintenance tax.** gtk-rs
   bindings for gtk3 are in maintenance mode and pinned to
   glib 0.18, which has picked up a handful of
   `#[deprecated]` soundness advisories that we have had to
   manually triage even when our code couldn't reach the
   unsafe paths (the most recent being `RUSTSEC-2024-0429`).
2. **`--auth-mode paste` covers the same UX.** A desktop user
   already has a browser open; handing them a URL to click is
   almost indistinguishable from opening an embedded window,
   and it has the considerable upside that the user's password
   manager, bookmarks, and session cookies all work normally.
3. **Deployment story consistency.** pangolin targets SSH
   sessions, systemd units, containers, and hardened production
   hosts. Making the default build demand a 30-MB GUI runtime
   was contradicting the README's own pitch.

If you really need an in-process webview — kiosk mode, an IdP
that rejects external redirects, a niche scenario we haven't
thought of — open an issue with the concrete requirement.

---

## Install

### From source

You need:

- Rust **1.89+** (2021 edition) — pinned in `rust-toolchain.toml`,
  so `rustup` will install the right version automatically
- `libopenconnect-dev` ≥ 8.20 (with `--protocol=gp` support)
- `libclang-dev` (for `bindgen`)
- `libssl-dev`, `libdbus-1-dev`

No GUI libraries — pangolin's auth flow runs entirely over
stdin + a local HTTP callback, so there's nothing to link
against webkit2gtk or GTK.

Debian / Ubuntu:

```bash
sudo apt install -y libopenconnect-dev libclang-dev libssl-dev \
    libdbus-1-dev pkg-config
```

Fedora / RHEL:

```bash
sudo dnf install -y openconnect-devel clang-devel openssl-devel \
    dbus-devel pkgconf-pkg-config
```

Then:

```bash
git clone https://github.com/kyaky/pangolin
cd pangolin
cargo build --release
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn
```

The resulting binary has ~65 entries in its `ldd` output and
no runtime dependency on GTK, WebKit, GDK, Soup, Cairo, Pango,
or JavaScriptCore — shrinking the footprint relative to any
GP client that embeds a browser by ~30 MB of shared libraries.

### Windows

You need:

- Rust **1.89+** (MSVC toolchain)
- [MSYS2](https://www.msys2.org/) with libopenconnect built from
  source (GnuTLS backend)
- [LLVM/Clang](https://llvm.org/) (for `bindgen` — `libclang.dll`)
- [Wintun](https://www.wintun.net/) driver (`wintun.dll`)

Build steps:

```powershell
# 1. Install MSYS2 dependencies (in MSYS2 MINGW64 terminal)
pacman -S mingw-w64-x86_64-{gnutls,libxml2,zlib,lz4,p11-kit,gmp,nettle,autotools,gcc,pkg-config,libidn2,jq,tools-git}

# 2. Build libopenconnect
cd /tmp && git clone --depth 1 https://gitlab.com/openconnect/openconnect.git
cd openconnect && ./autogen.sh
mkdir -p /mingw64/etc && echo "#!/bin/sh" > /mingw64/etc/vpnc-script && chmod +x /mingw64/etc/vpnc-script
./configure --prefix=/mingw64 --with-gnutls --without-openssl --disable-nls --disable-docs --without-libpskc --without-stoken --without-libpcsclite --with-vpnc-script=/mingw64/etc/vpnc-script
make -j$(nproc) && make install

# 3. Generate MSVC import library (in normal PowerShell/cmd)
gendef /mingw64/bin/libopenconnect-5.dll   # produces .def file
lib.exe /def:libopenconnect-5.def /out:C:\msys64\mingw64\lib\openconnect.lib /machine:x64

# 4. Build pangolin
$env:OPENCONNECT_DIR = "C:\msys64\mingw64"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
cargo build --release

# 5. Copy runtime DLLs + Wintun next to pgn.exe
# (libopenconnect-5.dll + ~20 MinGW runtime DLLs + wintun.dll)
```

Run with **Administrator privileges** (Wintun requires it):

```powershell
.\target\release\pgn.exe connect vpn.example.com --log info
```

---

## Quick start

### SAML via your browser + terminal paste (default)

```bash
sudo -E pgn connect vpn.example.com --only 10.0.0.0/8
```

`pgn` will print something like:

```
┌─ Pangolin — headless SAML authentication ─────────────────────────────────┐
│  Open this URL in any browser (any machine):                              │
│    http://127.0.0.1:29999/                                                │
│                                                                           │
│  Over SSH? Port-forward first:                                            │
│    ssh -L 29999:localhost:29999 …                                         │
│                                                                           │
│  After login, paste the `globalprotectcallback:…` URL here:               │
└───────────────────────────────────────────────────────────────────────────┘
```

Open the printed URL on whatever machine has a browser, complete
your identity provider's flow (Azure AD, Okta, Shibboleth, …),
copy the final `globalprotectcallback:` URL out of the browser's
address bar and paste it back into the terminal. pgn turns TTY
echo off during the paste so the short-TTL JWT doesn't end up in
`script(1)` logs, tmux scrollback, or terminal history. The
tunnel comes up with only `10.0.0.0/8` routed through the VPN —
your SSH connection and the rest of your traffic keep their
normal path.

Works identically from a laptop desktop, an SSH session, a
tmux pane, a systemd service, a distroless container — no
display server required.

### SAML via Okta headless (no browser at all)

```bash
sudo -E pgn connect vpn.example.com \
    --auth-mode okta \
    --okta-url https://my-tenant.okta.com \
    --user alice
```

pgn drives Okta's `/api/v1/authn` transaction directly. Password
comes from `--passwd-on-stdin`; MFA prompts (TOTP, push, SMS)
are served inline in the terminal.

### Windows — SAML via browser + HTTP callback

Run in an **Administrator** PowerShell:

```powershell
pgn.exe connect vpn.example.com --log info
```

pgn prints a local URL. Open it in your browser, complete SAML,
then POST the `globalprotectcallback:` URI back:

```powershell
curl.exe -X POST http://127.0.0.1:29999/callback --data-raw 'globalprotectcallback:cas-as=1&un=...'
```

Use **single quotes** — PowerShell interprets `&` in double quotes.

### Full tunnel

If you want every byte to go through the VPN, point at a real
vpnc-script:

```bash
sudo -E pgn connect vpn.example.com \
    --vpnc-script /etc/vpnc/vpnc-script
```

(install the `vpnc-scripts` package first).

---

## CLI reference (work in progress)

```
pgn connect [PORTAL] [OPTIONS]

Options:
  -u, --user <USER>             Username (rarely needed for SAML)
      --passwd-on-stdin         Read password from stdin (non-SAML auth)
      --os <OS>                 Reported OS: win | mac | linux (default: linux)
      --esp[=BOOL]              Enable ESP/UDP transport (default: on; pass
                                `--esp=false` as an escape hatch when UDP 4501
                                is blocked end-to-end and you want CSTP-only)
      --insecure                Accept invalid TLS certificates
      --vpnc-script <PATH>      vpnc-compatible script for routes/DNS
      --auth-mode <MODE>        paste | okta (default: paste)
      --okta-url <URL>          Okta tenant base URL (required with
                                `--auth-mode okta`)
      --saml-port <PORT>        Local port for paste-mode HTTP server (29999)
      --hip-script <PATH>       Use an external HIP wrapper script instead of
                                pgn's built-in `hip-report` subcommand
      --only <CIDR|IP|HOST>     Comma-separated split-tunnel targets
      --hip <MODE>              HIP reporting: auto (default) | force | off
      --reconnect[=BOOL]        Keep tunnel alive across short network blips
                                (10-min libopenconnect reconnect budget)
  -i, --instance <NAME>         Instance name (drives the control socket
                                path and lets you run multiple tunnels
                                in parallel). Default: "default".

pgn status [-i NAME] [--all]    Show running session(s). 0 live → disconnected.
                                1 live → full details. 2+ live → list view,
                                or pass -i/--all to pick.
pgn disconnect [-i NAME] [--all]
                                Tear down one or every running session.
                                Refuses to guess when 2+ are live.

pgn portal add <NAME> --url <URL> [FLAGS]   Save a portal profile
pgn portal list                             List all saved profiles
pgn portal use <NAME>                       Set the default profile
pgn portal show <NAME>                      Show one profile's details
pgn portal rm <NAME>                        Remove a profile
```

Profiles live in `~/.config/pangolin/config.toml` and store any of
the `pgn connect` flags. Once you've saved one and marked it as
the default, `sudo pgn connect` (no arguments) will pick it up.
CLI flags always override the profile's settings.

### Multiple tunnels at once

Each `pgn connect` is scoped by an **instance name** (defaults to
`default`). Every instance gets its own control socket at
`/run/pangolin/<instance>.sock`, its own TUN device, its own
routes, and its own DNS state, so you can run several tunnels
in parallel:

```bash
sudo pgn connect -i work       work
sudo pgn connect -i client-a   client-a
sudo pgn status --all          # list every live instance
sudo pgn disconnect -i work    # tear down just one
```

No other open-source GlobalProtect client (openconnect, yuezk,
the official Prisma Access Linux client) supports concurrent
tunnels — for consultants / pentesters / migration scenarios,
pangolin is the only option.

`status` and `disconnect` talk to the running `pgn connect`
process(es) over IPC — Unix domain sockets on Linux
(`/run/pangolin/<instance>.sock`, mode `0600`) or Named Pipes on
Windows (`\\.\pipe\pangolin-<instance>`). On Linux the sockets are
created by the root-owned connect processes, so those subcommands
also need `sudo`:

```bash
# Linux
sudo pgn status
sudo pgn disconnect

# Windows (admin PowerShell)
pgn.exe status
pgn.exe disconnect
```

Both support `--json` for machine-readable output. Instance names
must match `[A-Za-z0-9_-]{1,32}`.

## Running as a systemd service

`packaging/systemd/pangolin@.service` is a template unit — one
instance per saved profile, and multiple units run in parallel
without collision.

```bash
sudo install -m 0644 packaging/systemd/pangolin@.service \
    /etc/systemd/system/pangolin@.service
sudo systemctl daemon-reload
sudo systemctl enable --now pangolin@work.service
sudo systemctl enable --now pangolin@client-a.service   # parallel, fully supported
sudo journalctl -u pangolin@work.service -f
```

The instance name (after the `@`) is a saved profile name — it
must match `[A-Za-z0-9_-]{1,32}`, so bare URLs are not supported
as instance names. Save the URL as a profile first. The unit
uses `Restart=on-failure` with a 15-second backoff, plumbs
stdout/stderr to `journald`, and relies on `SIGTERM → cmd pipe`
for clean shutdown (no racy `ExecStop=pgn disconnect`). See
[packaging/systemd/README.md](packaging/systemd/README.md) for
the full install + troubleshooting guide.

---

## How it works

`pangolin` is a Cargo workspace. The interesting crates:

| crate | what it does |
|---|---|
| `gp-proto` | GlobalProtect XML protocol types (no I/O) |
| `gp-auth` | Authentication providers (`Password`, `SamlPaste`, `Okta`) plus the HTTP client for portal/gateway login. The paste provider turns off TTY echo during input so the short-TTL SAML JWT never ends up in `script(1)` logs, terminal scrollback, or tmux capture |
| `gp-tunnel` | Safe wrapper around `libopenconnect`. Owns the VPN session lifecycle, cancellation via `openconnect_setup_cmd_pipe`, and a C trampoline for libopenconnect's variadic progress callback (stable Rust can't define one) |
| `gp-openconnect-sys` | Raw bindgen FFI bindings + the C trampoline shim |
| `gp-route` | Native route management. Linux: `ip(8)`. Windows: `netsh` + `route.exe`. Automatically installs a `/32` host-route pin for the gateway IP before any split route lands (mirrors what `vpn-slice` does with `$VPNGATEWAY`), so `--only` lists that cover the gateway's own subnet don't trigger the 20-second ESP self-loop death |
| `gp-dns` | Native DNS management. Linux: per-interface `resolvectl` on systemd-resolved. Windows: NRPT (Name Resolution Policy Table) via PowerShell — the first open-source GP client to use NRPT for proper split DNS on Windows |
| `gp-ipc` | Cross-platform IPC for `pgn status` / `pgn disconnect`. Linux: Unix domain sockets. Windows: Named Pipes |
| `gp-hip` | HIP (Host Information Profile) report XML generator. OS-aware: ships Windows / macOS / Linux profiles with plausible antivirus / firewall / disk-encryption / disk-backup entries, picked by the caller's `--client-os` choice so the HIP XML and the HTTP `clientos` header always agree. Submission happens via libopenconnect's csd-wrapper slot so the HIP `client_ip` always matches the gateway's view of the session |
| `gp-config` | `~/.config/pangolin/config.toml` schema and atomic load/save. Drives `pgn portal add/rm/list/use/show` |
| `bins/pgn` | The CLI, `tokio`-based |

Architecture rule of thumb: **`libopenconnect` handles the tunnel,
Rust handles everything else.** That includes authentication, portal
config, gateway selection, HIP, route installation, and reconnect
policy. We never reimplement ESP/UDP, never shell out to the
`openconnect` binary, and never run a Python helper script.

---

## Roadmap

### Phase 1 — done

- Workspace scaffold + libopenconnect FFI
- GP protocol types and XML parsing
- Password + SAML paste-mode auth providers
- Prisma Access `globalprotectcallback:` JWT capture
- `pgn connect` end-to-end: prelogin → SAML → portal config → gateway
  login → CSTP → TUN → DPD keepalives
- `--only` client-controlled split tunnel, hostname + CIDR aware
- Clean Ctrl-C cancellation via `openconnect_setup_cmd_pipe`

### Phase 2 — implemented

Everything below is landed, unit-tested, and clippy-clean. Items
marked with the footnote still need live verification against a
production portal before they can be called production-ready.

- `pgn status` / `pgn disconnect` via unix control socket
- Native route management (`gp-route`) — `ip(8)` for now,
  rtnetlink later
- Native DNS management (`gp-dns`) — systemd-resolved backend;
  resolvconf / direct-resolv.conf later
- HIP report generation (`gp-hip`) — XML generator, submitted
  through libopenconnect's csd-wrapper slot (our own `pgn`
  binary is registered via `openconnect_setup_csd`, so the
  wrapper runs inside libopenconnect's session and inherits
  the live `client_ip`, avoiding the getconfig-round-trip
  mismatch that plagued the earlier HTTP-submission path) ¹
- Multi-portal profiles (`gp-config` + `pgn portal add/use/list/
  show/rm`, `~/.config/pangolin/config.toml`)

¹ Not yet exercised against a gateway that actually enforces HIP.

### Phase 2b — implemented

- ~~Application-level auto-reconnect state machine~~ ✅ When
  `--reconnect` is on, pangolin now retries the tunnel up to 10
  times with exponential backoff (5s → 10s → ... → 5min cap),
  keeping the IPC control socket and metrics endpoint alive
  across retries. State flips to `Reconnecting` during backoff
  so `pgn status` reflects reality. Re-auth on cookie expiry
  is the remaining sub-item (Phase 2c) — the current loop
  re-uses the existing gateway cookie, which covers the common
  case where libopenconnect's internal reconnect window was
  simply too short.
- ~~systemd unit~~ ✅ (template at `packaging/systemd/pangolin@.service`)
- ~~Multi-instance parallel tunnels~~ ✅ (per-instance control
  sockets in `gp-ipc`, `pgn connect --instance <name>`, `pgn
  status --all`, `pgn disconnect --all`)
- ~~Prometheus metrics endpoint~~ ✅ (`pgn connect
  --metrics-port 9100` exposes `pangolin_session_info`,
  `pangolin_session_state`, `pangolin_session_uptime_seconds`,
  `pangolin_reconnect_attempts_total`,
  `pangolin_tunnel_restarts_total`, and more)

### Phase 2c — next

- Re-auth on cookie expiry for the auto-reconnect loop (gateway
  cookie re-issue without asking the user to re-do SAML when
  possible)
- Metrics endpoint TLS (rustls-based) for off-host scrapes

### Phase 3 — differentiation

- ~~Okta headless auth (no browser, even for the IdP step)~~ ✅
  Implemented as `--auth-mode okta --okta-url
  https://tenant.okta.com`. Drives `/api/v1/authn` directly with
  full state-machine support for password, TOTP, SMS, push, and
  `PASSWORD_WARN` skip. Push factor polls until the user taps
  approve (or the device times out). Pure Okta state machine is
  unit-tested against canned API responses; the GP-portal SAML
  handoff (post-Okta sessionCookieRedirect → portal headers)
  still needs live verification against a real customer Okta+GP
  pairing — the code is there, the wire format is from
  `_refs/pan-gp-okta` plus Okta API docs, but no integration
  test environment has been available. Webauthn / FIDO2 is
  deferred.
- ~~Windows support~~ ✅ — SAML auth, Wintun tunnel, ESP/UDP,
  NRPT split DNS, netsh route management, Named Pipe IPC.
  Live-verified on Windows 11 against UNSW Prisma Access.
- Client certificate auth (PEM / PKCS#12) ✅
- FIDO2 / YubiKey
- macOS
- NetworkManager plugin
- Windows HIP report submission (builtin XML via HTTP POST,
  bypassing openconnect's unsupported CSD script path)
- Windows service integration (`windows-service` crate)

---

## Contributing

Issues and PRs welcome. Before sending a patch:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The project intentionally has very few dependencies — please justify
new crates in the PR description.

---

## License

Dual-licensed under either of:

- Apache License 2.0 (see [LICENSE-APACHE](LICENSE-APACHE))
- MIT License (see [LICENSE-MIT](LICENSE-MIT))

at your option.

`pangolin` is not affiliated with, endorsed by, or sponsored by Palo
Alto Networks. "GlobalProtect" and "Prisma Access" are trademarks of
their respective owners.
