# Pangolin

> A modern, headless-friendly GlobalProtect VPN client for Linux,
> written in Rust.

`pangolin` (CLI binary `pgn`) connects to Palo Alto Networks
GlobalProtect VPN portals — including modern **Prisma Access**
deployments that use cloud authentication — without needing a desktop
environment, a graphical browser, or `vpn-slice`.

> **Status: early development.** Phase 1 (auth → tunnel handshake)
> is verified end-to-end against a real Prisma Access portal.
> Phase 2 (routing, DNS, daemon mode, multi-portal management,
> HIP reports) is implemented and unit-tested; live verification
> against each feature on production portals is in progress.
> Windows / macOS support is the main Phase 3 item still
> outstanding. See [Roadmap](#roadmap) below.

---

## Why another GlobalProtect client?

There are two main open-source options today:

| | openconnect | yuezk/GlobalProtect-openconnect | **pangolin** |
|---|---|---|---|
| Tunnel | Native ESP/HTTPS | Native (via libopenconnect) | Native (via libopenconnect) |
| SAML auth on a server (no display) | ❌ paste mode only | ❌ requires WebKitGTK window | ✅ **headless paste mode** |
| Prisma Access cloud-auth (`globalprotectcallback:`) | ✅ | ✅ | ✅ |
| Split tunnel without `vpn-slice` | ❌ | ❌ | ✅ **native, hostname-aware** |
| Client-managed routes (`ip(8)` from Rust) | ❌ | ❌ shell script | ✅ `gp-route` |
| CLI-first, daemon-friendly | ⚠️ | ⚠️ GUI-first | ✅ goal |
| HIP report generator + submission | partial | partial | ✅ `gp-hip` + `gp-auth` |
| Multi-portal profiles (config file) | ❌ | partial (GUI-only) | ✅ `pgn portal add/use/list` |
| Native DNS (`resolvectl` per-interface) | ❌ | ❌ | ✅ `gp-dns` |

The two things that already make `pangolin` worth using over the
alternatives:

1. **Headless SAML.** `pgn connect --auth-mode paste` starts a tiny
   local HTTP server and walks you through completing SAML in *any*
   browser on *any* machine (the SSH-port-forward case is a one-liner).
   No display, no embedded WebKit, no `xvfb` workaround. The yuezk
   client cannot do this — its `gpauth` is hard-coded to spawn a
   webkit2gtk window.
2. **Client-controlled split tunnel, managed natively.** `pgn connect
   --only 10.0.0.0/8,intranet.example.com` resolves the hostnames
   before the tunnel comes up, then the `gp-route` crate installs
   *only* those routes through the VPN using `ip(8)` directly from
   Rust — no shell vpnc-script in the loop, no `vpn-slice`
   dependency, no `CISCO_SPLIT_INC_*` env-var plumbing. The default
   route is left untouched, so your SSH session (and anything else
   not explicitly routed) keeps using its normal path. Routes are
   reverted on disconnect.

A graphical webview path is still available for users who prefer it
(`--auth-mode webview`, default when you have a display).

---

## Install

### From source

You need:

- Rust **1.80+** (2021 edition)
- `libopenconnect-dev` ≥ 8.20 (with `--protocol=gp` support)
- `libclang-dev` (for `bindgen`)
- `libssl-dev`, `libdbus-1-dev`
- For the optional `webview` SAML mode: `libwebkit2gtk-4.1-dev`,
  `libgtk-3-dev`, plus a working display (X11, Wayland, or WSLg)

Debian / Ubuntu:

```bash
sudo apt install -y libopenconnect-dev libclang-dev libssl-dev \
    libdbus-1-dev libwebkit2gtk-4.1-dev libgtk-3-dev pkg-config
```

Fedora / RHEL:

```bash
sudo dnf install -y openconnect-devel clang-devel openssl-devel \
    dbus-devel webkit2gtk4.1-devel gtk3-devel pkgconf-pkg-config
```

Then:

```bash
git clone https://github.com/kyaky/pangolin
cd pangolin
cargo build --release
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn
```

If you only need headless mode and want to skip the webview deps:

```bash
cargo build --release --no-default-features
```

---

## Quick start

### Headless (server / SSH / container)

```bash
sudo -E pgn connect vpn.example.com \
    --auth-mode paste \
    --only 10.0.0.0/8
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

Open the printed URL on whatever machine has a browser, complete your
identity provider's flow (Azure AD, Okta, Shibboleth, …), copy the
final `globalprotectcallback:` URL out of the browser's address bar
and paste it back into the terminal. The tunnel comes up with only
`10.0.0.0/8` routed through the VPN — your SSH connection survives.

### Desktop (graphical)

```bash
sudo -E pgn connect vpn.example.com
```

By default `pgn` opens a small WebKitGTK window for the SAML flow.

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
      --os <OS>                 Reported OS: win | mac | linux (default: win)
      --insecure                Accept invalid TLS certificates
      --vpnc-script <PATH>      vpnc-compatible script for routes/DNS
      --auth-mode <MODE>        webview | paste (default: webview)
      --saml-port <PORT>        Local port for paste-mode HTTP server (29999)
      --only <CIDR|IP|HOST>     Comma-separated split-tunnel targets
      --hip <MODE>              HIP reporting: auto (default) | force | off
      --reconnect[=BOOL]        Keep tunnel alive across short network blips
                                (10-min libopenconnect reconnect budget)

pgn status                     Show the running session (or "disconnected")
pgn disconnect                 Tear down the running session

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

`status` and `disconnect` talk to the running `pgn connect` process
over a Unix control socket at `/run/pangolin/pangolin.sock` (mode
`0600`, owner-only). Because the socket is created by the root-owned
connect process, those subcommands also need `sudo`:

```bash
sudo pgn status
sudo pgn disconnect
```

Both support `--json` for machine-readable output.

## Running as a systemd service

`packaging/systemd/pangolin@.service` is a template unit — one
instance per saved profile.

```bash
sudo install -m 0644 packaging/systemd/pangolin@.service \
    /etc/systemd/system/pangolin@.service
sudo systemctl daemon-reload
sudo systemctl enable --now pangolin@work.service
sudo journalctl -u pangolin@work.service -f
```

The instance name (after the `@`) is whatever you'd type to
`pgn connect` — a saved profile name OR a bare URL. The unit
uses `Restart=on-failure` with a 15-second backoff, plumbs
stdout/stderr to `journald`, and calls `pgn disconnect` on
stop so the tunnel tears down through the same code path as
`Ctrl-C`. See [packaging/systemd/README.md](packaging/systemd/README.md)
for the full install + troubleshooting guide.

---

## How it works

`pangolin` is a Cargo workspace. The interesting crates:

| crate | what it does |
|---|---|
| `gp-proto` | GlobalProtect XML protocol types (no I/O) |
| `gp-auth` | Authentication providers (`Password`, `SamlBrowser`, `SamlPaste`) and the HTTP client for portal/gateway login |
| `gp-tunnel` | Safe wrapper around `libopenconnect`. Owns the VPN session lifecycle, cancellation via `openconnect_setup_cmd_pipe`, and a C trampoline for libopenconnect's variadic progress callback (stable Rust can't define one) |
| `gp-openconnect-sys` | Raw bindgen FFI bindings + the C trampoline shim |
| `gp-route` | Native route / address / link management via `ip(8)`. Installs and reverts split-tunnel routes after `setup_tun_device` returns — no shell script in the loop |
| `gp-dns` | Native DNS management. Per-interface `resolvectl` on systemd-resolved hosts; graceful no-op + warning elsewhere |
| `gp-ipc` | Unix control socket protocol (serde JSON) for `pgn status` / `pgn disconnect` |
| `gp-hip` | HIP (Host Information Profile) report XML generator. Introspects hostname and machine id, ships a Windows-spoofed `HostProfile` with plausible antivirus/firewall/disk-encryption entries. HTTP submission via `gp-auth::GpClient::submit_hip_report` |
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
- Password + SAML (webview + paste) auth providers
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
- HIP report generation (`gp-hip`) — XML generator + HTTP
  submission via `gp-auth::GpClient`  ¹
- Multi-portal profiles (`gp-config` + `pgn portal add/use/list/
  show/rm`, `~/.config/pangolin/config.toml`)

¹ Not yet exercised against a gateway that actually enforces HIP.

### Phase 2b — next

- Application-level auto-reconnect state machine. The current
  `--reconnect` flag bumps libopenconnect's internal reconnect
  budget from 60 seconds to 10 minutes, which covers brief
  blips. A full retry-after-libopenconnect-gives-up loop with
  exponential backoff and re-auth on cookie expiry is the
  next step. (`SessionState::Reconnecting` is already wired
  into the IPC snapshot, ready to be flipped.)
- ~~systemd unit~~ ✅ (template at `packaging/systemd/pangolin@.service`)
- Prometheus metrics endpoint

### Phase 3 — differentiation

- Okta headless auth (no browser, even for the IdP step)
- Client certificate auth (PEM / PKCS#12)
- FIDO2 / YubiKey
- macOS, Windows
- NetworkManager plugin

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
