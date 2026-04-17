<p align="center">
  <h1 align="center">Pangolin</h1>
  <p align="center">
    A modern, open-source GlobalProtect VPN client for <b>Linux</b> and <b>Windows</b>.<br>
    Written in Rust. Headless-first. No GUI dependencies.
  </p>
  <p align="center">
    <a href="https://github.com/kyaky/pangolin/actions/workflows/ci.yml"><img src="https://github.com/kyaky/pangolin/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/kyaky/pangolin/releases/latest"><img src="https://img.shields.io/github/v/release/kyaky/pangolin?include_prereleases&label=release" alt="Release"></a>
    <a href="https://github.com/kyaky/pangolin/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  </p>
</p>

---

**pangolin** (`pgn`) connects to Palo Alto Networks GlobalProtect VPN portals — including **Prisma Access** with cloud authentication — without a desktop environment, graphical browser, or `vpn-slice`.

> **Download:** [Latest Release](https://github.com/kyaky/pangolin/releases/latest) (Linux + Windows pre-built binaries)

---

## Highlights

| | pangolin |
|---|---|
| **Single binary** | One `pgn` executable. No Python helpers, no webkit2gtk, no sidecar processes. |
| **Headless SAML** | Browser-of-your-choice + local HTTP callback. Works over SSH, in containers, in systemd units. Okta headless mode needs no browser at all. |
| **Split tunnel that works** | Built-in gateway `/32` pin prevents the 20-second ESP death loop that plagues openconnect + vpn-slice setups. `--only` Just Works. |
| **Windows native** | Wintun + ESP tunnel, NRPT split DNS, Named Pipe IPC. First open-source GP client with proper Windows split DNS. |
| **Multi-instance** | `pgn connect -i work` + `pgn connect -i client-a` — parallel tunnels with independent routes and DNS. |
| **OS-aware HIP** | Plausible host integrity profiles for Windows, macOS, and Linux — matched to the session's `clientos`. |
| **Prometheus metrics** | `--metrics-port 9100` for monitoring dashboards. |
| **systemd ready** | Template unit `pangolin@.service` — one service per saved profile. |

---

## Quick start

### Linux — split tunnel with SAML

```bash
sudo -E pgn connect vpn.example.com \
    --only 10.0.0.0/8,172.16.0.0/12
```

pgn starts a local HTTP server, prints a URL. Open it in any browser, complete SAML, paste the `globalprotectcallback:` URL back. Done — only the specified subnets route through the VPN.

### Linux — Okta headless (no browser)

```bash
sudo -E pgn connect vpn.example.com \
    --auth-mode okta --okta-url https://tenant.okta.com --user alice
```

Drives Okta's API directly. Supports password, TOTP, push, SMS.

### Windows — SAML with split tunnel

Run in an **Administrator** PowerShell:

```powershell
pgn.exe connect vpn.example.com --only 10.0.0.0/8,172.16.0.0/12 --log info
```

Open the printed URL in your browser, complete SAML, then POST the callback:

```powershell
curl.exe -X POST http://127.0.0.1:29999/callback --data-raw 'globalprotectcallback:...'
```

> Use **single quotes** — PowerShell interprets `&` in double quotes.

### Verify

```bash
# Should go through VPN
ping 10.0.0.1

# Should still be your home IP (not tunneled)
curl https://ifconfig.me
```

---

## Install

### Pre-built binaries

Download from [Releases](https://github.com/kyaky/pangolin/releases/latest):

| Platform | Archive | Notes |
|----------|---------|-------|
| Linux x86_64 | `pangolin-linux-x86_64.tar.gz` | Requires `libopenconnect` at runtime |
| Windows x86_64 | `pangolin-windows-x86_64.zip` | Includes all DLLs + Wintun driver. Run as Administrator. |

### Build from source — Linux

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install -y libopenconnect-dev libclang-dev libssl-dev libdbus-1-dev pkg-config

# Build
git clone https://github.com/kyaky/pangolin && cd pangolin
cargo build --release
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn
```

<details>
<summary><b>Build from source — Windows</b></summary>

Requires MSYS2, LLVM, and a manual libopenconnect build:

```powershell
# 1. In MSYS2 MINGW64 terminal: install deps + build libopenconnect
pacman -S mingw-w64-x86_64-{gnutls,libxml2,zlib,lz4,p11-kit,gmp,nettle,autotools,gcc,pkg-config,libidn2,jq,tools-git}
cd /tmp && git clone --depth 1 https://gitlab.com/openconnect/openconnect.git && cd openconnect
./autogen.sh && mkdir -p /mingw64/etc && echo "#!/bin/sh" > /mingw64/etc/vpnc-script && chmod +x /mingw64/etc/vpnc-script
./configure --prefix=/mingw64 --with-gnutls --without-openssl --disable-nls --disable-docs \
    --without-libpskc --without-stoken --without-libpcsclite --with-vpnc-script=/mingw64/etc/vpnc-script
make -j$(nproc) && make install

# 2. In MSYS2: generate .def file
gendef /mingw64/bin/libopenconnect-5.dll

# 3. In PowerShell: create MSVC import library
lib.exe /def:C:\msys64\tmp\libopenconnect-5.def /out:C:\msys64\mingw64\lib\openconnect.lib /machine:x64

# 4. Build pangolin
$env:OPENCONNECT_DIR = "C:\msys64\mingw64"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
cargo build --release
```

Copy `libopenconnect-5.dll`, MinGW runtime DLLs, and [`wintun.dll`](https://www.wintun.net/) next to `pgn.exe`.

</details>

---

## CLI reference

```
pgn connect [PORTAL] [OPTIONS]
    -u, --user <USER>           Username
    --passwd-on-stdin            Read password from stdin
    --only <CIDR,CIDR,...>       Split-tunnel targets (comma-separated)
    --auth-mode <paste|okta>     Authentication method (default: paste)
    --okta-url <URL>             Okta tenant URL (with --auth-mode okta)
    --os <win|mac|linux>         Reported OS (default: linux)
    --esp[=BOOL]                 ESP/UDP transport (default: on)
    --reconnect[=BOOL]           Auto-reconnect on disconnect
    --hip <auto|force|off>       HIP reporting mode
    --metrics-port <PORT>        Prometheus endpoint
    -i, --instance <NAME>        Instance name for parallel tunnels
    --vpnc-script <PATH>         External route/DNS script
    --insecure                   Accept invalid TLS certificates

pgn status [-i NAME | --all]     Show running session(s)
pgn disconnect [-i NAME | --all] Tear down session(s)

pgn portal add <NAME> --url <URL> [FLAGS]   Save a profile
pgn portal list                             List profiles
pgn portal use <NAME>                       Set default
pgn portal show <NAME>                      Show details
pgn portal rm <NAME>                        Remove

pgn diagnose <PORTAL>           DNS + TCP + TLS connectivity check
pgn completions <bash|zsh|fish> Generate shell completions
```

All commands support `--json` for machine-readable output.

---

## Comparison

|  | openconnect | yuezk v2 | **pangolin** |
|--|:-----------:|:--------:|:------------:|
| Single binary, no GUI deps | | | **yes** |
| Split tunnel without vpn-slice | | | **yes** |
| Headless SAML (no webview) | | | **yes** |
| Okta headless API | | | **yes** |
| Windows tunnel (Wintun + ESP) | experimental | | **yes** |
| Windows NRPT split DNS | | | **yes** |
| Parallel multi-instance tunnels | | | **yes** |
| OS-aware HIP reports | partial | partial | **yes** |
| Prometheus metrics | | | **yes** |
| systemd template | | partial | **yes** |
| Client certificate auth | yes | | **yes** |
| Non-GP protocols (AnyConnect, etc.) | yes | | |
| macOS | yes | yes | planned |
| 15+ years production maturity | yes | | |

---

## Architecture

```
pgn connect vpn.example.com --only 10.0.0.0/8
    |
    v
 gp-auth          Prelogin -> SAML/Password/Okta -> Portal config -> Gateway login
    |
    v
 gp-tunnel         libopenconnect FFI: CSTP -> TUN device -> ESP/UDP
    |
    v
 gp-route          Install split routes + gateway pin (ip/netsh)
    |
    v
 gp-dns            Split DNS (systemd-resolved / NRPT)
    |
    v
 gp-ipc            Control socket (Unix) / Named Pipe (Windows)
```

| Crate | Role |
|-------|------|
| `gp-proto` | GP XML protocol types (no I/O) |
| `gp-auth` | Auth providers: Password, SAML paste, Okta headless |
| `gp-tunnel` | Safe libopenconnect wrapper (session lifecycle, cancellation) |
| `gp-openconnect-sys` | bindgen FFI + C variadic trampoline |
| `gp-route` | Route management — Linux: `ip(8)`, Windows: `netsh`/`route.exe` |
| `gp-dns` | DNS — Linux: `resolvectl`, Windows: NRPT via PowerShell |
| `gp-ipc` | IPC — Linux: Unix sockets, Windows: Named Pipes |
| `gp-hip` | OS-aware HIP report XML generator |
| `gp-config` | Profile storage (`~/.config/pangolin/config.toml`) |

**Design rule:** libopenconnect handles the tunnel. Rust handles everything else.

---

## Multiple tunnels

```bash
sudo pgn connect -i work       vpn.work.com    --only 10.0.0.0/8
sudo pgn connect -i client-a   vpn.client.com  --only 172.16.0.0/12
sudo pgn status --all
sudo pgn disconnect -i work
```

Each instance gets its own TUN device, routes, DNS, and control socket. No other open-source GP client supports this.

---

## systemd service

```bash
sudo install -m 0644 packaging/systemd/pangolin@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pangolin@work.service
sudo journalctl -u pangolin@work.service -f
```

The instance name is a saved profile. Uses `Restart=on-failure` with 15-second backoff.

---

## Roadmap

- [x] Phase 1 — Auth + tunnel handshake (SAML, password, ESP, CSTP)
- [x] Phase 2 — Routes, DNS, HIP, profiles, auto-reconnect, systemd, metrics
- [x] Phase 3a — Okta headless, client certificates, Windows support
- [ ] Phase 3b — macOS, FIDO2/YubiKey, NetworkManager, Windows service

---

## Contributing

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Justify new crate dependencies in the PR description.

---

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.

*Not affiliated with Palo Alto Networks. "GlobalProtect" and "Prisma Access" are trademarks of their respective owners.*
