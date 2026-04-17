<p align="center">
  <h1 align="center">OpenProtect</h1>
  <p align="center">
    A modern, open-source GlobalProtect VPN client for <b>Windows</b> and <b>Linux</b>.<br>
    CLI + GUI desktop app, written in Rust.
  </p>
  <p align="center">
    <a href="https://github.com/kyaky/openprotect/actions/workflows/ci.yml"><img src="https://github.com/kyaky/openprotect/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/kyaky/openprotect/releases/latest"><img src="https://img.shields.io/github/v/release/kyaky/openprotect?include_prereleases&label=release" alt="Release"></a>
    <a href="https://github.com/kyaky/openprotect/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  </p>
</p>

---

**OpenProtect** connects to Palo Alto Networks GlobalProtect VPN portals — including **Prisma Access** with cloud authentication — with both a **desktop GUI** and a powerful **CLI** (`opc`).

> **Download:** [Latest Release](https://github.com/kyaky/openprotect/releases/latest) (Windows GUI + CLI, Linux CLI)

---

## Desktop GUI

The GUI (`opc-gui`) provides a clean, modern interface for connecting to GlobalProtect VPN:

```
 ┌──────────────────────────────────────────────────────┐
 │  ┌──────────┐  ┌──────────────────────────────────┐  │
 │  │          │  │                                  │  │
 │  │ OPEN     │  │  Connect to VPN                  │  │
 │  │ PROTECT  │  │                                  │  │
 │  │          │  │  Portal address                  │  │
 │  │ * Conn.  │  │  ┌────────────────────────────┐  │  │
 │  │          │  │  │ vpn.example.com            │  │  │
 │  │ ● Status │  │  └────────────────────────────┘  │  │
 │  │          │  │                                  │  │
 │  │──────────│  │  Username (optional)             │  │
 │  │          │  │  ┌────────────────────────────┐  │  │
 │  │ Connect  │  │  │ user@example.com           │  │  │
 │  │ Logs     │  │  └────────────────────────────┘  │  │
 │  │ About    │  │                                  │  │
 │  │          │  │  Split tunnel routes (optional)  │  │
 │  │          │  │  ┌────────────────────────────┐  │  │
 │  │          │  │  │ 10.0.0.0/8, 172.16.0.0/12 │  │  │
 │  │          │  │  └────────────────────────────┘  │  │
 │  │          │  │                                  │  │
 │  │          │  │  ┌────────────────────────────┐  │  │
 │  │          │  │  │        Connect             │  │  │
 │  │          │  │  └────────────────────────────┘  │  │
 │  │          │  │                                  │  │
 │  └──────────┘  └──────────────────────────────────┘  │
 └──────────────────────────────────────────────────────┘
```

**Features:**

- **One-click SAML** — Click Connect, browser opens automatically, paste the callback URL and it auto-submits
- **Split tunnel** — Enter comma-separated CIDRs, routes are applied automatically
- **System tray** — Close to tray, double-click to restore, colored status icon (green/yellow/red)
- **Real-time logs** — View connection logs with verbose/info toggle
- **Cancel & reconnect** — Cancel mid-connection and retry without restarting
- **Dark theme** — Modern slate + blue accent color scheme

---

## Highlights

| | OpenProtect |
|---|---|
| **Desktop GUI** | egui-based dark-themed app with system tray, SAML browser flow, split tunnel input. |
| **Single binary CLI** | One `opc` executable. No Python helpers, no webkit2gtk, no sidecar processes. |
| **Headless SAML** | Browser-of-your-choice + local HTTP callback. Works over SSH, in containers, in systemd units. |
| **Okta headless** | Drives Okta API directly — password, TOTP, push, SMS. No browser needed. |
| **Split tunnel** | Built-in gateway pin prevents the 20-second ESP death loop. `--only` Just Works. |
| **Windows native** | Wintun + ESP tunnel, NRPT split DNS, Named Pipe IPC. |
| **Multi-instance** | `opc connect -i work` + `opc connect -i client-a` — parallel tunnels. |
| **OS-aware HIP** | Plausible host integrity profiles for Windows, macOS, and Linux. |
| **Prometheus metrics** | `--metrics-port 9100` for monitoring dashboards. |
| **systemd ready** | Template unit `openprotect@.service` — one service per saved profile. |

---

## Quick start

### Windows GUI (recommended)

1. Download `openprotect-gui-windows-x86_64.zip` from [Releases](https://github.com/kyaky/openprotect/releases/latest)
2. Extract and run `opc-gui.exe` as **Administrator**
3. Enter your portal address, click **Connect**
4. Complete SAML in the browser, right-click "click here" -> Copy Link
5. Paste the link in the GUI — it auto-submits and connects

### Windows CLI

Run in an **Administrator** PowerShell:

```powershell
opc.exe connect vpn.example.com --only 10.0.0.0/8,172.16.0.0/12 --log info
```

Open the printed URL in your browser, complete SAML, then POST the callback:

```powershell
curl.exe -X POST http://127.0.0.1:29999/callback --data-raw 'globalprotectcallback:...'
```

> Use **single quotes** — PowerShell interprets `&` in double quotes.

### Linux — split tunnel with SAML

```bash
sudo -E opc connect vpn.example.com \
    --only 10.0.0.0/8,172.16.0.0/12
```

opc starts a local HTTP server, prints a URL. Open it in any browser, complete SAML, paste the `globalprotectcallback:` URL back.

### Linux — Okta headless (no browser)

```bash
sudo -E opc connect vpn.example.com \
    --auth-mode okta --okta-url https://tenant.okta.com --user alice
```

Drives Okta's API directly. Supports password, TOTP, push, SMS.

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

Download from [Releases](https://github.com/kyaky/openprotect/releases/latest):

| Platform | Archive | Notes |
|----------|---------|-------|
| Windows GUI | `openprotect-gui-windows-x86_64.zip` | `opc.exe` + `opc-gui.exe` + DLLs + Wintun. Run as Administrator. |
| Windows CLI | `openprotect-cli-windows-x86_64.zip` | `opc.exe` + DLLs + Wintun. Run as Administrator. |
| Linux x86_64 | `openprotect-cli-linux-x86_64.tar.gz` | Requires `libopenconnect` at runtime. |

### Build from source — Linux

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install -y libopenconnect-dev libclang-dev libssl-dev libdbus-1-dev pkg-config

# Build
git clone https://github.com/kyaky/openprotect && cd openprotect
cargo build --release
sudo install -m 0755 target/release/opc /usr/local/bin/opc
```

### Build from source — Windows

<details>
<summary>Click to expand</summary>

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

# 4. Build openprotect
$env:OPENCONNECT_DIR = "C:\msys64\mingw64"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
cargo build --release

# 5. Build GUI (standalone, excluded from workspace)
cd bins/opc-gui && cargo build --release
```

Copy `libopenconnect-5.dll`, MinGW runtime DLLs, and [`wintun.dll`](https://www.wintun.net/) next to `opc.exe` / `opc-gui.exe`.

</details>

---

## CLI reference

```
opc connect [PORTAL] [OPTIONS]
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

opc status [-i NAME | --all]     Show running session(s)
opc disconnect [-i NAME | --all] Tear down session(s)

opc portal add <NAME> --url <URL> [FLAGS]   Save a profile
opc portal list                             List profiles
opc portal use <NAME>                       Set default
opc portal show <NAME>                      Show details
opc portal rm <NAME>                        Remove

opc diagnose <PORTAL>           DNS + TCP + TLS connectivity check
opc completions <bash|zsh|fish> Generate shell completions
```

All commands support `--json` for machine-readable output.

---

## Comparison

|  | openconnect | yuezk v2 | **OpenProtect** |
|--|:-----------:|:--------:|:------------:|
| Desktop GUI | | GTK/WebKit | **egui (no deps)** |
| Single binary CLI | | | **yes** |
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
opc connect vpn.example.com --only 10.0.0.0/8
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
| `gp-config` | Profile storage (`~/.config/openprotect/config.toml`) |
| `opc` | CLI binary |
| `opc-gui` | Desktop GUI (egui + system tray) |

**Design rule:** libopenconnect handles the tunnel. Rust handles everything else.

---

## Multiple tunnels

```bash
sudo opc connect -i work       vpn.work.com    --only 10.0.0.0/8
sudo opc connect -i client-a   vpn.client.com  --only 172.16.0.0/12
sudo opc status --all
sudo opc disconnect -i work
```

Each instance gets its own TUN device, routes, DNS, and control socket.

---

## systemd service

```bash
sudo install -m 0644 packaging/systemd/openprotect@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openprotect@work.service
sudo journalctl -u openprotect@work.service -f
```

The instance name is a saved profile. Uses `Restart=on-failure` with 15-second backoff.

---

## Roadmap

- [x] Phase 1 — Auth + tunnel handshake (SAML, password, ESP, CSTP)
- [x] Phase 2 — Routes, DNS, HIP, profiles, auto-reconnect, systemd, metrics
- [x] Phase 3a — Okta headless, client certificates, Windows support
- [x] Phase 3b — Desktop GUI (egui), system tray, SAML browser flow
- [ ] Phase 4 — macOS, FIDO2/YubiKey, NetworkManager, Windows service, auto-connect

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
