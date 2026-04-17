# systemd integration

`openprotect@.service` is a systemd template unit. One instance per
saved portal profile, and thanks to openprotect's per-instance control
sockets you can run several units **in parallel** — e.g. a `work`
tunnel and a `client-a` tunnel side by side, each with its own TUN
device, routes, DNS, and `/run/openprotect/<instance>.sock`.

## Install

```bash
# 1. Install the binary (cargo build --release done first).
sudo install -m 0755 target/release/opc /usr/local/bin/opc

# 2. Make sure the tun kernel module is loaded at boot.
#    The unit enables `ProtectKernelModules=yes` which blocks
#    auto-load from inside the sandbox, so if your distro
#    ships tun as a loadable module (Debian/Ubuntu default)
#    it has to be present before the unit starts — otherwise
#    opc's first `openconnect_setup_tun_device` call fails
#    with `ENODEV`.
echo tun | sudo tee /etc/modules-load.d/tun.conf
sudo modprobe tun

# 3. Create at least one portal profile.
#    The profile name is what you'll pass as the systemd instance
#    below, and it must match [A-Za-z0-9_-]{1,32}.
sudo opc portal add work \
    --url https://vpn.corp.example.com \
    --auth-mode paste \
    --only 10.0.0.0/8 \
    --hip auto \
    --reconnect

# 4. Drop the unit file in place and reload systemd.
sudo install -m 0644 packaging/systemd/openprotect@.service \
    /etc/systemd/system/openprotect@.service
sudo systemctl daemon-reload
```

### Sandboxing

The unit ships with aggressive systemd sandboxing enabled:
`NoNewPrivileges`, a minimal `CapabilityBoundingSet`
(`CAP_NET_ADMIN` + `CAP_NET_RAW` only), `ProtectSystem=strict`,
`ProtectHome=read-only`, `ProtectKernel*=yes`,
`ProtectControlGroups=yes`, `RestrictNamespaces=yes`,
`RestrictAddressFamilies` limited to `AF_UNIX` + `AF_INET` +
`AF_INET6` + `AF_NETLINK`, `SystemCallFilter=@system-service`
with `~@privileged ~@resources` subtracted, private `/tmp`,
private kernel keyring, and umask `0077`.

After installing the unit into `/etc/systemd/system/`, verify
the score with:

```bash
sudo systemd-analyze security openprotect@work.service
```

You should see an exposure level in the **2.x OK** band.
(An approximate 2.3 was measured during development via a
`~/.config/systemd/user/` workaround because the dev VPS
didn't have non-interactive sudo; your score on a real
system install will be in the same band but may differ by
±0.1 depending on your systemd version and what other
directives the host's `system.conf` defaults set.)

The unit still runs as `User=root` because CAP_NET_ADMIN
and CAP_NET_RAW are required for tun device management and
ESP raw sockets, and dropping to a non-root user would need
relocating the config directory out of `/root/.config/openprotect`
and chowning `/run/openprotect` to an openprotect-specific user —
a bigger refactor than the hardening pass itself. Today's
unit bounds what a compromised root opc process can reach:
no other users' home directories, no kernel tunables, no
other networking families, no namespace creation, and no
suid/sgid bit creation. The main surviving exposures are
the things that would break opc's job: access to
`/dev/net/tun` (`PrivateDevices=yes` is not enabled), the
host's network stack (`PrivateNetwork=yes` is not enabled,
obviously), and the read-only `/root/.config/openprotect`
config file.

### Further hardening you can try

If you want to push the score below 2.0 on your host, the
two realistic wins both need a live tunnel for verification:

* **`DevicePolicy=closed` + `DeviceAllow=/dev/net/tun rw`** —
  block every character / block device except the one
  explicitly listed. Needs a live boot test because tun
  device creation has ordering interactions with cgroup
  device rules, and I didn't want to ship it untested in
  the main unit. Worth ~0.2 in the exposure score.
* **`User=openprotect` + `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`** —
  drop to a non-root user. This is the biggest single
  remaining exposure (0.4) but requires relocating
  `/root/.config/openprotect` to `/etc/openprotect/` (or
  chowning it) and chowning `/run/openprotect` via
  `RuntimeDirectory=` mode + user owner. Bigger change
  than a single unit-file tweak.

### If you use `--hip-script`

A word of warning if you set `hip_script = "/path/to/my-wrapper"`
in your saved profile (or pass `--hip-script` to `opc
connect`): the wrapper script runs **inside the same
sandbox** as opc itself. libopenconnect `fork+execv`s the
wrapper from within the CSTP flow, which means the child
inherits:

* The same `CapabilityBoundingSet` (CAP_NET_ADMIN +
  CAP_NET_RAW, nothing else).
* The same `NoNewPrivileges` flag — the wrapper cannot
  gain any capability via setuid bits on its binary.
* The same filesystem view: `ProtectSystem=strict`,
  `ProtectHome=read-only`, private `/tmp`, read-only
  `/root/.config/openprotect`.
* The same `SystemCallFilter=@system-service ~@privileged
  ~@resources` seccomp rules.
* The same `RestrictAddressFamilies` + `RestrictNamespaces`
  restrictions.

This is usually what you want — a compromised HIP wrapper
is constrained to the same surface as opc. But if your
wrapper needs something the sandbox denies, you have to
loosen the unit explicitly. Common cases:

* The wrapper writes a temp file to `/root` or `/home/…` →
  add the target directory to `ReadWritePaths=` OR move
  the wrapper's scratch path under `/var/lib/openprotect`
  (which you'd then declare via `StateDirectory=openprotect`).
* The wrapper shells out to a binary in `/usr/local/bin`
  that needs CAP_DAC_OVERRIDE → you probably shouldn't be
  running that binary at all from a VPN credential path,
  but if you must, expand `CapabilityBoundingSet=` with
  exactly the one extra capability and document why in
  your local fork of the unit.
* The wrapper needs to read `/dev/something` → add
  `BindPaths=/dev/something`.

The safest pattern is to keep custom HIP wrappers stateless
— read the four argv values libopenconnect passes
(`--cookie`, `--client-ip`, `--md5`, `--client-os`), emit
HIP XML to stdout, exit 0. openconnect's own
`trojans/hipreport.sh` is a clean example.

## Use

The instance name (`%i`) after the `@` is a profile name saved
with `opc portal add`. Bare URLs are not supported as instance
names — they would collide with systemd's own `%i` escaping rules
and with openprotect's `[A-Za-z0-9_-]{1,32}` validator. Save them as
profiles first.

```bash
# Start the "work" profile and enable it at boot.
sudo systemctl enable --now openprotect@work.service

# Tail the live log.
sudo journalctl -u openprotect@work.service -f

# Stop and disable.
sudo systemctl disable --now openprotect@work.service

# Run a second profile in parallel — fully supported. Each
# instance gets its own /run/openprotect/<name>.sock, its own tun
# device, its own routes, and its own DNS state.
sudo systemctl enable --now openprotect@client-a.service
```

`opc status` and `opc disconnect` are instance-aware:

```bash
# List every live instance.
sudo opc status --all

# Query just one.
sudo opc status -i work

# Disconnect just one.
sudo opc disconnect -i work

# Disconnect everything.
sudo opc disconnect --all
```

With no flags:

* `opc status` prints a `disconnected` line if nothing is running,
  full details for a single live instance, or the list view if two
  or more are live.
* `opc disconnect` disconnects a single live instance without
  asking, but **refuses** if two or more are live — pass
  `--instance <name>` or `--all` to be explicit. This is on
  purpose: silently picking a target when the user was ambiguous
  is how you accidentally tear down the wrong tunnel.

## Restart policy

`openprotect@.service` uses `Restart=on-failure` with a 15-second
backoff and a burst limit of 5 restarts per 10 minutes. That's
aggressive enough to recover from a transient network blip while
still backing off if the portal is permanently broken (e.g.
expired credentials).

For longer-term resilience, also pass `--reconnect` (or set
`reconnect = true` in the profile, which is what the install
example above does). That bumps libopenconnect's internal
reconnect budget from 60 seconds to 10 minutes, so brief
outages are handled by the existing tunnel without systemd
needing to restart anything.

## Clean shutdown

The unit intentionally has **no `ExecStop=`**. Systemd sends
`SIGTERM` on `systemctl stop`, opc's signal handler translates
that into the libopenconnect cmd-pipe path, and the tunnel tears
down on exactly the same code path as `Ctrl-C` in foreground
mode. An `ExecStop=/usr/local/bin/opc disconnect` line would
race that path because `opc disconnect` returns as soon as the
IPC server acknowledges the request, not when the tunnel is
actually down.

## Troubleshooting

Common failure modes:

* **`opc: no portal given and no default profile set`** — the
  instance name doesn't match any saved profile. Run
  `sudo opc portal list` to see what's saved.
* **`instance name … contains an invalid character`** — the
  instance name isn't `[A-Za-z0-9_-]{1,32}`. Rename the profile.
* **`another opc instance is already running at /run/openprotect/<name>.sock`**
  — you already have a `openprotect@<name>.service` up (possibly a
  stale one from a previous session). `systemctl status openprotect@<name>`
  to check, or `sudo opc status --all` to see the live list.
* **`Failed to bind local tun device (TUNSETIFF): Operation
  not permitted`** — the unit started without `User=root`,
  or the install path is wrong. Check `systemctl cat
  openprotect@<name>.service`.
* **Repeated restarts hitting `StartLimitBurst`** — systemd
  has stopped trying. Look at `journalctl -u openprotect@<name>
  --since "5 minutes ago"` to see why the connect failed,
  fix the underlying issue, then `systemctl reset-failed
  openprotect@<name>` before re-enabling.
