# systemd integration

`pangolin@.service` is a systemd template unit. One instance per
saved portal profile, and thanks to pangolin's per-instance control
sockets you can run several units **in parallel** — e.g. a `work`
tunnel and a `client-a` tunnel side by side, each with its own TUN
device, routes, DNS, and `/run/pangolin/<instance>.sock`.

## Install

```bash
# 1. Install the binary (cargo build --release done first).
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn

# 2. Make sure the tun kernel module is loaded at boot.
#    The unit enables `ProtectKernelModules=yes` which blocks
#    auto-load from inside the sandbox, so if your distro
#    ships tun as a loadable module (Debian/Ubuntu default)
#    it has to be present before the unit starts — otherwise
#    pgn's first `openconnect_setup_tun_device` call fails
#    with `ENODEV`.
echo tun | sudo tee /etc/modules-load.d/tun.conf
sudo modprobe tun

# 3. Create at least one portal profile.
#    The profile name is what you'll pass as the systemd instance
#    below, and it must match [A-Za-z0-9_-]{1,32}.
sudo pgn portal add work \
    --url https://vpn.corp.example.com \
    --auth-mode paste \
    --only 10.0.0.0/8 \
    --hip auto \
    --reconnect

# 4. Drop the unit file in place and reload systemd.
sudo install -m 0644 packaging/systemd/pangolin@.service \
    /etc/systemd/system/pangolin@.service
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
private kernel keyring, and umask `0077`. Run
`systemd-analyze security pangolin@<name>.service` after the
install and you should see an exposure score in the
**2.x OK** band (down from 9.8 UNSAFE on the un-hardened
template).

The unit still runs as `User=root` because CAP_NET_ADMIN
and CAP_NET_RAW are required for tun device management and
ESP raw sockets, and dropping to a non-root user would need
relocating the config directory out of `/root/.config/pangolin`
and chowning `/run/pangolin` to a pangolin-specific user —
a bigger refactor than the hardening pass itself. Today's
unit bounds what a compromised root pgn process can reach:
no other users' home directories, no kernel tunables, no
other networking families, no namespace creation, and no
suid/sgid bit creation. The main surviving exposures are
the things that would break pgn's job: access to
`/dev/net/tun` (`PrivateDevices=yes` is not enabled), the
host's network stack (`PrivateNetwork=yes` is not enabled,
obviously), and the read-only `/root/.config/pangolin`
config file.

## Use

The instance name (`%i`) after the `@` is a profile name saved
with `pgn portal add`. Bare URLs are not supported as instance
names — they would collide with systemd's own `%i` escaping rules
and with pangolin's `[A-Za-z0-9_-]{1,32}` validator. Save them as
profiles first.

```bash
# Start the "work" profile and enable it at boot.
sudo systemctl enable --now pangolin@work.service

# Tail the live log.
sudo journalctl -u pangolin@work.service -f

# Stop and disable.
sudo systemctl disable --now pangolin@work.service

# Run a second profile in parallel — fully supported. Each
# instance gets its own /run/pangolin/<name>.sock, its own tun
# device, its own routes, and its own DNS state.
sudo systemctl enable --now pangolin@client-a.service
```

`pgn status` and `pgn disconnect` are instance-aware:

```bash
# List every live instance.
sudo pgn status --all

# Query just one.
sudo pgn status -i work

# Disconnect just one.
sudo pgn disconnect -i work

# Disconnect everything.
sudo pgn disconnect --all
```

With no flags:

* `pgn status` prints a `disconnected` line if nothing is running,
  full details for a single live instance, or the list view if two
  or more are live.
* `pgn disconnect` disconnects a single live instance without
  asking, but **refuses** if two or more are live — pass
  `--instance <name>` or `--all` to be explicit. This is on
  purpose: silently picking a target when the user was ambiguous
  is how you accidentally tear down the wrong tunnel.

## Restart policy

`pangolin@.service` uses `Restart=on-failure` with a 15-second
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
`SIGTERM` on `systemctl stop`, pgn's signal handler translates
that into the libopenconnect cmd-pipe path, and the tunnel tears
down on exactly the same code path as `Ctrl-C` in foreground
mode. An `ExecStop=/usr/local/bin/pgn disconnect` line would
race that path because `pgn disconnect` returns as soon as the
IPC server acknowledges the request, not when the tunnel is
actually down.

## Troubleshooting

Common failure modes:

* **`pgn: no portal given and no default profile set`** — the
  instance name doesn't match any saved profile. Run
  `sudo pgn portal list` to see what's saved.
* **`instance name … contains an invalid character`** — the
  instance name isn't `[A-Za-z0-9_-]{1,32}`. Rename the profile.
* **`another pgn instance is already running at /run/pangolin/<name>.sock`**
  — you already have a `pangolin@<name>.service` up (possibly a
  stale one from a previous session). `systemctl status pangolin@<name>`
  to check, or `sudo pgn status --all` to see the live list.
* **`Failed to bind local tun device (TUNSETIFF): Operation
  not permitted`** — the unit started without `User=root`,
  or the install path is wrong. Check `systemctl cat
  pangolin@<name>.service`.
* **Repeated restarts hitting `StartLimitBurst`** — systemd
  has stopped trying. Look at `journalctl -u pangolin@<name>
  --since "5 minutes ago"` to see why the connect failed,
  fix the underlying issue, then `systemctl reset-failed
  pangolin@<name>` before re-enabling.
