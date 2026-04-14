# systemd integration

`pangolin@.service` is a systemd template unit. One instance per
saved portal profile. Use it when you want a profile to come up
automatically at boot, get restarted on transient failure, and
have its logs collected by `journald`.

## Install

```bash
# 1. Install the binary (cargo build --release done first).
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn

# 2. Create at least one portal profile + mark it as default
#    (or pass the profile name as the systemd instance below).
sudo pgn portal add work \
    --url https://vpn.corp.example.com \
    --auth-mode paste \
    --only 10.0.0.0/8 \
    --hip auto \
    --reconnect

# 3. Drop the unit file in place and reload systemd.
sudo install -m 0644 packaging/systemd/pangolin@.service \
    /etc/systemd/system/pangolin@.service
sudo systemctl daemon-reload
```

## Use

The instance name (`%i`) after the `@` is whatever you'd type
to `pgn connect` — a profile name OR a bare URL.

```bash
# Start the "work" profile and enable it at boot.
sudo systemctl enable --now pangolin@work.service

# Tail the live log.
sudo journalctl -u pangolin@work.service -f

# Stop and disable.
sudo systemctl disable --now pangolin@work.service

# Run a second profile in parallel.
sudo systemctl enable --now pangolin@home-lab.service
```

`pgn status` and `pgn disconnect` continue to work the same way
they do in foreground mode — they talk to the running daemon
over the unix control socket at `/run/pangolin/pangolin.sock`,
which is the same socket regardless of how the daemon was
started.

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

## Troubleshooting

Common failure modes:

* **`pgn: no portal given and no default profile set`** — the
  instance name doesn't match any saved profile and isn't a
  valid URL. Run `sudo pgn portal list` to see what's saved.
* **`Failed to bind local tun device (TUNSETIFF): Operation
  not permitted`** — the unit started without `User=root`,
  or the install path is wrong. Check `systemctl cat
  pangolin@<name>.service`.
* **Repeated restarts hitting `StartLimitBurst`** — systemd
  has stopped trying. Look at `journalctl -u pangolin@<name>
  --since "5 minutes ago"` to see why the connect failed,
  fix the underlying issue, then `systemctl reset-failed
  pangolin@<name>` before re-enabling.
