//! IPC between the running `pgn connect` session and CLI sub-commands
//! like `pgn status` and `pgn disconnect`.
//!
//! Protocol: newline-delimited JSON over a Unix stream socket.
//!
//! * One request per connection.
//! * Server reads exactly one line, parses a [`Request`], writes exactly
//!   one line with a [`Response`], then closes the connection.
//! * Socket paths are per-instance: `/run/pangolin/<instance>.sock`.
//!   `pgn connect --instance work` and `pgn connect --instance client-a`
//!   run side by side, each with their own control socket, TUN device,
//!   and route/DNS state. Instance names are validated at the CLI layer
//!   to `[A-Za-z0-9_-]{1,32}`.
//! * `bind_server` refuses to start if another live server is already
//!   bound to the same instance name, but cleans up stale sockets left
//!   behind by a crashed session.
//!
//! This crate is deliberately tiny and has no dependency on any of the
//! VPN-specific crates — it only knows the shape of messages and how to
//! open a stream. The pgn binary wires it into the running session.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Directory that holds per-instance control sockets. Created on-demand
/// by [`prepare_socket_dir`].
pub const DEFAULT_SOCKET_DIR: &str = "/run/pangolin";

/// Default instance name when `pgn connect` is invoked without
/// `--instance`.
pub const DEFAULT_INSTANCE: &str = "default";

/// How long a client-side probe/connect is allowed to take before we
/// give up and treat the socket as either dead or wedged. Bounds the
/// cost of `bind_server` probing an abandoned-but-bound socket, and
/// of `status --all` scanning a directory full of sockets where one
/// server is hung.
pub const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a single [`client_roundtrip`] is allowed to take end-to-end
/// (connect + send + receive). Bounds the cost of a wedged server that
/// accepts the connection but never writes a response — without this
/// cap, the CLI would hang indefinitely waiting for the read side.
pub const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors surfaced by the ipc client and server.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("no running pgn session (socket {0} not found)")]
    NotRunning(PathBuf),

    #[error("permission denied on {0} — you probably need sudo")]
    PermissionDenied(PathBuf),

    /// Another live `pgn connect` instance is already bound to this
    /// socket path. Returned from [`bind_server`] so the caller can
    /// surface a clear "instance name already in use" message.
    #[error("another pgn instance is already running at {0}")]
    AlreadyRunning(PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("server returned error: {0}")]
    Server(String),
}

/// Request sent from CLI client to running session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Ask the session for its current [`StateSnapshot`].
    Status,
    /// Ask the session to tear down cleanly.
    Disconnect,
}

/// Response sent from running session back to CLI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Status payload.
    Status(StateSnapshot),
    /// Command accepted.
    Ok,
    /// Server-side error (message is user-facing).
    Error { message: String },
}

/// Coarse-grained session state. Clients use this to render UX — the
/// set is intentionally small and not a strict state machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Auth is done, libopenconnect session created, but CSTP/TUN
    /// setup hasn't finished yet.
    Connecting,
    /// CSTP is up, tun device is configured, routes installed.
    Connected,
    /// Reserved for a future auto-reconnect path.
    Reconnecting,
}

/// Point-in-time view of the running session.
///
/// Everything here is built up-front from the auth result and a start
/// `Instant`. `state` and `tun_ifname` / `local_ipv4` become available
/// after setup_tun_device returns; `uptime_seconds` is derived per
/// query from a stored Instant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Instance name this session was started with (`default` when
    /// none was supplied). Echoed in every `pgn status` / `--all`
    /// payload so multi-instance clients can tell which server each
    /// snapshot came from.
    #[serde(default = "default_instance_name")]
    pub instance: String,
    /// Portal URL the session is bound to.
    pub portal: String,
    /// Gateway address actually carrying the tunnel (may differ from portal).
    pub gateway: String,
    /// Authenticated username.
    pub user: String,
    /// Reported OS string that was sent to the gateway (`"win"`, …).
    pub reported_os: String,
    /// Seconds since the session was created. Stable across wall-clock jumps.
    pub uptime_seconds: u64,
    /// Unix timestamp (seconds) the session started, or 0 if unknown.
    pub started_at_unix: u64,
    /// Split-tunnel CIDRs installed by `gp-route`. Empty means "default
    /// routing; whatever the vpnc-script did."
    pub routes: Vec<String>,
    /// Tun interface libopenconnect created, e.g. `"tun0"`. `None`
    /// until setup_tun_device finishes.
    #[serde(default)]
    pub tun_ifname: Option<String>,
    /// Server-assigned IPv4 on the tun interface.
    #[serde(default)]
    pub local_ipv4: Option<String>,
    /// Coarse-grained state. Defaults to `Connected` for backward
    /// compatibility with older snapshots that didn't have this field.
    #[serde(default = "default_session_state")]
    pub state: SessionState,
}

fn default_session_state() -> SessionState {
    SessionState::Connected
}

fn default_instance_name() -> String {
    DEFAULT_INSTANCE.to_string()
}

/// Compute the per-instance control-socket path. `instance` is assumed
/// to be pre-validated (see `validate_instance_name` at the CLI
/// layer) — this helper does not re-check, because it's called on
/// hot paths like directory scans where the caller has already
/// filtered invalid names.
pub fn socket_path_for(instance: &str) -> PathBuf {
    let mut p = PathBuf::from(DEFAULT_SOCKET_DIR);
    p.push(format!("{instance}.sock"));
    p
}

/// Ensure [`DEFAULT_SOCKET_DIR`] (or the parent of `path`) exists with
/// tight permissions. Idempotent.
#[cfg(unix)]
pub fn prepare_socket_dir(path: &Path) -> Result<(), IpcError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().ok_or_else(|| {
        IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no parent directory",
        ))
    })?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }
    // Best-effort chmod on the parent directory. Confidentiality of the
    // IPC traffic comes from the socket file's own `0600` mode, not from
    // this chmod — if a packager pre-created the directory with looser
    // perms we still won't fail the bind, we just skip tightening it.
    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    Ok(())
}

/// Bind a [`UnixListener`] at `path`, refusing if another live server
/// is already there and cleaning up stale sockets otherwise.
///
/// Stale-detection: the function attempts a short-timeout `connect()`
/// to the existing socket. If that succeeds, another instance is
/// answering — refuse with [`IpcError::AlreadyRunning`]. If the
/// connect fails with `NotFound`, `ConnectionRefused`, or times out
/// quickly, the socket is treated as stale and removed.
///
/// This leaves a small TOCTOU window between the probe and the
/// `remove_file` + `bind`. Two processes trying to start the same
/// instance name simultaneously could both decide the socket is
/// stale; one will win the bind, the other will fail at
/// `UnixListener::bind` time with EADDRINUSE — still safe, just not
/// as friendly as the explicit `AlreadyRunning` error.
#[cfg(unix)]
pub async fn bind_server(path: &Path) -> Result<UnixListener, IpcError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    prepare_socket_dir(path)?;

    if path.exists() {
        // Is someone actually listening on it? Short-timeout connect
        // — a hung/wedged peer must not block startup indefinitely.
        match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
            Ok(Ok(_stream)) => {
                // Live server; refuse.
                return Err(IpcError::AlreadyRunning(path.to_path_buf()));
            }
            Ok(Err(e)) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                    // Stale socket file left by a crashed session — unlink.
                    let _ = fs::remove_file(path);
                }
                std::io::ErrorKind::PermissionDenied => {
                    return Err(IpcError::PermissionDenied(path.to_path_buf()));
                }
                _ => return Err(IpcError::Io(e)),
            },
            Err(_elapsed) => {
                // Peer accepted the connection but never served it — or
                // the kernel is sitting on the connect. Don't touch the
                // socket; something is still there.
                return Err(IpcError::AlreadyRunning(path.to_path_buf()));
            }
        }
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Connect to a running session, send one request, receive one response.
/// The connection is closed after the response is read.
///
/// Two timeouts apply:
///
/// * [`CLIENT_CONNECT_TIMEOUT`] bounds the initial `connect()` so a
///   wedged peer (abandoned-but-bound socket) doesn't hang startup.
/// * [`CLIENT_REQUEST_TIMEOUT`] bounds the full operation — connect
///   plus send plus receive — so a server that accepts but never
///   responds still lets the CLI return in a reasonable time.
#[cfg(unix)]
pub async fn client_roundtrip(path: &Path, req: &Request) -> Result<Response, IpcError> {
    match tokio::time::timeout(CLIENT_REQUEST_TIMEOUT, client_roundtrip_inner(path, req)).await {
        Ok(res) => res,
        Err(_) => Err(IpcError::Protocol(format!(
            "timed out talking to {}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
async fn client_roundtrip_inner(path: &Path, req: &Request) -> Result<Response, IpcError> {
    let stream = match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(path)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    IpcError::NotRunning(path.to_path_buf())
                }
                std::io::ErrorKind::PermissionDenied => {
                    IpcError::PermissionDenied(path.to_path_buf())
                }
                _ => IpcError::Io(e),
            })
        }
        Err(_) => {
            return Err(IpcError::Protocol(format!(
                "timed out connecting to {}",
                path.display()
            )))
        }
    };

    let (read_half, mut write_half) = stream.into_split();
    let line = serde_json::to_string(req)
        .map_err(|e| IpcError::Protocol(format!("serialize request: {e}")))?;
    write_half.write_all(line.as_bytes()).await?;
    write_half.write_all(b"\n").await?;
    write_half.flush().await?;
    // Half-close so the server knows we're done sending.
    write_half.shutdown().await?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    let n = reader.read_line(&mut response_line).await?;
    if n == 0 {
        return Err(IpcError::Protocol(
            "server closed connection without a response".into(),
        ));
    }
    let resp: Response = serde_json::from_str(response_line.trim())
        .map_err(|e| IpcError::Protocol(format!("parse response: {e}")))?;
    Ok(resp)
}

/// Read a single JSON request from a client connection. Used by server
/// implementations to parse the line the client wrote.
#[cfg(unix)]
pub async fn read_request(stream: &mut UnixStream) -> Result<Request, IpcError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(IpcError::Protocol("client closed without sending".into()));
    }
    serde_json::from_str(line.trim()).map_err(|e| IpcError::Protocol(format!("parse request: {e}")))
}

/// Write a single JSON response to a client connection.
#[cfg(unix)]
pub async fn write_response(stream: &mut UnixStream, resp: &Response) -> Result<(), IpcError> {
    let line =
        serde_json::to_string(resp).map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Enumerate live instances by scanning [`DEFAULT_SOCKET_DIR`] for
/// `*.sock` entries. Returns a `Vec<(instance_name, path)>` of sockets
/// that accepted a connection within [`CLIENT_CONNECT_TIMEOUT`]; stale
/// and wedged sockets are silently skipped so `status --all` never
/// hangs on a zombie.
///
/// * Only entries whose `file_type()` is actually a unix socket are
///   probed — symlinks, regular files, and directories under that
///   name are skipped. This both hardens against a hostile
///   `/run/pangolin/*.sock` symlink and avoids paying the connect
///   timeout for obvious junk.
/// * `PermissionDenied` on a probe is logged at debug level rather
///   than silently swallowed, so `sudo pgn status --all` on a half-
///   broken install gives the operator a hint in `-v` / RUST_LOG.
/// * Probes run **concurrently** via `FuturesUnordered` so a
///   directory full of zombies only costs one timeout window, not
///   N × timeout.
#[cfg(unix)]
pub async fn enumerate_live_instances(dir: &Path) -> Vec<(String, PathBuf)> {
    use std::os::unix::fs::FileTypeExt;

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!("gp-ipc enumerate: read_dir({}) failed: {e}", dir.display());
            }
            return Vec::new();
        }
    };

    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("gp-ipc enumerate: dir entry error: {e}");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sock") {
            continue;
        }
        // Must be an actual unix socket — not a regular file, not a
        // symlink (we'd follow to somewhere unexpected), not a dir.
        // `file_type()` does not traverse symlinks, so a symlink
        // under this name will report as `is_symlink()` and be
        // skipped by the socket check.
        match entry.file_type() {
            Ok(ft) if ft.is_socket() => {}
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!(
                    "gp-ipc enumerate: file_type({}) failed: {e}",
                    path.display()
                );
                continue;
            }
        }
        let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
        else {
            continue;
        };
        candidates.push((name, path));
    }

    // Probe every candidate concurrently — one shared timeout window,
    // not N sequential ones. tokio::task::JoinSet is the stdlib-only
    // way to run N independent futures in parallel and harvest them
    // as they finish, without dragging in the futures crate.
    let mut set = tokio::task::JoinSet::new();
    for (name, path) in candidates {
        set.spawn(async move {
            let outcome =
                tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(&path)).await;
            (name, path, outcome)
        });
    }
    let mut live = Vec::new();
    while let Some(joined) = set.join_next().await {
        let (name, path, outcome) = match joined {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("gp-ipc enumerate: probe task panicked: {e}");
                continue;
            }
        };
        match outcome {
            Ok(Ok(_)) => live.push((name, path)),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::debug!("gp-ipc enumerate: permission denied on {}", path.display());
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }
    live.sort_by(|a, b| a.0.cmp(&b.0));
    live
}

/// Helper: compute a [`StateSnapshot`] from stable fields + a start
/// `Instant`. The server calls this once per `Status` request so
/// `uptime_seconds` stays fresh, but `started_at_unix` is read from
/// the base — captured once when the session booted, immune to
/// wall-clock jumps during the session.
pub fn build_snapshot(base: &StateSnapshotBase, started_at: std::time::Instant) -> StateSnapshot {
    StateSnapshot {
        instance: base.instance.clone(),
        portal: base.portal.clone(),
        gateway: base.gateway.clone(),
        user: base.user.clone(),
        reported_os: base.reported_os.clone(),
        uptime_seconds: started_at.elapsed().as_secs(),
        started_at_unix: base.started_at_unix,
        routes: base.routes.clone(),
        tun_ifname: base.tun_ifname.clone(),
        local_ipv4: base.local_ipv4.clone(),
        state: base.state,
    }
}

/// Stable, never-mutating fields of a [`StateSnapshot`]. Used with
/// [`build_snapshot`] to avoid locking over a shared mutable state.
///
/// `started_at_unix` is captured **once** at session boot (by the
/// client of this crate) so subsequent NTP steps or manual wall-clock
/// changes don't make the reported start time drift between queries.
#[derive(Debug, Clone)]
pub struct StateSnapshotBase {
    pub instance: String,
    pub portal: String,
    pub gateway: String,
    pub user: String,
    pub reported_os: String,
    pub routes: Vec<String>,
    pub started_at_unix: u64,
    pub tun_ifname: Option<String>,
    pub local_ipv4: Option<String>,
    pub state: SessionState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_is_per_instance() {
        // Use components comparison to be path-separator agnostic.
        let p = socket_path_for("default");
        assert!(p.ends_with("default.sock"), "got: {}", p.display());
        let p = socket_path_for("work");
        assert!(p.ends_with("work.sock"), "got: {}", p.display());
        let p = socket_path_for("client-a");
        assert!(p.ends_with("client-a.sock"), "got: {}", p.display());
    }

    #[test]
    fn request_response_json_round_trip() {
        let reqs = vec![Request::Status, Request::Disconnect];
        for req in reqs {
            let s = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&s).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }

        let resps = vec![
            Response::Ok,
            Response::Error {
                message: "boom".into(),
            },
            Response::Status(StateSnapshot {
                instance: "work".into(),
                portal: "vpn.example.com".into(),
                gateway: "gw.example.com".into(),
                user: "alice".into(),
                reported_os: "win".into(),
                uptime_seconds: 42,
                started_at_unix: 1_700_000_000,
                routes: vec!["10.0.0.0/8".into()],
                tun_ifname: Some("tun0".into()),
                local_ipv4: Some("10.1.2.3".into()),
                state: SessionState::Connected,
            }),
        ];
        for resp in resps {
            let s = serde_json::to_string(&resp).unwrap();
            let back: Response = serde_json::from_str(&s).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn snapshot_deserializes_without_instance_field_for_backcompat() {
        // Older daemons (before multi-instance) emitted StateSnapshot
        // without an `instance` key. Clients should still parse those,
        // filling in the default name.
        let older = r#"{
            "portal": "vpn.example.com",
            "gateway": "gw.example.com",
            "user": "alice",
            "reported_os": "win",
            "uptime_seconds": 10,
            "started_at_unix": 1700000000,
            "routes": []
        }"#;
        let s: StateSnapshot = serde_json::from_str(older).unwrap();
        assert_eq!(s.instance, DEFAULT_INSTANCE);
    }
}
