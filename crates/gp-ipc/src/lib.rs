//! IPC between the running `pgn connect` session and CLI sub-commands
//! like `pgn status` and `pgn disconnect`.
//!
//! Protocol: newline-delimited JSON over a Unix stream socket.
//!
//! * One request per connection.
//! * Server reads exactly one line, parses a [`Request`], writes exactly
//!   one line with a [`Response`], then closes the connection.
//! * The socket path defaults to [`DEFAULT_SOCKET_PATH`] but is
//!   configurable (e.g. for tests using a temp dir).
//!
//! This crate is deliberately tiny and has no dependency on any of the
//! VPN-specific crates — it only knows the shape of messages and how to
//! open a stream. The pgn binary wires it into the running session.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Default location of the control socket. One per machine; `pgn connect`
/// typically runs under `sudo` so the socket lives under `/run` with
/// restrictive permissions.
pub const DEFAULT_SOCKET_PATH: &str = "/run/pangolin/pangolin.sock";

/// Directory that holds [`DEFAULT_SOCKET_PATH`]. Created on-demand by
/// [`prepare_socket_dir`].
pub const DEFAULT_SOCKET_DIR: &str = "/run/pangolin";

/// Errors surfaced by the ipc client and server.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("no running pgn session (socket {0} not found)")]
    NotRunning(PathBuf),

    #[error("permission denied on {0} — you probably need sudo")]
    PermissionDenied(PathBuf),

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

/// Point-in-time view of the running session.
///
/// Everything here is built up-front from the auth result and a start
/// `Instant`. Nothing mutates while the session runs — no locking
/// required on the server side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Portal URL the session is bound to.
    pub portal: String,
    /// Gateway address actually carrying the tunnel (may differ from portal).
    pub gateway: String,
    /// Authenticated username.
    pub user: String,
    /// Reported OS string that was sent to the gateway (`"win"`, …).
    pub reported_os: String,
    /// Seconds since the tunnel came up.
    pub uptime_seconds: u64,
    /// Unix timestamp (seconds) the session started, or 0 if unknown.
    pub started_at_unix: u64,
    /// Comma-separated list of installed split-tunnel routes, or "default" if none.
    pub routes: Vec<String>,
}

/// Ensure [`DEFAULT_SOCKET_DIR`] (or the parent of `path`) exists with
/// tight permissions. Idempotent.
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

/// Bind a [`UnixListener`] at `path`, removing any stale socket first and
/// setting permissions to `0600`.
pub async fn bind_server(path: &Path) -> Result<UnixListener, IpcError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    prepare_socket_dir(path)?;
    // Remove any stale file left by a previous crashed session. Two pgn
    // instances running concurrently is already broken (they'd fight
    // over the TUN device), so we don't try to detect that case.
    if path.exists() {
        let _ = fs::remove_file(path);
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Connect to a running session, send one request, receive one response.
/// The connection is closed after the response is read.
pub async fn client_roundtrip(path: &Path, req: &Request) -> Result<Response, IpcError> {
    let stream = UnixStream::connect(path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            IpcError::NotRunning(path.to_path_buf())
        }
        std::io::ErrorKind::PermissionDenied => IpcError::PermissionDenied(path.to_path_buf()),
        _ => IpcError::Io(e),
    })?;

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
pub async fn read_request(stream: &mut UnixStream) -> Result<Request, IpcError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(IpcError::Protocol("client closed without sending".into()));
    }
    serde_json::from_str(line.trim())
        .map_err(|e| IpcError::Protocol(format!("parse request: {e}")))
}

/// Write a single JSON response to a client connection.
pub async fn write_response(stream: &mut UnixStream, resp: &Response) -> Result<(), IpcError> {
    let line =
        serde_json::to_string(resp).map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Helper: compute a [`StateSnapshot`] from stable fields + a start
/// `Instant`. The server calls this once per `Status` request so
/// `uptime_seconds` stays fresh, but `started_at_unix` is read from
/// the base — captured once when the session booted, immune to
/// wall-clock jumps during the session.
pub fn build_snapshot(
    base: &StateSnapshotBase,
    started_at: std::time::Instant,
) -> StateSnapshot {
    StateSnapshot {
        portal: base.portal.clone(),
        gateway: base.gateway.clone(),
        user: base.user.clone(),
        reported_os: base.reported_os.clone(),
        uptime_seconds: started_at.elapsed().as_secs(),
        started_at_unix: base.started_at_unix,
        routes: base.routes.clone(),
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
    pub portal: String,
    pub gateway: String,
    pub user: String,
    pub reported_os: String,
    pub routes: Vec<String>,
    pub started_at_unix: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

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
                portal: "vpn.example.com".into(),
                gateway: "gw.example.com".into(),
                user: "alice".into(),
                reported_os: "win".into(),
                uptime_seconds: 42,
                started_at_unix: 1_700_000_000,
                routes: vec!["10.0.0.0/8".into()],
            }),
        ];
        for resp in resps {
            let s = serde_json::to_string(&resp).unwrap();
            let back: Response = serde_json::from_str(&s).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }
}
