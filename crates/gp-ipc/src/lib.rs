//! IPC between the running `pgn connect` session and CLI sub-commands
//! like `pgn status` and `pgn disconnect`.
//!
//! Protocol: newline-delimited JSON over a stream transport.
//!
//! * **Linux** — Unix domain sockets at `/run/pangolin/<instance>.sock`.
//! * **Windows** — Named pipes at `\\.\pipe\pangolin-<instance>`.
//!
//! One request per connection. Server reads one line, parses a
//! [`Request`], writes one line with a [`Response`], then closes.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Default instance name.
pub const DEFAULT_INSTANCE: &str = "default";

/// How long a client connect is allowed to take.
pub const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a full request-response roundtrip is allowed to take.
pub const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors surfaced by the IPC client and server.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("no running pgn session ({0})")]
    NotRunning(PathBuf),

    #[error("permission denied on {0} — you probably need elevated privileges")]
    PermissionDenied(PathBuf),

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
    Status,
    Disconnect,
}

/// Response sent from running session back to CLI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status(StateSnapshot),
    Ok,
    Error { message: String },
}

/// Coarse-grained session state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Connecting,
    Connected,
    Reconnecting,
}

/// Point-in-time view of the running session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    #[serde(default = "default_instance_name")]
    pub instance: String,
    pub portal: String,
    pub gateway: String,
    pub user: String,
    pub reported_os: String,
    pub uptime_seconds: u64,
    pub started_at_unix: u64,
    pub routes: Vec<String>,
    #[serde(default)]
    pub tun_ifname: Option<String>,
    #[serde(default)]
    pub local_ipv4: Option<String>,
    #[serde(default = "default_session_state")]
    pub state: SessionState,
}

fn default_session_state() -> SessionState {
    SessionState::Connected
}
fn default_instance_name() -> String {
    DEFAULT_INSTANCE.to_string()
}

/// Stable fields of a [`StateSnapshot`] used with [`build_snapshot`].
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

/// Build a fresh snapshot from stable base fields + elapsed time.
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

// ---------------------------------------------------------------------------
// Platform-agnostic endpoint naming
// ---------------------------------------------------------------------------

/// Per-instance IPC endpoint identifier.
///
/// On Unix: `/run/pangolin/<instance>.sock`
/// On Windows: `\\.\pipe\pangolin-<instance>`
pub fn endpoint_for(instance: &str) -> String {
    #[cfg(unix)]
    {
        format!("/run/pangolin/{instance}.sock")
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\pangolin-{instance}")
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = instance;
        String::new()
    }
}

/// Legacy helper — returns a [`PathBuf`] for the endpoint.
pub fn socket_path_for(instance: &str) -> PathBuf {
    PathBuf::from(endpoint_for(instance))
}

/// Socket directory (Unix only).
#[cfg(unix)]
pub const DEFAULT_SOCKET_DIR: &str = "/run/pangolin";

// Unconditional re-export for code that references the constant.
#[cfg(not(unix))]
pub const DEFAULT_SOCKET_DIR: &str = "";

// ---------------------------------------------------------------------------
// Cross-platform client roundtrip
// ---------------------------------------------------------------------------

/// Connect to a running session, send one request, receive one response.
pub async fn client_roundtrip(endpoint: &str, req: &Request) -> Result<Response, IpcError> {
    #[cfg(unix)]
    {
        client_roundtrip_unix(std::path::Path::new(endpoint), req).await
    }
    #[cfg(windows)]
    {
        client_roundtrip_pipe(endpoint, req).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (endpoint, req);
        Err(IpcError::Protocol("unsupported platform".into()))
    }
}

/// Enumerate live instances on this host.
pub async fn enumerate_live_instances() -> Vec<(String, PathBuf)> {
    #[cfg(unix)]
    {
        enumerate_live_instances_unix(std::path::Path::new(DEFAULT_SOCKET_DIR)).await
    }
    #[cfg(windows)]
    {
        enumerate_live_instances_pipe().await
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Unix backend
// ---------------------------------------------------------------------------

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(unix)]
pub fn prepare_socket_dir(path: &std::path::Path) -> Result<(), IpcError> {
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
    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    Ok(())
}

#[cfg(unix)]
pub async fn bind_server(path: &std::path::Path) -> Result<UnixListener, IpcError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    prepare_socket_dir(path)?;

    if path.exists() {
        match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
            Ok(Ok(_)) => return Err(IpcError::AlreadyRunning(path.to_path_buf())),
            Ok(Err(e)) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                    let _ = fs::remove_file(path);
                }
                std::io::ErrorKind::PermissionDenied => {
                    return Err(IpcError::PermissionDenied(path.to_path_buf()));
                }
                _ => return Err(IpcError::Io(e)),
            },
            Err(_) => return Err(IpcError::AlreadyRunning(path.to_path_buf())),
        }
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

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

#[cfg(unix)]
pub async fn write_response(stream: &mut UnixStream, resp: &Response) -> Result<(), IpcError> {
    let line =
        serde_json::to_string(resp).map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(unix)]
async fn client_roundtrip_unix(
    path: &std::path::Path,
    req: &Request,
) -> Result<Response, IpcError> {
    match tokio::time::timeout(CLIENT_REQUEST_TIMEOUT, async {
        let stream =
            match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
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
            .map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
        write_half.write_all(line.as_bytes()).await?;
        write_half.write_all(b"\n").await?;
        write_half.flush().await?;
        write_half.shutdown().await?;

        let mut reader = BufReader::new(read_half);
        let mut response_line = String::new();
        let n = reader.read_line(&mut response_line).await?;
        if n == 0 {
            return Err(IpcError::Protocol("server closed without response".into()));
        }
        serde_json::from_str(response_line.trim())
            .map_err(|e| IpcError::Protocol(format!("parse response: {e}")))
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(IpcError::Protocol(format!(
            "timed out talking to {}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
async fn enumerate_live_instances_unix(dir: &std::path::Path) -> Vec<(String, PathBuf)> {
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

// ---------------------------------------------------------------------------
// Windows Named Pipe backend
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

/// Create the first pipe instance (fails if another server exists).
#[cfg(windows)]
pub async fn bind_server_pipe(pipe_name: &str) -> Result<NamedPipeServer, IpcError> {
    ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)
        .map_err(|e| map_win_pipe_error(e, pipe_name))
}

/// Create an additional pipe instance for the next client.
#[cfg(windows)]
pub fn create_pipe_instance(pipe_name: &str) -> Result<NamedPipeServer, IpcError> {
    ServerOptions::new()
        .first_pipe_instance(false)
        .create(pipe_name)
        .map_err(IpcError::Io)
}

/// Read a request from a connected Named Pipe server.
#[cfg(windows)]
pub async fn read_request_pipe(server: &mut NamedPipeServer) -> Result<Request, IpcError> {
    // NamedPipeServer is !Unpin-safe for split, so read sequentially
    // using a temporary buffer approach.
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        use tokio::io::AsyncReadExt;
        match server.read(&mut byte).await {
            Ok(0) => {
                return Err(IpcError::Protocol("client closed without sending".into()));
            }
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > 64 * 1024 {
                    return Err(IpcError::Protocol("request too large".into()));
                }
            }
            Err(e) => return Err(IpcError::Io(e)),
        }
    }
    let line = String::from_utf8_lossy(&buf);
    serde_json::from_str(line.trim()).map_err(|e| IpcError::Protocol(format!("parse request: {e}")))
}

/// Write a response to a connected Named Pipe server.
#[cfg(windows)]
pub async fn write_response_pipe(
    server: &mut NamedPipeServer,
    resp: &Response,
) -> Result<(), IpcError> {
    use tokio::io::AsyncWriteExt;
    let line =
        serde_json::to_string(resp).map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
    server.write_all(line.as_bytes()).await?;
    server.write_all(b"\n").await?;
    server.flush().await?;
    Ok(())
}

#[cfg(windows)]
async fn client_roundtrip_pipe(pipe_name: &str, req: &Request) -> Result<Response, IpcError> {
    use tokio::io::AsyncWriteExt;
    match tokio::time::timeout(CLIENT_REQUEST_TIMEOUT, async {
        let mut client = ClientOptions::new()
            .open(pipe_name)
            .map_err(|e| map_win_pipe_error(e, pipe_name))?;

        // Write request.
        let line = serde_json::to_string(req)
            .map_err(|e| IpcError::Protocol(format!("serialize: {e}")))?;
        client.write_all(line.as_bytes()).await?;
        client.write_all(b"\n").await?;
        client.flush().await?;

        // Read response (byte-at-a-time until newline).
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match client.read(&mut byte).await {
                Ok(0) => {
                    if buf.is_empty() {
                        return Err(IpcError::Protocol("server closed without response".into()));
                    }
                    break;
                }
                Ok(_) => {
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(e) => return Err(IpcError::Io(e)),
            }
        }
        let resp_str = String::from_utf8_lossy(&buf);
        serde_json::from_str(resp_str.trim())
            .map_err(|e| IpcError::Protocol(format!("parse response: {e}")))
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(IpcError::Protocol(format!(
            "timed out talking to {pipe_name}"
        ))),
    }
}

/// Enumerate live pangolin instances by probing the pipe namespace.
#[cfg(windows)]
async fn enumerate_live_instances_pipe() -> Vec<(String, PathBuf)> {
    // Scan \\.\pipe\ for pipes matching our naming convention.
    // std::fs::read_dir works on \\.\pipe\ on modern Windows.
    let entries = match std::fs::read_dir(r"\\.\pipe\") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let prefix = "pangolin-";
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let name = match entry.file_name().to_str().map(String::from) {
            Some(n) => n,
            None => continue,
        };
        if let Some(instance) = name.strip_prefix(prefix) {
            if !instance.is_empty() {
                let pipe_name = format!(r"\\.\pipe\{name}");
                candidates.push((instance.to_string(), PathBuf::from(pipe_name)));
            }
        }
    }

    // Probe each candidate concurrently.
    let mut set = tokio::task::JoinSet::new();
    for (instance, pipe_path) in candidates {
        let pipe_name = pipe_path.to_string_lossy().to_string();
        set.spawn(async move {
            let ok = ClientOptions::new().open(&pipe_name).is_ok();
            (instance, pipe_path, ok)
        });
    }

    let mut live = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((instance, path, true)) = joined {
            live.push((instance, path));
        }
    }
    live.sort_by(|a, b| a.0.cmp(&b.0));
    live
}

/// Map Windows pipe errors to typed IpcError variants.
#[cfg(windows)]
fn map_win_pipe_error(e: std::io::Error, pipe_name: &str) -> IpcError {
    match e.raw_os_error() {
        Some(2) => IpcError::NotRunning(PathBuf::from(pipe_name)), // ERROR_FILE_NOT_FOUND
        Some(5) => IpcError::PermissionDenied(PathBuf::from(pipe_name)), // ERROR_ACCESS_DENIED
        Some(231) => IpcError::AlreadyRunning(PathBuf::from(pipe_name)), // ERROR_PIPE_BUSY
        _ => IpcError::Io(e),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_per_instance() {
        let e = endpoint_for("default");
        assert!(e.contains("default"), "got: {e}");
        let e = endpoint_for("work");
        assert!(e.contains("work"), "got: {e}");
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
    fn snapshot_deserializes_without_instance_field() {
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

#[cfg(all(test, windows))]
mod tests_windows {
    use super::*;

    #[tokio::test]
    async fn named_pipe_roundtrip() {
        let pipe_name = format!(r"\\.\pipe\pangolin-test-{}", std::process::id());

        // Start server.
        let mut server = bind_server_pipe(&pipe_name).await.unwrap();

        // Spawn server handler.
        let pipe_name2 = pipe_name.clone();
        let handle = tokio::spawn(async move {
            server.connect().await.unwrap();
            let req = read_request_pipe(&mut server).await.unwrap();
            assert!(matches!(req, Request::Status));
            let resp = Response::Ok;
            write_response_pipe(&mut server, &resp).await.unwrap();
        });

        // Small delay to let server start listening.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client roundtrip.
        let resp = client_roundtrip(&pipe_name2, &Request::Status)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipe_not_running() {
        let pipe_name = r"\\.\pipe\pangolin-test-nonexistent-42";
        let result = client_roundtrip(pipe_name, &Request::Status).await;
        assert!(matches!(result, Err(IpcError::NotRunning(_))));
    }
}

#[cfg(all(test, unix))]
mod tests_unix_roundtrip {
    // Unix socket integration test is in tests/roundtrip.rs.
}
