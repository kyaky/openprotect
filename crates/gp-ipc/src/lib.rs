//! IPC between the running `opc connect` session and CLI sub-commands
//! like `opc status` and `opc disconnect`.
//!
//! Protocol: newline-delimited JSON over a stream transport.
//!
//! * **Linux** — Unix domain sockets at `/run/openprotect/<instance>.sock`.
//! * **macOS** — Unix domain sockets at `/tmp/openprotect-<uid>/<instance>.sock`.
//! * **Windows** — Named pipes at `\\.\pipe\openprotect-<instance>`.
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

/// How long a busy pipe client keeps waiting for a free server
/// instance before classifying the endpoint busy — `WaitNamedPipe`
/// semantics.
///
/// Implemented as bounded polling rather than an actual
/// `WaitNamedPipeW` import: verified live on Windows 11 26100 that
/// `CreateFileW(OPEN_EXISTING)` against a named pipe whose instances
/// are all attached returns `ERROR_PIPE_BUSY` (231) **immediately**
/// (~50 µs; it does not park inside the pipe manager), so retrying
/// the open every `PIPE_BUSY_POLL_INTERVAL` until this deadline
/// reproduces the wait-for-available semantics without another FFI
/// surface. `ERROR_SEM_TIMEOUT` (121) is what the real
/// `WaitNamedPipeW` sets when its own timeout expires on a busy
/// pipe — same outcome, same classification (`Unknown`, never
/// `Absent`).
pub const PIPE_BUSY_RETRY_DEADLINE: Duration = Duration::from_secs(2);

/// Hard wall-clock bound on one synchronous `CreateFileW` pipe open.
///
/// Same discipline class as [`CLIENT_CONNECT_TIMEOUT`], but enforced
/// differently: a tokio `timeout` cannot preempt a blocking FFI call
/// that never returns to the executor, so the open runs on a
/// throwaway OS thread and this deadline classifies at expiry
/// (`BoundedOpen::Parked` → `Unknown`/`PipeBusy`). Every pipe state
/// we could construct on the test host returned from `CreateFileW`
/// in microseconds (no pipe → code 2; closed instance → `Ok`; all
/// busy → code 231 — live-probed Win11 26100); the bound exists for
/// the case we could NOT construct locally: an EDR / filesystem
/// minifilter delaying completion of the create indefinitely.
pub const PIPE_OPEN_DEADLINE: Duration = CLIENT_CONNECT_TIMEOUT;

/// Poll interval while waiting out [`PIPE_BUSY_RETRY_DEADLINE`].
#[cfg(windows)]
const PIPE_BUSY_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Poll interval while waiting out [`PIPE_OPEN_DEADLINE`].
#[cfg(windows)]
const PIPE_OPEN_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Errors surfaced by the IPC client and server.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("no running opc session ({0})")]
    NotRunning(PathBuf),

    #[error("permission denied on {0} — you probably need elevated privileges")]
    PermissionDenied(PathBuf),

    #[error("another opc instance is already running at {0}")]
    AlreadyRunning(PathBuf),

    /// The endpoint provably **exists** but no server instance could
    /// be attached to within [`PIPE_BUSY_RETRY_DEADLINE`] (or the
    /// open itself never completed, see [`PIPE_OPEN_DEADLINE`]).
    ///
    /// This is deliberately distinct from [`IpcError::AlreadyRunning`]:
    /// for a *client* `CreateFileW`, `ERROR_PIPE_BUSY` (231) is what
    /// a live-but-fully-attached server returns — it is an existence
    /// proof, not a conflict. Callers classifying liveness must map
    /// it to `Unknown`/present, never to absence (see [`Liveness`]).
    #[error("named pipe {0} exists but all of its server instances are busy")]
    PipeBusy(PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("server returned error: {0}")]
    Server(String),
}

/// Tri-state outcome of a bounded liveness probe against one endpoint.
///
/// [`Liveness::Absent`] means the endpoint **provably** does not
/// exist (`ERROR_FILE_NOT_FOUND` on Windows, `ENOENT`/`ECONNREFUSED`
/// on Unix). Everything a probe cannot prove — busy
/// (`ERROR_PIPE_BUSY`), permission-denied, or an open that never
/// completed within [`PIPE_OPEN_DEADLINE`] — is
/// [`Liveness::Unknown`].
///
/// The split exists because downstream sweep/recovery decisions
/// (`opc recover`, the connect-time NRPT sweep) read "absent" as
/// licence to delete system state; a live-but-busy or wedged session
/// must never be collapsed into absent. `Unknown` callers should
/// surface the uncertainty explicitly rather than acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The server accepted the probe connection: session is alive.
    Alive,
    /// The endpoint provably does not exist.
    Absent,
    /// Existence could not be classified — busy, denied, or the open
    /// itself timed out. Treat as *possibly alive*.
    Unknown,
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
    /// True when this session's LAST route teardown ended DEGRADED (a
    /// killed command never confirmed its death, so route state was
    /// unconfirmed at the time). Surfaced so a GUI user polling
    /// `status --json` can see it even in the window before the
    /// process exits GENERAL(1) — the degraded class never reconnects,
    /// so the flag is terminal for the session. Healthy sessions
    /// carry `false`.
    #[serde(default)]
    pub teardown_degraded: bool,
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
    /// Set the moment a teardown ends DEGRADED (see
    /// [`StateSnapshot::teardown_degraded`]); `false` for every
    /// healthy session.
    pub teardown_degraded: bool,
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
        teardown_degraded: base.teardown_degraded,
    }
}

// ---------------------------------------------------------------------------
// Platform-agnostic endpoint naming
// ---------------------------------------------------------------------------

/// Per-instance IPC endpoint identifier.
///
/// On Linux: `/run/openprotect/<instance>.sock`
/// On macOS: `/tmp/openprotect-<uid>/<instance>.sock`
/// On Windows: `\\.\pipe\openprotect-<instance>`
pub fn endpoint_for(instance: &str) -> String {
    #[cfg(unix)]
    {
        socket_path_for(instance).to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\openprotect-{instance}")
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = instance;
        String::new()
    }
}

/// Legacy helper — returns a [`PathBuf`] for the endpoint.
pub fn socket_path_for(instance: &str) -> PathBuf {
    #[cfg(unix)]
    {
        default_socket_dir().join(format!("{instance}.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from(endpoint_for(instance))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = instance;
        PathBuf::new()
    }
}

/// Platform-default socket directory (Unix only).
#[cfg(unix)]
pub fn default_socket_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(format!("/tmp/openprotect-{}", unsafe { libc::geteuid() }))
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/run/openprotect")
    }
}

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
        let dir = default_socket_dir();
        enumerate_live_instances_unix(&dir).await
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
fn path_is_socket(path: &std::path::Path) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::FileTypeExt;

    Ok(std::fs::symlink_metadata(path)?.file_type().is_socket())
}

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
        if !path_is_socket(path)? {
            let _ = fs::remove_file(path);
        } else {
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
    if path.exists() && !path_is_socket(path)? {
        return Err(IpcError::NotRunning(path.to_path_buf()));
    }

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
use tokio::net::windows::named_pipe::ServerOptions;

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

    // Phase 1: bounded, busy-aware pipe open. The old code called
    // tokio's synchronous `ClientOptions::open` *inside* the phase-2
    // timeout — a timeout that can never fire while the blocking
    // `CreateFileW` holds the worker — and mapped its `ERROR_PIPE_BUSY`
    // onto `AlreadyRunning`. Both defects are removed here; see
    // [`pipe_open_with_busy_retry`].
    let outcome = pipe_open_with_busy_retry(pipe_name).await;
    let handle = match outcome {
        BoundedOpen::Connected(h) => h,
        BoundedOpen::Failed(e) => return Err(map_client_open_error(e, pipe_name)),
        // An open that never completed is an existence-preserving
        // "busy", never `NotRunning`/`AlreadyRunning`.
        BoundedOpen::Parked => return Err(IpcError::PipeBusy(PathBuf::from(pipe_name))),
    };

    // Phase 2: request/response roundtrip under the usual budget.
    match tokio::time::timeout(CLIENT_REQUEST_TIMEOUT, async {
        // `from_raw_handle` takes ownership of the raw handle on the
        // success path; on the error path tokio has already wrapped it
        // in a mio NamedPipe that drops (closes) it — closing here
        // ourselves would be a double-close of a recycled HANDLE.
        let mut client = match unsafe {
            tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(handle as _)
        } {
            Ok(c) => c,
            Err(e) => return Err(IpcError::Io(e)),
        };

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

/// Enumerate live openprotect instances by probing the pipe namespace.
#[cfg(windows)]
async fn enumerate_live_instances_pipe() -> Vec<(String, PathBuf)> {
    enumerate_live_instances_pipe_with_liveness()
        .await
        .into_iter()
        .filter(|(_, _, live)| !matches!(live, Liveness::Absent))
        .map(|(instance, path, _)| (instance, path))
        .collect()
}

/// Tri-state variant of [`enumerate_live_instances`] for Windows.
///
/// Exposed for callers that make destructive decisions from the
/// result (`opc recover`, the connect-time NRPT/adapters sweeps):
/// only [`Liveness::Absent`] is safe to treat as "no session here".
/// [`Liveness::Unknown`] (busy pipe, denied open, open that never
/// completed) must be surfaced as uncertainty, never collapsed into
/// absence — a wedge that holds its pipe must not be swept as though
/// it were gone (verified anchors: gp-ipc ERROR_PIPE_BUSY at
/// HEAD 04d7276 :622, consumers at bins/opc/src/main.rs:1923-1924,
/// :2079-2083).
#[cfg(windows)]
pub async fn enumerate_live_instances_with_liveness() -> Vec<(String, PathBuf, Liveness)> {
    enumerate_live_instances_pipe_with_liveness().await
}

#[cfg(windows)]
async fn enumerate_live_instances_pipe_with_liveness() -> Vec<(String, PathBuf, Liveness)> {
    // Scan \\.\pipe\ for pipes matching our naming convention.
    // std::fs::read_dir works on \\.\pipe\ on modern Windows.
    let entries = match std::fs::read_dir(r"\\.\pipe\") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let prefix = "openprotect-";
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

    // Probe each candidate concurrently, bounded per-attempt by
    // PIPE_OPEN_DEADLINE / PIPE_BUSY_RETRY_DEADLINE (the old probe
    // called `ClientOptions::open().is_ok()` unbounded and folded
    // every error — including ERROR_PIPE_BUSY — into "not live").
    let mut set = tokio::task::JoinSet::new();
    for (instance, pipe_path) in candidates {
        let pipe_name = pipe_path.to_string_lossy().to_string();
        set.spawn(async move {
            let live = probe_liveness(&pipe_name).await;
            (instance, pipe_path, live)
        });
    }

    let mut probed = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(v) => probed.push(v),
            Err(e) => tracing::debug!("gp-ipc enumerate: probe task failed: {e}"),
        }
    }
    probed.sort_by(|a, b| a.0.cmp(&b.0));
    probed
}

/// Classify one bounded pipe-open outcome into [`Liveness`].
///
/// Pure + table-testable — no OS state involved. Only
/// `ERROR_FILE_NOT_FOUND` (2) / `ERROR_PATH_NOT_FOUND` (3) are
/// treated as [`Liveness::Absent`]; everything else that cannot prove
/// liveness is [`Liveness::Unknown`] (busy and parked opens prove
/// existence; access-denied proves the object exists but denies us).
#[cfg(windows)]
pub(crate) fn classify_open_outcome(outcome: &BoundedOpen) -> Liveness {
    match outcome {
        BoundedOpen::Connected(_) => Liveness::Alive,
        BoundedOpen::Parked => Liveness::Unknown,
        BoundedOpen::Failed(e) => match e.raw_os_error() {
            Some(2) | Some(3) => Liveness::Absent, // ERROR_FILE_NOT_FOUND / _PATH_NOT_FOUND
            _ => Liveness::Unknown,
        },
    }
}

/// Bounded outcome of attempting to attach a client to a named pipe.
#[cfg(windows)]
pub(crate) enum BoundedOpen {
    /// `CreateFileW` returned a usable client handle (as `usize`;
    /// ownership: caller must `close_raw_handle` it or feed it to
    /// `NamedPipeClient::from_raw_handle`).
    Connected(usize),
    /// The open failed with this OS error.
    Failed(std::io::Error),
    /// The open has not completed within [`PIPE_OPEN_DEADLINE`].
    /// The worker thread may still finish later (the handle it
    /// produces is closed by the worker in that case).
    Parked,
}

#[cfg(windows)]
fn close_raw_handle(handle: usize) {
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe { CloseHandle(handle as _) };
}

/// Synchronous client-side `CreateFileW` with tokio-identical flags
/// (tokio 1.53.1 `ClientOptions::open`: `GENERIC_READ | GENERIC_WRITE`,
/// share 0, `OPEN_EXISTING`, `SECURITY_IDENTIFICATION |
/// SECURITY_SQOS_PRESENT | FILE_FLAG_OVERLAPPED`).
///
/// Kept separate from the bounded wrapper so the FFI body stays
/// auditable; returns the raw handle as `usize` so it can cross the
/// thread boundary.
#[cfg(windows)]
fn raw_pipe_open(pipe_name: &str) -> Result<usize, std::io::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    const GENERIC_RW: u32 = 0x8000_0000 | 0x4000_0000;

    let name: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_RW,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ))
    } else {
        Ok(h as usize)
    }
}

/// Run [`raw_pipe_open`] on a throwaway OS thread and classify its
/// result with a hard wall-clock bound.
///
/// The clock starts *before* the thread spawn, so spawn scheduling
/// counts against [`PIPE_OPEN_DEADLINE`] (the sibling runner defects
/// — gp-route run_with_timeout at HEAD 04d7276 :229 — started their
/// clocks after spawn and inherited unbounded pre-timeout waits).
/// A completed-late open whose receiver has gone (caller already saw
/// `Parked`) is closed by the worker itself, so no handle leaks.
#[cfg(windows)]
async fn bounded_pipe_open(pipe_name: &str) -> BoundedOpen {
    use std::sync::mpsc::TryRecvError;

    let (tx, rx) = std::sync::mpsc::channel();
    let name = pipe_name.to_string();
    std::thread::spawn(move || {
        let outcome = raw_pipe_open(&name);
        if let Err(e) = tx.send(outcome) {
            // Receiver dropped: the caller already gave up and was
            // handed `Parked`. Close the late handle ourselves.
            if let Ok(h) = e.0 {
                close_raw_handle(h);
            }
        }
    });

    let start = std::time::Instant::now();
    loop {
        match rx.try_recv() {
            Ok(Ok(h)) => return BoundedOpen::Connected(h),
            Ok(Err(e)) => return BoundedOpen::Failed(e),
            Err(TryRecvError::Disconnected) => {
                // Worker panicked before sending (raw_pipe_open has no
                // panicking paths today; be defensive, it is
                // indistinguishable from a lost probe).
                return BoundedOpen::Parked;
            }
            Err(TryRecvError::Empty) => {
                if start.elapsed() >= PIPE_OPEN_DEADLINE {
                    return BoundedOpen::Parked;
                }
                tokio::time::sleep(PIPE_OPEN_POLL_INTERVAL).await;
            }
        }
    }
}

/// [`bounded_pipe_open`] + the `WaitNamedPipe`-style bounded busy
/// retry. `ERROR_PIPE_BUSY` (231) returns *instantly* from
/// `CreateFileW` on our test host (live-probed, see
/// [`PIPE_BUSY_RETRY_DEADLINE`]), so polling re-attaches as soon as
/// an instance frees. The overall wall-clock budget for the retry is
/// [`PIPE_BUSY_RETRY_DEADLINE`] measured from before the first
/// attempt (clock-before-spawn discipline again).
#[cfg(windows)]
async fn pipe_open_with_busy_retry(pipe_name: &str) -> BoundedOpen {
    let start = std::time::Instant::now();
    loop {
        let outcome = bounded_pipe_open(pipe_name).await;
        let busy = matches!(&outcome, BoundedOpen::Failed(e) if e.raw_os_error() == Some(231));
        if !busy || start.elapsed() >= PIPE_BUSY_RETRY_DEADLINE {
            return outcome;
        }
        tokio::time::sleep(PIPE_BUSY_POLL_INTERVAL).await;
    }
}

/// Probe one endpoint and classify liveness, fully bounded: the
/// whole probe can never exceed roughly
/// `PIPE_OPEN_DEADLINE + PIPE_BUSY_RETRY_DEADLINE`.
///
/// This is the helper the sweep/cleanup decision sites should use;
/// [`enumerate_live_instances_with_liveness`] applies it per pipe.
#[cfg(windows)]
pub async fn probe_liveness(endpoint: &str) -> Liveness {
    let outcome = pipe_open_with_busy_retry(endpoint).await;
    let live = classify_open_outcome(&outcome);
    if let BoundedOpen::Connected(h) = outcome {
        close_raw_handle(h);
    }
    live
}

/// Unix-side tri-state probe: connect with the connect budget, map
/// refusal/absence to [`Liveness::Absent`] and everything else
/// (permission, timeout) to [`Liveness::Unknown`].
#[cfg(unix)]
pub async fn probe_liveness(endpoint: &str) -> Liveness {
    let path = std::path::Path::new(endpoint);
    if path.exists() && !path_is_socket(path).unwrap_or(false) {
        return Liveness::Absent; // stale non-socket file: no server behind it
    }
    match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(_)) => Liveness::Alive,
        Ok(Err(e)) => match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                Liveness::Absent
            }
            _ => Liveness::Unknown,
        },
        Err(_) => Liveness::Unknown,
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn probe_liveness(endpoint: &str) -> Liveness {
    let _ = endpoint;
    Liveness::Unknown
}

/// Map **client-side** pipe-open errors to typed IpcError variants.
///
/// ERROR_PIPE_BUSY (231) from a client `CreateFileW` proves the pipe
/// exists — every instance is simply attached. It must never surface
/// as `AlreadyRunning` (a conflict verdict) nor reach the
/// false-absence sweeps. Use [`map_win_pipe_error`] (server side) at
/// `CreateNamedPipe` sites; there, 231/5 genuinely indicate a live
/// foreign server.
#[cfg(windows)]
fn map_client_open_error(e: std::io::Error, pipe_name: &str) -> IpcError {
    match e.raw_os_error() {
        Some(2) => IpcError::NotRunning(PathBuf::from(pipe_name)), // ERROR_FILE_NOT_FOUND
        Some(5) => IpcError::PermissionDenied(PathBuf::from(pipe_name)), // ERROR_ACCESS_DENIED
        Some(231) => IpcError::PipeBusy(PathBuf::from(pipe_name)), // ERROR_PIPE_BUSY
        _ => IpcError::Io(e),
    }
}

/// Map Windows pipe errors **at the server-create site** to typed
/// IpcError variants. Behaviour intentionally unchanged from before
/// the client/server split (live-probe G on Win11 26100: rebinding a
/// `first_pipe_instance` name that already exists surfaces as
/// `ERROR_ACCESS_DENIED`(5), while `CreateNamedPipeW` also documents
/// `ERROR_PIPE_BUSY`(231) for the all-instances-busy case — both keep
/// their pre-split meanings here because at this site either one
/// means a foreign server owns the name).
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

    #[cfg(unix)]
    #[test]
    fn socket_path_uses_platform_default_dir() {
        let path = socket_path_for("default");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("default.sock")
        );
        assert_eq!(path.parent(), Some(default_socket_dir().as_path()));
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
                teardown_degraded: false,
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

    /// PR-B item 4 pins: a session whose last teardown was DEGRADED
    /// carries `teardown_degraded: true` in the STATUS payload; a
    /// healthy session carries `false`; and the field is absent-tolerant
    /// (an older peer's JSON without the key deserializes as `false`,
    /// never an error).
    #[test]
    fn teardown_degraded_field_pins() {
        let base = |degraded: bool| StateSnapshotBase {
            instance: "work".into(),
            portal: "vpn.example.com".into(),
            gateway: "gw.example.com".into(),
            user: "alice".into(),
            reported_os: "win".into(),
            routes: vec!["10.0.0.0/8".into()],
            started_at_unix: 1_700_000_000,
            tun_ifname: Some("tun0".into()),
            local_ipv4: Some("10.1.2.3".into()),
            state: SessionState::Connected,
            teardown_degraded: degraded,
        };
        // A degraded session's serialized status carries the field TRUE.
        let degraded = build_snapshot(&base(true), std::time::Instant::now());
        let json = serde_json::to_string(&degraded).unwrap();
        assert!(
            json.contains("\"teardown_degraded\":true"),
            "the degraded session's status must carry the field: {json}"
        );
        // A healthy session carries FALSE (never absent: the GUI and
        // scripts read one stable shape).
        let healthy = build_snapshot(&base(false), std::time::Instant::now());
        let json = serde_json::to_string(&healthy).unwrap();
        assert!(
            json.contains("\"teardown_degraded\":false"),
            "the healthy session's status must carry the field as false: {json}"
        );
        // Round trip keeps the verdict.
        let back: StateSnapshot = serde_json::from_str(&json).unwrap();
        assert!(!back.teardown_degraded);
        // A payload from an older build (no key) deserializes as false.
        let older = r#"{
            "instance": "work",
            "portal": "vpn.example.com",
            "gateway": "gw.example.com",
            "user": "alice",
            "reported_os": "win",
            "uptime_seconds": 10,
            "started_at_unix": 1700000000,
            "routes": [],
            "state": "connected"
        }"#;
        let s: StateSnapshot = serde_json::from_str(older).unwrap();
        assert!(
            !s.teardown_degraded,
            "a missing key must read as a healthy session, not fail"
        );
    }
}

#[cfg(all(test, windows))]
mod tests_windows {
    use super::*;

    #[tokio::test]
    async fn named_pipe_roundtrip() {
        // Deliberately OUTSIDE the `openprotect-` scan namespace:
        // concurrent tests that exercise `enumerate_live_instances`
        // probe every `openprotect-*` pipe, and a probe completing this
        // server's pending `connect()` would steal the roundtrip
        // client's connection slot.
        let pipe_name = format!(r"\\.\pipe\gp-ipc-test-{}", std::process::id());

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
        let pipe_name = r"\\.\pipe\openprotect-test-nonexistent-42";
        let result = client_roundtrip(pipe_name, &Request::Status).await;
        assert!(matches!(result, Err(IpcError::NotRunning(_))));
    }

    /// Put a pipe into the genuinely-busy state: one instance, already
    /// attached to an unserviced client, no further instances.
    ///
    /// The state machine here is verified live on Windows 11 26100
    /// (this project's test host): `CreateFileW(OPEN_EXISTING)` against
    /// a created-but-never-`connect()`ed instance returns **Ok**
    /// immediately (the client attaches without the server ever
    /// calling `ConnectNamedPipe`), and once that sole instance is
    /// attached, the next client open returns **ERROR_PIPE_BUSY (231)
    /// instantly** — it does not park. So `srv.connect().await` below
    /// completes with the already-attached client, and any subsequent
    /// open sees 231.
    fn busy_pipe_fixture(
        pipe_name: &str,
    ) -> (
        NamedPipeServer,
        tokio::net::windows::named_pipe::NamedPipeClient,
    ) {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)
            .unwrap();
        let attached = ClientOptions::new().open(pipe_name).unwrap();
        (server, attached)
    }

    #[tokio::test]
    async fn busy_pipe_roundtrip_is_never_already_running() {
        // RED: the client-open error mapper currently folds
        // ERROR_PIPE_BUSY (231) into `AlreadyRunning`, which callers
        // read as "a *different* opc owns this pipe". For a client
        // `CreateFileW` 231 only proves the endpoint EXISTS with all
        // instances busy — reporting it as AlreadyRunning (or letting
        // liveness treat it as absent) is the false-absence class this
        // change removes.
        let pipe_name = format!(r"\\.\pipe\openprotect-test-busy1-{}", std::process::id());
        let (server, _c1) = busy_pipe_fixture(&pipe_name);
        // Drain the pending ConnectNamedPipe against the held client
        // so the pipe is in the verified "all instances busy" state.
        let _ = tokio::time::timeout(Duration::from_secs(1), server.connect()).await;

        let start = std::time::Instant::now();
        let err = client_roundtrip(&pipe_name, &Request::Status)
            .await
            .expect_err("a busy pipe must be an error");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(6),
            "roundtrip must be bounded (busy retry budget + connect + request), took {elapsed:?}"
        );
        assert!(
            !matches!(err, IpcError::AlreadyRunning(_)),
            "ERROR_PIPE_BUSY on a client open must NOT be classified as AlreadyRunning: {err:?}"
        );
        assert!(
            matches!(err, IpcError::PipeBusy(_)),
            "busy pipe must surface the dedicated explicit Busy classification: {err:?}"
        );
    }

    #[tokio::test]
    async fn probe_liveness_is_tri_state_and_never_absent_on_busy() {
        // The liveness helper the sweep/cleanup decisions consume:
        //   * busy pipe    -> Unknown (NOT Absent — absence is what
        //     feeds main.rs's false-absence recovery decisions),
        //   * absent pipe  -> Absent (only provable state),
        //   * serving pipe -> Alive.
        // All within the probe's bounded wall-clock.
        let busy = format!(r"\\.\pipe\openprotect-probe-busy-{}", std::process::id());
        let (server, _c1) = busy_pipe_fixture(&busy);
        let _ = tokio::time::timeout(Duration::from_secs(1), server.connect()).await;
        let t0 = std::time::Instant::now();
        assert_eq!(
            probe_liveness(&busy).await,
            Liveness::Unknown,
            "busy endpoint must classify Unknown, not Absent"
        );
        assert!(t0.elapsed() < Duration::from_secs(6), "probe unbounded");
        drop((server, _c1));

        assert_eq!(
            probe_liveness(r"\\.\pipe\openprotect-probe-absent-98765").await,
            Liveness::Absent,
            "a never-created pipe is the only provably-Absent state"
        );

        let live = format!(r"\\.\pipe\openprotect-probe-live-{}", std::process::id());
        let srv2 = bind_server_pipe(&live).await.unwrap();
        let accepting = tokio::spawn(async move { srv2.connect().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            probe_liveness(&live).await,
            Liveness::Alive,
            "a server with a free listening instance is Alive"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), accepting).await;
    }

    /// Table-driven check of the pure liveness classifier against the
    /// OS error codes we verified live on Windows 11 26100 (scratch
    /// probe: absent→2 instantly, busy→231 instantly, created-not-
    /// connected→Ok). The whole point of the tri-state: **absence may
    /// only be asserted where the OS proves it.**
    #[test]
    fn classify_open_outcome_table() {
        let case = |raw: Option<i32>| {
            BoundedOpen::Failed(std::io::Error::from_raw_os_error(raw.unwrap_or(0)))
        };
        let rows: Vec<(BoundedOpen, Liveness, &str)> = vec![
            (BoundedOpen::Connected(1), Liveness::Alive, "attached"),
            (case(Some(2)), Liveness::Absent, "ERROR_FILE_NOT_FOUND"),
            (case(Some(3)), Liveness::Absent, "ERROR_PATH_NOT_FOUND"),
            // The false-absence class — every one of these proves the
            // pipe EXISTS (or that we could not tell); none is Absent:
            (case(Some(231)), Liveness::Unknown, "ERROR_PIPE_BUSY"),
            (case(Some(5)), Liveness::Unknown, "ERROR_ACCESS_DENIED"),
            (
                case(Some(121)),
                Liveness::Unknown,
                "ERROR_SEM_TIMEOUT (WaitNamedPipe expiry)",
            ),
            (
                case(Some(232)),
                Liveness::Unknown,
                "ERROR_PIPE_NOT_AVAILABLE (closing)",
            ),
            (case(Some(1231)), Liveness::Unknown, "unexpected OS error"),
            (
                BoundedOpen::Parked,
                Liveness::Unknown,
                "open deadline expiry",
            ),
        ];
        for (outcome, want, why) in rows {
            assert_eq!(classify_open_outcome(&outcome), want, "{why}");
        }
    }

    /// Client-open error mapping: ERROR_PIPE_BUSY must land on the
    /// dedicated `PipeBusy` variant, never `AlreadyRunning` (which
    /// means *conflict*, and whose sibling collapse fed the
    /// false-absence sweeps at main.rs:1923-1924/:2079-2083).
    #[test]
    fn map_client_open_error_busy_is_pipe_busy_not_already_running() {
        let mapped =
            |raw: i32| map_client_open_error(std::io::Error::from_raw_os_error(raw), "pipe");
        assert!(matches!(mapped(231), IpcError::PipeBusy(_)));
        assert!(!matches!(mapped(231), IpcError::AlreadyRunning(_)));
        assert!(matches!(mapped(2), IpcError::NotRunning(_)));
        assert!(matches!(mapped(5), IpcError::PermissionDenied(_)));
        assert!(matches!(mapped(121), IpcError::Io(_)));
    }

    /// Regression guard for the *server-create* site: the split must
    /// not have silently downgraded conflict detection there.
    #[test]
    fn map_win_pipe_error_create_site_keeps_conflict_semantics() {
        let mapped = |raw: i32| map_win_pipe_error(std::io::Error::from_raw_os_error(raw), "pipe");
        assert!(matches!(mapped(231), IpcError::AlreadyRunning(_)));
        assert!(matches!(mapped(2), IpcError::NotRunning(_)));
        assert!(matches!(mapped(5), IpcError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn enumerate_keeps_busy_pipe_as_candidate() {
        // RED: the liveness probe in `enumerate_live_instances_pipe`
        // collapses every open error (including ERROR_PIPE_BUSY) into
        // "not live". A busy pipe is provably NOT absent — dropping it
        // here is what lets main.rs's sweep/recover decisions see a
        // live-but-busy session as gone and delete its NRPT rule.
        let instance = format!("test-busy2-{}", std::process::id());
        let pipe_name = endpoint_for(&instance);
        let (server, _c1) = busy_pipe_fixture(&pipe_name);
        let _ = tokio::time::timeout(Duration::from_secs(1), server.connect()).await;

        let live = enumerate_live_instances().await;
        assert!(
            live.iter().any(|(name, _)| *name == instance),
            "busy instance {instance:?} must survive enumeration as a \
             candidate (never reported absent on ERROR_PIPE_BUSY); got {live:?}"
        );
    }
}

#[cfg(all(test, unix))]
mod tests_unix_roundtrip {
    // Unix socket integration test is in tests/roundtrip.rs.
}
