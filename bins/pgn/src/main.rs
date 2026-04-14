//! `pgn` — Pangolin GlobalProtect VPN CLI.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use gp_auth::{
    AuthContext, AuthProvider, GpClient, PasswordAuthProvider, SamlBrowserAuthProvider,
    SamlPasteAuthProvider,
};
use gp_ipc::{
    bind_server, build_snapshot, client_roundtrip, read_request, write_response, IpcError,
    Request as IpcRequest, Response as IpcResponse, StateSnapshotBase, DEFAULT_SOCKET_PATH,
};
use gp_proto::{AuthCookie, ClientOs, GatewayLoginResult, GpParams};
use gp_tunnel::OpenConnectSession;

#[derive(Parser)]
#[command(name = "pgn", version, about = "Pangolin GlobalProtect VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output as JSON.
    #[arg(long, global = true, env = "PGN_JSON")]
    json: bool,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, global = true, env = "PGN_LOG", default_value = "info")]
    log: String,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum SamlAuthMode {
    /// Embedded WebKitGTK window (requires a display).
    Webview,
    /// Headless — local HTTP server + terminal paste.
    Paste,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a GlobalProtect VPN portal.
    Connect {
        /// Portal URL or config profile name.
        portal: String,

        /// Username.
        #[arg(short, long, env = "PGN_USER")]
        user: Option<String>,

        /// Read password from stdin.
        #[arg(long)]
        passwd_on_stdin: bool,

        /// OS to spoof (win, mac, linux).
        #[arg(long, env = "PGN_OS", default_value = "win")]
        os: String,

        /// Accept invalid TLS certificates.
        #[arg(long)]
        insecure: bool,

        /// Path to a vpnc-compatible script for route/DNS setup.
        /// Defaults to /etc/vpnc/vpnc-script if present.
        #[arg(long, env = "PGN_VPNC_SCRIPT")]
        vpnc_script: Option<String>,

        /// SAML auth mode: `webview` (opens a local GTK+WebKit window,
        /// needs a display) or `paste` (headless — starts a local HTTP
        /// server, you complete auth in any browser and paste/POST the
        /// callback URL back).
        #[arg(long, value_enum, default_value_t = SamlAuthMode::Webview, env = "PGN_AUTH_MODE")]
        auth_mode: SamlAuthMode,

        /// Local port for paste-mode's callback server.
        #[arg(long, default_value_t = 29999, env = "PGN_SAML_PORT")]
        saml_port: u16,

        /// Only route these targets through the VPN (split tunnel).
        /// Accepts a comma-separated mix of CIDRs (`10.0.0.0/8`), bare IPs
        /// (`1.2.3.4`), and hostnames (`moodle.example.com` — resolved
        /// through your local DNS *before* the tunnel comes up). When set,
        /// pgn uses its bundled vpnc-script which installs exactly these
        /// routes and nothing else — default route and DNS stay untouched.
        #[arg(long, value_name = "CIDR|IP|HOST", env = "PGN_ONLY")]
        only: Option<String>,
    },

    /// Disconnect from VPN.
    Disconnect,

    /// Show connection status.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log)),
        )
        .init();

    match cli.command {
        Some(Commands::Connect {
            portal,
            user,
            passwd_on_stdin,
            os,
            insecure,
            vpnc_script,
            auth_mode,
            saml_port,
            only,
        }) => {
            connect(ConnectArgs {
                portal,
                user,
                passwd_on_stdin,
                os,
                insecure,
                vpnc_script,
                auth_mode,
                saml_port,
                only,
            })
            .await
        }
        Some(Commands::Disconnect) => disconnect(cli.json).await,
        Some(Commands::Status) | None => status(cli.json).await,
    }
}

/// Where the running session keeps its control socket. Currently a
/// hard-coded path; switch to reading a `PGN_CONTROL_SOCKET` env var
/// if a per-user override is ever needed.
fn control_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

/// `pgn status` — query the running session (if any) and pretty-print.
async fn status(json: bool) -> Result<()> {
    let path = control_socket_path();
    match client_roundtrip(&path, &IpcRequest::Status).await {
        Ok(IpcResponse::Status(s)) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&s).unwrap_or_else(|_| "{}".into())
                );
            } else {
                let mins = s.uptime_seconds / 60;
                let secs = s.uptime_seconds % 60;
                println!("state:     connected");
                println!("portal:    {}", s.portal);
                println!("gateway:   {}", s.gateway);
                println!("user:      {}", s.user);
                println!("os-spoof:  {}", s.reported_os);
                println!("uptime:    {}m{}s", mins, secs);
                if s.routes.is_empty() {
                    println!("routes:    (default — script-managed)");
                } else {
                    println!("routes:    {}", s.routes.join(", "));
                }
            }
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("server error: {message}");
        }
        Ok(IpcResponse::Ok) => {
            anyhow::bail!("server returned Ok to a Status request — protocol bug");
        }
        Err(IpcError::NotRunning(_)) => {
            if json {
                println!(r#"{{"state":"disconnected"}}"#);
            } else {
                println!("state:     disconnected");
            }
            Ok(())
        }
        Err(IpcError::PermissionDenied(_)) => {
            anyhow::bail!(
                "control socket exists but you don't have permission to read it — \
                 try `sudo pgn status`"
            );
        }
        Err(e) => Err(anyhow::anyhow!(e).context("querying pgn status")),
    }
}

/// `pgn disconnect` — ask the running session to tear down.
async fn disconnect(json: bool) -> Result<()> {
    let path = control_socket_path();
    match client_roundtrip(&path, &IpcRequest::Disconnect).await {
        Ok(IpcResponse::Ok) => {
            if json {
                println!(r#"{{"result":"disconnect-requested"}}"#);
            } else {
                println!("disconnect requested");
            }
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("server error: {message}");
        }
        Ok(IpcResponse::Status(_)) => {
            anyhow::bail!("server returned Status to a Disconnect request — protocol bug");
        }
        Err(IpcError::NotRunning(_)) => {
            if json {
                println!(r#"{{"result":"not-running"}}"#);
            } else {
                println!("no running pgn session");
            }
            Ok(())
        }
        Err(IpcError::PermissionDenied(_)) => {
            anyhow::bail!(
                "control socket exists but you don't have permission to read it — \
                 try `sudo pgn disconnect`"
            );
        }
        Err(e) => Err(anyhow::anyhow!(e).context("requesting pgn disconnect")),
    }
}

struct ConnectArgs {
    portal: String,
    user: Option<String>,
    passwd_on_stdin: bool,
    os: String,
    insecure: bool,
    vpnc_script: Option<String>,
    auth_mode: SamlAuthMode,
    saml_port: u16,
    only: Option<String>,
}

async fn connect(args: ConnectArgs) -> Result<()> {
    let ConnectArgs {
        portal,
        user,
        passwd_on_stdin,
        os,
        insecure,
        vpnc_script,
        auth_mode,
        saml_port,
        only,
    } = args;
    let portal = portal.as_str();
    let os = os.as_str();
    // 1. Load config
    let config = gp_config::PangolinConfig::load().context("loading config")?;

    let (portal_url, cfg_user) = if let Some(profile) = config.find_portal(portal) {
        (profile.url.clone(), profile.username.clone())
    } else {
        (portal.to_string(), None)
    };

    // Normalize: strip scheme and trailing slash so we never build
    // "https://https://..." URLs.
    let portal_url = gp_proto::params::normalize_server(&portal_url).to_string();

    let client_os: ClientOs = os.parse().unwrap_or_default();
    let mut gp_params = GpParams::new(client_os);
    gp_params.ignore_tls_errors = insecure;

    let client = GpClient::new(gp_params.clone()).context("creating HTTP client")?;

    // 2. Portal prelogin
    tracing::info!("connecting to portal {portal_url}");
    let prelogin = client
        .prelogin(&portal_url)
        .await
        .context("portal prelogin")?;

    tracing::info!(
        "region: {}, auth: {}",
        prelogin.region(),
        if prelogin.is_saml() {
            "SAML"
        } else {
            "password"
        }
    );

    // 3. Authenticate
    let password = if passwd_on_stdin {
        let mut pw = String::new();
        std::io::stdin().read_line(&mut pw)?;
        Some(pw.trim().to_string())
    } else {
        None
    };

    let auth_ctx = AuthContext {
        server: portal_url.clone(),
        username: user.or(cfg_user),
        password,
        max_mfa_attempts: 3,
    };

    let cred = if prelogin.is_saml() {
        match auth_mode {
            SamlAuthMode::Webview => {
                SamlBrowserAuthProvider
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("SAML (webview) authentication")?
            }
            SamlAuthMode::Paste => {
                SamlPasteAuthProvider::new(saml_port)
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("SAML (paste) authentication")?
            }
        }
    } else {
        PasswordAuthProvider
            .authenticate(&prelogin, &auth_ctx)
            .await
            .context("password authentication")?
    };

    tracing::info!("authenticated as {}", cred.username());

    // 4. Portal config
    let portal_config = client
        .portal_config(&portal_url, &cred)
        .await
        .context("portal config")?;

    tracing::info!("found {} gateway(s)", portal_config.gateways.len());
    for gw in &portal_config.gateways {
        tracing::info!("  {} — {}", gw.address, gw.description);
    }

    // 5. Select gateway
    let gateway = portal_config
        .preferred_gateway(Some(prelogin.region()))
        .context("no gateways available")?;
    tracing::info!(
        "selected gateway: {} ({})",
        gateway.address,
        gateway.description
    );

    // 6. Gateway login (with MFA retry loop)
    let gw_cred = portal_config.to_gateway_credential();
    let mut gw_params = gp_params.clone();
    gw_params.is_gateway = true;

    let auth_cookie = {
        let max_attempts = auth_ctx.max_mfa_attempts;
        let mut attempts = 0u32;

        loop {
            let gw_client = GpClient::new(gw_params.clone()).context("creating gateway client")?;
            let login_result = gw_client
                .gateway_login(&gateway.address, &gw_cred)
                .await
                .context("gateway login")?;

            match login_result {
                GatewayLoginResult::Success(cookie) => break cookie,
                GatewayLoginResult::MfaChallenge { message, input_str } => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        anyhow::bail!("MFA failed after {attempts} attempts");
                    }
                    println!("{message}");
                    print!("OTP Code: ");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    let mut otp = String::new();
                    std::io::stdin().read_line(&mut otp)?;
                    let otp = otp.trim().to_string();
                    if otp.is_empty() {
                        anyhow::bail!("MFA cancelled");
                    }
                    gw_params.input_str = Some(input_str);
                    gw_params.otp = Some(otp);
                }
            }
        }
    };

    tracing::info!("obtained gateway authcookie");

    // 7. Resolve --only (split-tunnel) spec, if any.
    //
    // Hostnames are resolved here — BEFORE the tunnel comes up — via
    // the normal system resolver. That's usually what you want: the
    // public address is what you'll route through the VPN. Resolving
    // *after* tunnel-up would require internal DNS, which we don't
    // manage yet.
    let routes: Vec<String> = match only.as_deref() {
        Some(spec) => resolve_only_spec(spec).await.context("resolving --only")?,
        None => Vec::new(),
    };
    if !routes.is_empty() {
        tracing::info!("split tunnel: {} route(s) — {}", routes.len(), routes.join(" "));
        // SAFETY: set_var is only unsound under concurrent access. We're
        // on the async main thread before spawning the tunnel thread, so
        // no other thread is reading the environment yet.
        std::env::set_var("PANGOLIN_ROUTES", routes.join(" "));
    }

    // 8. Hand off to libopenconnect via gp-tunnel.
    let cookie_str = build_openconnect_cookie(&auth_cookie);
    let oc_os = map_os_to_openconnect(os);
    let gateway_host = gateway.address.clone();

    // The bundled-script guard, if any, must outlive `run_tunnel` so the
    // file isn't unlinked while libopenconnect is still calling it.
    let bundled_script_guard: Option<BundledVpncScript>;
    let script: Option<String> = match vpnc_script {
        Some(explicit) => {
            bundled_script_guard = None;
            Some(explicit)
        }
        None if !routes.is_empty() => {
            let g = install_bundled_vpnc_script()
                .context("installing bundled vpnc-script for --only")?;
            let p = g.path_str()
                .context("bundled vpnc-script path is not utf-8")?
                .to_string();
            bundled_script_guard = Some(g);
            Some(p)
        }
        None => {
            bundled_script_guard = None;
            default_vpnc_script()
        }
    };

    tracing::info!(
        "starting tunnel: gateway={gateway_host} os={oc_os} vpnc_script={:?}",
        script
    );

    // libopenconnect's main loop blocks, so run it on a dedicated OS thread.
    // The session itself is !Send (raw pointer) so we construct it inside the
    // thread and hand the cancel handle back via a oneshot.
    let (handle_tx, handle_rx) = std::sync::mpsc::channel();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<()>>();

    let tunnel_thread = std::thread::Builder::new()
        .name("pgn-tunnel".into())
        .spawn(move || {
            let result = run_tunnel(
                &gateway_host,
                &cookie_str,
                oc_os,
                script.as_deref(),
                handle_tx,
            );
            let _ = done_tx.send(result);
        })
        .context("spawning tunnel thread")?;

    // Receive the cancel handle from the tunnel thread (available as soon as
    // the session is created; before the blocking main loop starts).
    let cancel_handle = handle_rx
        .recv()
        .context("tunnel thread failed before signalling readiness")?;

    // Spawn the IPC server so `pgn status` / `pgn disconnect` from another
    // shell can talk to this session.
    //
    // `started_at_unix` is captured ONCE here from the wall clock so the
    // reported session start time stays stable across `pgn status` queries
    // — NTP steps and manual clock changes during the session won't
    // drift it.
    let started_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ipc_base = StateSnapshotBase {
        portal: portal_url.clone(),
        gateway: gateway.address.clone(),
        user: auth_cookie.username.clone(),
        reported_os: oc_os.to_string(),
        routes: routes.clone(),
        started_at_unix,
    };
    let ipc_start = Instant::now();
    let (ipc_disconnect_tx, mut ipc_disconnect_rx) =
        tokio::sync::oneshot::channel::<()>();
    let ipc_socket_path = control_socket_path();
    let ipc_handle = spawn_ipc_server(
        ipc_socket_path.clone(),
        Arc::new(ipc_base),
        ipc_start,
        ipc_disconnect_tx,
    )
    .await
    .context("starting ipc server")?;

    tracing::info!("tunnel running — press Ctrl-C (or `pgn disconnect`) to tear down");

    // All three exit paths fall through to the same cleanup block. The
    // `early_exit` slot captures the tunnel's own return value when
    // `done_rx` wins the race, so the shared cleanup block can decide
    // between "await done_rx" and "use what we already have".
    let mut early_exit: Option<Result<()>> = None;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
        }
        _ = &mut ipc_disconnect_rx => {
            tracing::info!("disconnect request received via control socket, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
        }
        res = &mut done_rx => {
            early_exit = Some(match res {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("tunnel thread panicked")),
            });
        }
    }

    // Unified cleanup regardless of which arm fired.
    ipc_handle.abort();
    let _ = std::fs::remove_file(&ipc_socket_path);

    let final_res = match early_exit {
        Some(r) => r,
        None => done_rx.await.context("tunnel thread did not report exit")?,
    };
    let _ = tunnel_thread.join();
    // Drop the bundled-script guard AFTER the tunnel thread is joined
    // so the file is only unlinked once libopenconnect has finished
    // invoking it.
    drop(bundled_script_guard);
    final_res
}

/// Build the GlobalProtect cookie string that libopenconnect expects.
///
/// Format matches openconnect's own `auth-globalprotect.c`: a `&`-joined
/// set of `key=value` pairs with the keys `authcookie`, `portal`, `user`,
/// `domain`, `computer`, and `preferred-ip`.
fn build_openconnect_cookie(c: &AuthCookie) -> String {
    let mut parts = vec![
        format!("authcookie={}", c.authcookie),
        format!("portal={}", c.portal),
        format!("user={}", c.username),
    ];
    if let Some(d) = &c.domain {
        parts.push(format!("domain={d}"));
    }
    if let Some(comp) = &c.computer {
        parts.push(format!("computer={comp}"));
    }
    if let Some(ip) = &c.preferred_ip {
        parts.push(format!("preferred-ip={ip}"));
    }
    parts.join("&")
}

/// Spawn the IPC server on a tokio task. Returns a `JoinHandle` so the
/// caller can `abort()` it on tunnel teardown.
///
/// The server owns the `UnixListener` and an `Arc<StateSnapshotBase>`.
/// On every connection it reads a single JSON request and writes a
/// single JSON response. A `Disconnect` request is forwarded exactly
/// once to `disconnect_tx` — subsequent `Disconnect` requests reply `Ok`
/// without firing again.
async fn spawn_ipc_server(
    path: PathBuf,
    base: Arc<StateSnapshotBase>,
    started_at: Instant,
    disconnect_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = bind_server(&path)
        .await
        .with_context(|| format!("binding control socket at {}", path.display()))?;
    tracing::info!("control socket listening on {}", path.display());

    // The disconnect sender is consumed on first use. `Arc<Mutex<Option<..>>>`
    // lets multiple concurrent status requests coexist with an eventual
    // single disconnect request without panicking.
    let disconnect_tx = Arc::new(tokio::sync::Mutex::new(Some(disconnect_tx)));

    Ok(tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    // A persistent accept error (e.g. EMFILE, listener
                    // fd closed) would otherwise spin this loop at
                    // ~100% CPU. A tiny sleep turns it into a slow
                    // retry without hiding the problem from tracing.
                    tracing::debug!("control socket accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let base = Arc::clone(&base);
            let disconnect_tx = Arc::clone(&disconnect_tx);
            tokio::spawn(async move {
                if let Err(e) = handle_ipc_client(stream, base, started_at, disconnect_tx).await {
                    tracing::debug!("control socket client error: {e}");
                }
            });
        }
    }))
}

/// How long a client gets to send its request line before we give up
/// on the connection. Bounds the cost of a client that half-opens a
/// socket and never writes anything.
const IPC_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle one client connection: one request, one response, close.
async fn handle_ipc_client(
    mut stream: tokio::net::UnixStream,
    base: Arc<StateSnapshotBase>,
    started_at: Instant,
    disconnect_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
) -> Result<(), IpcError> {
    let req = match tokio::time::timeout(IPC_READ_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(IpcError::Protocol(
                "client did not send a request within the timeout".into(),
            ))
        }
    };
    let resp = match req {
        IpcRequest::Status => IpcResponse::Status(build_snapshot(&base, started_at)),
        IpcRequest::Disconnect => {
            let mut slot = disconnect_tx.lock().await;
            if let Some(tx) = slot.take() {
                let _ = tx.send(());
            }
            IpcResponse::Ok
        }
    };
    write_response(&mut stream, &resp).await?;
    Ok(())
}

/// Map the pangolin `--os` flag to the string libopenconnect expects for
/// `openconnect_set_reported_os`.
fn map_os_to_openconnect(os: &str) -> &'static str {
    match os {
        "win" | "windows" => "win",
        "mac" | "macos" | "mac-intel" => "mac-intel",
        "linux" => "linux",
        _ => "win",
    }
}

fn default_vpnc_script() -> Option<String> {
    for path in [
        "/etc/vpnc/vpnc-script",
        "/usr/share/vpnc-scripts/vpnc-script",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Bundled minimal vpnc-script. Compiled into the binary so pgn doesn't
/// need anything installed on disk.
const BUNDLED_VPNC_SCRIPT: &str =
    include_str!("../../../scripts/pangolin-vpnc-script.sh");

/// Owned guard for the bundled vpnc-script we install on disk. Drop
/// unlinks the file so we don't leave dead scripts lying around in
/// `/tmp` or `$XDG_RUNTIME_DIR` between runs.
struct BundledVpncScript {
    path: std::path::PathBuf,
}

impl BundledVpncScript {
    /// Return the path as a `&str` for downstream APIs that take string
    /// paths. Errors (rather than panics) if `XDG_RUNTIME_DIR` happens
    /// to contain non-UTF-8 bytes — rare but legal on Linux.
    fn path_str(&self) -> Result<&str> {
        self.path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "bundled vpnc-script path is not valid UTF-8: {}",
                self.path.display()
            )
        })
    }
}

impl Drop for BundledVpncScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write the bundled vpnc-script to a runtime location and return a
/// guard that owns its lifetime. The path is unique per invocation
/// (PID + monotonic nanos) and the file is created with `O_CREAT |
/// O_EXCL` and mode `0700` to defeat predictable-path symlink races
/// — the previous version of this function used a fixed filename and
/// was vulnerable.
///
/// `$XDG_RUNTIME_DIR` is preferred (per-user, tmpfs, mode 0700 on most
/// distros). `/tmp` is the fallback; even then the `O_EXCL` + unique
/// suffix combination keeps things safe.
fn install_bundled_vpnc_script() -> Result<BundledVpncScript> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

    let pid = std::process::id();
    // Nanos since boot via CLOCK_MONOTONIC, mixed with a thread-local
    // counter to defend against same-nanosecond collisions.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_else(|_| pid as u128);

    // Try a few suffix variations until O_EXCL succeeds (handles the
    // astronomically unlikely collision case without panicking).
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0u32..16 {
        let name = format!("pangolin-vpnc-{pid}-{nanos}-{attempt}.sh");
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT | O_EXCL
            .mode(0o700) // owner rwx only — refuse group/other access
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(BUNDLED_VPNC_SCRIPT.as_bytes())
                    .with_context(|| format!("writing {}", path.display()))?;
                return Ok(BundledVpncScript { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "creating bundled vpnc-script at {}: {e}",
                    path.display()
                ));
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not create a unique bundled vpnc-script in {} after 16 attempts: {:?}",
        dir.display(),
        last_err
    ))
}

/// Parse a `--only` spec into a list of `ip/prefix` route strings suitable
/// for `ip route add`.
///
/// Each comma-separated entry is one of:
///   * a CIDR like `10.0.0.0/8` → used verbatim
///   * a bare IP like `1.2.3.4` → turned into `1.2.3.4/32` (v4) or
///     `::1/128` (v6)
///   * a hostname → resolved via the system DNS *before* the tunnel
///     comes up, each resulting address yielding one /32 or /128 entry.
///
/// Returns an error if any entry fails to parse/resolve, OR if the
/// effective list is empty (after trimming + dropping blanks). An empty
/// `--only` would silently disable split-tunneling, which is almost
/// never what the user intended.
async fn resolve_only_spec(spec: &str) -> Result<Vec<String>> {
    let entries: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        anyhow::bail!(
            "--only was given but resolved to no targets (got {spec:?}). \
             Pass at least one CIDR / IP / hostname, or omit --only entirely."
        );
    }

    let mut routes = Vec::new();
    for entry in entries {
        if let Some((ip_str, mask_str)) = entry.split_once('/') {
            let ip: std::net::IpAddr = ip_str
                .parse()
                .with_context(|| format!("invalid address in {entry:?}"))?;
            let mask: u8 = mask_str
                .parse()
                .with_context(|| format!("invalid mask in {entry:?}"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            anyhow::ensure!(
                mask <= max,
                "mask {mask} out of range for {}",
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            );
            routes.push(format!("{ip}/{mask}"));
        } else if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
            let mask = if ip.is_ipv4() { 32 } else { 128 };
            routes.push(format!("{ip}/{mask}"));
        } else {
            // Hostname. tokio::net::lookup_host takes `host:port`; the port
            // is irrelevant for route installation, we only read `.ip()`.
            let addrs = tokio::net::lookup_host(format!("{entry}:0"))
                .await
                .with_context(|| format!("resolving {entry}"))?;
            let mut any = false;
            for sa in addrs {
                let ip = sa.ip();
                let mask = if ip.is_ipv4() { 32 } else { 128 };
                routes.push(format!("{ip}/{mask}"));
                any = true;
            }
            anyhow::ensure!(any, "{entry} resolved to zero addresses");
        }
    }
    Ok(routes)
}

/// Drive the openconnect session on its own OS thread.
///
/// On success, sends a `CancelHandle` through `handle_tx` before entering the
/// blocking main loop, so the async runtime can trigger cancellation.
fn run_tunnel(
    gateway_host: &str,
    cookie: &str,
    os: &str,
    vpnc_script: Option<&str>,
    handle_tx: std::sync::mpsc::Sender<gp_tunnel::CancelHandle>,
) -> Result<()> {
    let mut session =
        OpenConnectSession::new("PAN GlobalProtect").context("creating openconnect session")?;

    session.set_protocol_gp().context("set_protocol_gp")?;
    session.set_hostname(gateway_host).context("set_hostname")?;
    session.set_os_spoof(os).context("set_os_spoof")?;
    session.set_cookie(cookie).context("set_cookie")?;

    // Hand the cancel fd out before we start the blocking work.
    let cancel = session
        .cancel_handle()
        .expect("cancel handle must be available");
    handle_tx
        .send(cancel)
        .context("sending cancel handle to main thread")?;

    session
        .make_cstp_connection()
        .context("make_cstp_connection")?;
    session
        .setup_tun_device(vpnc_script)
        .context("setup_tun_device")?;

    session.run(60, 10).context("openconnect mainloop")?;
    Ok(())
}
