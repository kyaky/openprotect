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
    Request as IpcRequest, Response as IpcResponse, SessionState, StateSnapshotBase,
    DEFAULT_SOCKET_PATH,
};
use gp_proto::{AuthCookie, ClientOs, GatewayLoginResult, GpParams};
use gp_tunnel::{IpInfoSnapshot, OpenConnectSession};

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
                let state_str = match s.state {
                    SessionState::Connected => "connected",
                    SessionState::Connecting => "connecting",
                    SessionState::Reconnecting => "reconnecting",
                };
                println!("state:     {state_str}");
                println!("portal:    {}", s.portal);
                println!("gateway:   {}", s.gateway);
                println!("user:      {}", s.user);
                println!("os-spoof:  {}", s.reported_os);
                println!("uptime:    {}m{}s", mins, secs);
                println!(
                    "interface: {}",
                    s.tun_ifname.as_deref().unwrap_or("(unknown)")
                );
                println!(
                    "local-ip:  {}",
                    s.local_ipv4.as_deref().unwrap_or("(none)")
                );
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
        tracing::info!(
            "split tunnel: {} route(s) resolved — {}",
            routes.len(),
            routes.join(" ")
        );
    }

    // 8. Hand off to libopenconnect via gp-tunnel.
    //
    // Decision matrix for the tun-device configuration path:
    //
    //   --vpnc-script <path>   → pass through as-is. The user is
    //                            opting into the traditional
    //                            libopenconnect behaviour (server-
    //                            pushed routes, DNS, etc.). `--only`
    //                            is ignored on this path.
    //   no --vpnc-script,
    //   --only <targets>       → pass NULL to libopenconnect so no
    //                            script runs; gp-route installs
    //                            `--only` routes natively from Rust
    //                            after `setup_tun_device` returns.
    //   no --vpnc-script,
    //   no --only              → fall back to `/etc/vpnc/vpnc-script`
    //                            if it exists; otherwise NULL and the
    //                            interface comes up but does no
    //                            routing (safe default for testing).
    let cookie_str = build_openconnect_cookie(&auth_cookie);
    let oc_os = map_os_to_openconnect(os);
    let gateway_host = gateway.address.clone();

    let script: Option<String> = match (vpnc_script.as_ref(), routes.is_empty()) {
        (Some(explicit), _) => Some(explicit.clone()),
        (None, false) => None, // native gp-route path
        (None, true) => default_vpnc_script(),
    };

    tracing::info!(
        "starting tunnel: gateway={gateway_host} os={oc_os} vpnc_script={:?} native_routes={}",
        script,
        routes.len()
    );

    // Channels used by `run_tunnel` to talk back to us:
    //  * `cancel_rx` receives the CancelHandle as soon as the session
    //    is created — available before any blocking work so Ctrl-C
    //    can interrupt the CSTP / setup_tun path.
    //  * `ready_rx` receives a TunnelReady once setup_tun_device has
    //    succeeded — carries the tun ifname + libopenconnect's ip_info.
    //  * `done_rx` receives the tunnel thread's final Result.
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<TunnelReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<()>>();

    let split_routes = routes.clone();
    let tunnel_thread = std::thread::Builder::new()
        .name("pgn-tunnel".into())
        .spawn(move || {
            let result = run_tunnel(
                &gateway_host,
                &cookie_str,
                oc_os,
                script.as_deref(),
                split_routes,
                cancel_tx,
                ready_tx,
            );
            let _ = done_tx.send(result);
        })
        .context("spawning tunnel thread")?;

    // 9. Wait for the cancel handle. If the tunnel thread failed before
    //    even getting this far, `recv` returns Err and we propagate via
    //    the `done_rx` path below.
    let cancel_handle = match cancel_rx.recv() {
        Ok(c) => c,
        Err(_) => {
            // The tunnel thread exited before sending the cancel handle.
            // Pick up its error from done_rx.
            let _ = tunnel_thread.join();
            done_rx
                .await
                .context("tunnel thread died without reporting a result")??;
            return Ok(());
        }
    };

    // 10. Wait for setup_tun_device to finish, then spawn the IPC server
    //     with the real ifname / local IP. `recv_timeout` on a blocking
    //     channel from inside a tokio task is awkward, so we race a
    //     `spawn_blocking` call against ctrl_c and done_rx.
    let tunnel_ready = tokio::select! {
        res = tokio::task::spawn_blocking(move || ready_rx.recv()) => {
            match res {
                Ok(Ok(ready)) => ready,
                Ok(Err(_)) | Err(_) => {
                    // Tunnel thread failed before setup_tun_device finished.
                    done_rx.await.context("tunnel thread did not report exit")??;
                    let _ = tunnel_thread.join();
                    return Ok(());
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received during tunnel setup, cancelling...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
            done_rx.await.context("tunnel thread did not report exit")??;
            let _ = tunnel_thread.join();
            return Ok(());
        }
        res = &mut done_rx => {
            let _ = tunnel_thread.join();
            return match res {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("tunnel thread panicked")),
            };
        }
    };

    // 11. Build the IPC state snapshot from auth info + tunnel state.
    //     `started_at_unix` is captured ONCE here so subsequent NTP
    //     steps or manual wall-clock changes don't make `pgn status`
    //     report a drifting start time.
    let started_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let local_ipv4 = tunnel_ready
        .ip_info
        .as_ref()
        .and_then(|i| i.addr.clone());
    let ipc_base = StateSnapshotBase {
        portal: portal_url.clone(),
        gateway: gateway.address.clone(),
        user: auth_cookie.username.clone(),
        reported_os: oc_os.to_string(),
        routes: routes.clone(),
        started_at_unix,
        tun_ifname: tunnel_ready.ifname.clone(),
        local_ipv4,
        state: SessionState::Connected,
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

// The bundled vpnc-script shim that earlier releases installed under
// `$XDG_RUNTIME_DIR/pangolin-vpnc-*.sh` is gone. Native route
// management in `gp-route` replaces it, driven directly from the
// tunnel thread after `setup_tun_device` returns. Users who want
// the classic libopenconnect script behaviour still have
// `--vpnc-script /path/to/script`.

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

/// State captured from libopenconnect after `setup_tun_device`
/// succeeds. Flows from the tunnel thread back to the main thread so
/// the IPC server can advertise the real tun ifname, local IP, etc.
struct TunnelReady {
    ifname: Option<String>,
    ip_info: Option<IpInfoSnapshot>,
}

/// Drive the openconnect session on its own OS thread.
///
/// Sends two messages back to the main thread over separate channels:
///
/// * `cancel_tx` receives a `CancelHandle` as soon as the session has
///   been created (before any blocking work), so Ctrl-C can interrupt
///   the slow CSTP / setup_tun path.
/// * `ready_tx` receives a [`TunnelReady`] snapshot once
///   `setup_tun_device` completes, so the main thread can populate
///   the `StateSnapshotBase` for the IPC server and start serving
///   `pgn status` / `pgn disconnect`.
///
/// If `split_routes` is non-empty, the thread uses `gp-route` to
/// install those routes natively on the tun interface after
/// `setup_tun_device` returns — no shell script involvement. Routes
/// are reverted on the way out.
#[allow(clippy::too_many_arguments)]
fn run_tunnel(
    gateway_host: &str,
    cookie: &str,
    os: &str,
    vpnc_script: Option<&str>,
    split_routes: Vec<String>,
    cancel_tx: std::sync::mpsc::Sender<gp_tunnel::CancelHandle>,
    ready_tx: std::sync::mpsc::Sender<TunnelReady>,
) -> Result<()> {
    let mut session =
        OpenConnectSession::new("PAN GlobalProtect").context("creating openconnect session")?;

    session.set_protocol_gp().context("set_protocol_gp")?;
    session.set_hostname(gateway_host).context("set_hostname")?;
    session.set_os_spoof(os).context("set_os_spoof")?;
    session.set_cookie(cookie).context("set_cookie")?;

    // Hand the cancel fd out BEFORE any blocking work so Ctrl-C can
    // interrupt the slow CSTP / TUN setup path. Receiver drops it on
    // our error path.
    let cancel = session
        .cancel_handle()
        .expect("cancel handle must be available");
    cancel_tx
        .send(cancel)
        .context("sending cancel handle to main thread")?;

    session
        .make_cstp_connection()
        .context("make_cstp_connection")?;
    session
        .setup_tun_device(vpnc_script)
        .context("setup_tun_device")?;

    // Snapshot everything the main thread needs for its IPC server.
    // `get_ip_info` is only valid on this thread and its string
    // pointers are invalidated on the next libopenconnect call — we
    // copy out into an owned `IpInfoSnapshot` and never retain the
    // raw pointers.
    let ifname = session.get_ifname();
    let ip_info = session.get_ip_info().ok();

    // Native route installation — only when the caller provided
    // `--only` routes AND didn't also pass an explicit --vpnc-script
    // (the caller's resolve logic collapses those cases, but double-
    // check here defensively).
    //
    // NOTE: gp-route runs BEFORE we send `TunnelReady`. That means
    // `pgn status` reports `Connecting` until the routes are fully
    // installed and only flips to `Connected` once apply() has
    // succeeded. Users never see a Connected state with broken
    // routing, and the Connecting window correctly covers the time
    // when cancellation via the cmd pipe is not yet polled by the
    // main loop.
    let native_route_state = if !split_routes.is_empty() && vpnc_script.is_none() {
        let ifname = ifname.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "libopenconnect did not report a tun ifname; cannot install native routes"
            )
        })?;
        let ipv4 = ip_info
            .as_ref()
            .and_then(|i| i.addr.as_deref())
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
        let mtu = ip_info.as_ref().and_then(|i| i.mtu);
        let config = gp_route::TunConfig {
            ifname,
            ipv4,
            mtu,
            routes: split_routes.clone(),
        };
        tracing::info!(
            "gp-route: applying {} route(s) natively on {}",
            split_routes.len(),
            config.ifname
        );
        Some(gp_route::apply(&config).context("gp-route apply")?)
    } else {
        None
    };

    // Native DNS configuration — runs only when we also took the
    // native route path. Any vpnc-script the user pointed `pgn` at
    // is expected to handle its own DNS. `gp_dns::apply` auto-
    // detects systemd-resolved and no-ops gracefully on systems
    // that don't have it, so this branch is always safe to enter
    // when route config is native.
    let native_dns_state = if native_route_state.is_some() {
        let ifname_str = ifname.clone().unwrap_or_default();
        let servers: Vec<std::net::IpAddr> = ip_info
            .as_ref()
            .map(|i| &i.dns)
            .into_iter()
            .flatten()
            .filter_map(|s| s.parse().ok())
            .collect();
        let search_domains: Vec<String> = ip_info
            .as_ref()
            .and_then(|i| i.domain.clone())
            // Server pushes a whitespace-separated list in one string.
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();
        // Derive split-DNS domains from the --only hostnames: any
        // entry that looks like a DNS name (not a CIDR or bare IP)
        // contributes a split-DNS domain that resolved will treat
        // as routing-only (`~domain`). This makes `--only
        // intranet.example.com` resolve internal names through the
        // VPN while external names stay on the system resolver.
        let split_domains: Vec<String> = Vec::new();
        let config = gp_dns::DnsConfig {
            ifname: ifname_str,
            servers,
            search_domains,
            split_domains,
        };
        if !config.servers.is_empty() {
            tracing::info!(
                "gp-dns: applying {} nameserver(s) on {} (search={:?})",
                config.servers.len(),
                config.ifname,
                config.search_domains
            );
            Some(gp_dns::apply(&config).context("gp-dns apply")?)
        } else {
            None
        }
    } else {
        None
    };

    // Now that routes AND DNS (if any) are installed, announce
    // readiness. Dropping this Sender on the error path is fine —
    // the main thread's recv will return Err and we'll be picked
    // up via `done_rx` instead.
    let _ = ready_tx.send(TunnelReady {
        ifname: ifname.clone(),
        ip_info: ip_info.clone(),
    });

    // The blocking main loop. Returns when cancelled or the remote drops.
    let run_res = session.run(60, 10);

    // Best-effort cleanup. DNS first (short-lived resolved state),
    // then routes (we want the interface to have no dangling route
    // references when its last config bit comes down). Neither
    // short-circuits the other or the main-loop result.
    if let Some(state) = native_dns_state {
        for err in gp_dns::revert(&state) {
            tracing::warn!("gp-dns revert: {err}");
        }
    }
    if let Some(state) = native_route_state {
        for err in gp_route::revert(&state) {
            tracing::warn!("gp-route revert: {err}");
        }
    }

    run_res.context("openconnect mainloop")?;
    Ok(())
}
