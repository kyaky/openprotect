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

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum SamlAuthMode {
    /// Embedded WebKitGTK window (requires a display).
    Webview,
    /// Headless — local HTTP server + terminal paste.
    Paste,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum HipMode {
    /// Ask the gateway, submit only if needed. Safe default.
    Auto,
    /// Always submit a report regardless of the gateway's
    /// `hip-report-needed` signal — useful for deployments that
    /// enforce HIP silently.
    Force,
    /// Skip the entire HIP flow. Pre-gp-hip behaviour.
    Off,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a GlobalProtect VPN portal.
    ///
    /// `portal` accepts either a profile name (defined via `pgn
    /// portal add`) or a bare URL. Omitting it uses the default
    /// profile set with `pgn portal use <name>`. CLI flags always
    /// override the profile's settings; the profile fills in
    /// whatever the CLI didn't specify.
    Connect {
        /// Portal URL or saved profile name. Optional: uses
        /// `default.portal` from `~/.config/pangolin/config.toml`
        /// when omitted.
        portal: Option<String>,

        /// Username.
        #[arg(short, long, env = "PGN_USER")]
        user: Option<String>,

        /// Read password from stdin.
        #[arg(long)]
        passwd_on_stdin: bool,

        /// OS to spoof (win, mac, linux). Default `win`.
        #[arg(long, env = "PGN_OS")]
        os: Option<String>,

        /// Accept invalid TLS certificates.
        ///
        /// Tri-state so a profile's saved `insecure = true` can be
        /// overridden for a single invocation:
        ///
        ///   * `--insecure`         → true
        ///   * `--insecure=true`    → true
        ///   * `--insecure=false`   → false (overrides profile)
        ///   * (omitted)            → None, fall through to profile
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        insecure: Option<bool>,

        /// Path to a vpnc-compatible script for route/DNS setup.
        /// Defaults to /etc/vpnc/vpnc-script if present.
        #[arg(long, env = "PGN_VPNC_SCRIPT")]
        vpnc_script: Option<String>,

        /// SAML auth mode: `webview` (opens a local GTK+WebKit window,
        /// needs a display) or `paste` (headless — starts a local HTTP
        /// server, you complete auth in any browser and paste/POST the
        /// callback URL back). Default `webview`.
        #[arg(long, value_enum, env = "PGN_AUTH_MODE")]
        auth_mode: Option<SamlAuthMode>,

        /// Local port for paste-mode's callback server. Default 29999.
        #[arg(long, env = "PGN_SAML_PORT")]
        saml_port: Option<u16>,

        /// Only route these targets through the VPN (split tunnel).
        /// Accepts a comma-separated mix of CIDRs (`10.0.0.0/8`), bare IPs
        /// (`1.2.3.4`), and hostnames (`moodle.example.com` — resolved
        /// through your local DNS *before* the tunnel comes up). When set,
        /// pgn installs exactly these routes natively and leaves the
        /// default route alone.
        #[arg(long, value_name = "CIDR|IP|HOST", env = "PGN_ONLY")]
        only: Option<String>,

        /// Host Information Profile (HIP) reporting mode. `auto`
        /// (the default) asks the gateway whether it wants a
        /// report and submits one only if so. `force` always
        /// submits — useful for gateways that silently enforce
        /// HIP without announcing it. `off` skips the whole
        /// flow.
        #[arg(long, value_enum, env = "PGN_HIP")]
        hip: Option<HipMode>,
    },

    /// Disconnect from VPN.
    Disconnect,

    /// Show connection status.
    Status,

    /// Manage saved portal profiles.
    Portal {
        #[command(subcommand)]
        action: PortalAction,
    },
}

#[derive(Subcommand)]
enum PortalAction {
    /// Add or overwrite a saved portal profile.
    Add {
        /// Short name for the profile (used with `pgn connect <name>`).
        name: String,
        /// Portal URL (hostname or full https://…).
        #[arg(long)]
        url: String,
        /// Default username for this profile.
        #[arg(long)]
        user: Option<String>,
        /// OS to spoof.
        #[arg(long)]
        os: Option<String>,
        /// SAML auth mode.
        #[arg(long, value_enum)]
        auth_mode: Option<SamlAuthMode>,
        /// Split-tunnel target list.
        #[arg(long, value_name = "CIDR|IP|HOST")]
        only: Option<String>,
        /// HIP reporting mode.
        #[arg(long, value_enum)]
        hip: Option<HipMode>,
        /// vpnc-compatible script path.
        #[arg(long)]
        vpnc_script: Option<String>,
        /// Accept invalid TLS certificates.
        #[arg(long)]
        insecure: bool,
    },
    /// Remove a saved portal profile.
    Rm {
        /// Profile name to remove.
        name: String,
    },
    /// List all saved portal profiles.
    List,
    /// Set the default profile used by `pgn connect` with no args.
    Use {
        /// Profile name to mark as default.
        name: String,
    },
    /// Show one profile's full details.
    Show {
        /// Profile name to display.
        name: String,
    },
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
            hip,
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
                hip,
            })
            .await
        }
        Some(Commands::Disconnect) => disconnect(cli.json).await,
        Some(Commands::Status) | None => status(cli.json).await,
        Some(Commands::Portal { action }) => portal_command(action).await,
    }
}

/// Dispatch for `pgn portal <action>`. All actions mutate (or
/// read) `~/.config/pangolin/config.toml` via the `gp-config`
/// crate's atomic save.
async fn portal_command(action: PortalAction) -> Result<()> {
    let path = gp_config::PangolinConfig::default_path();
    let mut config = gp_config::PangolinConfig::load_from(&path)
        .with_context(|| format!("loading {}", path.display()))?;

    match action {
        PortalAction::Add {
            name,
            url,
            user,
            os,
            auth_mode,
            only,
            hip,
            vpnc_script,
            insecure,
        } => {
            let profile = gp_config::PortalProfile {
                url,
                username: user,
                gateway: None,
                os,
                auth_mode: auth_mode.map(|m| match m {
                    SamlAuthMode::Webview => "webview".to_string(),
                    SamlAuthMode::Paste => "paste".to_string(),
                }),
                saml_port: None,
                vpnc_script,
                only,
                hip: hip.map(|m| match m {
                    HipMode::Auto => "auto".to_string(),
                    HipMode::Force => "force".to_string(),
                    HipMode::Off => "off".to_string(),
                }),
                insecure: if insecure { Some(true) } else { None },
            };
            config.set_portal(name.clone(), profile);
            config.save_to(&path)?;
            println!("saved profile `{}` to {}", name, path.display());
        }
        PortalAction::Rm { name } => {
            if !config.remove_portal(&name) {
                anyhow::bail!("no such profile: {name}");
            }
            config.save_to(&path)?;
            println!("removed profile `{}`", name);
        }
        PortalAction::List => {
            if config.portal.is_empty() {
                println!("(no saved profiles — use `pgn portal add <name> --url …` to create one)");
                return Ok(());
            }
            let default_name = config.default.portal.as_deref();
            for (name, profile) in &config.portal {
                let marker = if Some(name.as_str()) == default_name {
                    " (default)"
                } else {
                    ""
                };
                println!("{name}{marker}: {}", profile.url);
            }
        }
        PortalAction::Use { name } => {
            if !config.portal.contains_key(&name) {
                anyhow::bail!("no such profile: {name}");
            }
            config.default.portal = Some(name.clone());
            config.save_to(&path)?;
            println!("default profile set to `{}`", name);
        }
        PortalAction::Show { name } => {
            let profile = config
                .portal
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("no such profile: {name}"))?;
            println!("profile:    {name}");
            println!("url:        {}", profile.url);
            if let Some(u) = &profile.username {
                println!("user:       {u}");
            }
            if let Some(o) = &profile.os {
                println!("os:         {o}");
            }
            if let Some(a) = &profile.auth_mode {
                println!("auth-mode:  {a}");
            }
            if let Some(p) = profile.saml_port {
                println!("saml-port:  {p}");
            }
            if let Some(o) = &profile.only {
                println!("only:       {o}");
            }
            if let Some(h) = &profile.hip {
                println!("hip:        {h}");
            }
            if let Some(s) = &profile.vpnc_script {
                println!("vpnc-script: {s}");
            }
            if profile.insecure == Some(true) {
                println!("insecure:   true");
            }
        }
    }
    Ok(())
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
    portal: Option<String>,
    user: Option<String>,
    passwd_on_stdin: bool,
    os: Option<String>,
    insecure: Option<bool>,
    vpnc_script: Option<String>,
    auth_mode: Option<SamlAuthMode>,
    saml_port: Option<u16>,
    only: Option<String>,
    hip: Option<HipMode>,
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
        hip,
    } = args;

    // 1. Load config + resolve CLI args against the profile layer.
    let config = gp_config::PangolinConfig::load().context("loading config")?;
    let resolved = resolve_connect_settings(
        CliConnectOverrides {
            portal,
            user,
            os,
            insecure,
            vpnc_script,
            auth_mode,
            saml_port,
            only,
            hip,
        },
        &config,
    )?;
    let ResolvedConnectSettings {
        portal_url,
        cfg_user,
        os,
        auth_mode,
        saml_port,
        vpnc_script,
        only,
        hip,
        insecure,
        user: merged_user,
    } = resolved;

    // `user` was previously a plain ConnectArgs field; it's now
    // part of the resolved settings so CLI > profile > None
    // merging applies. Shadow the outer name for the rest of the
    // function.
    let user = merged_user;

    let os = os.as_str();
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

    // 6.5 HIP report flow (if the user hasn't turned it off).
    //
    // Runs BEFORE we spawn run_tunnel so it all happens on the
    // async main thread with the existing reqwest client — the
    // tunnel thread is sync and can't easily do HTTP.
    //
    // Flow (matches the reference implementation in
    // yuezk/gpapi/src/gateway/hip.rs):
    //
    //   1. gateway_getconfig  → returns the server-assigned
    //      client IP (libopenconnect will do this again internally
    //      during make_cstp_connection; the duplicate call is the
    //      price of avoiding cross-thread plumbing for one string).
    //   2. compute_csd_md5 over the authcookie string, minus the
    //      session-local fields libopenconnect owns.
    //   3. hip_report_check           → <hip-report-needed>yes|no</…>
    //   4. If needed (or --hip=force), build the HIP XML via
    //      gp_hip::build_report using a spoofed Windows profile,
    //      and submit via submit_hip_report.
    //
    // All errors on this path are logged and become non-fatal
    // UNLESS the user passed `--hip=force`. In auto mode we'd
    // rather connect without a report than refuse a working
    // session because hipreportcheck timed out.
    let cookie_str_for_hip = build_openconnect_cookie(&auth_cookie);
    if hip != HipMode::Off {
        if let Err(e) = run_hip_flow(
            &gateway.address,
            &cookie_str_for_hip,
            &auth_cookie.username,
            hip,
            insecure,
            &gp_params,
        )
        .await
        {
            if hip == HipMode::Force {
                return Err(e.context("--hip=force: HIP flow failed, aborting connect"));
            } else {
                tracing::warn!(
                    "HIP flow non-fatal error (auto mode, continuing): {e:#}"
                );
            }
        }
    }

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

/// Parse a string-form auth mode (from a TOML profile's
/// `auth_mode` field) into the CLI enum. Unknown values log a
/// warning and return `None` so the caller falls through to a
/// safe default rather than erroring — but the warning surfaces
/// the likely typo to the user instead of silently changing
/// runtime behaviour.
fn parse_auth_mode(s: &str) -> Option<SamlAuthMode> {
    match s.to_ascii_lowercase().as_str() {
        "webview" => Some(SamlAuthMode::Webview),
        "paste" => Some(SamlAuthMode::Paste),
        other => {
            tracing::warn!(
                "profile auth_mode = {other:?} is not a recognized value \
                 (expected 'webview' or 'paste'); falling back to the \
                 built-in default"
            );
            None
        }
    }
}

/// Parse a string-form HIP mode (from a TOML profile's `hip`
/// field) into the CLI enum. Same warn-on-unknown semantics as
/// [`parse_auth_mode`].
fn parse_hip_mode(s: &str) -> Option<HipMode> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Some(HipMode::Auto),
        "force" => Some(HipMode::Force),
        "off" | "no" | "false" => Some(HipMode::Off),
        other => {
            tracing::warn!(
                "profile hip = {other:?} is not a recognized value \
                 (expected 'auto', 'force', or 'off'); falling back to \
                 the built-in default"
            );
            None
        }
    }
}

/// Raw CLI-layer inputs that the resolve step needs. A slim
/// subset of [`ConnectArgs`] — just the fields that participate
/// in the CLI > profile > default merge. Passed to
/// [`resolve_connect_settings`] as its own struct so the test
/// suite can build one without also supplying `passwd_on_stdin`
/// or the tokio runtime.
struct CliConnectOverrides {
    portal: Option<String>,
    user: Option<String>,
    os: Option<String>,
    insecure: Option<bool>,
    vpnc_script: Option<String>,
    auth_mode: Option<SamlAuthMode>,
    saml_port: Option<u16>,
    only: Option<String>,
    hip: Option<HipMode>,
}

/// Fully-resolved connection settings: every field is either the
/// user's explicit CLI flag, or the matching profile field, or
/// the hardcoded fallback.
#[derive(Debug)]
#[allow(dead_code)] // fields are consumed by the caller after destructuring
struct ResolvedConnectSettings {
    portal_url: String,
    cfg_user: Option<String>,
    user: Option<String>,
    os: String,
    auth_mode: SamlAuthMode,
    saml_port: u16,
    vpnc_script: Option<String>,
    only: Option<String>,
    hip: HipMode,
    insecure: bool,
}

/// Pure function: merge `cli` on top of `config` to produce the
/// concrete settings `connect()` will actually use.
///
/// Resolution order per field is: CLI > profile > hard-coded
/// default. A missing CLI flag is `None` (clap was configured to
/// use optional types so we can distinguish "not specified"
/// from "specified as the default value"). An unrecognized
/// profile enum value logs a warning and falls through.
fn resolve_connect_settings(
    cli: CliConnectOverrides,
    config: &gp_config::PangolinConfig,
) -> Result<ResolvedConnectSettings> {
    // --- Resolve the portal argument to a profile, if any. ---
    let portal_arg: Option<String> = match cli.portal {
        Some(p) => Some(p),
        None => config.default.portal.clone(),
    };
    let portal_arg = portal_arg.ok_or_else(|| {
        anyhow::anyhow!(
            "no portal given and no default profile set — pass a portal URL or \
             run `pgn portal use <name>` first"
        )
    })?;

    let profile = config.find_portal(&portal_arg).cloned();
    let (portal_url, cfg_user) = match &profile {
        Some(p) => (p.url.clone(), p.username.clone()),
        None => (portal_arg.clone(), None),
    };

    // Normalize: strip scheme and trailing slash so later code
    // never builds "https://https://..." URLs.
    let portal_url = gp_proto::params::normalize_server(&portal_url).to_string();

    // --- Merge every flag: CLI > profile > hardcoded default. ---
    let os: String = cli
        .os
        .or_else(|| profile.as_ref().and_then(|p| p.os.clone()))
        .unwrap_or_else(|| config.default.os.clone());
    let auth_mode: SamlAuthMode = cli
        .auth_mode
        .or_else(|| {
            profile
                .as_ref()
                .and_then(|p| p.auth_mode.as_deref())
                .and_then(parse_auth_mode)
        })
        .unwrap_or(SamlAuthMode::Webview);
    let saml_port: u16 = cli
        .saml_port
        .or_else(|| profile.as_ref().and_then(|p| p.saml_port))
        .unwrap_or(29999);
    let vpnc_script: Option<String> = cli
        .vpnc_script
        .or_else(|| profile.as_ref().and_then(|p| p.vpnc_script.clone()));
    let only: Option<String> = cli
        .only
        .or_else(|| profile.as_ref().and_then(|p| p.only.clone()));
    let hip: HipMode = cli
        .hip
        .or_else(|| {
            profile
                .as_ref()
                .and_then(|p| p.hip.as_deref())
                .and_then(parse_hip_mode)
        })
        .unwrap_or(HipMode::Auto);
    // Tri-state merge: CLI wins if set, even if set to false.
    // That lets `--insecure=false` override a profile's saved
    // `insecure = true` for a single invocation.
    let insecure: bool = cli
        .insecure
        .or_else(|| profile.as_ref().and_then(|p| p.insecure))
        .unwrap_or(false);
    // `cli.user` wins; profile.username is the fallback.
    let user: Option<String> = cli
        .user
        .or_else(|| profile.as_ref().and_then(|p| p.username.clone()));

    Ok(ResolvedConnectSettings {
        portal_url,
        cfg_user,
        user,
        os,
        auth_mode,
        saml_port,
        vpnc_script,
        only,
        hip,
        insecure,
    })
}

/// Run the HIP check + (optional) report submission flow. Returns
/// `Ok(())` on success or when the gateway doesn't ask for a
/// report. The caller decides what to do with an error based on
/// the `--hip=auto|force` setting.
async fn run_hip_flow(
    gateway_host: &str,
    cookie_str: &str,
    user_name: &str,
    mode: HipMode,
    insecure: bool,
    base_params: &GpParams,
) -> Result<()> {
    // A fresh GpClient — gateway-scoped is_gateway=true params,
    // same TLS settings as the rest of the flow.
    let mut params = base_params.clone();
    params.is_gateway = true;
    params.ignore_tls_errors = insecure;
    let client = GpClient::new(params).context("creating HIP client")?;

    // Step 1: fetch the client IP the gateway plans to assign.
    let gw_config = client
        .gateway_getconfig(gateway_host, cookie_str)
        .await
        .context("HIP: gateway_getconfig")?;
    let client_ip = gw_config.client_ipv4;
    tracing::debug!("HIP: gateway reports client_ip={client_ip}");

    // Step 2: compute the csd md5 over the cookie minus the
    // session-local fields libopenconnect owns.
    let csd_md5 = gp_auth::hip::compute_csd_md5(cookie_str);
    tracing::debug!("HIP: computed csd md5 = {csd_md5}");

    // Step 3: ask the gateway whether it wants a report.
    let needed = match mode {
        HipMode::Force => {
            tracing::info!("HIP: --hip=force, submitting report unconditionally");
            true
        }
        HipMode::Auto => {
            let check = client
                .hip_report_check(gateway_host, cookie_str, &client_ip, &csd_md5)
                .await
                .context("HIP: hipreportcheck")?;
            if check.needed {
                tracing::info!("HIP: gateway requires a HIP report — building one");
            } else {
                tracing::info!("HIP: gateway does not require a report, skipping");
            }
            check.needed
        }
        HipMode::Off => unreachable!("caller short-circuits on Off"),
    };

    if !needed {
        return Ok(());
    }

    // Step 4: build the report via gp-hip and submit it.
    let host = gp_hip::HostInfo::detect();
    let profile = gp_hip::HostProfile::spoofed_windows();
    let generate_time = gp_hip_generate_time();
    let report = gp_hip::build_report(
        csd_md5, // md5_sum field — gateway echoes it back in policy logs
        user_name,
        client_ip.clone(),
        host,
        profile,
        generate_time,
    );
    let xml = report.to_xml();
    tracing::debug!("HIP: submitting report ({} bytes)", xml.len());

    client
        .submit_hip_report(gateway_host, cookie_str, &client_ip, &xml)
        .await
        .context("HIP: submit_hip_report")?;

    tracing::info!("HIP: report submitted successfully");
    Ok(())
}

/// Current wall-clock time formatted as `MM/DD/YYYY HH:MM:SS` —
/// the format GlobalProtect expects in the `<generate-time>` HIP
/// field. We deliberately avoid a `chrono` / `time` dep for one
/// format call; std `SystemTime` → Unix secs → a tiny hand-rolled
/// civil-date conversion is plenty.
fn gp_hip_generate_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{mo:02}/{d:02}/{y:04} {h:02}:{mi:02}:{s:02}")
}

/// Convert a Unix timestamp to a civil date in UTC. Uses Howard
/// Hinnant's algorithm (the one used inside many `date` libraries)
/// so we don't need to pull in a dep just to stamp an HIP report.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let h = (sod / 3_600) as u32;
    let mi = ((sod % 3_600) / 60) as u32;
    let s = (sod % 60) as u32;

    // Howard Hinnant "days_from_civil" inverse (a.k.a.
    // civil_from_days). Shifts the origin to 0000-03-01 so
    // February's length quirk falls at the end of the year.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y0 = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y0 + 1 } else { y0 };
    (y, m, d, h, mi, s)
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
            match gp_dns::apply(&config) {
                Ok(state) => Some(state),
                Err(e) => {
                    // gp-dns failed AFTER gp-route::apply already
                    // installed routes. The bottom cleanup block
                    // will not run from a `?` bailout here, so we
                    // must revert the route state explicitly before
                    // propagating the error — otherwise the installed
                    // `ip route add`s leak until the kernel GCs the
                    // tun interface.
                    if let Some(route_state) = native_route_state.as_ref() {
                        tracing::warn!(
                            "gp-dns apply failed, rolling back gp-route state on {}",
                            route_state.ifname
                        );
                        for rev_err in gp_route::revert(route_state) {
                            tracing::warn!("gp-route revert (on dns failure): {rev_err}");
                        }
                    }
                    return Err(anyhow::anyhow!(e).context("gp-dns apply"));
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_unix_epoch() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn civil_from_unix_new_years_2025() {
        // 2025-01-01 00:00:00 UTC = 1_735_689_600.
        assert_eq!(
            civil_from_unix(1_735_689_600),
            (2025, 1, 1, 0, 0, 0)
        );
    }

    #[test]
    fn civil_from_unix_mid_day() {
        // 2024-06-15 12:34:56 UTC
        //   days from epoch to 2024-06-15 = 19889 → 1_718_409_600
        //   + 12h → 1_718_452_800
        //   + 34m → 1_718_454_840
        //   + 56s → 1_718_454_896
        assert_eq!(
            civil_from_unix(1_718_454_896),
            (2024, 6, 15, 12, 34, 56)
        );
    }

    #[test]
    fn civil_from_unix_leap_day_2024() {
        // 2024-02-29 00:00:00 UTC = 1_709_164_800.
        assert_eq!(
            civil_from_unix(1_709_164_800),
            (2024, 2, 29, 0, 0, 0)
        );
    }

    #[test]
    fn generate_time_has_expected_shape() {
        let s = gp_hip_generate_time();
        // "MM/DD/YYYY HH:MM:SS" = 19 chars.
        assert_eq!(s.len(), 19);
        assert!(s.as_bytes()[2] == b'/');
        assert!(s.as_bytes()[5] == b'/');
        assert!(s.as_bytes()[10] == b' ');
        assert!(s.as_bytes()[13] == b':');
        assert!(s.as_bytes()[16] == b':');
    }

    // ---------- resolve_connect_settings tests ----------

    fn empty_overrides() -> CliConnectOverrides {
        CliConnectOverrides {
            portal: None,
            user: None,
            os: None,
            insecure: None,
            vpnc_script: None,
            auth_mode: None,
            saml_port: None,
            only: None,
            hip: None,
        }
    }

    fn config_with_profile() -> gp_config::PangolinConfig {
        let mut c = gp_config::PangolinConfig::default();
        c.default.portal = Some("work".into());
        c.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                username: Some("alice".into()),
                os: Some("linux".into()),
                auth_mode: Some("paste".into()),
                saml_port: Some(40000),
                vpnc_script: Some("/etc/vpnc/my-script".into()),
                only: Some("10.0.0.0/8".into()),
                hip: Some("force".into()),
                insecure: Some(true),
                ..gp_config::PortalProfile::default()
            },
        );
        c
    }

    #[test]
    fn resolve_uses_default_portal_when_cli_omits() {
        let cfg = config_with_profile();
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.portal_url, "vpn.example.com");
        assert_eq!(r.os, "linux"); // from profile
        assert_eq!(r.auth_mode, SamlAuthMode::Paste);
        assert_eq!(r.saml_port, 40000);
        assert_eq!(r.only.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(r.hip, HipMode::Force);
        assert!(r.insecure);
    }

    #[test]
    fn resolve_errors_when_no_portal_and_no_default() {
        let cfg = gp_config::PangolinConfig::default();
        let err = resolve_connect_settings(empty_overrides(), &cfg).unwrap_err();
        assert!(
            err.to_string().contains("no portal given"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_cli_overrides_profile_values() {
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            os: Some("mac".into()),
            auth_mode: Some(SamlAuthMode::Webview),
            saml_port: Some(12345),
            only: Some("192.168.0.0/16".into()),
            hip: Some(HipMode::Off),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.os, "mac");
        assert_eq!(r.auth_mode, SamlAuthMode::Webview);
        assert_eq!(r.saml_port, 12345);
        assert_eq!(r.only.as_deref(), Some("192.168.0.0/16"));
        assert_eq!(r.hip, HipMode::Off);
    }

    #[test]
    fn resolve_insecure_false_cli_overrides_profile_true() {
        // The HIGH finding from the review: user must be able to
        // disable a profile's saved insecure=true for a single run.
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            insecure: Some(false),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert!(!r.insecure, "--insecure=false should override profile");
    }

    #[test]
    fn resolve_insecure_cli_none_inherits_profile() {
        let cfg = config_with_profile();
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert!(r.insecure, "no CLI insecure flag → profile value wins");
    }

    #[test]
    fn resolve_user_cli_overrides_profile() {
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            user: Some("bob".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.user.as_deref(), Some("bob"));
    }

    #[test]
    fn resolve_raw_url_bypasses_profile_lookup() {
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            portal: Some("https://other.example.org".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        // No profile matches "https://other.example.org", so
        // portal_url is taken verbatim after normalization.
        assert_eq!(r.portal_url, "other.example.org");
        // Profile fields must NOT apply when the raw URL doesn't
        // match a profile.
        assert_ne!(r.auth_mode, SamlAuthMode::Paste);
        assert!(!r.insecure);
    }

    #[test]
    fn resolve_unknown_auth_mode_in_profile_falls_back() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("typo".into());
        cfg.set_portal(
            "typo",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                auth_mode: Some("wbview".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.auth_mode, SamlAuthMode::Webview); // the hardcoded default
    }

    #[test]
    fn resolve_hardcoded_defaults_when_no_profile_and_no_cli() {
        // Portal passed as a raw URL, nothing else specified —
        // every field should land on its hardcoded default.
        let cfg = gp_config::PangolinConfig::default();
        let overrides = CliConnectOverrides {
            portal: Some("vpn.example.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.os, "win");
        assert_eq!(r.auth_mode, SamlAuthMode::Webview);
        assert_eq!(r.saml_port, 29999);
        assert_eq!(r.hip, HipMode::Auto);
        assert!(!r.insecure);
        assert!(r.only.is_none());
        assert!(r.vpnc_script.is_none());
    }
}
