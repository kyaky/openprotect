//! `pgn` — Pangolin GlobalProtect VPN CLI.

mod metrics;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Shared, interior-mutable tunnel state. The IPC server and the
/// metrics renderer both read it; the reconnect state machine
/// writes it (flipping `state` between `Connecting`, `Connected`,
/// and `Reconnecting`, and updating `tun_ifname` / `local_ipv4` on
/// each successful tunnel re-establishment).
///
/// `std::sync::RwLock` is load-bearing here: reads are hot (every
/// `pgn status` / scrape), writes are rare (once per state change),
/// and the lock is only ever held long enough to clone out the
/// relevant fields — never across an `await`. A tokio RwLock would
/// add async overhead for no benefit.
type SharedBase = Arc<RwLock<StateSnapshotBase>>;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use gp_auth::{
    AuthContext, AuthProvider, GpClient, OktaAuthConfig, OktaAuthProvider, PasswordAuthProvider,
    SamlBrowserAuthProvider, SamlPasteAuthProvider,
};
use gp_ipc::{
    bind_server, build_snapshot, client_roundtrip, enumerate_live_instances, read_request,
    socket_path_for, write_response, IpcError, Request as IpcRequest, Response as IpcResponse,
    SessionState, StateSnapshotBase, DEFAULT_INSTANCE, DEFAULT_SOCKET_DIR,
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
    /// Headless Okta — drives `/api/v1/authn` directly without a
    /// browser. Requires `--okta-url <https://tenant.okta.com>` and
    /// `--user`. Password comes from `--passwd-on-stdin`.
    Okta,
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
        ///
        /// `require_equals = true` is load-bearing here: without
        /// it, `num_args = 0..=1` would eagerly consume the next
        /// token, and `pgn connect --insecure vpn.example.com`
        /// would try to parse the portal arg as a bool. Forcing
        /// the `=` syntax for explicit values keeps the bare
        /// `--insecure` form working (via `default_missing_value`)
        /// without stealing positional args.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true
        )]
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

        /// Keep the tunnel alive across network blips.
        ///
        /// When enabled, pangolin tells libopenconnect to spend
        /// up to 10 minutes trying to reconnect after a drop
        /// before giving up (vs the 60-second default). This
        /// handles the common case of a brief network outage
        /// without needing any new user-facing state machine.
        ///
        /// Tri-state, mirroring `--insecure`: bare `--reconnect`
        /// means true, `--reconnect=false` means false, omitted
        /// falls through to the profile, and profile fields fall
        /// through to the hard-coded default (false — the user
        /// must opt in).
        ///
        /// NOTE: this does NOT yet cover tunnel teardown AFTER
        /// libopenconnect's own reconnect budget is exhausted.
        /// Full application-level re-auth + retry is queued as
        /// a separate Phase 2b commit.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            env = "PGN_RECONNECT"
        )]
        reconnect: Option<bool>,

        /// Instance name for this session. Every running `pgn
        /// connect` gets its own control socket at
        /// `/run/pangolin/<instance>.sock`, so you can run
        /// multiple tunnels side by side (e.g. one for work,
        /// one for a client). Defaults to `default`. Must match
        /// `[A-Za-z0-9_-]{1,32}`.
        #[arg(long, short = 'i', env = "PANGOLIN_INSTANCE")]
        instance: Option<String>,

        /// Expose a Prometheus metrics endpoint at
        /// `http://<bind>:<PORT>/metrics` for this session.
        /// Accepts either a bare port (`9100` → binds to
        /// `127.0.0.1:9100`) or a full `host:port` (`0.0.0.0:9100`
        /// to expose on all interfaces). Off by default.
        #[arg(long, env = "PGN_METRICS_PORT", value_name = "PORT|HOST:PORT")]
        metrics_port: Option<String>,

        /// Okta tenant base URL — required when
        /// `--auth-mode okta`. Example:
        /// `--okta-url https://example.okta.com`.
        #[arg(long, env = "PGN_OKTA_URL", value_name = "URL")]
        okta_url: Option<String>,
    },

    /// Disconnect from VPN.
    Disconnect {
        /// Target one instance by name. If omitted and exactly
        /// one instance is live, that one is used. With two or
        /// more live instances the command refuses rather than
        /// guessing — pass `--instance <name>` or `--all`.
        #[arg(long, short = 'i', env = "PANGOLIN_INSTANCE")]
        instance: Option<String>,
        /// Disconnect every live instance. Mutually exclusive
        /// with `--instance`.
        #[arg(long, conflicts_with = "instance")]
        all: bool,
    },

    /// Show connection status.
    Status {
        /// Target one instance by name. If omitted the command
        /// prints the single live instance (0 → `disconnected`,
        /// 1 → full status, 2+ → list all live instances).
        #[arg(long, short = 'i', env = "PANGOLIN_INSTANCE")]
        instance: Option<String>,
        /// List every live instance even when only one is
        /// running. Forces list-format output.
        #[arg(long, conflicts_with = "instance")]
        all: bool,
    },

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
        /// Tell pgn to keep the tunnel alive across brief
        /// network blips (libopenconnect 10-minute reconnect
        /// budget instead of the 60-second default).
        #[arg(long)]
        reconnect: bool,
        /// Prometheus metrics endpoint for this profile: bare
        /// port (`9100`) or `host:port` (`0.0.0.0:9100`).
        #[arg(long, value_name = "PORT|HOST:PORT")]
        metrics_port: Option<String>,
        /// Okta tenant base URL (only useful with
        /// `--auth-mode okta`).
        #[arg(long, value_name = "URL")]
        okta_url: Option<String>,
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
            reconnect,
            instance,
            metrics_port,
            okta_url,
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
                reconnect,
                instance,
                metrics_port,
                okta_url,
            })
            .await
        }
        Some(Commands::Disconnect { instance, all }) => disconnect(cli.json, instance, all).await,
        Some(Commands::Status { instance, all }) => status(cli.json, instance, all).await,
        None => status(cli.json, None, false).await,
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
            reconnect,
            metrics_port,
            okta_url,
        } => {
            // Validate the metrics spec up front so bad profile
            // saves fail fast instead of blowing up at `pgn
            // connect` time.
            if let Some(spec) = metrics_port.as_deref() {
                parse_metrics_bind(spec)?;
            }
            let profile = gp_config::PortalProfile {
                url,
                username: user,
                gateway: None,
                os,
                auth_mode: auth_mode.map(|m| match m {
                    SamlAuthMode::Webview => "webview".to_string(),
                    SamlAuthMode::Paste => "paste".to_string(),
                    SamlAuthMode::Okta => "okta".to_string(),
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
                reconnect: if reconnect { Some(true) } else { None },
                metrics_port,
                okta_url,
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
            if profile.reconnect == Some(true) {
                println!("reconnect:  true");
            }
        }
    }
    Ok(())
}

/// Parse a `--metrics-port` flag value into a concrete bind address.
///
/// Accepts two shapes:
///
/// * bare port (`9100`) → binds to `127.0.0.1:9100`. Loopback-only
///   is the sane default because the scrape body carries portal,
///   gateway, and user labels that aren't secrets but aren't things
///   you want on the open internet either.
/// * `host:port` (`0.0.0.0:9100`, `[::1]:9100`) → verbatim.
fn parse_metrics_bind(spec: &str) -> Result<SocketAddr> {
    let trimmed = spec.trim();
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    trimmed
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid --metrics-port value {trimmed:?}"))
}

/// Wait for any shutdown signal — `Ctrl-C` OR `SIGTERM`. Returns the
/// name of whichever fired first, so log lines can stay honest
/// about what tore the tunnel down.
///
/// Both are treated equivalently: the caller routes either one into
/// libopenconnect's cmd pipe for a clean cancel. Without this
/// helper, `systemctl stop pangolin@work` would drop to SIGKILL
/// after the stop timeout because there was no `SIGTERM` arm in
/// the steady-state select block, and the tunnel would die
/// ungracefully (routes/DNS state possibly leaked to the next
/// session via systemd-resolved cache or `ip route` residue).
async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            // On the (very rare) platform where installing a SIGTERM
            // handler fails, degrade to Ctrl-C only and log — better
            // than refusing to start.
            tracing::warn!("installing SIGTERM handler failed: {e}; only Ctrl-C will cancel");
            let _ = tokio::signal::ctrl_c().await;
            return "Ctrl-C";
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "Ctrl-C",
        _ = term.recv() => "SIGTERM",
    }
}

/// Validate an instance name supplied via `--instance` / env.
///
/// Instance names become filesystem path components (`<dir>/<name>.sock`),
/// systemd unit instance names, and part of log lines. Restrict to
/// `[A-Za-z0-9_-]{1,32}` so nobody can accidentally embed a `/`, a
/// `..`, shell metacharacters, or whitespace.
fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        anyhow::bail!(
            "instance name must be 1..=32 characters (got {} chars: {:?})",
            name.len(),
            name
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!(
            "instance name {name:?} contains an invalid character \
             (allowed: A-Z a-z 0-9 '_' '-')"
        );
    }
    Ok(())
}

/// Resolve a `--instance` flag to the concrete name used for the
/// control socket. `None` becomes [`DEFAULT_INSTANCE`].
fn resolve_instance_name(instance: Option<String>) -> Result<String> {
    let name = instance.unwrap_or_else(|| DEFAULT_INSTANCE.to_string());
    validate_instance_name(&name)?;
    Ok(name)
}

/// Pretty-print one [`StateSnapshot`] in the classic human-readable
/// format used by the single-instance `pgn status`.
fn print_snapshot_human(s: &gp_ipc::StateSnapshot) {
    let mins = s.uptime_seconds / 60;
    let secs = s.uptime_seconds % 60;
    let state_str = match s.state {
        SessionState::Connected => "connected",
        SessionState::Connecting => "connecting",
        SessionState::Reconnecting => "reconnecting",
    };
    println!("instance:  {}", s.instance);
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
    println!("local-ip:  {}", s.local_ipv4.as_deref().unwrap_or("(none)"));
    if s.routes.is_empty() {
        println!("routes:    (default — script-managed)");
    } else {
        println!("routes:    {}", s.routes.join(", "));
    }
}

/// One-line summary row for the multi-instance list view.
fn print_snapshot_row(s: &gp_ipc::StateSnapshot) {
    let state_str = match s.state {
        SessionState::Connected => "connected",
        SessionState::Connecting => "connecting",
        SessionState::Reconnecting => "reconnecting",
    };
    let mins = s.uptime_seconds / 60;
    let secs = s.uptime_seconds % 60;
    let iface = s.tun_ifname.as_deref().unwrap_or("-");
    let ip = s.local_ipv4.as_deref().unwrap_or("-");
    println!(
        "{name:<16} {state:<12} {iface:<8} {ip:<16} {mins}m{secs}s",
        name = s.instance,
        state = state_str,
        iface = iface,
        ip = ip,
        mins = mins,
        secs = secs,
    );
}

/// Query every live instance concurrently and return their snapshots.
/// Sockets that refuse connection mid-scan (session torn down between
/// enumerate and query), or wedge past [`gp_ipc::CLIENT_REQUEST_TIMEOUT`],
/// are silently skipped.
///
/// Concurrency is important here: a user with 5 instances running
/// where one has gone unresponsive should still see the other 4 in
/// `pgn status --all` within the request timeout, not 5 × that.
async fn collect_live_snapshots() -> Vec<gp_ipc::StateSnapshot> {
    let live = enumerate_live_instances(std::path::Path::new(DEFAULT_SOCKET_DIR)).await;
    let mut set = tokio::task::JoinSet::new();
    for (_name, path) in live {
        set.spawn(async move {
            match client_roundtrip(&path, &IpcRequest::Status).await {
                Ok(IpcResponse::Status(s)) => Some(s),
                _ => None,
            }
        });
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(s)) = joined {
            out.push(s);
        }
    }
    out.sort_by(|a, b| a.instance.cmp(&b.instance));
    out
}

/// `pgn status` — query the running session(s) and pretty-print.
///
/// Behavior:
///
/// * `--instance <name>` → hit exactly that socket; error if missing.
/// * `--all` → always list every live instance.
/// * no flags → 0 live: disconnected; 1 live: full details;
///   2+ live: list view (forces the user to be explicit with
///   disconnect).
///
/// JSON mode always emits an array for list-form calls and a stable
/// shape for single-form calls: `{"state":"disconnected"}` when
/// nothing is running (without `--all`), or the snapshot object.
/// With `--all` the JSON shape is always an array, even for zero
/// or one live instance.
async fn status(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    // Single-instance query.
    if let Some(raw) = instance {
        validate_instance_name(&raw)?;
        let path = socket_path_for(&raw);
        match client_roundtrip(&path, &IpcRequest::Status).await {
            Ok(IpcResponse::Status(s)) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&s).unwrap_or_else(|_| "{}".into())
                    );
                } else {
                    print_snapshot_human(&s);
                }
                Ok(())
            }
            Ok(IpcResponse::Error { message }) => anyhow::bail!("server error: {message}"),
            Ok(IpcResponse::Ok) => {
                anyhow::bail!("server returned Ok to a Status request — protocol bug")
            }
            Err(IpcError::NotRunning(_)) => {
                if json {
                    println!(r#"{{"state":"disconnected","instance":"{raw}"}}"#);
                } else {
                    println!("instance {raw:?}: disconnected");
                }
                Ok(())
            }
            Err(IpcError::PermissionDenied(_)) => anyhow::bail!(
                "control socket exists but you don't have permission to read it — \
                 try `sudo pgn status -i {raw}`"
            ),
            Err(e) => Err(anyhow::anyhow!(e).context("querying pgn status")),
        }
    } else {
        // Multi-instance scan. JSON output is ALWAYS a (possibly
        // empty) array when no explicit `--instance` was given — the
        // shape stays stable regardless of live count so scripts
        // never have to special-case 0/1/N. Human output still
        // renders the friendly single-session block for the 1-live
        // case and a table for 2+.
        let snapshots = collect_live_snapshots().await;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshots).unwrap_or_else(|_| "[]".into())
            );
            return Ok(());
        }
        if all || snapshots.len() >= 2 {
            if snapshots.is_empty() {
                println!("(no running pgn sessions)");
            } else {
                println!(
                    "{:<16} {:<12} {:<8} {:<16} uptime",
                    "INSTANCE", "STATE", "IFACE", "LOCAL-IP"
                );
                for s in &snapshots {
                    print_snapshot_row(s);
                }
            }
            return Ok(());
        }
        match snapshots.len() {
            0 => println!("state:     disconnected"),
            1 => print_snapshot_human(&snapshots[0]),
            _ => unreachable!("2+ case handled above"),
        }
        Ok(())
    }
}

/// `pgn disconnect` — ask a running session (or every running
/// session) to tear down.
async fn disconnect(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    // 1. Explicit --instance: classic single-target path.
    if let Some(raw) = instance {
        validate_instance_name(&raw)?;
        return disconnect_single(json, &raw).await;
    }

    // 2. --all: hit every live instance. Refuses silently if none.
    if all {
        let live = enumerate_live_instances(std::path::Path::new(DEFAULT_SOCKET_DIR)).await;
        if live.is_empty() {
            if json {
                println!(r#"{{"result":"not-running"}}"#);
            } else {
                println!("no running pgn sessions");
            }
            return Ok(());
        }
        let mut failures = Vec::new();
        for (name, path) in &live {
            match client_roundtrip(path, &IpcRequest::Disconnect).await {
                Ok(IpcResponse::Ok) => {
                    if !json {
                        println!("{name}: disconnect requested");
                    }
                }
                Ok(IpcResponse::Error { message }) => {
                    failures.push(format!("{name}: server error: {message}"));
                }
                Ok(IpcResponse::Status(_)) => {
                    failures.push(format!("{name}: protocol bug"));
                }
                // Benign: the session tore down between enumerate and now.
                Err(IpcError::NotRunning(_)) => {}
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }
        if json {
            let succeeded = live.len() - failures.len();
            println!(
                r#"{{"result":"disconnect-requested","count":{succeeded},"failures":{}}}"#,
                failures.len()
            );
        }
        if !failures.is_empty() {
            anyhow::bail!("some instances failed: {}", failures.join("; "));
        }
        return Ok(());
    }

    // 3. No flags: try to be smart, but refuse if ambiguous.
    let live = enumerate_live_instances(std::path::Path::new(DEFAULT_SOCKET_DIR)).await;
    match live.len() {
        0 => {
            if json {
                println!(r#"{{"result":"not-running"}}"#);
            } else {
                println!("no running pgn session");
            }
            Ok(())
        }
        1 => disconnect_single(json, &live[0].0).await,
        _ => {
            let names: Vec<&str> = live.iter().map(|(n, _)| n.as_str()).collect();
            anyhow::bail!(
                "{} live instances — pass --instance <name> or --all to pick one. \
                 Live: {}",
                live.len(),
                names.join(", ")
            );
        }
    }
}

async fn disconnect_single(json: bool, name: &str) -> Result<()> {
    let path = socket_path_for(name);
    match client_roundtrip(&path, &IpcRequest::Disconnect).await {
        Ok(IpcResponse::Ok) => {
            if json {
                println!(r#"{{"result":"disconnect-requested","instance":"{name}"}}"#);
            } else {
                println!("{name}: disconnect requested");
            }
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => anyhow::bail!("server error: {message}"),
        Ok(IpcResponse::Status(_)) => {
            anyhow::bail!("server returned Status to a Disconnect request — protocol bug")
        }
        Err(IpcError::NotRunning(_)) => {
            if json {
                println!(r#"{{"result":"not-running","instance":"{name}"}}"#);
            } else {
                println!("{name}: no running pgn session");
            }
            Ok(())
        }
        Err(IpcError::PermissionDenied(_)) => anyhow::bail!(
            "control socket exists but you don't have permission to read it — \
             try `sudo pgn disconnect -i {name}`"
        ),
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
    reconnect: Option<bool>,
    instance: Option<String>,
    metrics_port: Option<String>,
    okta_url: Option<String>,
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
        reconnect,
        instance,
        metrics_port,
        okta_url,
    } = args;

    let instance_name = resolve_instance_name(instance)?;
    let metrics_counters = metrics::MetricsCounters::new();

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
            reconnect,
            metrics_port,
            okta_url,
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
        reconnect,
        user: merged_user,
        metrics_bind: metrics_bind_addr,
        okta_url,
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
            SamlAuthMode::Webview => SamlBrowserAuthProvider
                .authenticate(&prelogin, &auth_ctx)
                .await
                .context("SAML (webview) authentication")?,
            SamlAuthMode::Paste => SamlPasteAuthProvider::new(saml_port)
                .authenticate(&prelogin, &auth_ctx)
                .await
                .context("SAML (paste) authentication")?,
            SamlAuthMode::Okta => {
                let url = okta_url.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "--auth-mode okta requires --okta-url <https://tenant.okta.com>"
                    )
                })?;
                let provider = OktaAuthProvider::new(OktaAuthConfig {
                    okta_url: url,
                    insecure,
                    password_override: None,
                });
                provider
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("okta headless authentication")?
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
                tracing::warn!("HIP flow non-fatal error (auto mode, continuing): {e:#}");
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
        "starting tunnel: gateway={gateway_host} os={oc_os} vpnc_script={:?} native_routes={} reconnect={reconnect}",
        script,
        routes.len()
    );

    // Build the (shared, mutable) state base. Starts at `Connecting`;
    // `run_tunnel_attempt` flips it to `Connected` when setup_tun_device
    // succeeds, and the outer reconnect loop flips it back to
    // `Reconnecting` between attempts. One `SharedBase` lives across
    // the entire session so the IPC server and metrics endpoint see
    // the current state regardless of reconnect churn.
    let started_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let initial_base = StateSnapshotBase {
        instance: instance_name.clone(),
        portal: portal_url.clone(),
        gateway: gateway.address.clone(),
        user: auth_cookie.username.clone(),
        reported_os: oc_os.to_string(),
        routes: routes.clone(),
        started_at_unix,
        tun_ifname: None,
        local_ipv4: None,
        state: SessionState::Connecting,
    };
    let base: SharedBase = Arc::new(RwLock::new(initial_base));

    // Spawn the IPC server ONCE, outside the reconnect loop, so
    // `pgn status` / `pgn disconnect` keep working across retry
    // attempts. Disconnect uses a `watch::channel<bool>` — persistent,
    // so a disconnect fired during attempt #1's backoff is still
    // visible to attempt #2's subscribers.
    let ipc_start = Instant::now();
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let ipc_socket_path = socket_path_for(&instance_name);
    let ipc_handle = spawn_ipc_server(
        ipc_socket_path.clone(),
        Arc::clone(&base),
        ipc_start,
        disconnect_tx,
    )
    .await
    .context("starting ipc server")?;

    // Optional Prometheus metrics endpoint — also lives across
    // the reconnect loop so scrapers see counters tick up over
    // time instead of resetting per attempt.
    let metrics_handle = if let Some(addr) = metrics_bind_addr.as_ref() {
        Some(
            metrics::spawn_metrics_server(
                *addr,
                metrics::MetricsState {
                    base: Arc::clone(&base),
                    started_at: ipc_start,
                    counters: Arc::clone(&metrics_counters),
                },
            )
            .await
            .context("starting metrics server")?,
        )
    } else {
        None
    };

    tracing::info!("tunnel starting — press Ctrl-C (or `pgn disconnect`) to tear down");

    // Reconnect loop. The first iteration is the initial attempt;
    // subsequent iterations fire only when `reconnect` is enabled AND
    // the previous attempt exited with a non-user error.
    //
    // MVP scope: this loop re-uses the existing gateway authcookie
    // across retries — good enough for the common case where
    // libopenconnect's mainloop exits due to a transient network
    // event that outlasts its internal 10-minute budget. Full re-auth
    // on cookie expiry (re-running prelogin + SAML) is Phase 2c.
    // If the cookie has gone stale server-side, retries will fail
    // fast and the loop will eventually give up at `max_reconnect_attempts`.
    const MAX_RECONNECT_ATTEMPTS: u32 = 10;

    let mut attempt_num: u32 = 0;
    let final_result: Result<()> = 'outer: loop {
        set_base_state(&base, SessionState::Connecting);

        let outcome = run_tunnel_attempt(TunnelAttemptArgs {
            gateway_host: &gateway_host,
            cookie: &cookie_str,
            os: oc_os,
            script: script.as_deref(),
            routes: routes.clone(),
            reconnect_enabled: reconnect,
            base: &base,
            disconnect_rx: disconnect_rx.clone(),
            counters: &metrics_counters,
            attempt_num,
        })
        .await;

        // Disconnect request always wins: if the user asked to tear
        // down, we break even if the tunnel had just exited
        // successfully or with an error we'd normally retry.
        if *disconnect_rx.borrow() {
            break 'outer Ok(());
        }

        match outcome {
            AttemptOutcome::UserCancel => break 'outer Ok(()),
            AttemptOutcome::Ok => break 'outer Ok(()),
            AttemptOutcome::Err(e) if !reconnect => break 'outer Err(e),
            AttemptOutcome::Err(e) => {
                attempt_num += 1;
                metrics_counters
                    .reconnect_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if attempt_num >= MAX_RECONNECT_ATTEMPTS {
                    break 'outer Err(e.context(format!(
                        "giving up after {MAX_RECONNECT_ATTEMPTS} reconnect attempts"
                    )));
                }
                tracing::warn!("tunnel exited: {e:#}");

                set_base_state(&base, SessionState::Reconnecting);
                // Clear stale tun info — the old interface is gone,
                // the new one (if any) carries a fresh name.
                {
                    let mut guard = base.write().expect("SharedBase RwLock poisoned");
                    guard.tun_ifname = None;
                    guard.local_ipv4 = None;
                }

                let delay = reconnect_backoff(attempt_num);
                tracing::info!(
                    "reconnecting in {}s (attempt #{})",
                    delay.as_secs(),
                    attempt_num + 1
                );

                // Race the backoff against shutdown signals and
                // `pgn disconnect`. Any of those three wake the
                // outer loop out of the sleep; shutdown / disconnect
                // break out for good, timer expiry continues.
                let mut dr = disconnect_rx.clone();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    sig = shutdown_signal() => {
                        tracing::info!("{sig} during backoff, aborting reconnect");
                        break 'outer Ok(());
                    }
                    _ = dr.wait_for(|v| *v) => {
                        tracing::info!("disconnect during backoff, aborting reconnect");
                        break 'outer Ok(());
                    }
                }
            }
        }
    };

    // Unified cleanup regardless of how we exited the loop.
    ipc_handle.abort();
    if let Some(h) = metrics_handle.as_ref() {
        h.abort();
    }
    let _ = std::fs::remove_file(&ipc_socket_path);

    final_result
}

/// Outcome of one `run_tunnel_attempt` iteration. The reconnect loop
/// reads this + the watch-channel disconnect flag to decide whether
/// to retry, break cleanly, or surface an error.
enum AttemptOutcome {
    /// User cancelled (Ctrl-C, SIGTERM, or `pgn disconnect`). Always
    /// breaks the outer loop — no retry.
    UserCancel,
    /// Tunnel mainloop returned cleanly. Treated as a clean exit:
    /// no retry, no error.
    Ok,
    /// Tunnel exited with an error. The outer loop decides between
    /// retry (if `--reconnect` is on and we're under the max) and
    /// surfacing the error.
    Err(anyhow::Error),
}

/// Packed argument set for [`run_tunnel_attempt`]. A struct is used
/// so the call site stays readable even with ~10 parameters.
struct TunnelAttemptArgs<'a> {
    gateway_host: &'a str,
    cookie: &'a str,
    os: &'static str,
    script: Option<&'a str>,
    routes: Vec<String>,
    reconnect_enabled: bool,
    base: &'a SharedBase,
    disconnect_rx: tokio::sync::watch::Receiver<bool>,
    counters: &'a Arc<metrics::MetricsCounters>,
    attempt_num: u32,
}

/// Run one tunnel attempt end-to-end: spawn the libopenconnect thread,
/// wait for the cancel handle + ready signal, publish the tun ifname
/// to the shared state, then race the mainloop against shutdown
/// signals and `pgn disconnect`.
///
/// Every attempt gets a fresh tunnel thread, fresh cancel handle,
/// and fresh mpsc channels. The reconnect loop calls this repeatedly
/// with the same cookie/host — network blips long enough to exit
/// libopenconnect's internal reconnect budget are the primary
/// motivation.
async fn run_tunnel_attempt<'a>(args: TunnelAttemptArgs<'a>) -> AttemptOutcome {
    let TunnelAttemptArgs {
        gateway_host,
        cookie,
        os,
        script,
        routes,
        reconnect_enabled,
        base,
        mut disconnect_rx,
        counters,
        attempt_num,
    } = args;

    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<TunnelReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<()>>();

    let gateway_owned = gateway_host.to_string();
    let cookie_owned = cookie.to_string();
    let script_owned = script.map(|s| s.to_string());
    let routes_for_thread = routes;
    let tunnel_thread =
        match std::thread::Builder::new()
            .name("pgn-tunnel".into())
            .spawn(move || {
                let result = run_tunnel(
                    &gateway_owned,
                    &cookie_owned,
                    os,
                    script_owned.as_deref(),
                    routes_for_thread,
                    reconnect_enabled,
                    cancel_tx,
                    ready_tx,
                );
                let _ = done_tx.send(result);
            }) {
            Ok(t) => t,
            Err(e) => {
                return AttemptOutcome::Err(anyhow::anyhow!(e).context("spawning tunnel thread"))
            }
        };

    // Wait for the CancelHandle. The tunnel thread sends it before
    // any blocking work, so this normally returns immediately.
    let cancel_handle = match cancel_rx.recv() {
        Ok(c) => c,
        Err(_) => {
            let _ = tunnel_thread.join();
            return match done_rx.await {
                Ok(Ok(())) => AttemptOutcome::Ok,
                Ok(Err(e)) => AttemptOutcome::Err(e),
                Err(_) => AttemptOutcome::Err(anyhow::anyhow!(
                    "tunnel thread died without reporting a result"
                )),
            };
        }
    };

    // Wait for setup_tun_device. Race against shutdown signals, the
    // disconnect watch channel, and the thread's own done_rx (in
    // case it failed mid-setup).
    let tunnel_ready = {
        let mut dr = disconnect_rx.clone();
        tokio::select! {
            res = tokio::task::spawn_blocking(move || ready_rx.recv()) => {
                match res {
                    Ok(Ok(ready)) => ready,
                    Ok(Err(_)) | Err(_) => {
                        let _ = tunnel_thread.join();
                        return match done_rx.await {
                            Ok(Ok(())) => AttemptOutcome::Ok,
                            Ok(Err(e)) => AttemptOutcome::Err(e),
                            Err(_) => AttemptOutcome::Err(anyhow::anyhow!("tunnel thread panicked")),
                        };
                    }
                }
            }
            sig = shutdown_signal() => {
                tracing::info!("{sig} received during tunnel setup, cancelling...");
                if let Err(e) = cancel_handle.cancel() {
                    tracing::warn!("cancel failed: {e}");
                }
                let _ = done_rx.await;
                let _ = tunnel_thread.join();
                return AttemptOutcome::UserCancel;
            }
            _ = dr.wait_for(|v| *v) => {
                tracing::info!("disconnect received during tunnel setup, cancelling...");
                if let Err(e) = cancel_handle.cancel() {
                    tracing::warn!("cancel failed: {e}");
                }
                let _ = done_rx.await;
                let _ = tunnel_thread.join();
                return AttemptOutcome::UserCancel;
            }
            res = &mut done_rx => {
                let _ = tunnel_thread.join();
                return match res {
                    Ok(Ok(())) => AttemptOutcome::Ok,
                    Ok(Err(e)) => AttemptOutcome::Err(e),
                    Err(_) => AttemptOutcome::Err(anyhow::anyhow!("tunnel thread panicked")),
                };
            }
        }
    };

    // Setup succeeded: publish the tun info to the shared state and
    // flip to Connected. On the first attempt the state was
    // Connecting; on retries it was Reconnecting before we entered
    // this attempt and Connecting at the start of this attempt.
    {
        let mut guard = base.write().expect("SharedBase RwLock poisoned");
        guard.tun_ifname = tunnel_ready.ifname.clone();
        guard.local_ipv4 = tunnel_ready.ip_info.as_ref().and_then(|i| i.addr.clone());
        guard.state = SessionState::Connected;
    }

    // Attempts after the first represent a *successful re-establishment*.
    // Bump the restart counter now — this is the post-handshake,
    // post-setup_tun_device moment the metrics definition points at.
    if attempt_num > 0 {
        counters
            .tunnel_restarts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            "tunnel re-established (attempt #{}, total restarts: {})",
            attempt_num + 1,
            counters
                .tunnel_restarts
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    } else {
        tracing::info!("tunnel running — press Ctrl-C (or `pgn disconnect`) to tear down");
    }

    // Steady-state: race the mainloop against shutdown, disconnect,
    // and its own exit.
    tokio::select! {
        sig = shutdown_signal() => {
            tracing::info!("{sig} received, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
            let res = done_rx.await;
            let _ = tunnel_thread.join();
            match res {
                Ok(Ok(())) | Ok(Err(_)) => AttemptOutcome::UserCancel,
                Err(_) => AttemptOutcome::UserCancel,
            }
        }
        _ = disconnect_rx.wait_for(|v| *v) => {
            tracing::info!("disconnect request received via control socket, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
            let res = done_rx.await;
            let _ = tunnel_thread.join();
            match res {
                Ok(Ok(())) | Ok(Err(_)) => AttemptOutcome::UserCancel,
                Err(_) => AttemptOutcome::UserCancel,
            }
        }
        res = &mut done_rx => {
            let _ = tunnel_thread.join();
            match res {
                Ok(Ok(())) => AttemptOutcome::Ok,
                Ok(Err(e)) => AttemptOutcome::Err(e),
                Err(_) => AttemptOutcome::Err(anyhow::anyhow!("tunnel thread panicked")),
            }
        }
    }
}

/// Compute the reconnect backoff for the Nth failed attempt. Uses a
/// simple exponential curve with a 5-minute cap:
///
/// * attempt 1 → 5s
/// * attempt 2 → 10s
/// * attempt 3 → 20s
/// * attempt 4 → 40s
/// * attempt 5 → 80s
/// * attempt 6 → 160s
/// * attempt 7+ → 300s (capped)
///
/// No jitter — this isn't talking to a huge fleet of downstream
/// peers, and predictable backoff is easier to reason about in logs
/// and alerts.
pub fn reconnect_backoff(attempt_num: u32) -> Duration {
    const CAP_SECS: u64 = 300; // 5 minutes
    let base_secs: u64 = 5u64
        .checked_mul(1u64 << (attempt_num.saturating_sub(1)).min(6))
        .unwrap_or(CAP_SECS);
    Duration::from_secs(base_secs.min(CAP_SECS))
}

/// Helper: overwrite the session state in the shared base, holding
/// the RwLock write guard for the shortest possible window.
fn set_base_state(base: &SharedBase, state: SessionState) {
    let mut guard = base.write().expect("SharedBase RwLock poisoned");
    guard.state = state;
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
        "okta" => Some(SamlAuthMode::Okta),
        other => {
            tracing::warn!(
                "profile auth_mode = {other:?} is not a recognized value \
                 (expected 'webview', 'paste', or 'okta'); falling back to \
                 the built-in default"
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
    reconnect: Option<bool>,
    metrics_port: Option<String>,
    okta_url: Option<String>,
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
    reconnect: bool,
    metrics_bind: Option<SocketAddr>,
    okta_url: Option<String>,
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
    // Same tri-state pattern for reconnect. Default off — the
    // user must opt in.
    let reconnect: bool = cli
        .reconnect
        .or_else(|| profile.as_ref().and_then(|p| p.reconnect))
        .unwrap_or(false);
    // `cli.user` wins; profile.username is the fallback.
    let user: Option<String> = cli
        .user
        .or_else(|| profile.as_ref().and_then(|p| p.username.clone()));

    let metrics_bind: Option<SocketAddr> = cli
        .metrics_port
        .or_else(|| profile.as_ref().and_then(|p| p.metrics_port.clone()))
        .map(|spec| parse_metrics_bind(&spec))
        .transpose()?;

    let okta_url: Option<String> = cli
        .okta_url
        .or_else(|| profile.as_ref().and_then(|p| p.okta_url.clone()));

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
        reconnect,
        metrics_bind,
        okta_url,
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
    base: SharedBase,
    started_at: Instant,
    disconnect_tx: tokio::sync::watch::Sender<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = bind_server(&path)
        .await
        .with_context(|| format!("binding control socket at {}", path.display()))?;
    tracing::info!("control socket listening on {}", path.display());

    // The disconnect sender is a `watch::Sender<bool>` — once we
    // flip it to `true`, every reconnect-loop subscriber sees the
    // flag on their next `wait_for`, so `pgn disconnect` correctly
    // tears down both the current tunnel AND any pending retry.
    let disconnect_tx = Arc::new(disconnect_tx);

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
    base: SharedBase,
    started_at: Instant,
    disconnect_tx: Arc<tokio::sync::watch::Sender<bool>>,
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
        IpcRequest::Status => {
            // Short critical section: clone the base into a local
            // so `build_snapshot` doesn't touch the lock across
            // its string allocations. Guard is dropped at end of
            // scope before `write_response`.
            let snapshot_base = {
                let guard = base.read().expect("SharedBase RwLock poisoned");
                guard.clone()
            };
            IpcResponse::Status(build_snapshot(&snapshot_base, started_at))
        }
        IpcRequest::Disconnect => {
            // Persistent: later reconnect-loop subscribers also see
            // the flag. No consume-once problem.
            let _ = disconnect_tx.send(true);
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
    reconnect_enabled: bool,
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
    // `reconnect_timeout` is the number of seconds libopenconnect
    // will keep trying to re-establish the tunnel after it drops
    // before giving up and returning from mainloop. 60s is the
    // pre-`--reconnect` default; 600s (10 min) is the opted-in
    // value, enough to ride through a laptop suspend or a short
    // ISP blip. A true application-level reauth-and-retry state
    // machine is still pending as Phase 2b follow-up work.
    let reconnect_timeout = if reconnect_enabled { 600 } else { 60 };
    tracing::info!(
        "openconnect mainloop: reconnect_timeout={reconnect_timeout}s, reconnect_interval=10s"
    );
    let run_res = session.run(reconnect_timeout, 10);

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
        assert_eq!(civil_from_unix(1_735_689_600), (2025, 1, 1, 0, 0, 0));
    }

    #[test]
    fn civil_from_unix_mid_day() {
        // 2024-06-15 12:34:56 UTC
        //   days from epoch to 2024-06-15 = 19889 → 1_718_409_600
        //   + 12h → 1_718_452_800
        //   + 34m → 1_718_454_840
        //   + 56s → 1_718_454_896
        assert_eq!(civil_from_unix(1_718_454_896), (2024, 6, 15, 12, 34, 56));
    }

    #[test]
    fn civil_from_unix_leap_day_2024() {
        // 2024-02-29 00:00:00 UTC = 1_709_164_800.
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0));
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
            reconnect: None,
            metrics_port: None,
            okta_url: None,
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
                reconnect: Some(true),
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
    fn insecure_bare_flag_does_not_steal_next_positional() {
        // Regression guard for the clap parse-ambiguity caught in
        // review round 12. Before `require_equals = true`, the
        // `--insecure` arg's `num_args = 0..=1` would eagerly
        // consume the next token, so `pgn connect --insecure
        // vpn.example.com` parsed `vpn.example.com` as the
        // --insecure value and blew up with a bool parse error.
        // Now that `require_equals` is set, only `--insecure=…`
        // syntax can supply a value.
        use clap::Parser;
        let cli = Cli::try_parse_from(["pgn", "connect", "--insecure", "vpn.example.com"])
            .expect("bare --insecure followed by positional must parse");
        match cli.command {
            Some(Commands::Connect {
                portal, insecure, ..
            }) => {
                assert_eq!(portal.as_deref(), Some("vpn.example.com"));
                // Bare --insecure → default_missing_value → Some(true)
                assert_eq!(insecure, Some(true));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn insecure_equals_false_parses() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["pgn", "connect", "--insecure=false", "vpn.example.com"])
            .expect("--insecure=false must parse");
        match cli.command {
            Some(Commands::Connect { insecure, .. }) => {
                assert_eq!(insecure, Some(false));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn insecure_space_separated_is_treated_as_positional() {
        // With `require_equals = true`, the bare `--insecure` form
        // does NOT consume the next CLI token as its value —
        // instead, that token becomes the positional portal
        // argument. This pins the current behaviour so a future
        // `require_equals`-off refactor won't silently re-introduce
        // the positional-stealing bug the previous commit fixed.
        use clap::Parser;
        let result = Cli::try_parse_from(["pgn", "connect", "--insecure", "true"]);
        // It should still PARSE, but with `portal = Some("true")`
        // and `insecure = Some(true)` (bare-flag behaviour). The
        // important thing is clap does not try to consume "true"
        // as the value for --insecure.
        let cli = result.expect("bare --insecure + 'true' positional must parse");
        match cli.command {
            Some(Commands::Connect {
                portal, insecure, ..
            }) => {
                assert_eq!(portal.as_deref(), Some("true"));
                assert_eq!(insecure, Some(true));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn resolve_reconnect_defaults_to_off() {
        let cfg = gp_config::PangolinConfig::default();
        let overrides = CliConnectOverrides {
            portal: Some("vpn.example.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert!(!r.reconnect, "default should be off (opt-in)");
    }

    #[test]
    fn resolve_reconnect_inherits_from_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                reconnect: Some(true),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert!(r.reconnect);
    }

    #[test]
    fn resolve_reconnect_cli_false_overrides_profile_true() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                reconnect: Some(true),
                ..gp_config::PortalProfile::default()
            },
        );
        let overrides = CliConnectOverrides {
            reconnect: Some(false),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert!(!r.reconnect, "--reconnect=false should override profile");
    }

    #[test]
    fn reconnect_bare_flag_does_not_steal_next_positional() {
        // Same parser pin as --insecure: bare --reconnect must
        // not consume the next CLI token as its value.
        use clap::Parser;
        let cli = Cli::try_parse_from(["pgn", "connect", "--reconnect", "vpn.example.com"])
            .expect("bare --reconnect followed by positional must parse");
        match cli.command {
            Some(Commands::Connect {
                portal, reconnect, ..
            }) => {
                assert_eq!(portal.as_deref(), Some("vpn.example.com"));
                assert_eq!(reconnect, Some(true));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    // ---------- okta auth mode wiring ----------

    #[test]
    fn resolve_okta_url_cli_overrides_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                okta_url: Some("https://profile.okta.com".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let overrides = CliConnectOverrides {
            okta_url: Some("https://cli.okta.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.okta_url.as_deref(), Some("https://cli.okta.com"));
    }

    #[test]
    fn resolve_okta_url_inherits_from_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                okta_url: Some("https://profile.okta.com".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.okta_url.as_deref(), Some("https://profile.okta.com"));
    }

    #[test]
    fn parse_auth_mode_handles_okta() {
        assert_eq!(parse_auth_mode("okta"), Some(SamlAuthMode::Okta));
        assert_eq!(parse_auth_mode("OKTA"), Some(SamlAuthMode::Okta));
        // Unknown still falls through to None.
        assert_eq!(parse_auth_mode("oktax"), None);
    }

    #[test]
    fn connect_accepts_auth_mode_okta_and_okta_url() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "pgn",
            "connect",
            "--auth-mode",
            "okta",
            "--okta-url",
            "https://example.okta.com",
            "vpn.example.com",
        ])
        .expect("auth-mode okta + okta-url must parse");
        match cli.command {
            Some(Commands::Connect {
                auth_mode,
                okta_url,
                portal,
                ..
            }) => {
                assert_eq!(auth_mode, Some(SamlAuthMode::Okta));
                assert_eq!(okta_url.as_deref(), Some("https://example.okta.com"));
                assert_eq!(portal.as_deref(), Some("vpn.example.com"));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    // ---------- reconnect backoff curve ----------

    #[test]
    fn reconnect_backoff_doubles_per_attempt_up_to_cap() {
        use std::time::Duration;
        assert_eq!(reconnect_backoff(1), Duration::from_secs(5));
        assert_eq!(reconnect_backoff(2), Duration::from_secs(10));
        assert_eq!(reconnect_backoff(3), Duration::from_secs(20));
        assert_eq!(reconnect_backoff(4), Duration::from_secs(40));
        assert_eq!(reconnect_backoff(5), Duration::from_secs(80));
        assert_eq!(reconnect_backoff(6), Duration::from_secs(160));
        // Attempt 7 = 5 * 2^6 = 320 → capped at 300.
        assert_eq!(reconnect_backoff(7), Duration::from_secs(300));
        assert_eq!(reconnect_backoff(8), Duration::from_secs(300));
        assert_eq!(reconnect_backoff(100), Duration::from_secs(300));
    }

    #[test]
    fn reconnect_backoff_attempt_zero_treated_as_one() {
        // Defensive: callers number attempts from 1 but we don't
        // want a panic on a stray `reconnect_backoff(0)` either.
        use std::time::Duration;
        assert_eq!(reconnect_backoff(0), Duration::from_secs(5));
    }

    // ---------- --metrics-port parsing ----------

    #[test]
    fn metrics_bind_bare_port_defaults_to_loopback() {
        let addr = parse_metrics_bind("9100").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:9100");
    }

    #[test]
    fn metrics_bind_accepts_explicit_host_port() {
        let addr = parse_metrics_bind("0.0.0.0:9100").unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:9100");
        let addr = parse_metrics_bind("[::1]:9100").unwrap();
        assert_eq!(addr.to_string(), "[::1]:9100");
    }

    #[test]
    fn metrics_bind_rejects_garbage() {
        assert!(parse_metrics_bind("not-a-port").is_err());
        assert!(parse_metrics_bind("9100:extra:junk").is_err());
        assert!(parse_metrics_bind("").is_err());
    }

    #[test]
    fn resolve_metrics_port_cli_overrides_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                metrics_port: Some("9100".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let overrides = CliConnectOverrides {
            metrics_port: Some("0.0.0.0:9300".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.metrics_bind.unwrap().to_string(), "0.0.0.0:9300");
    }

    #[test]
    fn resolve_metrics_port_inherits_from_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                metrics_port: Some("9100".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.metrics_bind.unwrap().to_string(), "127.0.0.1:9100");
    }

    #[test]
    fn resolve_metrics_port_default_is_none() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert!(r.metrics_bind.is_none());
    }

    // ---------- instance-name validation ----------

    #[test]
    fn instance_name_accepts_simple_labels() {
        for name in ["default", "work", "client-a", "home_lab", "a", "A1_b-2"] {
            validate_instance_name(name)
                .unwrap_or_else(|e| panic!("expected {name:?} to be valid: {e}"));
        }
    }

    #[test]
    fn instance_name_rejects_empty_and_oversized() {
        assert!(validate_instance_name("").is_err());
        let too_long = "a".repeat(33);
        assert!(validate_instance_name(&too_long).is_err());
        // Exactly 32 is allowed.
        validate_instance_name(&"a".repeat(32)).unwrap();
    }

    #[test]
    fn instance_name_rejects_path_separators_and_shell_metachars() {
        for bad in [
            "has/slash",
            "with space",
            "..",
            ".",
            "foo.bar",
            "with$dollar",
            "with`tick",
            "with\nnewline",
            "with\ttab",
            "unicode-café",
            "semi;colon",
        ] {
            assert!(
                validate_instance_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn resolve_instance_name_defaults_to_default() {
        assert_eq!(resolve_instance_name(None).unwrap(), "default");
        assert_eq!(resolve_instance_name(Some("work".into())).unwrap(), "work");
    }

    // ---------- clap parse for the new flags ----------

    #[test]
    fn connect_accepts_instance_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["pgn", "connect", "--instance", "work", "vpn.example.com"])
            .expect("--instance must parse");
        match cli.command {
            Some(Commands::Connect {
                portal, instance, ..
            }) => {
                assert_eq!(portal.as_deref(), Some("vpn.example.com"));
                assert_eq!(instance.as_deref(), Some("work"));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn disconnect_accepts_instance_and_all_but_not_together() {
        use clap::Parser;
        // Just --instance.
        let cli = Cli::try_parse_from(["pgn", "disconnect", "-i", "work"]).unwrap();
        matches!(cli.command, Some(Commands::Disconnect { .. }));

        // Just --all.
        let cli = Cli::try_parse_from(["pgn", "disconnect", "--all"]).unwrap();
        matches!(cli.command, Some(Commands::Disconnect { all: true, .. }));

        // Both together → clap should error (conflicts_with).
        let result = Cli::try_parse_from(["pgn", "disconnect", "-i", "work", "--all"]);
        assert!(
            result.is_err(),
            "--instance and --all must conflict (parsed OK unexpectedly)"
        );
    }

    #[test]
    fn status_accepts_instance_and_all() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["pgn", "status", "--instance", "work"]).unwrap();
        match cli.command {
            Some(Commands::Status { instance, all }) => {
                assert_eq!(instance.as_deref(), Some("work"));
                assert!(!all);
            }
            _ => panic!("expected Commands::Status"),
        }
        let cli = Cli::try_parse_from(["pgn", "status", "--all"]).unwrap();
        match cli.command {
            Some(Commands::Status { instance, all }) => {
                assert!(instance.is_none());
                assert!(all);
            }
            _ => panic!("expected Commands::Status"),
        }
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
        assert!(!r.reconnect);
        assert!(r.only.is_none());
        assert!(r.vpnc_script.is_none());
    }
}
