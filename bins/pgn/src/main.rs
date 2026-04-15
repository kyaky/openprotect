//! `pgn` — Pangolin GlobalProtect VPN CLI.

mod metrics;

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
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
    SamlPasteAuthProvider,
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
    /// Headless — pgn runs a local HTTP server, you complete
    /// the SAML flow in your own browser, then paste the
    /// `globalprotectcallback:` URL back into the terminal.
    /// Default. Works everywhere: laptops, servers, SSH
    /// sessions, containers.
    Paste,
    /// Headless Okta — drives `/api/v1/authn` directly without a
    /// browser. Requires `--okta-url <https://tenant.okta.com>`
    /// and `--user`. Password comes from `--passwd-on-stdin`.
    Okta,
    /// Legacy embedded GTK+WebKit window. Removed during the
    /// headless-first architecture cleanup — pgn no longer
    /// contains a browser. The variant is hidden from
    /// `--help` but kept in the clap enum so that `--auth-mode
    /// webview` gives a migration hint at the CLI instead of
    /// clap's generic "invalid value" error. Selecting it at
    /// connect time bails with a clear message pointing at
    /// `--auth-mode paste` and `--auth-mode okta`.
    #[clap(hide = true)]
    Webview,
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

        /// OS to spoof (win, mac, linux). Default `linux`.
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

        /// SAML auth mode. `paste` (default) starts a local HTTP
        /// server, has you complete auth in any browser you already
        /// have open, and reads the `globalprotectcallback:` URL
        /// back from the terminal. `okta` drives an Okta tenant's
        /// `/api/v1/authn` directly, never touching a browser. Both
        /// modes are headless — pangolin has no embedded browser.
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

        /// Explicit split-DNS zone list — comma-separated suffixes
        /// (`corp.example.com,intranet.example.org`). When set, this
        /// **replaces** the zone list derived from `--only`
        /// hostnames; the derivation heuristic is skipped entirely.
        ///
        /// Use this escape hatch when your VPN targets live directly
        /// under a public suffix (`host.co.uk`): the derivation
        /// would naively yield `co.uk`, which is the wrong thing
        /// to hand to `resolvectl domain ~…`. Set `--dns-zone
        /// host.co.uk` (or whatever the real internal zone is)
        /// and the derivation is bypassed.
        ///
        /// Pass `--dns-zone ""` to force an empty zone list —
        /// useful when you want `--only` hostnames installed as
        /// routes but do NOT want pangolin to register any split
        /// DNS zones at all (e.g. your gateway's pushed resolver
        /// already owns the relevant zones through other means).
        #[arg(long, value_name = "ZONE[,ZONE...]", env = "PGN_DNS_ZONE")]
        dns_zone: Option<String>,

        /// Host Information Profile (HIP) reporting mode. `auto`
        /// (the default) asks the gateway whether it wants a
        /// report and submits one only if so. `force` always
        /// submits — useful for gateways that silently enforce
        /// HIP without announcing it. `off` skips the whole
        /// flow.
        #[arg(long, value_enum, env = "PGN_HIP")]
        hip: Option<HipMode>,

        /// Path to an external HIP wrapper script. Escape hatch
        /// for tenants whose policy engine rejects the HIP XML
        /// pangolin ships with. When set, libopenconnect's
        /// csd-wrapper slot gets pointed at your script instead
        /// of the `pgn hip-report` subcommand.
        ///
        /// The script must accept the argv libopenconnect passes
        /// to csd wrappers: at minimum `--cookie <v>`,
        /// `--client-ip <v>`, `--md5 <v>`, `--client-os <v>`,
        /// and the optional `--client-ipv6 <v>` when the gateway
        /// assigns an IPv6 address. The wrapper should be
        /// tolerant of additional flags libopenconnect may add
        /// in future versions. On success it prints HIP XML on
        /// stdout and exits 0. openconnect's own
        /// `trojans/hipreport.sh` is a drop-in example that
        /// already honours this contract.
        ///
        /// The path is validated and canonicalised (symlinks
        /// followed, relative paths resolved against the current
        /// working directory) before libopenconnect sees it so
        /// a typo surfaces at the CLI instead of deep inside
        /// the tunnel thread. Passing `--hip-script` with
        /// `--hip=off` is a hard error.
        #[arg(long, env = "PGN_HIP_SCRIPT", value_name = "PATH")]
        hip_script: Option<String>,

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

        /// Enable the ESP (IPsec UDP 4501) transport alongside CSTP.
        ///
        /// **On by default**, matching yuezk/GlobalProtect-openconnect
        /// and upstream openconnect's behaviour. libopenconnect's
        /// GP driver calls `openconnect_setup_dtls` unconditionally;
        /// when the ESP probe succeeds `gpst.c` exits the HTTPS
        /// mainloop and the tunnel runs purely over ESP/UDP,
        /// which is how virtually every stable GlobalProtect
        /// session against Prisma Access survives long-lived.
        ///
        /// Pass `--esp=false` as an escape hatch if UDP 4501 is
        /// blocked end-to-end and ESP probe failure + CSTP fallback
        /// still beats the alternatives. We previously defaulted
        /// this off to dodge an idle-DPD death mode; web evidence
        /// (openconnect gitlab #701, yuezk #364/#451) and a
        /// matched-pair test against UNSW Prisma Access showed
        /// the off-by-default path is far less stable because
        /// CSTP-only sessions get DPD'd after 60s–3min on Prisma
        /// Access gateways. See `.pgn-logs/run-os-linux.log` for
        /// the matched-pair diagnostic that settled this.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            env = "PGN_ESP"
        )]
        esp: Option<bool>,
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

    /// INTERNAL: HIP report generator invoked by libopenconnect as a
    /// csd-wrapper child process.
    ///
    /// libopenconnect calls `openconnect_setup_csd` to register this
    /// binary as the HIP wrapper, then `fork()` + `execv()`s it with
    /// the argv contract from upstream openconnect `gpst.c:1012-1027`:
    ///
    /// ```text
    /// pgn hip-report --cookie <urlenc> [--client-ip <v4>]
    ///                [--client-ipv6 <v6>] --md5 <token>
    ///                --client-os <Windows|Linux|Mac>
    /// ```
    ///
    /// The subcommand parses those flags, builds a HIP XML document
    /// via `gp-hip::build_report`, and prints it to stdout. libopen-
    /// connect reads stdin-style and POSTs the content as the
    /// `report` form field on `/ssl-vpn/hipreport.esp`. Because
    /// libopenconnect runs this wrapper from inside its own CSTP
    /// flow — after `getconfig.esp` has already fetched the session-
    /// local `client_ip` — the HIP report always lands against the
    /// same session key libopenconnect's CSTP uses. This is the only
    /// reliable way to survive gateways that rotate `client_ip` per
    /// `getconfig.esp` request (observed: UNSW Prisma Access).
    ///
    /// The command is deliberately hidden from `--help` output to
    /// keep the user-visible CLI tree clean. End users never type
    /// `pgn hip-report` directly; it's invoked only by libopenconnect.
    #[command(hide = true)]
    HipReport {
        /// URL-encoded GP cookie string (same value libopenconnect
        /// passed to `openconnect_set_cookie`). The subcommand
        /// parses `user=…` out of this to populate the HIP XML
        /// `<user-name>` field.
        #[arg(long)]
        cookie: String,
        /// Client's assigned IPv4 on the tun interface. Comes from
        /// libopenconnect after its own getconfig.esp.
        #[arg(long)]
        client_ip: Option<String>,
        /// IPv6 equivalent. We don't use this today, accepted to
        /// match the upstream argv contract.
        #[arg(long)]
        client_ipv6: Option<String>,
        /// CSD md5 token. libopenconnect computes this from the
        /// cookie (minus `authcookie`/`preferred-ip`/`preferred-ipv6`)
        /// and passes it in. We echo it straight into the HIP
        /// XML's `<md5-sum>` element.
        #[arg(long)]
        md5: String,
        /// Client OS string — one of `Windows`, `Linux`, `Mac`,
        /// `iOS`, `Android`. gp-hip uses this to pick the HIP XML
        /// profile family so the report matches the rest of the
        /// session identity.
        #[arg(long)]
        client_os: Option<String>,
    },
}

#[derive(Subcommand)]
// The `Add` variant is a clap struct with ~16 optional profile
// fields, which dwarfs the two-field `Rm`/`Use`/`Show` variants.
// Boxing it would force every call site to match-and-deref and
// obscure the clap derive surface for zero real payoff — this
// enum is constructed once per CLI invocation and immediately
// matched into its variant, so the stack size difference never
// matters in practice.
#[allow(clippy::large_enum_variant)]
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
        /// Explicit split-DNS zone list (comma-separated). See
        /// `pgn connect --dns-zone` for the full semantics —
        /// setting this replaces the `--only`-derived zones.
        #[arg(long, value_name = "ZONE[,ZONE...]")]
        dns_zone: Option<String>,
        /// HIP reporting mode.
        #[arg(long, value_enum)]
        hip: Option<HipMode>,
        /// Path to an external HIP wrapper script saved with
        /// this profile. See the `pgn connect --hip-script`
        /// help text for the argv contract.
        #[arg(long, value_name = "PATH")]
        hip_script: Option<String>,
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
        /// Enable ESP/UDP transport. Defaults to on at `pgn
        /// connect` time; set `--esp=false` here to persist the
        /// CSTP-only escape hatch for this profile.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
        )]
        esp: Option<bool>,
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
    // libopenconnect's csd-wrapper mechanism (`gpst.c::run_hip_script`)
    // `execv()`s our binary with flags as argv[1..], NO subcommand
    // token in the middle:
    //
    //     argv = [wrapper_path, --cookie <v>, --client-ip <v>,
    //             --md5 <v>, --client-os <v>]
    //
    // But our clap tree has `hip-report` as a subcommand under the
    // main `Commands` enum, so clap sees `--cookie` as an unknown
    // top-level flag and aborts. Detect the invocation BEFORE clap
    // parses by sniffing argv[1] — if it's `--cookie`, synthesize
    // the missing `hip-report` subcommand token in front of it.
    // Zero user-visible change; the main CLI surface remains clean
    // and `pgn hip-report --cookie …` still works for manual
    // testing.
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let looks_like_csd_wrapper_invocation = raw_args
        .get(1)
        .and_then(|s| s.to_str())
        .map(|s| s == "--cookie")
        .unwrap_or(false);
    let cli = if looks_like_csd_wrapper_invocation {
        let mut rewritten: Vec<std::ffi::OsString> = Vec::with_capacity(raw_args.len() + 1);
        rewritten.push(raw_args[0].clone());
        rewritten.push("hip-report".into());
        rewritten.extend(raw_args.into_iter().skip(1));
        Cli::parse_from(rewritten)
    } else {
        Cli::parse()
    };

    // HIP wrapper mode MUST keep stdout clean because
    // `gpst.c:1006-1007` dup2's fd 1 to a pipe that libopenconnect
    // reads as the HIP XML `report=` field. Any stray tracing byte
    // corrupts the XML and the gateway rejects the submission.
    // tracing-subscriber's default writer is stdout, so we skip
    // init entirely when we're in the hip-report path. gp-hip /
    // serde_urlencoded / anyhow are silent on happy paths, and the
    // wrapper exits before anything interesting could happen.
    //
    // For manual `pgn hip-report …` invocations we also skip
    // tracing init — callers debugging by hand can still set
    // RUST_LOG if they want and redirect stderr. Codex round-26
    // caught this silent corruption before it bit us live.
    let in_hip_report_mode = matches!(cli.command, Some(Commands::HipReport { .. }));
    if !in_hip_report_mode {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log)),
            )
            .init();
    }

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
            dns_zone,
            hip,
            hip_script,
            reconnect,
            instance,
            metrics_port,
            okta_url,
            esp,
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
                dns_zone,
                hip,
                hip_script,
                reconnect,
                instance,
                metrics_port,
                okta_url,
                esp,
            })
            .await
        }
        Some(Commands::Disconnect { instance, all }) => disconnect(cli.json, instance, all).await,
        Some(Commands::Status { instance, all }) => status(cli.json, instance, all).await,
        None => status(cli.json, None, false).await,
        Some(Commands::Portal { action }) => portal_command(action).await,
        Some(Commands::HipReport {
            cookie,
            client_ip,
            client_ipv6: _,
            md5,
            client_os,
        }) => hip_report(cookie, client_ip, md5, client_os).await,
    }
}

/// `pgn hip-report` subcommand: csd-wrapper entry point for
/// libopenconnect. Builds a HIP XML document from the argv flags
/// libopenconnect passes us, prints it to stdout, exits 0.
///
/// Runs in a `fork()` + `execv()` child, so printing to stdout is
/// fine (libopenconnect has set up a pipe on fd 1 for us). Any
/// tracing output from this path would go to the already-unreachable
/// stderr, so we keep the function silent on success and only emit
/// errors via `eprintln!` before `process::exit(1)`.
async fn hip_report(
    cookie: String,
    client_ip: Option<String>,
    md5: String,
    client_os: Option<String>,
) -> Result<()> {
    use std::io::Write;

    // Extract `user=...` from the cookie for the HIP XML <user-name>
    // field. `serde_urlencoded` handles the percent-decoding the same
    // way the rest of our HIP path does, so the username ends up as
    // the real `alice@example.com` form even if libopenconnect
    // handed us `alice%40example.com`.
    let user_name: String = serde_urlencoded::from_str::<Vec<(String, String)>>(&cookie)
        .unwrap_or_default()
        .into_iter()
        .find_map(|(k, v)| if k == "user" { Some(v) } else { None })
        .unwrap_or_else(|| "pangolin".to_string());

    // client_ip is optional per the upstream argv contract (gpst.c:
    // 1015-1018 only appends --client-ip when vpninfo->ip_info.addr
    // is non-null). Fall back to empty string to preserve XML shape.
    let client_ip = client_ip.unwrap_or_default();

    let host = gp_hip::HostInfo::detect();
    let profile = gp_hip::HostProfile::from_client_os(client_os.as_deref());
    let generate_time = gp_hip_generate_time();
    let report = gp_hip::build_report(md5, user_name, client_ip, host, profile, generate_time);
    let xml = report.to_xml();

    // Write to stdout — this is the pipe libopenconnect's parent is
    // reading from. flush() is load-bearing: if we exit without
    // flushing, the parent sees a short read and the HIP submission
    // body gets truncated.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(xml.as_bytes())
        .context("writing HIP XML to stdout")?;
    out.flush().context("flushing HIP XML")?;
    Ok(())
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
            dns_zone,
            hip,
            hip_script,
            vpnc_script,
            insecure,
            reconnect,
            metrics_port,
            okta_url,
            esp,
        } => {
            // Validate the metrics spec up front so bad profile
            // saves fail fast instead of blowing up at `pgn
            // connect` time.
            if let Some(spec) = metrics_port.as_deref() {
                parse_metrics_bind(spec)?;
            }
            // Same fail-fast rule for the explicit split-DNS zone
            // list: if the user typed a garbage zone, surface the
            // error at save time from the `pgn portal add`
            // invocation they just made, not hours later at
            // `pgn connect` time from a profile they may no
            // longer remember editing.
            if let Some(spec) = dns_zone.as_deref() {
                parse_dns_zone_spec(spec).context("validating --dns-zone")?;
            }
            // Canonicalise the HIP wrapper path now so the saved
            // profile holds an absolute path. Relative-path
            // `hip_script` values would otherwise be re-resolved
            // against whatever CWD `pgn connect` is invoked from
            // later, which is almost never the shell the user
            // ran `pgn portal add` from — systemd units run
            // with `WorkingDirectory=/`, for example. Doing it
            // here also catches bad inputs at save time instead
            // of at tunnel-setup time.
            let hip_script = hip_script
                .as_deref()
                .map(resolve_hip_script_path)
                .transpose()?;
            let profile = gp_config::PortalProfile {
                url,
                username: user,
                gateway: None,
                os,
                auth_mode: match auth_mode {
                    None => None,
                    Some(SamlAuthMode::Paste) => Some("paste".to_string()),
                    Some(SamlAuthMode::Okta) => Some("okta".to_string()),
                    Some(SamlAuthMode::Webview) => {
                        anyhow::bail!(
                            "`--auth-mode webview` is no longer supported — \
                             pangolin retired the embedded GTK+WebKit window \
                             in favour of headless SAML. Use \
                             `--auth-mode paste` or `--auth-mode okta` \
                             when saving the profile."
                        );
                    }
                },
                saml_port: None,
                vpnc_script,
                only,
                dns_zones: dns_zone,
                hip: hip.map(|m| match m {
                    HipMode::Auto => "auto".to_string(),
                    HipMode::Force => "force".to_string(),
                    HipMode::Off => "off".to_string(),
                }),
                insecure: if insecure { Some(true) } else { None },
                reconnect: if reconnect { Some(true) } else { None },
                metrics_port,
                okta_url,
                esp,
                hip_script,
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
            if let Some(z) = &profile.dns_zones {
                println!("dns-zones:  {z}");
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

fn resolve_gateway_for_exclude(gateway_host: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = gateway_host.parse::<Ipv4Addr>() {
        return Some(ip);
    }

    match (gateway_host, 443).to_socket_addrs() {
        Ok(mut addrs) => {
            let resolved = addrs.find_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            });
            if resolved.is_none() {
                tracing::warn!(
                    "gp-route: gateway exclude skipped for {gateway_host:?}: resolver returned no IPv4 addresses"
                );
            }
            resolved
        }
        Err(err) => {
            tracing::warn!(
                "gp-route: gateway exclude skipped for {gateway_host:?}: failed to resolve IPv4 address: {err}"
            );
            None
        }
    }
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
    dns_zone: Option<String>,
    hip: Option<HipMode>,
    hip_script: Option<String>,
    reconnect: Option<bool>,
    instance: Option<String>,
    metrics_port: Option<String>,
    okta_url: Option<String>,
    esp: Option<bool>,
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
        dns_zone,
        hip,
        hip_script,
        reconnect,
        instance,
        metrics_port,
        okta_url,
        esp,
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
            dns_zone,
            hip,
            hip_script,
            reconnect,
            metrics_port,
            okta_url,
            esp,
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
        dns_zones_override,
        hip,
        hip_script,
        insecure,
        reconnect,
        user: merged_user,
        metrics_bind: metrics_bind_addr,
        okta_url,
        esp,
    } = resolved;

    // `user` was previously a plain ConnectArgs field; it's now
    // part of the resolved settings so CLI > profile > None
    // merging applies. Shadow the outer name for the rest of the
    // function.
    let user = merged_user;

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
                anyhow::bail!(
                    "`--auth-mode webview` is no longer supported — pangolin \
                     retired the embedded GTK+WebKit window in favour of \
                     headless SAML. Use `--auth-mode paste` (the default; \
                     local HTTP callback + terminal paste) or `--auth-mode \
                     okta --okta-url <https://tenant.okta.com>` (direct \
                     Okta API, no browser at all). See the README for the \
                     migration reasoning."
                );
            }
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

    // 6.5 HIP report flow is now called from inside
    //     `run_tunnel_attempt` on every attempt, not just the
    //     first. GlobalProtect's HIP machinery is per-CSTP-session,
    //     so if we only submitted once here (before the reconnect
    //     loop) the second and subsequent tunnel sessions would
    //     have no HIP credited and the gateway would kick each one
    //     at its 60-second grace window. See the long comment at
    //     the top of run_tunnel_attempt for the full reasoning.

    // 7. Resolve --only (split-tunnel) spec, if any.
    //
    // Hostnames are resolved here — BEFORE the tunnel comes up — via
    // the normal system resolver. That's usually what you want: the
    // public address is what you'll route through the VPN. Resolving
    // *after* tunnel-up would require internal DNS, which we don't
    // manage yet. We keep the original hostnames around so gp-dns can
    // register matching split-DNS zones once we know which tun
    // interface libopenconnect ended up with.
    let (routes, only_hostnames): (Vec<String>, Vec<String>) = match only.as_deref() {
        Some(spec) => {
            let resolved = resolve_only_spec(spec).await.context("resolving --only")?;
            (resolved.routes, resolved.hostnames)
        }
        None => (Vec::new(), Vec::new()),
    };
    if !routes.is_empty() {
        tracing::info!(
            "split tunnel: {} route(s) resolved — {}",
            routes.len(),
            routes.join(" ")
        );
    }
    // Split-DNS zones: either the explicit `--dns-zone` override
    // (which replaces the derivation entirely, including the
    // empty-list case) or the heuristic in
    // `derive_split_dns_zones` run against `--only` hostnames.
    //
    // When the user has opted into an external `--vpnc-script`,
    // that script owns DNS configuration and gp-dns will not
    // run — in which case any zones we'd compute never land,
    // and advertising them would mislead operators reading the
    // logs. Suppress the info line and carry on with an empty
    // vector (cheap clones, no extra branches later).
    let split_dns_zones = select_split_dns_zones(SplitDnsSelection {
        vpnc_script_in_use: vpnc_script.is_some(),
        dns_zones_override: dns_zones_override.clone(),
        only_hostnames: &only_hostnames,
    });

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
    let oc_os = client_os.openconnect_os();
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
            enable_esp: esp,
            base: &base,
            disconnect_rx: disconnect_rx.clone(),
            counters: &metrics_counters,
            attempt_num,
            hip_mode: hip,
            hip_script: hip_script.clone(),
            split_dns_zones: split_dns_zones.clone(),
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
            // Terminal error: gateway explicitly ended the session
            // or the authcookie is dead. Retrying with the same
            // cookie either fails immediately or reconnects and
            // gets kicked at the next grace window — either way
            // we'd just flap. Break out with a useful error.
            AttemptOutcome::TerminalErr(e) => {
                tracing::error!("tunnel exited with terminal error: {e:#}");
                break 'outer Err(e);
            }
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
    /// The gateway or authcookie state said "don't come back" —
    /// `TunnelError::MainloopTerminated` (remote `-EPIPE`) or
    /// `TunnelError::MainloopAuthExpired` (remote `-EPERM`).
    /// The reconnect loop must NOT retry: re-using the same cookie
    /// would flap. Distinct from `Err` so the loop can surface a
    /// clear "server ended the session, re-run `pgn connect`"
    /// instead of spinning backoffs and eventually giving up at
    /// `MAX_RECONNECT_ATTEMPTS`.
    TerminalErr(anyhow::Error),
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
    /// Enable libopenconnect's ESP (IPsec UDP) transport. See the
    /// `--esp` CLI flag docstring for why this defaults off.
    enable_esp: bool,
    base: &'a SharedBase,
    disconnect_rx: tokio::sync::watch::Receiver<bool>,
    counters: &'a Arc<metrics::MetricsCounters>,
    attempt_num: u32,
    /// Final split-DNS zone suffixes for `gp-dns` to register
    /// via `resolvectl domain <iface> ~<zone>` once the tun is
    /// up. Resolution happens in `connect()` and picks one of
    /// three paths: empty when `--vpnc-script` owns DNS (gp-dns
    /// is skipped), the explicit list from `--dns-zone` /
    /// profile `dns_zones` when set (replacing derivation), or
    /// the output of `derive_split_dns_zones` over the `--only`
    /// hostnames otherwise. Pre-computed and cloned per attempt
    /// so reconnects see the same zones.
    split_dns_zones: Vec<String>,
    /// HIP reporting mode. `Off` skips the flow entirely. `Auto`
    /// and `Force` drive the full HIP submission on every attempt
    /// (not just the first) because GlobalProtect's HIP state is
    /// per-CSTP-session, not per-authcookie — the gateway opens a
    /// fresh 60-second grace window on each new tunnel setup and
    /// will kick the client if a valid HIP report hasn't landed
    /// against the session key by the time the grace window
    /// expires. Verified live against UNSW Prisma Access on
    /// 2026-04-14 (see commit c654874 for the csd-wrapper
    /// delegation that fixed the 60-second kick loop).
    hip_mode: HipMode,
    /// Optional user-supplied HIP wrapper script path. When
    /// present, `run_tunnel` registers this with libopenconnect
    /// via `openconnect_setup_csd` INSTEAD of the built-in
    /// `pgn hip-report` subcommand. Already canonicalised and
    /// validated in `resolve_connect_settings`.
    hip_script: Option<String>,
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
        enable_esp,
        base,
        mut disconnect_rx,
        counters,
        attempt_num,
        hip_mode,
        hip_script,
        split_dns_zones,
    } = args;

    // HIP submission is delegated to libopenconnect's csd-wrapper
    // hook via `openconnect_setup_csd`. `run_tunnel` (below)
    // registers either `pgn hip-report` or the user-supplied
    // `--hip-script` path as the wrapper before calling
    // `make_cstp_connection`, and libopenconnect `fork()`+`execv()`s
    // the wrapper from within its own CSTP flow — AFTER it has
    // already obtained the session's `client_ip` from its own
    // `getconfig.esp` call. The wrapper prints HIP XML to stdout
    // and libopenconnect POSTs it to `/ssl-vpn/hipreport.esp` on
    // the same TLS session as the CSTP tunnel.
    //
    // This guarantees the HIP report is credited against the exact
    // `client_ip` libopenconnect's CSTP session uses, which is the
    // only reliable fix for gateways that rotate client IPs per
    // `getconfig.esp` request (observed against UNSW Prisma Access
    // on 2026-04-14, where a pre-CSTP HIP landed at `172.26.6.44`
    // while libopenconnect's CSTP used `172.26.6.45`, giving a
    // deterministic 60-second kick every attempt).

    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<TunnelReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<()>>();

    let gateway_owned = gateway_host.to_string();
    let cookie_owned = cookie.to_string();
    let script_owned = script.map(|s| s.to_string());
    let routes_for_thread = routes;
    let hip_script_owned = hip_script;
    let dns_zones_owned = split_dns_zones;
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
                    enable_esp,
                    hip_mode,
                    hip_script_owned,
                    dns_zones_owned,
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
    // any blocking work so this normally returns immediately, but
    // we still race the recv against shutdown signals + disconnect
    // — otherwise a SIGTERM arriving during attempt setup would
    // block on this sync recv until the tunnel thread reached its
    // first openconnect call.
    //
    // If shutdown OR disconnect wins the race, we MUST still pull
    // the CancelHandle out of the spawn_blocking task and use it
    // before tearing down — otherwise the tunnel thread may already
    // be inside `make_cstp_connection` or `setup_tun_device`, which
    // libopenconnect will only abort via the cmd pipe (i.e. the
    // CancelHandle). Without that, `done_rx.await` could block
    // until the network or libopenconnect's own timeout decides to
    // give up. The pattern below pins the spawn_blocking JoinHandle
    // so the shutdown branches can re-await it after winning.
    let mut recv_task = tokio::task::spawn_blocking(move || cancel_rx.recv());
    let mut dr_setup = disconnect_rx.clone();
    let cancel_handle = tokio::select! {
        res = &mut recv_task => {
            match res {
                Ok(Ok(c)) => c,
                Ok(Err(_)) | Err(_) => {
                    let _ = tunnel_thread.join();
                    return match done_rx.await {
                        Ok(Ok(())) => AttemptOutcome::Ok,
                        Ok(Err(e)) => classify_tunnel_err(e),
                        Err(_) => AttemptOutcome::Err(anyhow::anyhow!(
                            "tunnel thread died without reporting a result"
                        )),
                    };
                }
            }
        }
        sig = shutdown_signal() => {
            tracing::info!("{sig} received before cancel handle arrived, draining tunnel thread");
            await_handle_then_cancel_and_join(recv_task, done_rx, tunnel_thread).await;
            return AttemptOutcome::UserCancel;
        }
        _ = dr_setup.wait_for(|v| *v) => {
            tracing::info!("disconnect received before cancel handle arrived, draining tunnel thread");
            await_handle_then_cancel_and_join(recv_task, done_rx, tunnel_thread).await;
            return AttemptOutcome::UserCancel;
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
                            Ok(Err(e)) => classify_tunnel_err(e),
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
                    Ok(Err(e)) => classify_tunnel_err(e),
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
            // Tunnel exited on its own — clear the tun info now,
            // not in the outer loop, so a `pgn status` racing the
            // reconnect decision sees a fresh (empty) state
            // instead of the dead interface.
            clear_tun_info(base);
            match res {
                Ok(Ok(())) => AttemptOutcome::Ok,
                Ok(Err(e)) => classify_tunnel_err(e),
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

/// Classify an `anyhow::Error` bubbled up from the tunnel thread
/// into an [`AttemptOutcome`]. Walks the error chain looking for a
/// [`gp_tunnel::TunnelError`] with one of the terminal variants; if
/// found, returns [`AttemptOutcome::TerminalErr`], otherwise
/// [`AttemptOutcome::Err`] for the reconnect loop to retry.
///
/// The reconnect loop's retry policy is not safe against errors
/// where the gateway has explicitly ended the session — re-running
/// the tunnel attempt with the same authcookie will just flap. This
/// classifier is the single place in the codebase that decides
/// "retry is futile".
fn classify_tunnel_err(e: anyhow::Error) -> AttemptOutcome {
    use gp_tunnel::TunnelError;
    let is_terminal = e.chain().any(|cause| {
        cause
            .downcast_ref::<TunnelError>()
            .is_some_and(|t| t.is_terminal())
    });
    if is_terminal {
        AttemptOutcome::TerminalErr(e)
    } else {
        AttemptOutcome::Err(e)
    }
}

/// Helper: clear `tun_ifname` + `local_ipv4` from the shared base so
/// `pgn status` and `/metrics` don't keep reporting a dead tunnel's
/// interface after the tunnel thread has exited but before the outer
/// reconnect loop has decided what to do with the failure.
fn clear_tun_info(base: &SharedBase) {
    let mut guard = base.write().expect("SharedBase RwLock poisoned");
    guard.tun_ifname = None;
    guard.local_ipv4 = None;
}

/// Drain the cancel-handle delivery channel after a shutdown signal
/// or disconnect request fired during attempt setup, then USE the
/// handle to cancel libopenconnect, then wait for the tunnel thread
/// to exit cleanly.
///
/// Why this exists: the tunnel thread is normally somewhere inside
/// `make_cstp_connection` or `setup_tun_device` when the cancel
/// handle has just arrived but the main task hasn't observed it
/// yet. Skipping `cancel()` and going straight to
/// `done_rx.await` would leave libopenconnect blocked on socket
/// I/O and the await would only return when the network or
/// libopenconnect's own timeout gives up — potentially many
/// seconds. The cmd-pipe `cancel()` is what tells libopenconnect
/// to drop everything immediately.
///
/// On the rare path where the tunnel thread died before sending
/// the handle (mpsc disconnect), we skip the cancel and just
/// wait for the done channel.
async fn await_handle_then_cancel_and_join(
    recv_task: tokio::task::JoinHandle<Result<gp_tunnel::CancelHandle, std::sync::mpsc::RecvError>>,
    done_rx: tokio::sync::oneshot::Receiver<Result<()>>,
    tunnel_thread: std::thread::JoinHandle<()>,
) {
    if let Ok(Ok(handle)) = recv_task.await {
        if let Err(e) = handle.cancel() {
            tracing::warn!("cancel after pre-handle shutdown failed: {e}");
        }
    } else {
        tracing::debug!("tunnel thread exited before delivering cancel handle");
    }
    let _ = done_rx.await;
    let _ = tunnel_thread.join();
}

/// Parse a string-form auth mode (from a TOML profile's
/// `auth_mode` field) into the CLI enum. Unknown values log a
/// warning and return `None` so the caller falls through to a
/// safe default rather than erroring — but the warning surfaces
/// the likely typo to the user instead of silently changing
/// runtime behaviour.
///
/// The legacy value `"webview"` was retired during the
/// headless-first architecture cleanup (the embedded GTK+WebKit
/// provider was removed in favour of `--auth-mode paste` +
/// `--auth-mode okta`). Profiles that still carry the old value
/// are migrated at parse time: we log a clear warning pointing
/// at the replacement, return `None` so the caller falls back
/// to the hard-coded default of `Paste`, and let the user
/// update their config at their leisure. Nothing crashes.
fn parse_auth_mode(s: &str) -> Option<SamlAuthMode> {
    match s.to_ascii_lowercase().as_str() {
        "webview" => {
            tracing::warn!(
                "profile auth_mode = \"webview\" is no longer supported — \
                 pangolin standardised on headless SAML. Falling back to \
                 `paste` for this session. Run `pgn portal add <name> \
                 --auth-mode paste …` (or edit \
                 `~/.config/pangolin/config.toml`) to silence this warning."
            );
            None
        }
        "paste" => Some(SamlAuthMode::Paste),
        "okta" => Some(SamlAuthMode::Okta),
        other => {
            tracing::warn!(
                "profile auth_mode = {other:?} is not a recognized value \
                 (expected 'paste' or 'okta'); falling back to the \
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
    dns_zone: Option<String>,
    hip: Option<HipMode>,
    hip_script: Option<String>,
    reconnect: Option<bool>,
    metrics_port: Option<String>,
    okta_url: Option<String>,
    esp: Option<bool>,
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
    /// Explicit split-DNS zone override.
    ///
    /// `None` means the derivation heuristic in
    /// [`derive_split_dns_zones`] runs against the `--only`
    /// hostnames. `Some(vec)` means the user (via CLI or profile)
    /// supplied an explicit zone list and the derivation is
    /// skipped entirely — the vec is handed to `gp-dns` as-is,
    /// even when empty. An empty vec is a valid "no split DNS"
    /// signal from the user, distinct from the `None` "derive
    /// normally" default.
    dns_zones_override: Option<Vec<String>>,
    hip: HipMode,
    /// Absolute path to an external HIP wrapper script, when the
    /// user has asked to replace the built-in `pgn hip-report`
    /// wrapper with their own. Resolved to an absolute path in
    /// `resolve_connect_settings` so libopenconnect can
    /// `fork+execv` it from any working directory.
    hip_script: Option<String>,
    insecure: bool,
    reconnect: bool,
    metrics_bind: Option<SocketAddr>,
    okta_url: Option<String>,
    /// Whether to enable libopenconnect's ESP transport. Default
    /// `false` because on idle sessions ESP dies at 2 * DPD and
    /// takes the CSTP socket with it — see the `--esp` flag
    /// docstring for the full explanation.
    esp: bool,
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
        .unwrap_or(SamlAuthMode::Paste);
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
    // Explicit split-DNS zone override: CLI wins over profile.
    // `Some(raw)` — even `Some("")` — means the user supplied an
    // explicit value and the derivation heuristic must be
    // bypassed. An empty raw string parses to an empty vec, which
    // is the user's way of saying "install --only routes but
    // don't register any split DNS zones". Normal derivation from
    // --only hostnames only happens when BOTH CLI and profile are
    // None.
    let dns_zones_override: Option<Vec<String>> = cli
        .dns_zone
        .or_else(|| profile.as_ref().and_then(|p| p.dns_zones.clone()))
        .map(|raw| parse_dns_zone_spec(&raw))
        .transpose()?;
    let hip: HipMode = cli
        .hip
        .or_else(|| {
            profile
                .as_ref()
                .and_then(|p| p.hip.as_deref())
                .and_then(parse_hip_mode)
        })
        .unwrap_or(HipMode::Auto);
    // Optional user-supplied HIP wrapper script. CLI wins over
    // profile. Validate + canonicalise HERE (before we get near
    // libopenconnect) so bad inputs fail fast with a clear error
    // pointing at the CLI flag, not at `setup_csd` buried in the
    // tunnel thread. Canonicalisation also handles the "user
    // passed `./hip.sh`" case — libopenconnect will `fork+execv`
    // the wrapper from whatever CWD the tunnel thread has, which
    // is NOT the shell the user invoked pgn from.
    let hip_script: Option<String> = cli
        .hip_script
        .or_else(|| profile.as_ref().and_then(|p| p.hip_script.clone()))
        .map(|raw| resolve_hip_script_path(&raw))
        .transpose()?;
    if hip_script.is_some() && hip == HipMode::Off {
        anyhow::bail!(
            "`--hip-script` is set but `--hip=off` — pick one. \
             The wrapper will not be registered when HIP is disabled."
        );
    }
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

    // Tri-state merge mirroring --insecure / --reconnect: CLI
    // wins if set (even explicitly to false), otherwise profile,
    // otherwise the hardcoded default of `true` (ESP on, matching
    // yuezk and upstream openconnect — see the `--esp` doc comment
    // for the rationale behind the flip from off-by-default).
    let esp: bool = cli
        .esp
        .or_else(|| profile.as_ref().and_then(|p| p.esp))
        .unwrap_or(true);

    Ok(ResolvedConnectSettings {
        portal_url,
        cfg_user,
        user,
        os,
        auth_mode,
        saml_port,
        vpnc_script,
        only,
        dns_zones_override,
        hip,
        hip_script,
        insecure,
        reconnect,
        metrics_bind,
        okta_url,
        esp,
    })
}

/// Validate + canonicalise a user-supplied HIP wrapper script
/// path. We check existence and executability up front because
/// libopenconnect's `openconnect_setup_csd` just stores whatever
/// string we give it — the failure mode for a bad path is a
/// confusing `execve: ENOENT` deep inside a fork'd child at
/// tunnel-setup time.
///
/// Canonicalisation is important for a second reason: libopenconnect
/// will `fork+execv` the wrapper from inside the tunnel thread,
/// whose CWD is not the shell the user ran `pgn connect` from
/// (systemd units run with `WorkingDirectory=/`, for example).
/// Relative paths would resolve against that CWD and silently
/// miss. `fs::canonicalize` turns them into absolute paths while
/// simultaneously confirming the file exists.
fn resolve_hip_script_path(raw: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::fs::canonicalize(raw)
        .with_context(|| format!("`--hip-script {raw}`: file not found or not accessible"))?;

    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("`--hip-script {raw}`: cannot stat {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "`--hip-script {raw}`: {} is not a regular file",
            path.display()
        );
    }
    // At least one execute bit must be set. Checking the effective
    // execute permission for the current process would require
    // `faccessat` and is overkill — libopenconnect runs the
    // wrapper via `execv`, which will surface any residual
    // permission error with a clear `EACCES` on the first attempt.
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        anyhow::bail!(
            "`--hip-script {raw}`: {} is not executable (mode {:o})",
            path.display(),
            mode & 0o777
        );
    }

    Ok(path.to_string_lossy().into_owned())
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
///
/// # Percent encoding
///
/// Values are percent-encoded via `serde_urlencoded::to_string`. This is
/// **load-bearing** for the HIP `csd_token` md5 to match libopenconnect's
/// (and the server's).
///
/// The HIP check/submit flow computes an md5 over the cookie string
/// (minus `authcookie`, `preferred-ip`, `preferred-ipv6`). libopenconnect's
/// `build_csd_token` (gpst.c) does a byte-level copy of the non-filtered
/// fields and md5s those bytes. Our [`crate::hip::compute_csd_md5`]
/// parses the cookie via `serde_urlencoded::from_str` and re-serializes
/// through `serde_urlencoded::to_string` before md5 — i.e. it produces
/// md5 over the *canonical form-urlencoded* representation.
///
/// For both md5s to agree, the cookie bytes handed to libopenconnect and
/// the cookie bytes we md5 over must be byte-identical **after** any
/// encoding normalization. Practically, that means the builder itself
/// must emit canonical serde_urlencoded output. If we emit raw (e.g.
/// `user=z3502076@ad.unsw.edu.au`), libopenconnect md5s `@` bytes while
/// our md5 is computed over `%40` bytes (the serde_urlencoded round
/// trip encodes `@`) — mismatch, and HIP submission lands in the
/// wrong server-side bucket. Observed live against UNSW Prisma Access.
///
/// yuezk v2's `build_gateway_token` follows the same rule via
/// `urlencoding::encode`; we use `serde_urlencoded::to_string` because
/// (a) our `compute_csd_md5` already uses `serde_urlencoded` so a
/// matching producer guarantees byte-level agreement, and (b) no new
/// dep.
fn build_openconnect_cookie(c: &AuthCookie) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("authcookie", &c.authcookie),
        ("portal", &c.portal),
        ("user", &c.username),
    ];
    if let Some(d) = &c.domain {
        pairs.push(("domain", d));
    }
    if let Some(comp) = &c.computer {
        pairs.push(("computer", comp));
    }
    if let Some(ip) = &c.preferred_ip {
        pairs.push(("preferred-ip", ip));
    }
    serde_urlencoded::to_string(&pairs).unwrap_or_default()
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
async fn resolve_only_spec(spec: &str) -> Result<OnlyResolved> {
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
    let mut hostnames: Vec<String> = Vec::new();
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
            // Record the original hostname so `gp-dns` can register
            // a matching split-DNS zone for it — otherwise the user
            // can reach the host by IP but any further sibling
            // lookup (`library.unsw.edu.au` when only
            // `moodle.unsw.edu.au` was in `--only`) falls through
            // to the system resolver and leaks outside the tunnel.
            hostnames.push(entry.to_string());
        }
    }
    Ok(OnlyResolved { routes, hostnames })
}

/// Output of [`resolve_only_spec`]: the CIDR-style routes that go
/// straight into `gp-route`, plus the list of original hostnames
/// that appeared in the user's `--only` spec (after resolution).
/// The hostnames feed [`derive_split_dns_zones`] so `gp-dns` can
/// register matching routing-only suffix zones via
/// `resolvectl domain <iface> ~<zone>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OnlyResolved {
    routes: Vec<String>,
    hostnames: Vec<String>,
}

/// Derive split-DNS zone suffixes from the set of hostnames the
/// user passed to `--only`. Each returned zone is handed to
/// `gp-dns` which prefixes it with `~` so systemd-resolved treats
/// it as a routing-only match: queries for `*.zone` go through
/// the VPN-assigned resolver, everything else stays on the system
/// resolver.
///
/// **Important — DNS only, not routing.** Registering a split-DNS
/// zone makes sibling hostnames *resolvable* through the tunnel's
/// resolver; it does NOT install any routes to the IP addresses
/// those names return. A user who passes
/// `--only moodle.unsw.edu.au` gets a `/32` route for moodle's
/// IP plus a `~unsw.edu.au` resolver hint. That's enough to
/// LOOK UP `library.unsw.edu.au` internally, but the library IP
/// has no matching route and traffic to it will go out whatever
/// interface the system default route points at (eth0, public
/// internet, whatever). Users who need full reachability for
/// sibling hosts should list a covering CIDR in `--only` (e.g.
/// `--only 10.0.0.0/8,moodle.unsw.edu.au`) so gp-route installs
/// a route that encompasses the sibling addresses too.
///
/// Heuristic:
///
/// * `host.corp.example.com` → register `corp.example.com`
///   (drop the left-most label). This is the common corporate
///   case where specifying one host from the VPN's internal
///   zone implies you want sibling lookups to go through the
///   same resolver.
/// * `host.corp` → parent is the bare `corp` single label.
///   That's too broad to register as a routing zone (it would
///   capture unrelated TLD-level names in the unlikely but
///   possible case that some user has a `corp` resolver set
///   up). Instead, register `host.corp` itself — resolvectl's
///   suffix match still covers subdomains of it.
/// * `host` (single label) → no meaningful zone; skipped.
/// * Case is normalised to ASCII lowercase and a trailing `.`
///   is stripped so `Host.EXAMPLE.com.` becomes `example.com`.
/// * Duplicates are collapsed via a `BTreeSet`, and the result
///   is sorted for stable `pgn status` / log output.
///
/// **Not covered**: the Public Suffix List. A hostname like
/// `host.co.uk` would yield a parent of `co.uk`, which is a
/// publicly-operated TLD and shouldn't be registered as a
/// routing zone. The function does not know this. Users whose
/// VPN targets live directly under a 2-label public suffix
/// should list exact IPs or CIDRs in `--only` instead of
/// hostnames, or pass the correct zone explicitly via
/// `--dns-zone` / the profile's `dns_zones` field (see
/// [`parse_dns_zone_spec`]).
fn derive_split_dns_zones(hostnames: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut zones = BTreeSet::new();
    for raw in hostnames {
        let normalised = raw.trim_end_matches('.').to_ascii_lowercase();
        if normalised.is_empty() {
            continue;
        }
        // `split_once('.')` gives `(first_label, rest)`. A zone
        // is `rest` only if it still contains at least one dot
        // (i.e. has two or more labels of its own). Otherwise
        // fall back to the full normalised hostname so we never
        // register a bare TLD-ish single label as a routing zone.
        let zone = match normalised.split_once('.') {
            Some((_, parent)) if parent.contains('.') => parent.to_string(),
            Some(_) => normalised.clone(),
            None => continue, // single-label, skip entirely
        };
        zones.insert(zone);
    }
    zones.into_iter().collect()
}

/// Inputs to [`select_split_dns_zones`]. Kept as a struct so the
/// test suite can build the three-state input matrix explicitly
/// without touching the rest of `connect()`.
struct SplitDnsSelection<'a> {
    vpnc_script_in_use: bool,
    /// CLI/profile explicit override. `None` = derive, `Some(vec)` =
    /// replace (empty vec is the "no split DNS at all" signal).
    dns_zones_override: Option<Vec<String>>,
    /// Original `--only` hostnames (for the derivation branch).
    only_hostnames: &'a [String],
}

/// Pick the final split-DNS zone list and emit the matching info /
/// warn log line. Pure except for `tracing` — the caller passes
/// in fully-resolved inputs so this function is trivially testable.
///
/// Resolution order:
///   1. `--vpnc-script` set → always empty, because gp-dns does
///      not run when an external route/DNS script owns the
///      session. Warns if the user also tried to set zones.
///   2. explicit override `Some(vec)` → replace derivation
///      entirely, including the empty-vec "skip split DNS"
///      signal.
///   3. otherwise derive from `--only` hostnames.
fn select_split_dns_zones(input: SplitDnsSelection<'_>) -> Vec<String> {
    let SplitDnsSelection {
        vpnc_script_in_use,
        dns_zones_override,
        only_hostnames,
    } = input;

    if vpnc_script_in_use {
        // Two distinct warn cases kept separate so the log line
        // names the exact user intent that's being ignored.
        if let Some(ref explicit) = dns_zones_override {
            tracing::warn!(
                "split DNS: explicit --dns-zone override ({}) ignored — \
                 --vpnc-script is set, so gp-dns is not running this session \
                 and the zone list would be dropped. Your vpnc-script must \
                 configure these zones itself.",
                if explicit.is_empty() {
                    "empty".to_string()
                } else {
                    explicit.join(" ")
                }
            );
        } else if !only_hostnames.is_empty() {
            tracing::warn!(
                "split DNS: --only included {} hostname(s) but --vpnc-script \
                 was set — gp-dns is not running this session, so any split \
                 zones derived from those hostnames would be dropped. Your \
                 vpnc-script must handle DNS for them.",
                only_hostnames.len()
            );
        }
        return Vec::new();
    }

    if let Some(explicit) = dns_zones_override {
        if explicit.is_empty() {
            tracing::info!(
                "split DNS: explicit --dns-zone override is empty — skipping \
                 split-DNS registration even though --only may include \
                 hostnames"
            );
        } else {
            tracing::info!(
                "split DNS: {} zone(s) from explicit --dns-zone override — {} \
                 (derivation from --only hostnames skipped)",
                explicit.len(),
                explicit.join(" ")
            );
        }
        return explicit;
    }

    let zones = derive_split_dns_zones(only_hostnames);
    if !zones.is_empty() {
        tracing::info!(
            "split DNS: {} zone(s) derived from --only hostnames — {} \
             (siblings resolve via the tunnel's resolver, but you still \
             need matching routes via --only CIDRs/IPs to actually reach \
             their addresses)",
            zones.len(),
            zones.join(" ")
        );
    }
    zones
}

/// Parse a `--dns-zone` / profile `dns_zones` string into a
/// validated, deduplicated zone list.
///
/// Input is the same comma-separated format `--only` uses:
/// entries are split on `,`, trimmed of whitespace, normalised
/// to ASCII lowercase with any trailing `.` stripped. Duplicates
/// are collapsed, order is preserved by first occurrence so
/// log lines and test assertions stay stable.
///
/// Each surviving entry must be a syntactically valid DNS name
/// per the RFC 1035 label rules: 1..=63 octets per label,
/// ASCII alphanumeric or `-`, no leading/trailing hyphen on a
/// label, whole name ≤ 253 octets. Invalid entries surface as a
/// `ProtoError::Validation`-flavoured `anyhow` error at
/// `resolve_connect_settings` time so a typo fails fast at
/// `pgn connect` / `pgn portal add` rather than hours later via
/// an opaque `resolvectl domain` complaint from `gp-dns`.
///
/// An entirely empty or whitespace-only spec returns an empty
/// vec — no error. That is a meaningful signal from the user:
/// "I set an explicit zone list and it's empty, so do NOT fall
/// back to the derivation heuristic" — see
/// [`ResolvedConnectSettings::dns_zones_override`].
fn parse_dns_zone_spec(spec: &str) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for part in spec.split(',') {
        let normalised = part.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalised.is_empty() {
            continue;
        }
        validate_dns_zone(&normalised)
            .with_context(|| format!("invalid --dns-zone entry {normalised:?}"))?;
        if seen.insert(normalised.clone()) {
            out.push(normalised);
        }
    }
    Ok(out)
}

/// Syntactic RFC 1035 validation for a single DNS zone name.
/// Accepts one or more labels separated by `.`; each label must
/// be 1..=63 bytes of `[a-z0-9-]` with no leading or trailing
/// hyphen; whole name must be ≤ 253 bytes. Called from
/// [`parse_dns_zone_spec`] after case-folding + trailing-dot
/// strip, so this sees a lowercase name with no trailing `.`.
fn validate_dns_zone(name: &str) -> Result<()> {
    anyhow::ensure!(
        name.len() <= 253,
        "zone name is {} bytes long; DNS names are limited to 253",
        name.len()
    );
    anyhow::ensure!(!name.is_empty(), "zone name must not be empty");
    for label in name.split('.') {
        anyhow::ensure!(!label.is_empty(), "empty label (stray dot)");
        anyhow::ensure!(
            label.len() <= 63,
            "label {label:?} is {} bytes; labels are limited to 63",
            label.len()
        );
        anyhow::ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "label {label:?} starts or ends with '-'"
        );
        anyhow::ensure!(
            label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "label {label:?} contains a character that is not \
             ASCII alphanumeric or '-'"
        );
    }
    Ok(())
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
    enable_esp: bool,
    hip_mode: HipMode,
    hip_script: Option<String>,
    split_dns_zones: Vec<String>,
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

    // Register our HIP wrapper via openconnect_setup_csd BEFORE
    // make_cstp_connection. libopenconnect will fork+execv the
    // wrapper from inside its own CSTP flow, after it has obtained
    // the session's client_ip. See `OpenConnectSession::setup_csd`
    // for the full rationale on why this must happen inside
    // libopenconnect instead of as a separate Rust HTTP path.
    if hip_mode != HipMode::Off {
        // Pick the wrapper path. If the user passed `--hip-script
        // <path>`, use that verbatim — it's already been
        // canonicalised + executable-checked in
        // `resolve_connect_settings`. Otherwise fall back to our
        // own binary's current_exe, which re-enters via the
        // `hip-report` argv-sniff shim.
        let (wrapper_path, wrapper_source) = match hip_script.as_deref() {
            Some(user_path) => (user_path.to_string(), "user (`--hip-script`)"),
            None => match std::env::current_exe() {
                Ok(p) => (p.to_string_lossy().into_owned(), "builtin (current_exe)"),
                Err(e) => {
                    tracing::warn!(
                        "HIP: could not resolve current_exe for csd wrapper path: {e}; \
                         HIP will not be submitted (libopenconnect will warn)"
                    );
                    (String::new(), "")
                }
            },
        };
        if !wrapper_path.is_empty() {
            // Drop privileges to the real user (SUDO_UID) when
            // available so the wrapper subprocess runs unprivileged.
            // If we're not under sudo, run as root (uid=0) — safe
            // because the wrapper only reads /etc/machine-id and
            // generates XML, no capabilities needed.
            let uid: u32 = std::env::var("SUDO_UID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            tracing::info!(
                "HIP: registering csd wrapper {wrapper_path} (uid={uid}, source={wrapper_source}) for libopenconnect"
            );
            if let Err(e) = session.setup_csd(uid, true, &wrapper_path) {
                if hip_mode == HipMode::Force {
                    return Err(e).context("--hip=force: openconnect_setup_csd failed, aborting");
                }
                tracing::warn!("HIP: openconnect_setup_csd failed (auto mode, continuing): {e:#}");
            }
        }
    }

    session
        .make_cstp_connection()
        .context("make_cstp_connection")?;

    // ESP setup is ON by default, matching yuezk/upstream
    // openconnect. When the ESP probe succeeds libopenconnect's
    // GP driver exits the HTTPS mainloop (`gpst.c:1115-1127`)
    // and runs the tunnel purely over ESP/UDP 4501, which is
    // what sustains long-lived sessions against Prisma Access
    // gateways. CSTP-only fallback is available via `--esp=false`
    // for networks where UDP 4501 is blocked end-to-end.
    //
    // Note: `setup_esp` returning 0 only means the FFI-level
    // setup call succeeded — the actual probe result and any
    // runtime fallback to HTTPS are visible only through
    // libopenconnect's progress callback stream. Do NOT treat
    // rc=0 as proof the gateway is ESP-reachable.
    let reconnect_timeout = if reconnect_enabled { 600 } else { 60 };
    tracing::info!(
        gateway = %gateway_host,
        os = %os,
        hip_mode = ?hip_mode,
        esp_requested = enable_esp,
        reconnect_timeout_secs = reconnect_timeout,
        "tunnel setup: resolved transport parameters"
    );
    if enable_esp {
        let rc = session.setup_esp(60);
        if rc == 0 {
            tracing::info!(
                attempt_period_secs = 60,
                "ESP: openconnect_setup_dtls ok (probe will run in mainloop)"
            );
        } else {
            tracing::warn!(
                rc,
                "ESP: openconnect_setup_dtls failed at FFI level — forcing CSTP-only"
            );
            session.disable_esp();
        }
    } else {
        tracing::info!("ESP: disabled by `--esp=false` escape hatch — tunnel will run CSTP-only");
        session.disable_esp();
    }

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

    // INFO-level diagnostic: the client IP libopenconnect's CSTP
    // session ended up with. This used to pair with a pre-CSTP
    // `gateway_getconfig` probe on the Rust side that's now
    // retired (HIP went through libopenconnect's csd-wrapper hook
    // ever since commit c654874), but the log line is still
    // useful on its own as a ground-truth for the session key
    // the gateway sees — any divergence from the HIP wrapper's
    // `--client-ip` argv would be a regression.
    let tun_ip_log = ip_info
        .as_ref()
        .and_then(|i| i.addr.as_deref())
        .unwrap_or("(unknown)");
    tracing::info!(
        "libopenconnect: setup_tun_device complete, assigned client_ip={tun_ip_log} (post-CSTP)"
    );

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
            gateway_exclude: resolve_gateway_for_exclude(gateway_host),
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
        // Split-DNS domains: any hostname the user passed to
        // `--only` contributes a routing-only zone entry
        // (`resolvectl domain <iface> ~<zone>`) so sibling names
        // under the same parent zone resolve through the VPN
        // too. For example `--only intranet.example.com` lets
        // `library.example.com` resolve internally without
        // needing a separate CLI entry. The exact heuristic
        // lives in `derive_split_dns_zones` — here we just pass
        // through whatever the caller computed up-front.
        let split_domains: Vec<String> = split_dns_zones.clone();
        let config = gp_dns::DnsConfig {
            ifname: ifname_str,
            servers,
            search_domains,
            split_domains,
        };
        if !config.servers.is_empty() {
            tracing::info!(
                "gp-dns: applying {} nameserver(s) on {} (search={:?}, split={:?})",
                config.servers.len(),
                config.ifname,
                config.search_domains,
                config.split_domains
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
    // (Actual value already computed above alongside the ESP
    // setup diagnostic log so both paths share a single source
    // of truth.)
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
            dns_zone: None,
            hip: None,
            hip_script: None,
            reconnect: None,
            metrics_port: None,
            okta_url: None,
            esp: None,
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
            auth_mode: Some(SamlAuthMode::Okta),
            saml_port: Some(12345),
            only: Some("192.168.0.0/16".into()),
            hip: Some(HipMode::Off),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.os, "mac");
        assert_eq!(r.auth_mode, SamlAuthMode::Okta);
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
        // match a profile. `saml_port` and `insecure` both differ
        // between the `config_with_profile` fixture and the
        // hardcoded defaults, so they're clean signals here —
        // and unlike `auth_mode` they stayed orthogonal to the
        // recent Paste-default flip.
        assert_eq!(r.saml_port, 29999);
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
        assert_eq!(r.auth_mode, SamlAuthMode::Paste); // the hardcoded default
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
    fn cli_auth_mode_webview_still_parses_via_hidden_variant() {
        use clap::Parser;
        // The webview variant is marked `#[clap(hide = true)]`
        // so it doesn't show up in `--help`, but clap still
        // accepts it as an input value. That lets pgn emit a
        // custom migration error at connect time instead of
        // clap's generic "invalid value" response. This is a
        // one-shot UX improvement for users who run the old
        // flag after upgrading.
        let cli = Cli::try_parse_from([
            "pgn",
            "connect",
            "--auth-mode",
            "webview",
            "vpn.example.com",
        ])
        .expect("hidden `--auth-mode webview` must still parse");
        match cli.command {
            Some(Commands::Connect { auth_mode, .. }) => {
                assert_eq!(auth_mode, Some(SamlAuthMode::Webview));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn parse_auth_mode_legacy_webview_migrates_to_none() {
        // Regression guard: profiles that still carry the
        // retired `auth_mode = "webview"` value must NOT crash
        // pgn — they should log a migration warning and return
        // None so the caller falls back to the hardcoded
        // default (`Paste`). This is the whole reason we didn't
        // delete the match arm entirely when the webview
        // provider was removed.
        assert_eq!(parse_auth_mode("webview"), None);
        assert_eq!(parse_auth_mode("WebView"), None);
        assert_eq!(parse_auth_mode("WEBVIEW"), None);
    }

    /// End-to-end resolve: a profile with the legacy
    /// `"webview"` value must surface as an effective
    /// `SamlAuthMode::Paste` (the hardcoded default), without
    /// erroring out.
    #[test]
    fn resolve_connect_settings_legacy_webview_profile_falls_back_to_paste() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("legacy".into());
        cfg.set_portal(
            "legacy",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                auth_mode: Some("webview".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.auth_mode, SamlAuthMode::Paste);
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
        assert_eq!(r.os, "linux");
        assert_eq!(r.auth_mode, SamlAuthMode::Paste);
        assert_eq!(r.saml_port, 29999);
        assert_eq!(r.hip, HipMode::Auto);
        assert!(!r.insecure);
        assert!(!r.reconnect);
        assert!(r.only.is_none());
        assert!(r.vpnc_script.is_none());
    }

    #[test]
    fn hip_report_subcommand_accepts_client_os() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "pgn",
            "hip-report",
            "--cookie",
            "user=alice",
            "--md5",
            "abc123",
            "--client-os",
            "Linux",
        ])
        .expect("hip-report --client-os must parse");
        match cli.command {
            Some(Commands::HipReport { client_os, .. }) => {
                assert_eq!(client_os.as_deref(), Some("Linux"));
            }
            _ => panic!("expected Commands::HipReport"),
        }
    }

    // ---------- resolve_hip_script_path ----------

    /// Build a temporary file with given mode and return its
    /// absolute path. Panics if setup fails — these are test-only
    /// helpers. Uses a unique name per test via process id + a
    /// monotonic counter so parallel test runs don't collide.
    fn tmp_file_with_mode(name: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "pgn-hip-script-test-{}-{}-{name}",
            std::process::id(),
            seq
        ));
        std::fs::write(&p, b"#!/bin/sh\necho '<hip-report/>'\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    // ---------- derive_split_dns_zones ----------

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn derive_split_dns_drops_left_label_for_3plus_label_hosts() {
        let zones = derive_split_dns_zones(&v(&["moodle.unsw.edu.au"]));
        assert_eq!(zones, v(&["unsw.edu.au"]));
    }

    #[test]
    fn derive_split_dns_two_label_host_keeps_itself() {
        // `host1.corp` — parent `corp` is a single label and too
        // broad; fall back to the full normalised hostname.
        let zones = derive_split_dns_zones(&v(&["host1.corp"]));
        assert_eq!(zones, v(&["host1.corp"]));
    }

    #[test]
    fn derive_split_dns_single_label_skipped() {
        assert!(derive_split_dns_zones(&v(&["localhost"])).is_empty());
        assert!(derive_split_dns_zones(&v(&["router"])).is_empty());
    }

    #[test]
    fn derive_split_dns_normalises_case_and_trailing_dot() {
        let zones = derive_split_dns_zones(&v(&[
            "Library.UNSW.edu.AU.",
            "library.unsw.edu.au",
            "LIBRARY.unsw.EDU.au",
        ]));
        // All three normalise to `library.unsw.edu.au`, parent is
        // `unsw.edu.au`, and BTreeSet collapses duplicates.
        assert_eq!(zones, v(&["unsw.edu.au"]));
    }

    #[test]
    fn derive_split_dns_collapses_siblings_into_one_zone() {
        let zones = derive_split_dns_zones(&v(&[
            "moodle.unsw.edu.au",
            "library.unsw.edu.au",
            "intranet.corp.example.com",
        ]));
        // Two distinct zones, sorted alphabetically by the
        // BTreeSet iteration order.
        assert_eq!(zones, v(&["corp.example.com", "unsw.edu.au"]));
    }

    #[test]
    fn derive_split_dns_empty_input() {
        assert!(derive_split_dns_zones(&[]).is_empty());
    }

    #[test]
    fn derive_split_dns_skips_empty_strings() {
        let zones = derive_split_dns_zones(&v(&["", "moodle.unsw.edu.au"]));
        assert_eq!(zones, v(&["unsw.edu.au"]));
    }

    #[test]
    fn derive_split_dns_handles_punycode_idn() {
        // Punycode is already ASCII; the heuristic should treat
        // it like any other hostname and drop the left-most
        // label.
        let zones = derive_split_dns_zones(&v(&["www.xn--fiqs8s.xn--fiqs8s"]));
        assert_eq!(zones, v(&["xn--fiqs8s.xn--fiqs8s"]));
    }

    #[test]
    fn derive_split_dns_empty_after_strip_skipped() {
        // A literal `.` or bare whitespace should not produce a
        // zone. `"."` strips to empty, `"  "` strips to `"  "`
        // (only trailing `.` is stripped), but the empty-after-
        // strip check catches the first case. The second case
        // is treated as a (garbage) single-label hostname and
        // skipped by the `split_once('.')` None arm.
        assert!(derive_split_dns_zones(&v(&["."])).is_empty());
        assert!(derive_split_dns_zones(&v(&["...."])).is_empty());
    }

    // ---------- parse_dns_zone_spec ----------

    #[test]
    fn parse_dns_zone_empty_string_is_empty_vec() {
        // Empty spec is a load-bearing signal from the user: "set
        // an override and make it empty" — distinct from None at
        // the CliConnectOverrides layer.
        assert!(parse_dns_zone_spec("").unwrap().is_empty());
        assert!(parse_dns_zone_spec("   ").unwrap().is_empty());
        assert!(parse_dns_zone_spec(",,,").unwrap().is_empty());
    }

    #[test]
    fn parse_dns_zone_comma_separated_normalised() {
        let zones = parse_dns_zone_spec("Corp.Example.com, intranet.example.org.").unwrap();
        assert_eq!(zones, v(&["corp.example.com", "intranet.example.org"]));
    }

    #[test]
    fn parse_dns_zone_drops_duplicates_stably() {
        let zones = parse_dns_zone_spec("a.example,b.example,A.EXAMPLE").unwrap();
        assert_eq!(zones, v(&["a.example", "b.example"]));
    }

    #[test]
    fn parse_dns_zone_rejects_invalid_syntax() {
        // Guard that garbage fails fast at CLI parse time rather
        // than silently flowing to `resolvectl domain ~<zone>`
        // deep in the tunnel setup path. Each of these should
        // return an error whose message names the offending
        // entry so the user knows which one to fix.
        for bad in [
            "bad zone",           // whitespace inside a label
            "with/slash",         // invalid character
            "-leading.example",   // leading hyphen
            "trailing-.example",  // trailing hyphen
            "..double.dot",       // empty label
            "ok.example,bad_one", // underscore not allowed
        ] {
            let err = parse_dns_zone_spec(bad)
                .unwrap_err()
                .to_string()
                .to_lowercase();
            assert!(
                err.contains("invalid --dns-zone entry")
                    || err.contains("label")
                    || err.contains("empty"),
                "parse_dns_zone_spec({bad:?}) error {err:?} did not identify the problem"
            );
        }
    }

    #[test]
    fn parse_dns_zone_rejects_overlong_label() {
        let long = "a".repeat(64);
        let spec = format!("{long}.example");
        let err = format!("{:#}", parse_dns_zone_spec(&spec).unwrap_err());
        assert!(err.contains("63"), "expected 63-byte label limit: {err}");
    }

    #[test]
    fn resolve_dns_zone_cli_replaces_derivation() {
        // CLI --dns-zone supersedes the derivation entirely. The
        // caller consumes this as `Some(vec)` to signal the
        // replace-don't-derive path in connect().
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            dns_zone: Some("corp.example.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.dns_zones_override, Some(v(&["corp.example.com"])));
    }

    #[test]
    fn resolve_dns_zone_profile_field_flows_through() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                dns_zones: Some("zone1.example, zone2.example".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(
            r.dns_zones_override,
            Some(v(&["zone1.example", "zone2.example"]))
        );
    }

    #[test]
    fn resolve_dns_zone_cli_overrides_profile() {
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                dns_zones: Some("profile.example".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let overrides = CliConnectOverrides {
            dns_zone: Some("cli.example".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.dns_zones_override, Some(v(&["cli.example"])));
    }

    #[test]
    fn resolve_dns_zone_empty_string_means_no_zones_override() {
        // `--dns-zone ""` is distinct from omitting the flag:
        // it parses to an empty vec, and the override is still
        // Some(...). Downstream this skips derive_split_dns_zones
        // even when --only contains hostnames.
        let cfg = config_with_profile();
        let overrides = CliConnectOverrides {
            dns_zone: Some(String::new()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.dns_zones_override, Some(Vec::<String>::new()));
    }

    #[test]
    fn resolve_dns_zone_none_when_neither_set() {
        let cfg = config_with_profile();
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert!(r.dns_zones_override.is_none());
    }

    // ---------- select_split_dns_zones ----------

    #[test]
    fn select_split_dns_explicit_override_replaces_derivation() {
        let got = select_split_dns_zones(SplitDnsSelection {
            vpnc_script_in_use: false,
            dns_zones_override: Some(v(&["corp.example.com"])),
            only_hostnames: &v(&["moodle.unsw.edu.au"]),
        });
        // Derivation from moodle.unsw.edu.au would yield
        // `unsw.edu.au`; explicit override must win.
        assert_eq!(got, v(&["corp.example.com"]));
    }

    #[test]
    fn select_split_dns_empty_override_forces_no_zones_even_with_hostnames() {
        let got = select_split_dns_zones(SplitDnsSelection {
            vpnc_script_in_use: false,
            dns_zones_override: Some(Vec::new()),
            only_hostnames: &v(&["moodle.unsw.edu.au"]),
        });
        assert!(
            got.is_empty(),
            "empty explicit override must skip derivation entirely"
        );
    }

    #[test]
    fn select_split_dns_no_override_derives_from_hostnames() {
        let got = select_split_dns_zones(SplitDnsSelection {
            vpnc_script_in_use: false,
            dns_zones_override: None,
            only_hostnames: &v(&["moodle.unsw.edu.au"]),
        });
        assert_eq!(got, v(&["unsw.edu.au"]));
    }

    #[test]
    fn select_split_dns_vpnc_script_always_empty() {
        // Both branches (explicit and derive) collapse to empty
        // when an external vpnc-script owns DNS.
        let with_override = select_split_dns_zones(SplitDnsSelection {
            vpnc_script_in_use: true,
            dns_zones_override: Some(v(&["corp.example.com"])),
            only_hostnames: &[],
        });
        assert!(with_override.is_empty());

        let with_hostnames = select_split_dns_zones(SplitDnsSelection {
            vpnc_script_in_use: true,
            dns_zones_override: None,
            only_hostnames: &v(&["moodle.unsw.edu.au"]),
        });
        assert!(with_hostnames.is_empty());
    }

    #[test]
    fn dns_zone_cli_parses_comma_separated() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "pgn",
            "connect",
            "--dns-zone",
            "corp.example.com,intranet.example.org",
            "vpn.example.com",
        ])
        .expect("--dns-zone must parse");
        match cli.command {
            Some(Commands::Connect { dns_zone, .. }) => {
                assert_eq!(
                    dns_zone.as_deref(),
                    Some("corp.example.com,intranet.example.org")
                );
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn dns_zone_portal_profile_roundtrip() {
        // End-to-end: serialize a profile with dns_zones set,
        // deserialize, verify the field survives. Guards against
        // a future #[serde(rename = ...)] or skip_serializing_if
        // regression dropping the field on disk.
        let profile = gp_config::PortalProfile {
            url: "vpn.example.com".into(),
            dns_zones: Some("corp.example.com,other.example".into()),
            ..gp_config::PortalProfile::default()
        };
        let mut cfg = gp_config::PangolinConfig::default();
        cfg.set_portal("work", profile.clone());

        // Round-trip through `PangolinConfig::save_to` + `load_from`
        // rather than `toml::to_string` directly — this crate has
        // no direct `toml` dep (it goes through gp-config), and the
        // save/load path is the real persistence surface anyway.
        let tmp = std::env::temp_dir().join(format!(
            "pgn-dns-zones-roundtrip-{}.toml",
            std::process::id()
        ));
        cfg.save_to(&tmp).expect("save");
        let on_disk = std::fs::read_to_string(&tmp).expect("read back");
        assert!(
            on_disk.contains("dns_zones"),
            "serialised TOML must contain dns_zones field:\n{on_disk}"
        );
        let round = gp_config::PangolinConfig::load_from(&tmp).expect("load");
        assert_eq!(
            round.portal.get("work").unwrap().dns_zones.as_deref(),
            Some("corp.example.com,other.example")
        );
        let _ = std::fs::remove_file(&tmp);
    }

    // ---------- resolve_hip_script_path ----------

    #[test]
    fn resolve_hip_script_path_accepts_executable_file() {
        let path = tmp_file_with_mode("ok", 0o755);
        let resolved =
            resolve_hip_script_path(path.to_str().unwrap()).expect("executable file must resolve");
        // Must be absolute so libopenconnect's fork+execv works
        // from any CWD.
        assert!(std::path::Path::new(&resolved).is_absolute());
        assert_eq!(
            std::fs::canonicalize(&path).unwrap().to_string_lossy(),
            resolved
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_hip_script_path_rejects_non_executable() {
        let path = tmp_file_with_mode("noexec", 0o644);
        let err = resolve_hip_script_path(path.to_str().unwrap())
            .expect_err("non-executable file must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not executable"),
            "expected 'not executable' in error, got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_hip_script_path_rejects_missing() {
        let missing = std::env::temp_dir().join(format!(
            "pgn-hip-script-does-not-exist-{}",
            std::process::id()
        ));
        // Defensive cleanup in case a previous run left one.
        let _ = std::fs::remove_file(&missing);
        let err = resolve_hip_script_path(missing.to_str().unwrap())
            .expect_err("missing file must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("file not found") || msg.contains("not accessible"),
            "expected 'file not found' in error, got: {msg}"
        );
    }

    #[test]
    fn resolve_connect_settings_rejects_hip_script_with_hip_off() {
        let path = tmp_file_with_mode("offconflict", 0o755);
        let mut overrides = empty_overrides();
        overrides.portal = Some("vpn.example.com".into());
        overrides.hip = Some(HipMode::Off);
        overrides.hip_script = Some(path.to_str().unwrap().into());
        let cfg = gp_config::PangolinConfig::default();
        let err = resolve_connect_settings(overrides, &cfg)
            .expect_err("hip=off + hip-script must conflict");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--hip-script") && msg.contains("--hip=off"),
            "expected conflict message, got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_connect_settings_canonicalises_hip_script_path() {
        let path = tmp_file_with_mode("canon", 0o755);
        let mut overrides = empty_overrides();
        overrides.portal = Some("vpn.example.com".into());
        overrides.hip_script = Some(path.to_str().unwrap().into());
        let cfg = gp_config::PangolinConfig::default();
        let resolved = resolve_connect_settings(overrides, &cfg).unwrap();
        let hip_script = resolved.hip_script.expect("hip_script must be set");
        assert!(std::path::Path::new(&hip_script).is_absolute());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_hip_script_falls_back_to_profile_and_cli_overrides() {
        let profile_path = tmp_file_with_mode("prof", 0o755);
        let cli_path = tmp_file_with_mode("cli", 0o755);

        let mut cfg = gp_config::PangolinConfig::default();
        cfg.portal.insert(
            "work".into(),
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                hip_script: Some(profile_path.to_string_lossy().into_owned()),
                ..Default::default()
            },
        );

        // CLI omits the flag → inherit from profile.
        let mut overrides = empty_overrides();
        overrides.portal = Some("work".into());
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(
            r.hip_script.as_deref(),
            Some(
                std::fs::canonicalize(&profile_path)
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            ),
        );

        // CLI sets the flag → override profile.
        let mut overrides = empty_overrides();
        overrides.portal = Some("work".into());
        overrides.hip_script = Some(cli_path.to_string_lossy().into_owned());
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(
            r.hip_script.as_deref(),
            Some(
                std::fs::canonicalize(&cli_path)
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            ),
        );

        let _ = std::fs::remove_file(&profile_path);
        let _ = std::fs::remove_file(&cli_path);
    }

    #[test]
    fn resolve_hip_script_accepts_relative_path() {
        // Drop a wrapper in the current working directory (which
        // under `cargo test` is the workspace root, writable), then
        // resolve it by a relative name.
        use std::os::unix::fs::PermissionsExt;
        let rel = format!("pgn-hip-rel-test-{}.sh", std::process::id());
        std::fs::write(&rel, b"#!/bin/sh\necho '<hip-report/>'\n").unwrap();
        std::fs::set_permissions(&rel, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved =
            resolve_hip_script_path(&rel).expect("relative path must resolve to absolute");
        assert!(
            std::path::Path::new(&resolved).is_absolute(),
            "resolved={resolved} must be absolute"
        );
        assert!(
            resolved.ends_with(&rel),
            "resolved={resolved} should still end in {rel}"
        );

        let _ = std::fs::remove_file(&rel);
    }

    #[test]
    fn connect_subcommand_accepts_hip_script_flag() {
        use clap::Parser;
        let path = tmp_file_with_mode("clap", 0o755);
        let cli = Cli::try_parse_from([
            "pgn",
            "connect",
            "--hip-script",
            path.to_str().unwrap(),
            "vpn.example.com",
        ])
        .expect("--hip-script must parse");
        match cli.command {
            Some(Commands::Connect { hip_script, .. }) => {
                assert_eq!(hip_script.as_deref(), Some(path.to_str().unwrap()));
            }
            _ => panic!("expected Commands::Connect"),
        }
        let _ = std::fs::remove_file(&path);
    }

    // ---------- build_openconnect_cookie percent encoding ----------

    fn cookie_with_username(username: &str) -> AuthCookie {
        AuthCookie {
            username: username.to_string(),
            authcookie: "AUTH-JWT-PLACEHOLDER".to_string(),
            portal: "vpn.example.com".to_string(),
            domain: None,
            preferred_ip: None,
            computer: Some("host".to_string()),
        }
    }

    #[test]
    fn build_openconnect_cookie_percent_encodes_at_sign_in_username() {
        // UNSW and most enterprise SAML IdPs use `user@domain.tld`
        // usernames. The cookie must percent-encode the `@` so that
        //   (a) libopenconnect's byte-level filter_opts + md5 path,
        //   (b) compute_csd_md5's serde_urlencoded round-trip, and
        //   (c) the server's own md5 over the received form body
        // all agree on the same bytes → same md5 → HIP report lands
        // on the session libopenconnect is asking the server about.
        //
        // Live regression: UNSW Prisma Access would return
        // `hip-report-needed=yes` even after our HIP submission
        // succeeded, because our md5 was computed over `%40` bytes
        // (via serde_urlencoded) but libopenconnect's was computed
        // over raw `@` bytes. Gateway kicked us 60s later.
        let cookie = build_openconnect_cookie(&cookie_with_username("z3502076@ad.unsw.edu.au"));
        assert!(
            cookie.contains("user=z3502076%40ad.unsw.edu.au"),
            "expected percent-encoded @, got: {cookie}"
        );
        assert!(
            !cookie.contains("user=z3502076@ad.unsw.edu.au"),
            "raw @ must not appear: {cookie}"
        );
    }

    #[test]
    fn build_openconnect_cookie_matches_compute_csd_md5_canonicalization() {
        // The contract: whatever build_openconnect_cookie emits,
        // compute_csd_md5 must treat its serde_urlencoded round-
        // trip as a no-op on the non-filtered fields. Guarantees
        // byte-level agreement with libopenconnect's filter_opts.
        //
        // We verify this by asserting compute_csd_md5 is stable
        // when the SAME cookie is re-fed through serde_urlencoded
        // round-trip externally — a no-op round trip proves
        // canonical form.
        use gp_auth::hip::compute_csd_md5;
        let cookie = build_openconnect_cookie(&cookie_with_username("alice@example.com"));
        // Round-trip the (filtered) non-authcookie fields through
        // serde_urlencoded and confirm it's byte-identical to the
        // filtered original — proving build_openconnect_cookie
        // already emits canonical form.
        let filtered: Vec<(String, String)> = serde_urlencoded::from_str(&cookie).unwrap();
        let non_auth: Vec<(String, String)> = filtered
            .into_iter()
            .filter(|(k, _)| k != "authcookie" && k != "preferred-ip" && k != "preferred-ipv6")
            .collect();
        let reserialized = serde_urlencoded::to_string(&non_auth).unwrap();
        // Also extract the non-auth prefix directly from the built cookie.
        let direct: String = cookie
            .split('&')
            .filter(|f| {
                !f.starts_with("authcookie=")
                    && !f.starts_with("preferred-ip=")
                    && !f.starts_with("preferred-ipv6=")
            })
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(
            reserialized, direct,
            "cookie is not in canonical serde_urlencoded form; \
             round-trip changed bytes: {reserialized:?} vs {direct:?}"
        );
        // And confirm compute_csd_md5 doesn't panic on this input.
        let _ = compute_csd_md5(&cookie);
    }

    #[test]
    fn build_openconnect_cookie_preserves_safe_chars() {
        // Chars that serde_urlencoded leaves alone should appear
        // verbatim. The JWT-style authcookie is base64url + `.`,
        // all of which are unreserved.
        let cookie = build_openconnect_cookie(&AuthCookie {
            username: "alice".to_string(),
            authcookie: "eyJ_base-64.url.chars".to_string(),
            portal: "vpn.example.com".to_string(),
            domain: None,
            preferred_ip: None,
            computer: None,
        });
        // `.` is preserved.
        assert!(cookie.contains("authcookie=eyJ_base-64.url.chars"));
        assert!(cookie.contains("portal=vpn.example.com"));
        assert!(cookie.contains("user=alice"));
    }
}
