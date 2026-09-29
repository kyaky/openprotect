//! `opc` — OpenProtect GlobalProtect VPN CLI.

#[cfg(windows)]
mod crash_cleanup;
mod metrics;
#[cfg(windows)]
mod wintun_cleanup;

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// Shared, interior-mutable tunnel state. The IPC server and the
/// metrics renderer both read it; the reconnect state machine
/// writes it (flipping `state` between `Connecting`, `Connected`,
/// and `Reconnecting`, and updating `tun_ifname` / `local_ipv4` on
/// each successful tunnel re-establishment).
///
/// `std::sync::RwLock` is load-bearing here: reads are hot (every
/// `opc status` / scrape), writes are rare (once per state change),
/// and the lock is only ever held long enough to clone out the
/// relevant fields — never across an `await`. A tokio RwLock would
/// add async overhead for no benefit.
type SharedBase = Arc<RwLock<StateSnapshotBase>>;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use gp_auth::SamlPasteAuthProvider;
use gp_auth::{
    AuthContext, AuthProvider, GpClient, OktaAuthConfig, OktaAuthProvider, PasswordAuthProvider,
};
#[cfg(unix)]
use gp_ipc::{bind_server, read_request, write_response};
use gp_ipc::{
    build_snapshot, client_roundtrip, endpoint_for, enumerate_live_instances, IpcError,
    Request as IpcRequest, Response as IpcResponse, SessionState, StateSnapshotBase,
    DEFAULT_INSTANCE,
};
use gp_proto::{AuthCookie, ClientOs, Gateway, GatewayLoginResult, GpParams};
use gp_tunnel::{IpInfoSnapshot, OpenConnectSession};

/// Build version — the release tag (CI) or `git describe` (local), captured
/// by `build.rs`. Falls back to the crate version if the build script didn't
/// set it. Shown by `--version`, `opc status`, and the connect banner so a
/// pasted log always identifies which build produced it.
const OPC_VERSION: &str = match option_env!("OPC_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(name = "opc", version = OPC_VERSION, about = "OpenProtect GlobalProtect VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output as JSON.
    #[arg(long, global = true, env = "PGN_JSON")]
    json: bool,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, global = true, env = "PGN_LOG", default_value = "info")]
    log: String,

    /// Additionally write logs to a rotating file (hourly rotation,
    /// date-suffixed sibling files next to `PATH`, same base name).
    ///
    /// OFF by default: without this flag the tracing stack is a
    /// single console sink and opc's behavior is byte-identical to
    /// before it existed. Designed for the "connect often hangs"
    /// class of reports — a file sink survives a wedged console
    /// and gives a post-mortem reader phase timestamps even after
    /// the terminal buffer is gone. The HIP csd-wrapper path never
    /// opens it: that invocation must keep stdout pristine for the
    /// XML `report=` pipe (see the init block in `run`), and a file
    /// there would leak per-fork handles.
    #[arg(long, global = true, env = "PGN_LOG_FILE", value_name = "PATH")]
    log_file: Option<String>,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum SamlAuthMode {
    /// Headless — opc runs a local HTTP server, you complete
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
    /// headless-first architecture cleanup — opc no longer
    /// contains a browser. The variant is hidden from
    /// `--help` but kept in the clap enum so that `--auth-mode
    /// webview` gives a migration hint at the CLI instead of
    /// clap's generic "invalid value" error. Selecting it at
    /// connect time bails with a clear message pointing at
    /// `--auth-mode paste` and `--auth-mode okta`.
    #[clap(hide = true)]
    Webview,
}

/// CLI surface for [`gp_route::RouteConflictPolicy`].
#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum RouteConflictArg {
    /// Take the prefix over for the session and restore the previous
    /// route on disconnect. The default.
    TakeOver,
    /// Refuse to connect, naming the interface that owns the prefix.
    Fail,
    /// Leave the existing route alone and route the prefix outside
    /// the tunnel.
    Skip,
}

impl From<RouteConflictArg> for gp_route::RouteConflictPolicy {
    fn from(arg: RouteConflictArg) -> Self {
        match arg {
            RouteConflictArg::TakeOver => gp_route::RouteConflictPolicy::TakeOver,
            RouteConflictArg::Fail => gp_route::RouteConflictPolicy::Fail,
            RouteConflictArg::Skip => gp_route::RouteConflictPolicy::Skip,
        }
    }
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
    /// `portal` accepts either a profile name (defined via `opc
    /// portal add`) or a bare URL. Omitting it uses the default
    /// profile set with `opc portal use <name>`. CLI flags always
    /// override the profile's settings; the profile fills in
    /// whatever the CLI didn't specify.
    Connect {
        /// Portal URL or saved profile name. Optional: uses
        /// `default.portal` from `~/.config/openprotect/config.toml`
        /// when omitted.
        portal: Option<String>,

        /// Username.
        #[arg(short, long, env = "PGN_USER")]
        user: Option<String>,

        /// Force a specific portal-advertised gateway by name or
        /// address. When set, openprotect skips the latency probe fan-out
        /// and connects to the matched gateway directly.
        #[arg(long, value_name = "NAME|ADDRESS")]
        gateway: Option<String>,

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
        /// token, and `opc connect --insecure vpn.example.com`
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
        /// modes are headless — openprotect has no embedded browser.
        #[arg(long, value_enum, env = "PGN_AUTH_MODE")]
        auth_mode: Option<SamlAuthMode>,

        /// Local port for paste-mode's callback server.
        ///
        /// Default `0` — the OS picks a free ephemeral port each run,
        /// so a previous opc instance with its port stuck in TIME_WAIT
        /// won't block a fresh connect. Pin a specific port (e.g. 29999)
        /// only if you need a stable URL for an SSH tunnel or bookmark.
        #[arg(long, env = "PGN_SAML_PORT")]
        saml_port: Option<u16>,

        /// Only route these targets through the VPN (split tunnel).
        /// Accepts a comma-separated mix of CIDRs (`10.0.0.0/8`), bare IPs
        /// (`1.2.3.4`), and hostnames (`moodle.example.com` — resolved
        /// through your local DNS *before* the tunnel comes up). When set,
        /// opc installs exactly these routes natively and leaves the
        /// default route alone.
        #[arg(long, value_name = "CIDR|IP|HOST", env = "PGN_ONLY")]
        only: Option<String>,

        /// What to do when a `--only` prefix is already routed by
        /// something else on this host — a Docker bridge, another
        /// VPN, a hypervisor host-only network.
        ///
        /// `take-over` (the default) hands the prefix to the tunnel
        /// for the session and puts the previous route back on
        /// disconnect, announcing both at WARN. `fail` refuses to
        /// connect and names what owns the prefix. `skip` installs
        /// every other route and leaves this prefix outside the
        /// tunnel.
        ///
        /// Restoring on disconnect is Linux-only: the macOS backend
        /// repoints the route but cannot put the original back, and
        /// Windows keys routes per-interface so conflicts do not
        /// arise there.
        #[arg(long, value_enum, env = "PGN_ROUTE_CONFLICT")]
        route_conflict: Option<RouteConflictArg>,

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
        /// routes but do NOT want openprotect to register any split
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
        /// openprotect ships with. When set, libopenconnect's
        /// csd-wrapper slot gets pointed at your script instead
        /// of the `opc hip-report` subcommand.
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
        /// When enabled, openprotect tells libopenconnect to spend
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

        /// Instance name for this session. Every running `opc
        /// connect` gets its own platform-default control socket
        /// (`/run/openprotect/<instance>.sock` on Linux,
        /// `/tmp/openprotect-<uid>/<instance>.sock` on macOS),
        /// so you can run multiple tunnels side by side
        /// (e.g. one for work, one for a client). Defaults to
        /// `default`. Must match `[A-Za-z0-9_-]{1,32}`.
        #[arg(long, short = 'i', env = "OPC_INSTANCE")]
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

        /// Path to a PEM-encoded client certificate for mutual TLS.
        /// Used for certificate-based portal/gateway authentication.
        /// Requires `--key` unless using `--pkcs12`.
        #[arg(long, value_name = "PATH", env = "PGN_CERT")]
        cert: Option<String>,

        /// Path to the PEM-encoded private key for `--cert`.
        #[arg(long, value_name = "PATH", env = "PGN_KEY")]
        key: Option<String>,

        /// Path to a PKCS#12 (.p12/.pfx) bundle. **Not currently
        /// supported** with the rustls TLS backend — openprotect will
        /// print an `openssl pkcs12` conversion command and exit.
        /// Use `--cert` + `--key` with PEM files instead.
        #[arg(long, value_name = "PATH", env = "PGN_PKCS12", conflicts_with_all = ["cert", "key"])]
        pkcs12: Option<String>,

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
        /// Access gateways. See `.opc-logs/run-os-linux.log` for
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
        #[arg(long, short = 'i', env = "OPC_INSTANCE")]
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
        #[arg(long, short = 'i', env = "OPC_INSTANCE")]
        instance: Option<String>,
        /// List every live instance even when only one is
        /// running. Forces list-format output.
        #[arg(long, conflicts_with = "instance")]
        all: bool,
    },

    /// Recover from a previous opc that died without cleaning up
    /// (crash, force-kill, or a Wintun/PnP kernel-mode wedge).
    ///
    /// On Windows this is the escape hatch for "network unavailable
    /// after a disconnect": a hard-killed session leaves its NRPT
    /// rule behind, and when that rule is the catch-all `.` it routes
    /// ALL DNS through the now-dead VPN resolver — breaking every name
    /// lookup until the next `opc connect` or a manual registry fix.
    /// `opc recover` deletes the leaked NRPT rule(s) and sweeps orphan
    /// Wintun adapters WITHOUT needing a reconnect, and works even
    /// while a wedged opc.exe still holds the control pipe (NRPT lives
    /// in the registry, not in the dead process).
    ///
    /// On Unix this is a near-no-op (utun/tun don't wedge and the DNS
    /// backends don't leak a machine-wide rule); it just clears any
    /// stale control socket.
    Recover {
        /// Only clean rules owned by this instance. Defaults to
        /// `default`. Safe to run while a sibling `opc -i other` is
        /// alive — its rules are never touched.
        #[arg(long, short = 'i', env = "OPC_INSTANCE")]
        instance: Option<String>,
        /// Clean EVERY openprotect-owned rule across all instances.
        /// Refuses if any opc session is still alive, so it can't
        /// tear down a healthy sibling. Use after a crash when the
        /// box is in DNS blackout. Mutually exclusive with
        /// `--instance`.
        #[arg(long, conflicts_with = "instance")]
        all: bool,
    },

    /// Report leaked NRPT DNS rules and orphan Wintun adapters
    /// (read-only — makes no changes). Run `opc recover` to clean
    /// whatever this reports.
    Doctor {
        /// Scope the NRPT-rule count to this instance. Omit to count
        /// every openprotect-owned rule across all instances.
        #[arg(long, short = 'i', env = "OPC_INSTANCE")]
        instance: Option<String>,
    },

    /// Manage saved portal profiles.
    Portal {
        #[command(subcommand)]
        action: PortalAction,
    },

    /// Run connectivity diagnostics against a portal.
    ///
    /// Checks DNS resolution, TCP reachability, TLS handshake, and
    /// portal prelogin response. Useful for debugging connection
    /// failures before opening a ticket.
    Diagnose {
        /// Portal URL or saved profile name.
        portal: String,
        /// Accept invalid TLS certificates for the diagnostic.
        #[arg(long)]
        insecure: bool,
    },

    /// Generate shell completions for bash, zsh, or fish.
    ///
    /// Prints the completion script to stdout. Example:
    ///
    ///     opc completions bash > ~/.local/share/bash-completion/completions/opc
    ///     opc completions zsh > ~/.zfunc/_pgn
    ///     opc completions fish > ~/.config/fish/completions/opc.fish
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// INTERNAL: HIP report generator invoked by libopenconnect as a
    /// csd-wrapper child process.
    ///
    /// libopenconnect calls `openconnect_setup_csd` to register this
    /// binary as the HIP wrapper, then `fork()` + `execv()`s it with
    /// the argv contract from upstream openconnect `gpst.c:1012-1027`:
    ///
    /// ```text
    /// opc hip-report --cookie <urlenc> [--client-ip <v4>]
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
    /// `opc hip-report` directly; it's invoked only by libopenconnect.
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
        /// Short name for the profile (used with `opc connect <name>`).
        name: String,
        /// Portal URL (hostname or full https://…).
        #[arg(long)]
        url: String,
        /// Default username for this profile.
        #[arg(long)]
        user: Option<String>,
        /// Preferred gateway name or address. When set, `opc connect`
        /// skips latency probing and connects directly to this
        /// gateway. The value is matched against the portal's
        /// gateway list by name (case-insensitive) or address.
        #[arg(long, value_name = "NAME|ADDRESS")]
        gateway: Option<String>,
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
        /// `opc connect --dns-zone` for the full semantics —
        /// setting this replaces the `--only`-derived zones.
        #[arg(long, value_name = "ZONE[,ZONE...]")]
        dns_zone: Option<String>,
        /// HIP reporting mode.
        #[arg(long, value_enum)]
        hip: Option<HipMode>,
        /// Path to an external HIP wrapper script saved with
        /// this profile. See the `opc connect --hip-script`
        /// help text for the argv contract.
        #[arg(long, value_name = "PATH")]
        hip_script: Option<String>,
        /// vpnc-compatible script path.
        #[arg(long)]
        vpnc_script: Option<String>,
        /// Accept invalid TLS certificates.
        #[arg(long)]
        insecure: bool,
        /// Tell opc to keep the tunnel alive across brief
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
        /// PEM client certificate path for mutual TLS.
        #[arg(long, value_name = "PATH")]
        cert: Option<String>,
        /// PEM private key path (required with --cert).
        #[arg(long, value_name = "PATH")]
        key: Option<String>,
        /// PKCS#12 bundle path (not supported with rustls — stored
        /// for forward-compatibility).
        #[arg(long, value_name = "PATH", conflicts_with_all = ["cert", "key"])]
        pkcs12: Option<String>,
        /// Enable ESP/UDP transport. Defaults to on at `opc
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
    /// Set the default profile used by `opc connect` with no args.
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

/// Exit codes for structured error reporting. Scripts and systemd
/// can branch on these instead of parsing stderr text.
mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL: i32 = 1;
    pub const AUTH_FAILED: i32 = 2;
    pub const GATEWAY_UNREACHABLE: i32 = 3;
    pub const HIP_REJECTED: i32 = 4;
    pub const TLS_ERROR: i32 = 5;
    pub const CONFIG_ERROR: i32 = 6;
}

/// Classify an exit code from the error chain using typed downcast
/// first, then narrowly-scoped string matching as a fallback. The
/// typed checks are exact and cannot false-positive; the string
/// fallbacks only fire when no typed match was found and use
/// specific multi-word phrases to avoid broad substring collisions
/// (e.g. "auth" alone would match "proxy-auth" or path names).
fn classify_exit_code(err: &anyhow::Error) -> i32 {
    // --- Typed checks (precise, no false positives) ---

    for cause in err.chain() {
        if let Some(t) = cause.downcast_ref::<gp_tunnel::TunnelError>() {
            return match t {
                gp_tunnel::TunnelError::MainloopAuthExpired => exit_code::AUTH_FAILED,
                gp_tunnel::TunnelError::MainloopTerminated => exit_code::GENERAL,
                _ => exit_code::GENERAL,
            };
        }
        if cause.downcast_ref::<gp_config::ConfigError>().is_some() {
            return exit_code::CONFIG_ERROR;
        }
        if let Some(e) = cause.downcast_ref::<gp_auth::AuthError>() {
            return match e {
                gp_auth::AuthError::Http(_) => exit_code::GATEWAY_UNREACHABLE,
                // Issue #36: a 5xx portal/gateway reject with no
                // X-Private-Pan-Sslvpn auth-failed signal is transient
                // server trouble, not broken credentials — it must keep
                // the exit-3 contract the legacy `.error_for_status()`
                // path had via AuthError::Http, so retry/backoff
                // automation does not alert on a "credential problem"
                // during a maintenance window.
                gp_auth::AuthError::Server(_) => exit_code::GATEWAY_UNREACHABLE,
                gp_auth::AuthError::Proto(_) => exit_code::GENERAL,
                _ => exit_code::AUTH_FAILED,
            };
        }
        // reqwest::Error is already caught by AuthError::Http above.
        // No need for a separate reqwest downcast — opc doesn't
        // directly depend on reqwest.
    }

    // --- Narrow string fallbacks for errors without typed context ---

    let msg = format!("{err:#}").to_lowercase();

    if msg.contains("saml authentication")
        || msg.contains("okta headless authentication")
        || msg.contains("password authentication")
        || msg.contains("mfa failed")
        || msg.contains("authcookie expired")
        || msg.contains("re-authentication failed")
    {
        return exit_code::AUTH_FAILED;
    }

    if msg.contains("hip report") || msg.contains("hip-report") || msg.contains("hip rejected") {
        return exit_code::HIP_REJECTED;
    }

    if msg.contains("tls error")
        || msg.contains("certificate verify failed")
        || msg.contains("rustls")
    {
        return exit_code::TLS_ERROR;
    }

    if msg.contains("loading config")
        || msg.contains("no portal given")
        || msg.contains("no such profile")
    {
        return exit_code::CONFIG_ERROR;
    }

    exit_code::GENERAL
}

// ---------------------------------------------------------------------------
// Connect-phase observability: opt-in rolling file sink, INFO phase
// stamps, and a report-only per-phase wall-budget watchdog.
//
// Motivation ("opc connect often hangs", Windows `--esp=false
// --only`): the hang reports were undiagnosable because every
// blocking step that can stall (NRPT sweep, adapter enumeration,
// gateway DNS resolution, prelogin/portal_config/gateway_login, the
// SAML paste wait, make_cstp, setup_tun, route/DNS apply, HIP
// submit) either logged nothing or logged only a one-sided hello.
// Now each is bracketed at default INFO with an attempt ID +
// monotonic elapsed, and an INDEPENDENTly-ticked watchdog reports
// (WARN only, never force-exits) any phase still in progress past a
// generous budget — including the windows the adversarial audit
// proved unwatched: the auth phase before the IPC server exists,
// the pre-handle wait, the HIP await whose enclosing select only
// resumes afterwards, and the setup select.
// ---------------------------------------------------------------------------

/// Process-monotonic clock origin for `t+…ms` phase stamps. Lazily
/// pinned on first use so tests that don't arm it never pay for it,
/// and every stamp in a run shares one origin (survives NTP jumps
/// that wall-clock timestamps would not).
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

fn process_elapsed() -> Duration {
    PROCESS_START.get_or_init(Instant::now).elapsed()
}

/// How long a phase may run before the watchdog reports it.
/// Deliberately generous — this is a REPORTING bound, not a new
/// hard exit. The whole posture of this fix pass is diagnosis-
/// independence: we refuse to kill operations the audit couldn't
/// bound, but we refuse to stay silent about them too.
const DEFAULT_PHASE_BUDGET: Duration = Duration::from_secs(120);

/// Env override for the watchdog budget, whole seconds
/// (`OPC_PHASE_BUDGET_SECS=45 opc connect …`). Garbage, empty, or
/// below one second falls back to the default rather than
/// disabling the watchdog — "watchdog silently off via typo" is
/// exactly the failure mode being removed.
fn parse_phase_budget(raw: Option<&str>) -> Duration {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .filter(|d| *d >= Duration::from_secs(1))
        .unwrap_or(DEFAULT_PHASE_BUDGET)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PhaseKind {
    /// Machine-bound step: WARN once past the budget.
    Auto,
    /// Human-bound step (the SAML paste wait). Budget-EXEMPT from
    /// WARN: the user is in the loop and the real bound is the
    /// gateway's `<saml-request-timeout>` (auth agent's area —
    /// gp-proto currently parses it at prelogin.rs:29-35 and
    /// discards it). A WARN screaming while someone is mid-SSO
    /// only trains users to ignore WARNs.
    HumanBound,
}

#[derive(Clone, Debug)]
struct PhaseEntry {
    name: String,
    kind: PhaseKind,
    entered: Instant,
}

/// Shared watchdog state. `std::sync::Mutex` held only long enough
/// to copy a small struct in or out — never across an `await`, and
/// writers include the DEDICATED opc-tunnel thread (no tokio
/// context there), so the lock must be runtime-independent.
#[derive(Default)]
struct WatchdogState {
    current: Mutex<Option<PhaseEntry>>,
}

impl WatchdogState {
    fn set(&self, name: &str, kind: PhaseKind) {
        if let Ok(mut cur) = self.current.lock() {
            *cur = Some(PhaseEntry {
                name: name.to_string(),
                kind,
                entered: Instant::now(),
            });
        }
    }
    fn clear(&self) {
        if let Ok(mut cur) = self.current.lock() {
            *cur = None;
        }
    }
    fn snapshot(&self) -> Option<PhaseEntry> {
        self.current.lock().ok().and_then(|c| c.clone())
    }
}

/// A watchdog report: "phase X in progress for Ys". The watchdog's
/// ENTIRE contract — it reports and nothing else. No cancel, no
/// exit, no retries.
#[derive(Debug, PartialEq, Eq)]
struct PhaseWarn {
    phase: String,
    elapsed: Duration,
}

/// Pure tick decision the spawned task delegates to (unit-tested
/// directly; no log capture seam needed — the formatting at the
/// call site is a one-liner). One-shot latch per phase name: past
/// budget report exactly once, don't re-report until the phase
/// changes, and clear the latch when returning to no-phase.
#[derive(Default)]
struct WatchdogLatch {
    warned: Option<String>,
}

impl WatchdogLatch {
    fn tick(
        &mut self,
        now: Instant,
        phase: Option<&PhaseEntry>,
        budget: Duration,
    ) -> Option<PhaseWarn> {
        let Some(p) = phase else {
            self.warned = None;
            return None;
        };
        if p.kind == PhaseKind::HumanBound {
            // EXEMPT: the human is the slow part. (Start/finish
            // stamps still bracket the wait; the auth agent owns
            // the actual timeout bound.)
            return None;
        }
        if self.warned.as_deref() == Some(p.name.as_str()) {
            return None;
        }
        let elapsed = now.saturating_duration_since(p.entered);
        if elapsed > budget {
            self.warned = Some(p.name.clone());
            Some(PhaseWarn {
                phase: p.name.clone(),
                elapsed,
            })
        } else {
            None
        }
    }
}

static PHASE_WATCHDOG: OnceLock<Arc<WatchdogState>> = OnceLock::new();

/// Arm (idempotently) and return the shared watchdog state. Called
/// by `connect()`; the spawned ticker task lives as long as the
/// runtime does, which is the process.
fn watchdog_state() -> Arc<WatchdogState> {
    Arc::clone(PHASE_WATCHDOG.get_or_init(|| Arc::new(WatchdogState::default())))
}

/// Post the currently-entered phase for the watchdog. No-op when
/// the watchdog was never armed (doctor/recover/status runs): a
/// non-connect command must not mint global state behind a flag
/// nobody asked for.
fn note_phase(name: &str, kind: PhaseKind) {
    if let Some(st) = PHASE_WATCHDOG.get() {
        st.set(name, kind);
    }
}

fn note_phase_clear() {
    if let Some(st) = PHASE_WATCHDOG.get() {
        st.clear();
    }
}

/// Spawn the ticker. Independent task on the main runtime: the
/// audit showed the blocking awaits can swallow everything that
/// runs *inside* the blocked select (Ctrl-C included), so the only
/// observer that cannot be starved is one that never touches the
/// blocked await. It reads ONLY the shared `WatchdogState` — no
/// channels (assignment: keep a SINGLE readiness receiver; the
/// ready_rx is touched exclusively by the setup select below and
/// is never re-created or abandoned per tick).
fn spawn_phase_watchdog(
    state: Arc<WatchdogState>,
    budget: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let tick = Duration::from_millis((budget.as_millis() / 4).clamp(250, 5_000) as u64);
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut latch = WatchdogLatch::default();
        loop {
            interval.tick().await;
            let phase = state.snapshot();
            if let Some(warn) = latch.tick(Instant::now(), phase.as_ref(), budget) {
                tracing::warn!(
                    "phase {} in progress for {}s (budget {}s) — report \
                     only, opc will not force-exit; cross-reference the \
                     phase START stamps around this line",
                    warn.phase,
                    warn.elapsed.as_secs(),
                    budget.as_secs()
                );
            }
        }
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PhaseEvent {
    Start,
    Finish,
}

/// Pure stamp renderer — takes the clock as an argument so tests
/// can pin `t+…ms` exactly. Format is grep-friendly for the bug
/// reports this whole pass exists to make possible:
/// `phase=make_cstp START attempt=2 t+4123ms`.
fn phase_line(
    ev: PhaseEvent,
    attempt: Option<u32>,
    name: &str,
    t: Duration,
    extra: Option<&str>,
) -> String {
    // `attempt=None` renders `attempt=pre` for connect-level
    // phases that run before any tunnel attempt exists (auth,
    // sweeps, IPC bind); per-attempt stamps inside
    // `run_tunnel_attempt` pass `Some(attempt_num)`.
    let head = format!(
        "phase={name} {} attempt={} t+{}ms",
        match ev {
            PhaseEvent::Start => "START",
            PhaseEvent::Finish => "FINISH",
        },
        match attempt {
            Some(a) => a.to_string(),
            None => "pre".to_string(),
        },
        t.as_millis(),
    );
    match extra {
        Some(x) => format!("{head} {x}"),
        None => head,
    }
}

/// Emit an INFO START stamp for `name` and return the entry instant
/// for the matching [`phase_finish`].
fn phase_start(attempt: Option<u32>, name: &str) -> Instant {
    tracing::info!(
        "{}",
        phase_line(PhaseEvent::Start, attempt, name, process_elapsed(), None)
    );
    Instant::now()
}

/// START stamp with a trailing fact (e.g. counts, target names).
fn phase_start_with(attempt: Option<u32>, name: &str, extra: &str) -> Instant {
    tracing::info!(
        "{}",
        phase_line(
            PhaseEvent::Start,
            attempt,
            name,
            process_elapsed(),
            Some(extra)
        )
    );
    Instant::now()
}

fn phase_finish(attempt: Option<u32>, name: &str, since: Instant) {
    let extra = format!("dur={}ms", since.elapsed().as_millis());
    tracing::info!(
        "{}",
        phase_line(
            PhaseEvent::Finish,
            attempt,
            name,
            process_elapsed(),
            Some(&extra)
        )
    );
}

/// Guards for the non-blocking tracing-appender workers, stashed so
/// the wedge-exit path can flush them before `process::exit` skips
/// destructors. Empty when the file sink is off (the default).
static TRACING_WORKER_GUARDS: OnceLock<Mutex<Vec<tracing_appender::non_blocking::WorkerGuard>>> =
    OnceLock::new();

/// Move `work` onto a dedicated thread and wait at most `budget`
/// for it, returning `true` iff it finished. Used by the emergency
/// flush: the guard's Drop joins the tracing worker (which drains
/// its queue), but we must NOT assume that join terminates — a
/// wedged disk turns the wedge-escape hatch into the next hang.
fn run_bounded<F>(work: F, budget: Duration) -> bool
where
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    match std::thread::Builder::new()
        .name("opc-emergency-flush".into())
        .spawn(move || {
            work();
            let _ = tx.send(());
        }) {
        Ok(_) => rx.recv_timeout(budget).is_ok(),
        Err(_) => false,
    }
}

/// Flush any queued tracing lines to the file sink within a hard
/// budget, then (optionally) return. Safe to call before
/// `process::exit`: it drops the worker guards on a throwaway
/// thread and abandons that thread if it doesn't finish.
fn flush_tracing_bounded(budget: Duration) -> bool {
    let Some(cell) = TRACING_WORKER_GUARDS.get() else {
        return true; // no file sink armed: console layer wrote synchronously
    };
    let guards = match cell.lock() {
        Ok(mut g) => std::mem::take(&mut *g),
        Err(_) => Vec::new(),
    };
    if guards.is_empty() {
        return true;
    }
    run_bounded(move || drop(guards), budget)
}

/// Install the global tracing subscriber: the console layer (stderr
/// — see the coherence note in `run`) plus, only when
/// `--log-file <path>` is given, a rolling hourly file sink.
///
/// Never fatal: a bad path warns on stderr and degrades to
/// console-only. Observability that can break `connect` is not
/// observability.
fn init_tracing(log_spec: &str, log_file: Option<&str>) {
    let console_only = |spec: &str| {
        let (sub, _guards): (Box<dyn tracing::Subscriber + Send + Sync>, Vec<_>) =
            build_tracing_subscriber(spec, std::io::stderr, None)
                .expect("console-only subscriber build cannot fail");
        sub
    };
    let subscriber = match log_file {
        Some(path) => {
            let file = PathBuf::from(path);
            match build_tracing_subscriber(log_spec, std::io::stderr, Some(&file)) {
                Ok((sub, guards)) => {
                    let _ = TRACING_WORKER_GUARDS.set(Mutex::new(guards));
                    sub
                }
                Err(e) => {
                    eprintln!(
                        "opc: --log-file {} unavailable ({e}); continuing with console logs only",
                        file.display()
                    );
                    console_only(log_spec)
                }
            }
        }
        None => console_only(log_spec),
    };
    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("opc: tracing subscriber install failed: {e}");
    }
}

/// Build the layered subscriber. Split from `init_tracing` (which
/// installs the global default) so the sink construction is unit-
/// testable: tests pass a capture writer as `console`, emit one
/// event through `tracing::subscriber::with_default`, and assert
/// which sinks saw it — proving both the dual-sink wiring and the
/// DEFAULT-OFF property (no file materialises without `file_sink`).
///
/// One shared `EnvFilter` fronts both layers, exactly matching
/// the pre-existing single-layer semantics (RUST_LOG overrides
/// `--log`).
fn build_tracing_subscriber<W>(
    log_spec: &str,
    console: W,
    file_sink: Option<&std::path::Path>,
) -> Result<(
    Box<dyn tracing::Subscriber + Send + Sync>,
    Vec<tracing_appender::non_blocking::WorkerGuard>,
)>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_spec));

    let console_layer = tracing_subscriber::fmt::layer().with_writer(console);

    let mut guards = Vec::new();
    let file_layer = match file_sink {
        Some(path) => {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating log dir {}", dir.display()))?;
            let prefix = path
                .file_name()
                .context("--log-file path has no file name")?
                .to_string_lossy()
                .into_owned();
            let appender = tracing_appender::rolling::hourly(&dir, prefix);
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            guards.push(guard);
            Some(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(move || non_blocking.clone()),
            )
        }
        None => None,
    };

    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(filter)
        .with(console_layer)
        .with(file_layer);
    let boxed: Box<dyn tracing::Subscriber + Send + Sync> = Box::new(subscriber);
    Ok((boxed, guards))
}

/// Whether `run()` must bring up the tracing subscriber for this
/// invocation. Pure so the HIP-wrapper stdout-isolation invariant is
/// unit-assertable at the DECISION, not just at the clap surface.
///
/// The csd-wrapper path (`gpst.c::run_hip_script` → `execv` of this
/// binary with `hip-report …`) dup2's stdout onto libopenconnect's XML
/// pipe; a tracing layer — console OR the opt-in rolling file sink —
/// started there would leak a handle per fork and corrupt the pristine
/// XML body. So we skip init entirely for `hip-report` (every other
/// subcommand, and the bare no-subcommand form, initialises normally).
fn tracing_init_needed(command: &Option<Commands>) -> bool {
    !matches!(command, Some(Commands::HipReport { .. }))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::from(exit_code::SUCCESS as u8),
        Err(e) => {
            let code = classify_exit_code(&e);
            eprintln!("error: {e:#}");
            std::process::ExitCode::from(code as u8)
        }
    }
}

async fn run() -> Result<()> {
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
    // and `opc hip-report --cookie …` still works for manual
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
    // corrupts the XML and the gateway rejects the submission — so
    // we skip init entirely when we're in the hip-report path,
    // including the opt-in --log-file sink (one tracing-appender
    // file handle per csd fork would be a fresh leak every HIP
    // cycle). gp-hip / serde_urlencoded / anyhow are silent on
    // happy paths, and the wrapper exits before anything
    // interesting could happen.
    //
    // Writer coherence (the :781-vs-788 review nit): the old
    // comment told hand-debuggers to "redirect stderr" while the
    // fmt default writer is actually STDOUT — the two spellings
    // disagreed, and stdout is also the one stream that must stay
    // parseable (`opc status --json` println!, hip_report's XML
    // body). `init_tracing` now pins the console layer to stderr
    // explicitly, matching every eprintln! site in this binary
    // (gateway table, saml instruction box), and leaving stdout for
    // data only. For manual `opc hip-report …` invocations we still
    // skip tracing init. Codex round-26 caught this silent
    // corruption before it bit us live.
    if tracing_init_needed(&cli.command) {
        init_tracing(&cli.log, cli.log_file.as_deref());
    }

    match cli.command {
        Some(Commands::Connect {
            portal,
            user,
            gateway,
            passwd_on_stdin,
            os,
            insecure,
            vpnc_script,
            auth_mode,
            saml_port,
            only,
            route_conflict,
            dns_zone,
            cert,
            key,
            pkcs12,
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
                gateway,
                passwd_on_stdin,
                os,
                insecure,
                vpnc_script,
                auth_mode,
                saml_port,
                only,
                route_conflict,
                dns_zone,
                cert,
                key,
                pkcs12,
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
        Some(Commands::Recover { instance, all }) => recover(cli.json, instance, all).await,
        Some(Commands::Doctor { instance }) => doctor(cli.json, instance).await,
        None => status(cli.json, None, false).await,
        Some(Commands::Portal { action }) => portal_command(action).await,
        Some(Commands::Diagnose { portal, insecure }) => diagnose(portal, insecure).await,
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "opc", &mut std::io::stdout());
            Ok(())
        }
        Some(Commands::HipReport {
            cookie,
            client_ip,
            client_ipv6: _,
            md5,
            client_os,
        }) => hip_report(cookie, client_ip, md5, client_os).await,
    }
}

/// `opc hip-report` subcommand: csd-wrapper entry point for
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
        .unwrap_or_else(|| "openprotect".to_string());

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

/// Dispatch for `opc portal <action>`. All actions mutate (or
/// read) `~/.config/openprotect/config.toml` via the `gp-config`
/// crate's atomic save.
async fn portal_command(action: PortalAction) -> Result<()> {
    let path = gp_config::OpenProtectConfig::default_path();
    let mut config = gp_config::OpenProtectConfig::load_from(&path)
        .with_context(|| format!("loading {}", path.display()))?;

    match action {
        PortalAction::Add {
            name,
            url,
            user,
            gateway,
            os,
            auth_mode,
            only,
            dns_zone,
            cert,
            key,
            pkcs12,
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
            // saves fail fast instead of blowing up at `opc
            // connect` time.
            if let Some(spec) = metrics_port.as_deref() {
                parse_metrics_bind(spec)?;
            }
            // Same fail-fast rule for the explicit split-DNS zone
            // list: if the user typed a garbage zone, surface the
            // error at save time from the `opc portal add`
            // invocation they just made, not hours later at
            // `opc connect` time from a profile they may no
            // longer remember editing.
            if let Some(spec) = dns_zone.as_deref() {
                parse_dns_zone_spec(spec).context("validating --dns-zone")?;
            }
            // Canonicalise the HIP wrapper path now so the saved
            // profile holds an absolute path. Relative-path
            // `hip_script` values would otherwise be re-resolved
            // against whatever CWD `opc connect` is invoked from
            // later, which is almost never the shell the user
            // ran `opc portal add` from — systemd units run
            // with `WorkingDirectory=/`, for example. Doing it
            // here also catches bad inputs at save time instead
            // of at tunnel-setup time.
            let hip_script = hip_script
                .as_deref()
                .map(resolve_hip_script_path)
                .transpose()?;
            // Validate cert/key consistency and canonicalise paths.
            if cert.is_some() && key.is_none() {
                anyhow::bail!("--cert requires --key");
            }
            if key.is_some() && cert.is_none() {
                anyhow::bail!("--key requires --cert");
            }
            let client_cert = cert
                .map(|p| {
                    std::fs::canonicalize(&p)
                        .with_context(|| format!("--cert path {p:?}"))
                        .map(|c| c.to_string_lossy().into_owned())
                })
                .transpose()?;
            let client_key = key
                .map(|p| {
                    std::fs::canonicalize(&p)
                        .with_context(|| format!("--key path {p:?}"))
                        .map(|c| c.to_string_lossy().into_owned())
                })
                .transpose()?;
            let client_pkcs12 = pkcs12
                .map(|p| {
                    std::fs::canonicalize(&p)
                        .with_context(|| format!("--pkcs12 path {p:?}"))
                        .map(|c| c.to_string_lossy().into_owned())
                })
                .transpose()?;
            let profile = gp_config::PortalProfile {
                url,
                username: user,
                gateway,
                os,
                auth_mode: match auth_mode {
                    None => None,
                    Some(SamlAuthMode::Paste) => Some("paste".to_string()),
                    Some(SamlAuthMode::Okta) => Some("okta".to_string()),
                    Some(SamlAuthMode::Webview) => {
                        anyhow::bail!(
                            "`--auth-mode webview` is no longer supported — \
                             openprotect retired the embedded GTK+WebKit window \
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
                client_cert,
                client_key,
                client_pkcs12,
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
                println!("(no saved profiles — use `opc portal add <name> --url …` to create one)");
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
            if profile.username.is_some() {
                println!("user:       (configured)");
            }
            if let Some(g) = &profile.gateway {
                println!("gateway:    {g}");
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
            if let Some(c) = &profile.client_cert {
                println!("cert:       {}", mask_path(c));
            }
            if let Some(k) = &profile.client_key {
                println!("key:        {}", mask_path(k));
            }
            if let Some(p) = &profile.client_pkcs12 {
                println!("pkcs12:     {}", mask_path(p));
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

/// `opc diagnose` — run step-by-step connectivity checks against a
/// portal and print results. Each step prints a pass/fail line so
/// the user (or support) can pinpoint which layer is broken.
async fn diagnose(portal_arg: String, insecure: bool) -> Result<()> {
    let config = gp_config::OpenProtectConfig::load().context("loading config")?;
    let portal_url = match config.find_portal(&portal_arg) {
        Some(p) => p.url.clone(),
        None => portal_arg.clone(),
    };
    let host = gp_proto::params::normalize_server(&portal_url);
    // Issue #43 (same class as the probe site): the portal URL may
    // carry a port; DNS/TCP checks must resolve + connect the bare
    // host at the ADVERTISED port, not hand `host:port` to the
    // resolver as a node with a hardcoded 443. The prelogin request
    // below keeps the full `host:port` authority (URL lane, #42).
    let (host_only, host_port) = {
        let (h, spec) = gp_proto::params::split_host_port(host);
        (h.to_string(), spec.port().unwrap_or(443))
    };

    eprintln!("diagnosing portal: {host}\n");

    // 1. DNS resolution
    eprint!("  DNS resolution ... ");
    match tokio::net::lookup_host((host_only.as_str(), host_port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            eprintln!(
                "OK ({} address(es): {})",
                addrs.len(),
                addrs
                    .iter()
                    .map(|a| a.ip().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Err(e) => {
            eprintln!("FAIL ({e})");
            anyhow::bail!("DNS resolution failed for {host}: {e}");
        }
    }

    // 2. TCP connectivity
    eprint!("  TCP :{host_port} ... ");
    let tcp_start = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host_only.as_str(), host_port)),
    )
    .await
    {
        Ok(Ok(_)) => eprintln!("OK ({}ms)", tcp_start.elapsed().as_millis()),
        Ok(Err(e)) => {
            eprintln!("FAIL ({e})");
            anyhow::bail!("TCP connection to {host_only}:{host_port} failed: {e}");
        }
        Err(_) => {
            eprintln!("FAIL (timeout after 5s)");
            anyhow::bail!("TCP connection to {host_only}:{host_port} timed out");
        }
    }

    // 3. TLS + prelogin (combined: the prelogin request itself
    //    exercises TLS, so a separate handshake-only step would be
    //    redundant. If TLS fails, the prelogin error message says so.)
    let client_os = ClientOs::default();
    let mut gp_params = GpParams::new(client_os);
    gp_params.ignore_tls_errors = insecure;
    let client = GpClient::new(gp_params.clone()).context("creating HTTP client")?;

    // 4. Portal prelogin (implicitly validates TLS)
    eprint!("  TLS + prelogin ... ");
    match client.prelogin(host).await {
        Ok(prelogin) => {
            eprintln!(
                "OK (region={}, auth={})",
                prelogin.region(),
                if prelogin.is_saml() {
                    "SAML"
                } else {
                    "password"
                }
            );
        }
        Err(e) => {
            eprintln!("FAIL ({e})");
            anyhow::bail!("portal prelogin failed: {e}");
        }
    }

    eprintln!("\nall checks passed");
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

/// Resolve the gateway's public IPv4 for the route-exclude pin (and
/// the Windows HIP pre-NRPT pin) — see [`resolve_gateway_for_exclude_with`].
fn resolve_gateway_for_exclude(gateway_host: &str) -> Option<Ipv4Addr> {
    resolve_gateway_for_exclude_with(gateway_host, &mut |host, port| {
        (host, port).to_socket_addrs().map(|addrs| addrs.collect())
    })
}

/// Issue #43 seam S3: resolution half of the gateway-exclude pin,
/// with the DNS resolver injected so the host:port contract is
/// unit-testable without ever touching the system resolver
/// (`resolve` receives the BARE host and the service port to use —
/// never a colon-bearing node string).
///
/// The portal can advertise a gateway entry as `host:port`
/// (`203.0.113.7:11443`). Feeding that whole string to
/// `getaddrinfo` fails with `WSAHOST_NOT_FOUND` (os error 11001 —
/// issue #43's `gp-route: gateway exclude skipped` WARN), which in
/// turn left `gateway_ip_pin = None` and silently degraded the
/// Windows HIP resolve_override. The advertised port must also be
/// honoured as the resolver *service*, not hardcoded 443.
fn resolve_gateway_for_exclude_with(
    gateway_host: &str,
    resolve: &mut dyn FnMut(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Option<Ipv4Addr> {
    // Issue #43: split the advertised port FIRST. Every consumer
    // below — the numeric fast path, the resolver NODE, and the
    // resolver SERVICE — must see a bare host; passing the whole
    // colon-bearing string to getaddrinfo is what produced the
    // reporter's WSAHOST_NOT_FOUND (11001) WARN and the None pin
    // that then silently degraded the Windows HIP resolve_override.
    let (host, spec) = gp_proto::params::split_host_port(gateway_host);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    // gp-route's gateway_exclude is IPv4-only
    // (gp_route::TunConfig::gateway_exclude: Option<Ipv4Addr>): a
    // v6 gateway is a KNOWN "no IPv4 to exclude" case — classify at
    // debug, never via the resolver-failure WARN (guaranteed noise
    // today, since `[addr]` / bare-v6 nodes cannot resolve).
    let bracketed_v6 = host.starts_with('[') && host.ends_with(']');
    if bracketed_v6 || host.parse::<std::net::Ipv6Addr>().is_ok() {
        tracing::debug!(
            "gp-route: gateway exclude skipped for {gateway_host:?}: IPv6-only gateway, no IPv4 to exclude"
        );
        return None;
    }
    if let gp_proto::params::PortSpec::OutOfRange(port) = spec {
        // Fail loudly, like the tunnel lane: an advertised-but-
        // unusable port must not quietly become a 443 probe whose
        // result would mispin the exclude/HIP routes.
        tracing::warn!(
            "gp-route: gateway exclude skipped for {gateway_host:?}: advertised port {port:?} is not a valid service port"
        );
        return None;
    }
    // Honour the advertised port as the resolver *service* — the
    // pre-#43 code hardcoded 443 there too.
    let port = spec.port().unwrap_or(443);

    // Blocking getaddrinfo. Called from THREE sites — the pre-loop
    // pin in connect(), the re-auth refresh, and the native-route
    // branch inside the tunnel thread — all flow through here, so
    // the stamp lives on the resolution itself rather than being
    // duplicated at the call sites. A wedged resolver (NRPT/DNS
    // client interference right after a crash leaves a catch-all
    // `.` rule behind) stalled here with no log at all before #40.
    note_phase("gateway_dns_resolve", PhaseKind::Auto);
    let dns_t0 = phase_start_with(None, "gateway_dns_resolve", &format!("host={gateway_host}"));
    match resolve(host, port) {
        Ok(mut addrs) => {
            let resolved = addrs.drain(..).find_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            });
            if resolved.is_none() {
                tracing::warn!(
                    "gp-route: gateway exclude skipped for {gateway_host:?}: resolver returned no IPv4 addresses"
                );
            }
            phase_finish(None, "gateway_dns_resolve", dns_t0);
            resolved
        }
        Err(err) => {
            tracing::warn!(
                "gp-route: gateway exclude skipped for {gateway_host:?}: failed to resolve IPv4 address: {err}"
            );
            phase_finish(None, "gateway_dns_resolve", dns_t0);
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
/// helper, `systemctl stop openprotect@work` would drop to SIGKILL
/// after the stop timeout because there was no `SIGTERM` arm in
/// the steady-state select block, and the tunnel would die
/// ungracefully (routes/DNS state possibly leaked to the next
/// session via systemd-resolved cache or `ip route` residue).
#[cfg(unix)]
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

#[cfg(not(unix))]
async fn shutdown_signal() -> &'static str {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
    "Ctrl-C"
}

#[cfg(unix)]
fn resolve_csd_wrapper_uid() -> u32 {
    resolve_csd_wrapper_uid_impl(std::env::var("SUDO_UID").ok().as_deref(), unsafe {
        libc::geteuid() as u32
    })
}

#[cfg(not(unix))]
fn resolve_csd_wrapper_uid() -> u32 {
    // Windows/libopenconnect ignores the uid argument because HIP
    // script execution is unsupported there; keep the callsite
    // cross-platform without inventing Unix privilege semantics.
    0
}

#[cfg(unix)]
fn resolve_csd_wrapper_uid_impl(sudo_uid: Option<&str>, current_euid: u32) -> u32 {
    sudo_uid
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(current_euid)
}

#[cfg(target_os = "macos")]
fn ensure_macos_connect_privileges() -> Result<()> {
    ensure_macos_connect_privileges_impl(unsafe { libc::geteuid() as u32 })
}

#[cfg(target_os = "macos")]
fn ensure_macos_connect_privileges_impl(current_euid: u32) -> Result<()> {
    if current_euid == 0 {
        return Ok(());
    }
    anyhow::bail!(
        "macOS tunnel setup needs elevated privileges to create the utun device. \
         Re-run this command with `sudo`."
    )
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

/// Pretty-print one [`gp_ipc::StateSnapshot`] in the classic human-readable
/// format used by the single-instance `opc status`.
fn print_snapshot_human(s: &gp_ipc::StateSnapshot) {
    let mins = s.uptime_seconds / 60;
    let secs = s.uptime_seconds % 60;
    let state_str = match s.state {
        SessionState::Connected => "connected",
        SessionState::Connecting => "connecting",
        SessionState::Reconnecting => "reconnecting",
    };
    println!("version:   {OPC_VERSION}");
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
/// `opc status --all` within the request timeout, not 5 × that.
async fn collect_live_snapshots() -> Vec<gp_ipc::StateSnapshot> {
    let live = enumerate_live_instances().await;
    let mut set = tokio::task::JoinSet::new();
    for (_name, path) in live {
        let endpoint = path.to_string_lossy().to_string();
        set.spawn(async move {
            match client_roundtrip(&endpoint, &IpcRequest::Status).await {
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

/// `opc status` — query the running session(s) and pretty-print.
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
        let endpoint = endpoint_for(&raw);
        match client_roundtrip(&endpoint, &IpcRequest::Status).await {
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
                 try `sudo opc status -i {raw}`"
            ),
            // A live-but-fully-busy session: its control pipe exists and
            // every server instance is attached (a concurrent client, or
            // a stalled status server). Distinct from `NotRunning`
            // (disconnected) — the instance IS running, it just cannot
            // service us this instant. Named explicitly so it is never
            // laundered through the generic catch-all into a bare io
            // error (and never mistaken for absence).
            Err(IpcError::PipeBusy(_)) => anyhow::bail!(
                "instance {raw:?} is running but its control pipe is momentarily busy \
                 (all server instances attached) — the session is alive, just not \
                 serviceable this instant; retry shortly"
            ),
            Err(e) => Err(anyhow::anyhow!(e).context("querying opc status")),
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
                println!("(no running opc sessions)");
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

/// `opc disconnect` — ask a running session (or every running
/// session) to tear down.
async fn disconnect(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    // 1. Explicit --instance: classic single-target path.
    if let Some(raw) = instance {
        validate_instance_name(&raw)?;
        return disconnect_single(json, &raw).await;
    }

    // 2. --all: hit every live instance. Refuses silently if none.
    if all {
        let live = enumerate_live_instances().await;
        if live.is_empty() {
            if json {
                println!(r#"{{"result":"not-running"}}"#);
            } else {
                println!("no running opc sessions");
            }
            return Ok(());
        }
        let mut failures = Vec::new();
        for (name, path) in &live {
            let ep = path.to_string_lossy().to_string();
            match client_roundtrip(&ep, &IpcRequest::Disconnect).await {
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
    let live = enumerate_live_instances().await;
    match live.len() {
        0 => {
            if json {
                println!(r#"{{"result":"not-running"}}"#);
            } else {
                println!("no running opc session");
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
    let endpoint = endpoint_for(name);
    match client_roundtrip(&endpoint, &IpcRequest::Disconnect).await {
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
                println!("{name}: no running opc session");
            }
            Ok(())
        }
        Err(IpcError::PermissionDenied(_)) => anyhow::bail!(
            "control socket exists but you don't have permission to read it — \
             try `sudo opc disconnect -i {name}`"
        ),
        Err(e) => Err(anyhow::anyhow!(e).context("requesting opc disconnect")),
    }
}

/// Recover from a previous opc that died without cleaning up. See the
/// `Commands::Recover` doc comment for the full rationale. The heavy
/// lifting is the native NRPT sweep (registry delete + `DnsCache`
/// paramchange — milliseconds, no PowerShell, can't wedge) plus a
/// synchronous orphan-Wintun-adapter sweep, both Windows-only.
async fn recover(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    if let Some(ref raw) = instance {
        validate_instance_name(raw)?;
    }
    recover_platform(json, instance, all).await
}

/// `true` if the current process token is elevated (Administrator).
/// NRPT registry writes and `pnputil /remove-device` both require it;
/// `opc recover` pre-checks so it can give an actionable message
/// rather than a raw "Access is denied (os error 5)".
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(windows)]
async fn recover_platform(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    if !is_elevated() {
        anyhow::bail!(
            "opc recover modifies system DNS (NRPT) state and removes orphaned \
             network adapters — both require Administrator. Re-run this command \
             from an elevated terminal (right-click your terminal → \"Run as \
             administrator\"). `opc doctor` works without elevation if you just \
             want to see what's leaked."
        );
    }

    // Refuse to delete the NRPT rule of any LIVE session —
    // its rule is in use, not leaked, and removing it would break a
    // healthy tunnel's DNS. A wedged opc that holds its pipe but no
    // longer answers Status is still `Alive`/`Unknown` here (its control
    // pipe is in the namespace), so we treat it as possibly-alive and do
    // NOT blanket-sweep it away: only a control pipe that probes
    // `Liveness::Absent` (the owning process is genuinely gone) is
    // eligible. This guards BOTH the blanket `--all` sweep and the
    // default instance-scoped sweep against the false-absence class the
    // plan's ipc fix exists to close.
    let rows = gp_ipc::enumerate_live_instances_with_liveness().await;
    let still_maybe_alive = possibly_alive_instances(&rows);
    let nrpt_removed = if all {
        if !still_maybe_alive.is_empty() {
            anyhow::bail!(
                "refusing --all: {} opc session(s) could not be confirmed dead ({}); a \
                 busy/denied/wedged-but-listening control pipe is treated as possibly-alive \
                 and its NRPT rule is NOT swept. Disconnect them first (or resolve the wedged \
                 session), or target a provably-dead instance with `opc recover -i <name>`.",
                still_maybe_alive.len(),
                still_maybe_alive.join(", ")
            );
        }
        gp_dns::cleanup_all_windows_nrpt().context("blanket NRPT recovery")?
    } else {
        let name = resolve_instance_name(instance)?;
        let target_liveness = rows
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, _, l)| *l)
            .unwrap_or(gp_ipc::Liveness::Absent);
        if !matches!(target_liveness, gp_ipc::Liveness::Absent) {
            anyhow::bail!(
                "instance {name:?} is possibly-alive (liveness {target_liveness:?}) — its DNS \
                 rule may be in use, not leaked. Disconnect it first with `opc disconnect -i \
                 {name}` if you really want to tear it down.",
            );
        }
        gp_dns::cleanup_stale_windows_nrpt(&name).context("NRPT recovery")?
    };

    let adapters_removed = wintun_cleanup::sweep_orphans_blocking();

    if json {
        println!(
            r#"{{"result":"recovered","nrpt_rules_removed":{nrpt_removed},"orphan_adapters_removed":{adapters_removed}}}"#
        );
    } else if nrpt_removed == 0 && adapters_removed == 0 {
        println!("nothing to recover — no leaked NRPT rules or orphan adapters found");
    } else {
        println!(
            "recovered: removed {nrpt_removed} leaked NRPT rule(s) and \
             {adapters_removed} orphan Wintun adapter(s) — DNS restored"
        );
    }
    Ok(())
}

#[cfg(not(windows))]
async fn recover_platform(json: bool, instance: Option<String>, all: bool) -> Result<()> {
    // utun/tun don't wedge and the Unix DNS backends don't leak a
    // machine-wide rule; `connect` already self-heals a stale control
    // socket. Nothing to do — report so the user isn't left wondering.
    let _ = (instance, all);
    if json {
        println!(r#"{{"result":"noop","platform":"unix"}}"#);
    } else {
        println!("nothing to recover on this platform");
    }
    Ok(())
}

/// `opc doctor`'s leak verdict.
///
/// Used by the Windows doctor path and by tests on every platform;
/// silence dead-code on non-Windows non-test builds.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum DoctorVerdict {
    /// Nothing leaked.
    NoLeak,
    /// NRPT rules and/or orphan adapters with no live owner.
    Leaked,
    /// Can't tell: not elevated, so we can't open an elevated session's
    /// control pipe to confirm it's alive. A rule we'd otherwise call
    /// "leaked" may actually belong to a running (elevated) VPN session.
    Inconclusive,
    /// Can't tell for a DIFFERENT reason: a count or liveness probe
    /// failed (registry enumerate error, pipe busy/timeout, permission
    /// weirdness). We refuse to read a failed probe as "absent" — a
    /// busy pipe can be a live-but-wedged session whose rules would
    /// otherwise be counted as leaks right now. Report UNKNOWN and
    /// name the failed probes instead of guessing either direction.
    Unknown,
}

/// Result of one liveness probe against an instance's control pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LivenessProbe {
    /// Answered an IPC Status request.
    Responsive,
    /// No control pipe at all (ERROR_FILE_NOT_FOUND) — the instance
    /// is genuinely not running.
    Absent,
    /// Probe failed for a reason that does NOT prove absence:
    /// busy (ERROR_PIPE_BUSY → the dedicated `IpcError::PipeBusy`
    /// variant after the ipc owner's gp-ipc lib.rs:622 fix — formerly
    /// the false-absence `AlreadyRunning` mapping), timeout,
    /// permission-denied, protocol error. Must
    /// never be counted as "absent" in a leak decision.
    Unknown,
}

/// Classify an IPC probe result for the doctor scan. Pure so the
/// honesty rule ("failed/busy probes yield UNKNOWN, never absent")
/// is unit-testable without a real pipe (integration gap noted: the
/// genuine ERROR_PIPE_BUSY path is exercised by gp-ipc's own suite,
/// not from here — we pin the DECISION over every IpcError variant).
#[cfg_attr(not(windows), allow(dead_code))]
fn classify_liveness(result: &Result<IpcResponse, IpcError>) -> LivenessProbe {
    match result {
        Ok(_) => LivenessProbe::Responsive,
        // ONLY a provably-absent pipe is Absent.
        Err(IpcError::NotRunning(_)) => LivenessProbe::Absent,
        Err(_) => LivenessProbe::Unknown,
    }
}

/// What we learned about one candidate opc instance (union of names
/// seen in the live pipe namespace and the scoped --instance request).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorInstance {
    name: String,
    liveness: LivenessProbe,
    /// NRPT rule subkeys owned by the `openprotect-<name>-` prefix.
    /// None = the COUNT probe failed (UNKNOWN: not zero!).
    rules: Option<usize>,
}

/// Full observation set behind `opc doctor`. Pure data so the
/// verdict is a table-testable decision function.
#[derive(Debug)]
struct DoctorScan {
    elevated: bool,
    /// Every openprotect-owned NRPT rule subkey, or None when the
    /// enumeration itself failed (UNKNOWN, never counted as zero).
    total_rules: Option<usize>,
    instances: Vec<DoctorInstance>,
    /// Wintun adapter NODES in the OpenConnect/OpenProtect snapshot
    /// closed set — INCLUDING the live session's own adapter (hence
    /// the "adapter nodes (incl. live)" label in the human output).
    /// Foreign devices (vgate0, O+Connect, Tailscale) cannot appear:
    /// report and removal share one closed set by construction.
    adapters: usize,
}

/// Decide the doctor verdict from per-instance attribution.
///
/// Replaces the old `nrpt_count > live_sessions` heuristic
/// (main.rs:1818 at the time of the hang audit). That comparison was
/// a category error: one healthy session installs ONE NRPT RULE PER
/// DNS-NAMESPACE (gp-dns windows_nrpt.rs apply_native loop, :200-210),
/// so `--only` with three zones legitimately yields rules=3 against
/// live=1 and the old code screamed "Leaked" — pushing users toward
/// the destructive `opc recover --all`. Attribution per instance
/// fixes it: rules belonging to a responsive instance are healthy at
/// any count; only rules NOT attributable to any responsive instance
/// are the leak signal.
#[cfg_attr(not(windows), allow(dead_code))]
fn doctor_verdict_scan(scan: &DoctorScan) -> DoctorVerdict {
    let any_unknown = scan.total_rules.is_none()
        || scan
            .instances
            .iter()
            .any(|i| i.rules.is_none() || i.liveness == LivenessProbe::Unknown);
    let total_visible = scan.total_rules.unwrap_or(0);

    // 1. Nothing is observable anywhere AND every probe succeeded:
    //    unambiguously clean, even non-elevated (old :1806 case).
    if !any_unknown && total_visible == 0 && scan.adapters == 0 {
        return DoctorVerdict::NoLeak;
    }
    // 2. A failed count or liveness probe: report UNKNOWN. Never
    //    reinterpret "couldn't ask" as "doesn't exist" — that is
    //    the false-absence class that made wedged-live sessions look
    //    leaked (and their rules eligible for sweeps).
    if any_unknown {
        return DoctorVerdict::Unknown;
    }
    // 3. Something present without elevation: we can't open an
    //    elevated session's pipe to confirm ownership (old :1812).
    if !scan.elevated {
        return DoctorVerdict::Inconclusive;
    }

    // Elevated: liveness is trustworthy. Attribute every rule to a
    // responsive owner; residue is the leak.
    let mut attributed = 0usize;
    let mut live_sessions = 0usize;
    for inst in scan.instances.iter() {
        if inst.liveness == LivenessProbe::Responsive {
            live_sessions += 1;
            attributed += inst.rules.unwrap_or(0);
        }
    }
    let total = scan.total_rules.unwrap_or_default();
    // More attributable than total means our reads raced a
    // concurrent connect/recover — honest answer is UNKNOWN again.
    if attributed > total {
        return DoctorVerdict::Unknown;
    }
    if total - attributed > 0 {
        return DoctorVerdict::Leaked;
    }
    // Adapters: compare INSIDE the OpenConnect/OpenProtect namespace
    // only (the snapshot closed set). Foreign-device blindness is
    // deliberate and CLOSED: report and removal authority are one
    // set — a device this count cannot see is also one no sweep of
    // ours may touch (do NOT widen this; reviewed stance). The live
    // session's own node is INCLUDED in `adapters`, so a healthy
    // single session sits at adapters == live_sessions; more nodes
    // than live owners means at least one orphan (the old code only
    // caught the live==0 && adapters>0 corner; the (live=1,
    // adapters=2) cell was missed).
    if scan.adapters > live_sessions {
        return DoctorVerdict::Leaked;
    }
    DoctorVerdict::NoLeak
}

/// CONSUMES the gp-dns cross-agent contract
/// `pub fn count_windows_nrpt_for_instance(instance: &str) ->
/// anyhow::Result<usize>` (added by the ipc-dns agent THIS run,
/// mirroring the per-instance cleanup targeting in windows_nrpt.rs).
///
/// INTEGRATION SWITCH POINT (impl-main → integration agent): during
/// the parallel pass the contract symbol does not exist yet, so this
/// SINGLE call site delegates to the pre-existing identical-scope
/// `count_stale_windows_nrpt` (Instance-scope count, same prefix
/// targeting). When gp-dns lands the contract fn, change the body to
/// call it — this is the only consumer.
#[cfg(windows)]
fn nrpt_count_for_instance(instance: &str) -> anyhow::Result<usize> {
    // Contract symbol (ipc-dns agent): mirrors the per-instance
    // cleanup targeting (NrptScope::Instance -> instance_prefix).
    // This single call site is the only consumer; during the
    // parallel pass it transiently delegated to the identical-scope
    // count_stale_windows_nrpt — integration agent, verify it now
    // points at the contract fn (it does).
    gp_dns::count_windows_nrpt_for_instance(instance)
}

/// Single-shot liveness probe for the doctor scan (decision-logic
/// half of the busy-pipe honesty fix; see [`classify_liveness`]).
#[cfg(windows)]
async fn probe_liveness(instance: &str) -> LivenessProbe {
    let endpoint = endpoint_for(instance);
    let result = client_roundtrip(&endpoint, &IpcRequest::Status).await;
    classify_liveness(&result)
}

/// Read-only health report: how many leaked NRPT DNS rules and
/// OpenProtect Wintun adapters are present, and how many live opc
/// sessions are responding. Makes no changes — points at `opc recover`.
async fn doctor(json: bool, instance: Option<String>) -> Result<()> {
    if let Some(ref raw) = instance {
        validate_instance_name(raw)?;
    }
    doctor_platform(json, instance).await
}

#[cfg(windows)]
async fn doctor_platform(json: bool, instance: Option<String>) -> Result<()> {
    note_phase("doctor_probe", PhaseKind::Auto);
    let scan_t0 = phase_start(None, "doctor_probe");

    // Enumeration failures become None (UNKNOWN) here instead of
    // bailing with `?`: a registry error must not be laundered into
    // "zero rules seen" downstream, and doctor must still report the
    // rest of what it observed.
    let total_rules = match instance.as_deref() {
        Some(name) => nrpt_count_for_instance(name).ok(),
        None => gp_dns::count_all_windows_nrpt().ok(),
    };
    let adapters = wintun_cleanup::snapshot_existing_orphans().len();

    // Candidate instance names = union of the live pipe namespace and
    // (for the scoped call) the requested name. Rules can only be
    // attributed to a NAME, so the probe set must cover every name a
    // responsive OR wedged-live session could be running under.
    let mut names: Vec<String> = enumerate_live_instances()
        .await
        .into_iter()
        .map(|(name, _path)| name)
        .collect();
    if let Some(ref name) = instance {
        if !names.iter().any(|n| n == name) {
            names.push(name.clone());
        }
    }
    names.sort();
    names.dedup();

    let mut instances = Vec::with_capacity(names.len());
    for name in &names {
        let liveness = probe_liveness(name).await;
        // Absent names still get counted so rules parked under a
        // dead prefix become visible as unattributed residue.
        let rules = nrpt_count_for_instance(name).ok();
        instances.push(DoctorInstance {
            name: name.clone(),
            liveness,
            rules,
        });
    }
    phase_finish(None, "doctor_probe", scan_t0);
    note_phase_clear();

    let elevated = is_elevated();
    let live_sessions = instances
        .iter()
        .filter(|i| i.liveness == LivenessProbe::Responsive)
        .count();
    let scan = DoctorScan {
        elevated,
        total_rules,
        instances,
        adapters,
    };
    let verdict = doctor_verdict_scan(&scan);
    let mut unknown_probes: Vec<String> = scan
        .instances
        .iter()
        .filter(|i| i.rules.is_none() || i.liveness == LivenessProbe::Unknown)
        .map(|i| i.name.clone())
        .collect();
    if scan.total_rules.is_none() {
        unknown_probes.push("<total-enumeration>".into());
    }

    if json {
        let verdict_str = match verdict {
            DoctorVerdict::NoLeak => "no_leak",
            DoctorVerdict::Leaked => "leaked",
            DoctorVerdict::Inconclusive => "inconclusive",
            DoctorVerdict::Unknown => "unknown",
        };
        // Fields the probes could not answer are JSON null - NOT 0 -
        // so scripted consumers can tell "clean" from "couldn't look".
        let nrpt_json = scan
            .total_rules
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_string());
        let unknown_json = unknown_probes
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(",");
        let per_instance_json = scan
            .instances
            .iter()
            .map(|i| {
                format!(
                    "{{\"instance\":\"{}\",\"liveness\":\"{:?}\",\"nrpt_rules\":{}}}",
                    i.name,
                    i.liveness,
                    i.rules
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "null".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"leaked_nrpt_rules\":{nrpt_json},\"openprotect_adapters\":{adapters},\"live_sessions\":{live_sessions},\"elevated\":{elevated},\"verdict\":\"{verdict_str}\",\"unknown_probes\":[{unknown_json}],\"per_instance\":[{per_instance_json}]}}"
        );
    } else {
        println!("opc doctor:");
        match scan.total_rules {
            Some(n) => println!("  NRPT DNS rules:              {n}"),
            None => println!("  NRPT DNS rules:              UNKNOWN (enumeration failed)"),
        }
        for i in &scan.instances {
            println!(
                "    - {}: liveness={:?} rules={}",
                i.name,
                i.liveness,
                i.rules
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "UNKNOWN (count failed)".into())
            );
        }
        println!("  OpenProtect adapter nodes:   {adapters} (incl. live)");
        println!("  live opc sessions:         {live_sessions}");
        match verdict {
            DoctorVerdict::Leaked => {
                println!(
                    "\nLeaked state detected. Run `opc recover` (as Administrator) to clean up."
                );
            }
            DoctorVerdict::NoLeak => {
                println!("\nNo leaks detected.");
            }
            DoctorVerdict::Inconclusive => {
                // The non-elevated false-positive case preserved
                // from before: we see the registry/adapters but
                // can't open an elevated session's pipe to confirm
                // ownership.
                println!(
                    "\nCan't determine leak status without Administrator: a present \
                     rule/adapter may belong to a running (elevated) VPN session. \
                     Re-run `opc doctor` from an elevated terminal for a definitive \
                     verdict."
                );
            }
            DoctorVerdict::Unknown => {
                println!(
                    "\nVerdict UNKNOWN: {} probe(s) failed and are NOT counted as absent: {}.",
                    unknown_probes.len(),
                    if unknown_probes.is_empty() {
                        "none".to_string()
                    } else {
                        unknown_probes.join(", ")
                    }
                );
                println!(
                    "A busy/unanswerable pipe can still be a LIVE (wedged) session; \
                     `opc recover` on this state may delete a live rule. Resolve the \
                     failing probes first (see the phase stamps above)."
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
async fn doctor_platform(json: bool, instance: Option<String>) -> Result<()> {
    let _ = instance;
    let responsive = collect_live_snapshots().await;
    if json {
        println!(
            r#"{{"leaked_nrpt_rules":0,"openprotect_adapters":0,"live_sessions":{}}}"#,
            responsive.len()
        );
    } else {
        println!(
            "opc doctor: no Windows-specific DNS/adapter leaks possible on this \
             platform; {} live session(s)",
            responsive.len()
        );
    }
    Ok(())
}

/// Decide the scope of the pre-connect / recover NRPT recovery sweep
/// from the tri-state **liveness** of every candidate sibling — never
/// from `Status`-roundtrip responsiveness alone.
///
/// Returns `true` (blanket: clear EVERY openprotect rule across all
/// instances) ONLY when every lingering `openprotect-*` control pipe is
/// provably dead ([`gp_ipc::Liveness::Absent`]). That is the post-crash
/// state where a catch-all `.` rule leaked by a *different* instance
/// (e.g. a crashed `opc -i work`) would hijack ALL DNS and deadlock this
/// connect's portal prelogin. If any sibling is `Alive` (a wedged-but-
/// listening server that simply has not answered) or `Unknown` (a busy
/// pipe with every instance attached, a denied open, or an open that
/// never completed) we must NOT blanket-sweep — that session's rule may
/// be in use, not leaked — so callers fall back to the instance-scoped
/// clear that only touches our own prefix.
///
/// This is the decision the responsiveness-only gate got wrong: a
/// healthy-but-momentarily-busy sibling answers no `Status` request (the
/// `collect_live_snapshots` roundtrip yields `Err(PipeBusy)` / a timed-
/// out `Protocol`, all dropped), counted as 0 responsive → the blanket
/// sweep then deleted that LIVE sibling's split-DNS rule, silently
/// hijacking resolution back to the physical resolver while its tunnel
/// kept forwarding. Treating `Unknown` as possibly-alive closes that
/// hole. An empty candidate set means no `openprotect-*` pipe survived
/// in the namespace at all, which IS the post-crash clean state (the
/// owning process is gone, so its pipe is gone), and remains blanket-
/// safe.
///
/// Only called from the Windows pre-connect / recover blocks (plus tests
/// on every platform); silence dead-code on non-Windows non-test builds.
#[cfg_attr(not(windows), allow(dead_code))]
fn preconnect_sweep_is_blanket(livenesses: &[gp_ipc::Liveness]) -> bool {
    livenesses
        .iter()
        .all(|l| matches!(l, gp_ipc::Liveness::Absent))
}

/// The possibly-alive sibling instances behind a non-blanket decision
/// (`Alive` or `Unknown`), for an operator-facing message that names who
/// we refused to sweep rather than reporting a bare count.
#[cfg_attr(not(windows), allow(dead_code))]
fn possibly_alive_instances(
    rows: &[(String, std::path::PathBuf, gp_ipc::Liveness)],
) -> Vec<String> {
    rows.iter()
        .filter(|(_, _, l)| !matches!(l, gp_ipc::Liveness::Absent))
        .map(|(name, _, _)| name.clone())
        .collect()
}

struct ConnectArgs {
    portal: Option<String>,
    user: Option<String>,
    gateway: Option<String>,
    passwd_on_stdin: bool,
    os: Option<String>,
    insecure: Option<bool>,
    vpnc_script: Option<String>,
    auth_mode: Option<SamlAuthMode>,
    saml_port: Option<u16>,
    only: Option<String>,
    route_conflict: Option<RouteConflictArg>,
    dns_zone: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    pkcs12: Option<String>,
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
        gateway,
        passwd_on_stdin,
        os,
        insecure,
        vpnc_script,
        auth_mode,
        saml_port,
        only,
        route_conflict,
        dns_zone,
        cert,
        key,
        pkcs12,
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

    // Arm the report-only phase watchdog BEFORE the first blocking
    // step. The pre-IPC auth stretch (sweep → prelogin → SAML paste
    // → portal_config → gateway_login) is the window the adversarial
    // audit proved has no observer at all today: the control pipe
    // does not exist yet, so `opc disconnect` can't reach us and a
    // stuck step there looked exactly like a healthy slow start.
    // The ticker runs as its own task, so it keeps reporting while
    // the operation it watches is blocked. Budget from
    // OPC_PHASE_BUDGET_SECS (whole seconds), default 120 — WARN
    // only, NEVER force-exit.
    {
        let budget = parse_phase_budget(std::env::var("OPC_PHASE_BUDGET_SECS").ok().as_deref());
        let _handle = spawn_phase_watchdog(watchdog_state(), budget);
        note_phase("pre_ipc_auth", PhaseKind::Auto);
        tracing::info!(
            "session {instance_name}: connect start attempt=0 t+{}ms (phase watchdog budget {}s; \
             report-only — opc will not force-exit on budget expiry)",
            process_elapsed().as_millis(),
            budget.as_secs(),
        );
    }

    // 1. Load config + resolve CLI args against the profile layer.
    let config = gp_config::OpenProtectConfig::load().context("loading config")?;
    let resolved = resolve_connect_settings(
        CliConnectOverrides {
            portal,
            user,
            gateway,
            os,
            insecure,
            vpnc_script,
            auth_mode,
            saml_port,
            only,
            route_conflict,
            dns_zone,
            cert,
            key,
            pkcs12,
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
        gateway: gateway_override_resolved,
        auth_mode,
        saml_port,
        vpnc_script,
        only,
        route_conflict,
        dns_zones_override,
        cert,
        key,
        pkcs12,
        hip,
        hip_script,
        insecure,
        reconnect,
        user: merged_user,
        metrics_bind: metrics_bind_addr,
        okta_url,
        esp,
    } = resolved;

    #[cfg(target_os = "macos")]
    ensure_macos_connect_privileges()?;

    // `user` was previously a plain ConnectArgs field; it's now
    // part of the resolved settings so CLI > profile > None
    // merging applies. Shadow the outer name for the rest of the
    // function.
    let user = merged_user;

    // Validate cert/key consistency up front.
    if cert.is_some() && key.is_none() {
        anyhow::bail!("--cert requires --key (path to the PEM private key)");
    }
    if key.is_some() && cert.is_none() {
        anyhow::bail!("--key requires --cert (path to the PEM certificate)");
    }

    let client_os: ClientOs = os.parse().unwrap_or_default();
    let mut gp_params = GpParams::new(client_os);
    gp_params.ignore_tls_errors = insecure;
    gp_params.client_cert = cert;
    gp_params.client_key = key;
    gp_params.client_pkcs12 = pkcs12;

    let client = GpClient::new(gp_params.clone()).context("creating HTTP client")?;

    // 1b. Recovery sweep for stale NRPT rules left behind by a
    // previous opc that died in a kernel-mode wait (Wintun /
    // PnP API hangs) — its rule still hijacks DNS for `.` to
    // the VPN's internal resolvers, which the new connect can't
    // reach until its OWN tunnel is up. That deadlocks portal
    // prelogin in `client.prelogin(...)` below. The sweep is
    // synchronous and bounded (one registry enumerate + a
    // handful of deletes + one SCM paramchange — milliseconds)
    // so the connect path can wait on it without risking the
    // hangs the connect-time gp-dns code historically had.
    //
    // Scope: only when EVERY other opc session is provably DEAD (no
    // lingering control pipe, or one that probes `Absent`) can a leak
    // have come from a dead session, so we blanket-clear EVERY openprotect
    // rule across all instances — otherwise a catch-all `.` rule leaked
    // by a *different* instance (e.g. a crashed `opc -i work` when we're
    // connecting as `default`) would hijack all DNS and deadlock our
    // prelogin. If any sibling is `Alive` OR `Unknown` (busy/denied/
    // wedged-but-holding its pipe) its rule may be in use, not leaked,
    // so we narrow to our own instance and never touch the sibling's.
    // The decision keys on tri-state liveness, NOT Status responsiveness
    // (a live-but-busy sibling answers no Status yet must never be
    // blanket-swept). See `preconnect_sweep_is_blanket`.
    #[cfg(windows)]
    {
        note_phase("preconnect_nrpt_sweep", PhaseKind::Auto);
        let sweep_t0 = phase_start(None, "preconnect_nrpt_sweep");
        // Gate the destructive sweep on tri-state liveness, NOT on
        // Status-roundtrip responsiveness: a live-but-busy sibling that
        // answers no `Status` request must count as possibly-alive and
        // force the narrow, instance-scoped clear (see
        // `preconnect_sweep_is_blanket`). Enumerating with liveness
        // surfaces a busy/denied/wedged-holding pipe as `Unknown`,
        // which the old responsiveness-only `collect_live_snapshots`
        // dropped — silently licensing the blanket sweep to delete that
        // sibling's live split-DNS rule mid-session.
        let rows = gp_ipc::enumerate_live_instances_with_liveness().await;
        let livenesses: Vec<gp_ipc::Liveness> = rows.iter().map(|(_, _, l)| *l).collect();
        let blanket = preconnect_sweep_is_blanket(&livenesses);
        let sweep = if blanket {
            gp_dns::cleanup_all_windows_nrpt()
        } else {
            gp_dns::cleanup_stale_windows_nrpt(&instance_name)
        };
        match sweep {
            Ok(n) if n > 0 => tracing::info!(
                "gp-dns: cleared {n} stale NRPT rule(s) from a previous session \
                 (blanket={blanket})"
            ),
            Ok(_) => {
                if blanket {
                    tracing::info!("gp-dns: pre-connect sweep found no stale rules");
                } else {
                    let maybe = possibly_alive_instances(&rows);
                    tracing::info!(
                        "gp-dns: pre-connect sweep narrowed to instance {instance_name} \
                         (sibling(s) possibly alive, not blanket-cleared: {})",
                        maybe.join(", ")
                    );
                }
            }
            Err(e) => tracing::warn!("gp-dns: pre-connect NRPT sweep failed: {e}"),
        }
        phase_finish(None, "preconnect_nrpt_sweep", sweep_t0);
        note_phase("pre_ipc_auth", PhaseKind::Auto);

        // 1c. Install best-effort crash-cleanup handlers so a console
        // close / logoff / shutdown / panic AFTER we install the NRPT
        // rule below still clears it (otherwise the user is left in DNS
        // blackout). The handlers no-op until `crash_cleanup::arm` runs
        // post-apply, and the console handler fires on its own thread so
        // it works even if the tunnel thread is wedged. See the module
        // docs for how this complements the cooperative-cancel path.
        crash_cleanup::install_console_handler();
        crash_cleanup::install_panic_hook();
    }

    // 2. Portal prelogin
    tracing::info!("connecting to portal {portal_url}");
    note_phase("prelogin", PhaseKind::Auto);
    let prelogin_t0 = phase_start_with(None, "prelogin", &format!("portal={portal_url}"));
    let prelogin = client
        .prelogin(&portal_url)
        .await
        .context("portal prelogin")?;
    phase_finish(None, "prelogin", prelogin_t0);

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
                    "`--auth-mode webview` is no longer supported — openprotect \
                     retired the embedded GTK+WebKit window in favour of \
                     headless SAML. Use `--auth-mode paste` (the default; \
                     local HTTP callback + terminal paste) or `--auth-mode \
                     okta --okta-url <https://tenant.okta.com>` (direct \
                     Okta API, no browser at all). See the README for the \
                     migration reasoning."
                );
            }
            SamlAuthMode::Paste => {
                // The wait is human-bound: budget-EXEMPT from the
                // watchdog WARN (the real bound is the gateway's
                // <saml-request-timeout>; the auth agent owns
                // enforcing it — gp-proto prelogin.rs:29-35
                // currently parses and discards that value). We stamp
                // START/FINISH only, and deliberately log ONLY the
                // local listener URL: the pasted
                // `globalprotectcallback:` query string carries
                // session credentials and must never reach a log
                // file. The provider itself prints the exact URL
                // (with the OS-assigned port when 0) to stderr;
                // this line just brackets the wait for post-mortem
                // timing.
                note_phase("saml_paste_wait", PhaseKind::HumanBound);
                let saml_t0 = phase_start_with(
                    Some(0),
                    "saml_paste_wait",
                    &format!(
                        "local listener http://127.0.0.1:{} (callback URL \
                         itself printed by the provider; pasted query is \
                         credentials and is not logged)",
                        if saml_port == 0 {
                            "<ephemeral, see provider \
                                                  stderr banner>"
                                .to_string()
                        } else {
                            saml_port.to_string()
                        },
                    ),
                );
                let cred = SamlPasteAuthProvider::new(saml_port)
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("SAML (paste) authentication")?;
                phase_finish(None, "saml_paste_wait", saml_t0);
                note_phase("pre_ipc_auth", PhaseKind::Auto);
                cred
            }
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
    note_phase("portal_config", PhaseKind::Auto);
    let portal_config_t0 = phase_start(None, "portal_config");
    let portal_config = client
        .portal_config(&portal_url, &cred)
        .await
        .context("portal config")?;
    phase_finish(None, "portal_config", portal_config_t0);

    tracing::debug!(
        "portal returned {} gateway(s)",
        portal_config.gateways.len()
    );

    // 5. Select gateway
    note_phase("gateway_selection", PhaseKind::Auto);
    let gw_sel_t0 = phase_start(None, "gateway_selection");
    let gateway_selection = select_gateway(
        &portal_config,
        prelogin.region(),
        gateway_override_resolved.as_deref(),
    )
    .await?;
    phase_finish(None, "gateway_selection", gw_sel_t0);
    print_gateway_connect_line(&gateway_selection);
    let gateway = gateway_selection.gateway;

    // 6. Gateway login (with MFA retry loop)
    // Issue #36: when the portal issued no pass-through cookies,
    // `to_gateway_credential` replays the portal password at the
    // gateway (libopenconnect `blind_retry` / yuezk conformance) — or
    // forwards the SAML/Prelogin secret — instead of the old
    // credential-less `passwd=&token=` POST the gateway 512s. When the
    // portal DID issue cookies the credential stays cookie-only (no
    // replay), preserving the request the working pass-through flow
    // sends today.
    let gw_cred = portal_config.to_gateway_credential(&cred);
    let mut gw_params = gp_params.clone();
    gw_params.is_gateway = true;

    note_phase("gateway_login", PhaseKind::Auto);
    let gw_login_t0 = phase_start(None, "gateway_login");
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

    phase_finish(None, "gateway_login", gw_login_t0);
    note_phase("pre_ipc_auth", PhaseKind::Auto);
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
            note_phase("only_spec_resolve", PhaseKind::Auto);
            let t0 = phase_start_with(None, "only_spec_resolve", &format!("spec={spec}"));
            let resolved = resolve_only_spec(spec).await.context("resolving --only")?;
            phase_finish(None, "only_spec_resolve", t0);
            note_phase("pre_ipc_auth", PhaseKind::Auto);
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

    // 7b. Sweep stale Wintun adapters left over from a previous opc
    // that crashed before libopenconnect could call WintunCloseAdapter.
    // Phantom OpenConnect adapters destabilise other Wintun-based apps
    // (notably Tailscale), so we clear them out around tunnel setup.
    //
    // Snapshot the orphan-candidate InstanceIds *synchronously now*,
    // before libopenconnect creates this run's adapter, then hand the
    // closed list to a background worker for the actual `pnputil`
    // removals. This is race-free: anything created after the snapshot
    // (including our own live adapter) cannot appear in the list and
    // therefore cannot be removed by the sweep. See wintun_cleanup.rs
    // for the longer rationale.
    #[cfg(windows)]
    {
        note_phase("adapter_enumeration", PhaseKind::Auto);
        // The snapshot itself logs at debug only; SetupAPI enumeration
        // can stall behind a PnP RPC, so bracket it at INFO here —
        // the wintun module's internals stay frozen.
        let snap_t0 = phase_start(None, "adapter_enumeration");
        let snapshot = wintun_cleanup::snapshot_existing_orphans();
        phase_finish(None, "adapter_enumeration", snap_t0);
        tracing::info!(
            "wintun-cleanup: snapshot of {} orphan candidate(s) handed to \
             background sweep (removal authority: snapshot closed set only)",
            snapshot.len()
        );
        wintun_cleanup::spawn_background_sweep(snapshot);
        note_phase("pre_ipc_auth", PhaseKind::Auto);
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
    let mut cookie_str = build_openconnect_cookie(&auth_cookie);
    let oc_os = client_os.openconnect_os();
    let mut gateway_host = gateway.address.clone();

    let script: Option<String> = match (vpnc_script.as_ref(), routes.is_empty()) {
        (Some(explicit), _) => Some(explicit.clone()),
        (None, false) => None, // native gp-route path
        (None, true) => default_vpnc_script(),
    };

    tracing::info!(
        "starting tunnel: opc={OPC_VERSION} gateway={gateway_host} os={oc_os} vpnc_script={:?} native_routes={} reconnect={reconnect}",
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
    // `opc status` / `opc disconnect` keep working across retry
    // attempts. Disconnect uses a `watch::channel<bool>` — persistent,
    // so a disconnect fired during attempt #1's backoff is still
    // visible to attempt #2's subscribers.
    let ipc_start = Instant::now();
    note_phase("ipc_server_bind", PhaseKind::Auto);
    let ipc_t0 = phase_start(None, "ipc_server_bind");
    let (disconnect_tx, disconnect_rx) = tokio::sync::watch::channel(false);
    let ipc_endpoint = endpoint_for(&instance_name);
    #[cfg(unix)]
    let ipc_handle = spawn_ipc_server(
        PathBuf::from(&ipc_endpoint),
        Arc::clone(&base),
        ipc_start,
        disconnect_tx,
    )
    .await
    .context("starting ipc server")?;
    #[cfg(windows)]
    let ipc_handle = spawn_ipc_server_pipe(
        ipc_endpoint.clone(),
        Arc::clone(&base),
        ipc_start,
        disconnect_tx,
    )
    .await
    .context("starting ipc server")?;
    phase_finish(None, "ipc_server_bind", ipc_t0);
    note_phase_clear();

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

    tracing::info!("tunnel starting — press Ctrl-C (or `opc disconnect`) to tear down");

    // Reconnect loop. The first iteration is the initial attempt;
    // subsequent iterations fire only when `reconnect` is enabled AND
    // the previous attempt exited with a non-user error.
    //
    // Two recovery paths:
    //
    //   * Transient network error → retry with the same authcookie
    //     (libopenconnect's mainloop exit without auth rejection).
    //     Handles the common case where a network blip outlasts
    //     libopenconnect's internal 10-minute reconnect budget.
    //
    //   * Auth cookie expired → full re-auth (prelogin + SAML/password
    //     + gateway login) to obtain a fresh cookie. Detected via
    //     `MainloopAuthExpired` (-EPERM from libopenconnect). Resets
    //     the reconnect attempt counter on success. Gated by
    //     `MAX_REAUTH_ATTEMPTS` so a truly expired IdP session
    //     terminates cleanly rather than looping forever.
    const MAX_RECONNECT_ATTEMPTS: u32 = 10;
    const MAX_REAUTH_ATTEMPTS: u32 = 2;
    let mut reauth_count: u32 = 0;

    // Capture the auth context for potential re-auth. The password
    // field is None for re-auth attempts (it was consumed on the
    // initial stdin read) — SAML and Okta providers don't need it,
    // and PasswordAuthProvider will prompt interactively if a
    // terminal is attached.
    let reauth_ctx = ReauthContext {
        portal_url: portal_url.clone(),
        gp_params: gp_params.clone(),
        auth_mode,
        saml_port,
        okta_url: okta_url.clone(),
        insecure,
        gateway_override: gateway_override_resolved.clone(),
    };

    // Pre-resolve the gateway hostname to its public IP BEFORE
    // running the connect loop. On Windows the HIP fallback
    // (`submit_hip_from_rust`) hits this IP via reqwest's resolve
    // override so it can keep talking to the gateway after gp-dns
    // has installed an NRPT rule that redirects DNS for the same
    // hostname through the VPN's internal resolver. Failure is
    // non-fatal — HIP will fall back to system DNS, which may or
    // may not work depending on the gateway's split-DNS policy.
    //
    // `mut` because the re-auth path below may swap `gateway_host`
    // to a different DNS name and we must re-resolve to refresh
    // this pin.
    let mut gateway_ip_pin: Option<Ipv4Addr> = resolve_gateway_for_exclude(&gateway_host);

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
            route_conflict,
            hip_mode: hip,
            hip_script: hip_script.clone(),
            split_dns_zones: split_dns_zones.clone(),
            client_cert: gp_params.client_cert.clone(),
            client_key: gp_params.client_key.clone(),
            gateway_ip_pin,
            instance: instance_name.clone(),
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
            AttemptOutcome::AuthExpired(e) => {
                if !reconnect {
                    break 'outer Err(e.context(
                        "authcookie expired — re-run `opc connect` or enable --reconnect \
                         for automatic re-authentication",
                    ));
                }
                reauth_count += 1;
                if reauth_count > MAX_REAUTH_ATTEMPTS {
                    break 'outer Err(e.context(format!(
                        "authcookie expired and re-auth failed after \
                         {MAX_REAUTH_ATTEMPTS} attempt(s) — the IdP session \
                         may have expired"
                    )));
                }
                tracing::info!(
                    "authcookie expired — attempting re-authentication \
                     (attempt {reauth_count}/{MAX_REAUTH_ATTEMPTS})"
                );
                set_base_state(&base, SessionState::Reconnecting);

                match run_reauth(&reauth_ctx).await {
                    Ok(fresh) => {
                        tracing::info!("re-authenticated successfully as {}", fresh.username);
                        cookie_str = build_openconnect_cookie(&fresh.auth_cookie);
                        let new_gw = fresh.gateway_address.clone();
                        // If the re-auth handed us a different gateway
                        // (DDNS rotation, multi-gateway portal moving
                        // us to a new POP), the IP pin we cached
                        // before the outer loop is now wrong for HIP
                        // submission. Re-resolve before we hand it to
                        // the next attempt.
                        if new_gw != gateway_host {
                            tracing::info!(
                                "re-auth: gateway changed {} -> {}, refreshing IP pin",
                                gateway_host,
                                new_gw
                            );
                            gateway_ip_pin = resolve_gateway_for_exclude(&new_gw);
                        }
                        gateway_host = new_gw;
                        // Update the shared state so `opc status` shows
                        // the new username / gateway if they changed.
                        {
                            let mut guard = base.write().expect("SharedBase RwLock poisoned");
                            guard.user = fresh.auth_cookie.username.clone();
                            guard.gateway = fresh.gateway_address.clone();
                        }
                        // Reset both counters — a fresh cookie gets a
                        // clean slate for transient retries AND future
                        // re-auth attempts.
                        attempt_num = 0;
                        reauth_count = 0;
                        continue 'outer;
                    }
                    Err(reauth_err) => {
                        tracing::error!("re-authentication failed: {reauth_err:#}");
                        break 'outer Err(
                            reauth_err.context("authcookie expired and re-authentication failed")
                        );
                    }
                }
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
                // `opc disconnect`. Any of those three wake the
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
    note_phase("session_teardown", PhaseKind::Auto);
    let teardown_t0 = phase_start(None, "session_teardown");
    ipc_handle.abort();
    if let Some(h) = metrics_handle.as_ref() {
        h.abort();
    }
    // On Unix, clean up the socket file. On Windows, named pipes
    // are cleaned up automatically when the process exits.
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&ipc_endpoint);
    }
    phase_finish(None, "session_teardown", teardown_t0);
    note_phase_clear();

    final_result
}

/// Inputs captured from the initial `connect()` flow that the
/// re-auth path needs to repeat prelogin + authenticate + gateway
/// login after an authcookie expiry. Lives across the reconnect
/// loop so re-auth doesn't need to reconstruct everything.
#[cfg_attr(not(unix), allow(dead_code))]
struct ReauthContext {
    portal_url: String,
    gp_params: GpParams,
    auth_mode: SamlAuthMode,
    saml_port: u16,
    okta_url: Option<String>,
    insecure: bool,
    gateway_override: Option<String>,
}

/// Output of a successful re-auth: a fresh authcookie and the
/// gateway address the new cookie is valid for.
struct ReauthResult {
    auth_cookie: AuthCookie,
    username: String,
    gateway_address: String,
}

/// Re-run the full authentication flow: prelogin → authenticate →
/// portal config → gateway login. Returns a fresh [`AuthCookie`]
/// and the gateway address.
///
/// For SAML paste mode, this re-opens the local callback server and
/// waits for the user to complete auth in their browser — the IdP
/// session cookie typically keeps them logged in, so the re-auth is
/// often a single redirect with no user interaction. For Okta mode,
/// the provider re-authenticates headlessly if the Okta session is
/// still valid. For password mode, the provider prompts interactively
/// on stdin — this works in terminal usage but will fail in headless
/// / systemd contexts where no one is watching. The error surfaces
/// cleanly in that case ("re-authentication failed").
async fn run_reauth(ctx: &ReauthContext) -> Result<ReauthResult> {
    let client =
        GpClient::new(ctx.gp_params.clone()).context("creating HTTP client for re-auth")?;

    // 1. Prelogin
    let prelogin = client
        .prelogin(&ctx.portal_url)
        .await
        .context("re-auth: portal prelogin")?;

    // 2. Authenticate (no saved password — providers prompt or use
    //    cached IdP sessions)
    let auth_ctx = AuthContext {
        server: ctx.portal_url.clone(),
        username: None,
        password: None,
        max_mfa_attempts: 3,
    };

    let cred = if prelogin.is_saml() {
        match ctx.auth_mode {
            SamlAuthMode::Webview => {
                anyhow::bail!(
                    "re-auth: webview mode is not supported — \
                     use paste or okta"
                );
            }
            SamlAuthMode::Paste => {
                // Same provider Unix and Windows use for the initial
                // connect — Windows added a native stdin reader plus
                // `CancelSynchronousIo`-based shutdown for re-auth,
                // and the HTTP callback path was already
                // cross-platform. No more bail!() here.
                SamlPasteAuthProvider::new(ctx.saml_port)
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("re-auth: SAML (paste) authentication")?
            }
            SamlAuthMode::Okta => {
                let url = ctx.okta_url.clone().ok_or_else(|| {
                    anyhow::anyhow!("re-auth: --auth-mode okta requires --okta-url")
                })?;
                let provider = OktaAuthProvider::new(OktaAuthConfig {
                    okta_url: url,
                    insecure: ctx.insecure,
                });
                provider
                    .authenticate(&prelogin, &auth_ctx)
                    .await
                    .context("re-auth: okta headless authentication")?
            }
        }
    } else {
        PasswordAuthProvider
            .authenticate(&prelogin, &auth_ctx)
            .await
            .context("re-auth: password authentication")?
    };

    let username = cred.username().to_string();
    tracing::info!("re-auth: authenticated as {username}");

    // 3. Portal config
    let portal_config = client
        .portal_config(&ctx.portal_url, &cred)
        .await
        .context("re-auth: portal config")?;

    // 4. Select gateway (re-use existing or override)
    let gateway = select_gateway(
        &portal_config,
        prelogin.region(),
        ctx.gateway_override.as_deref(),
    )
    .await
    .context("re-auth: gateway selection")?;
    let gateway_address = gateway.gateway.address.clone();

    // 5. Gateway login
    // Issue #36: same credential policy as the connect path —
    // portal-password replay (or SAML/Prelogin secret forward) only
    // when the portal issued no pass-through cookies; cookie-only
    // otherwise. run_reauth re-runs PasswordAuthProvider above, so
    // `cred` is available for every auth mode.
    let gw_cred = portal_config.to_gateway_credential(&cred);
    let mut gw_params = ctx.gp_params.clone();
    gw_params.is_gateway = true;
    let gw_client = GpClient::new(gw_params).context("re-auth: creating gateway client")?;
    let login_result = gw_client
        .gateway_login(&gateway_address, &gw_cred)
        .await
        .context("re-auth: gateway login")?;

    let auth_cookie = match login_result {
        GatewayLoginResult::Success(cookie) => cookie,
        GatewayLoginResult::MfaChallenge { .. } => {
            anyhow::bail!(
                "re-auth: gateway requires MFA challenge — interactive \
                 re-authentication is not supported in the reconnect \
                 path. Re-run `opc connect` manually."
            );
        }
    };

    Ok(ReauthResult {
        auth_cookie,
        username,
        gateway_address,
    })
}

const GATEWAY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
enum GatewayProbe {
    Reachable(Duration),
    TimedOut,
    Failed(String),
}

impl GatewayProbe {
    fn rtt(&self) -> Option<Duration> {
        match self {
            Self::Reachable(rtt) => Some(*rtt),
            Self::TimedOut | Self::Failed(_) => None,
        }
    }

    fn display_rtt(&self) -> String {
        match self {
            Self::Reachable(rtt) => format!("{}ms", rtt.as_millis()),
            Self::TimedOut => format!(">{}ms", GATEWAY_PROBE_TIMEOUT.as_millis()),
            Self::Failed(err) => format!("err:{err}"),
        }
    }
}

#[derive(Debug, Clone)]
struct RankedGateway {
    gateway: Gateway,
    probe: GatewayProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewaySelectionReason {
    Probed,
    Forced,
    Fallback,
}

#[derive(Debug, Clone)]
struct GatewaySelection {
    gateway: Gateway,
    rtt: Option<Duration>,
    reason: GatewaySelectionReason,
}

async fn select_gateway(
    portal_config: &gp_proto::PortalConfig,
    region: &str,
    gateway_override: Option<&str>,
) -> Result<GatewaySelection> {
    if let Some(raw) = gateway_override {
        tracing::debug!("skipping gateway probes because --gateway was provided");
        return Ok(GatewaySelection {
            gateway: match_gateway_override(&portal_config.gateways, raw)?,
            rtt: None,
            reason: GatewaySelectionReason::Forced,
        });
    }

    let ranked = rank_gateways_by_latency(&portal_config.gateways).await;
    print_ranked_gateway_table(&ranked);

    if let Some(best) = ranked.iter().find(|entry| entry.probe.rtt().is_some()) {
        return Ok(GatewaySelection {
            gateway: best.gateway.clone(),
            rtt: best.probe.rtt(),
            reason: GatewaySelectionReason::Probed,
        });
    }

    let fallback = portal_config
        .preferred_gateway(Some(region))
        .context("no gateways available")?
        .clone();
    tracing::warn!(
        "all gateway probes failed within {}s; falling back to portal priority",
        GATEWAY_PROBE_TIMEOUT.as_secs()
    );
    Ok(GatewaySelection {
        gateway: fallback,
        rtt: None,
        reason: GatewaySelectionReason::Fallback,
    })
}

async fn rank_gateways_by_latency(gateways: &[Gateway]) -> Vec<RankedGateway> {
    let mut set = tokio::task::JoinSet::new();
    for gateway in gateways {
        let gateway = gateway.clone();
        set.spawn(async move {
            let probe = probe_gateway(&gateway.address).await;
            RankedGateway { gateway, probe }
        });
    }

    let mut ranked = Vec::with_capacity(gateways.len());
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(entry) => ranked.push(entry),
            Err(err) => tracing::warn!("gateway probe task failed: {err}"),
        }
    }

    ranked.sort_by(|a, b| {
        gateway_probe_sort_key(&a.probe)
            .cmp(&gateway_probe_sort_key(&b.probe))
            .then_with(|| gateway_name(&a.gateway).cmp(gateway_name(&b.gateway)))
            .then_with(|| a.gateway.address.cmp(&b.gateway.address))
    });
    ranked
}

/// Split a gateway address into the (host, service-port) the
/// latency probe should dial (issue #43 seam S3). A portal entry
/// advertised as `203.0.113.7:11443` must be probed at 11443 — the
/// pre-#43 code hardcoded 443, so a custom-port gateway could never
/// rank Reachable (masked in the #43 repro only because `--gateway`
/// skips probes). Uses the single shared splitter, same as the
/// tunnel and exclude-pin lanes.
fn probe_target(address: &str) -> (String, u16) {
    let host = gp_proto::params::normalize_server(address);
    let (h, spec) = gp_proto::params::split_host_port(host);
    // Absent → the implicit https port; an advertised-but-unusable
    // port yields 0 so the connect fails FAST and the entry ranks
    // unreachable, rather than being probed (and falsely ranked) on
    // a port the gateway never advertised.
    let port = spec
        .port()
        .unwrap_or(if matches!(spec, gp_proto::params::PortSpec::Absent) {
            443
        } else {
            0
        });
    (h.to_string(), port)
}

async fn probe_gateway(address: &str) -> GatewayProbe {
    let (host, port) = probe_target(address);
    let started = Instant::now();
    match tokio::time::timeout(
        GATEWAY_PROBE_TIMEOUT,
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            GatewayProbe::Reachable(started.elapsed())
        }
        Ok(Err(err)) => GatewayProbe::Failed(err.to_string()),
        Err(_) => GatewayProbe::TimedOut,
    }
}

fn gateway_name(gateway: &Gateway) -> &str {
    if gateway.description.trim().is_empty() {
        gateway.address.as_str()
    } else {
        gateway.description.as_str()
    }
}

fn gateway_probe_sort_key(probe: &GatewayProbe) -> (bool, Duration) {
    (probe.rtt().is_none(), probe.rtt().unwrap_or(Duration::MAX))
}

fn match_gateway_override(gateways: &[Gateway], raw: &str) -> Result<Gateway> {
    let needle = raw.trim();
    let normalized = gp_proto::params::normalize_server(needle);
    let matches: Vec<&Gateway> = gateways
        .iter()
        .filter(|gateway| {
            gateway_name(gateway).eq_ignore_ascii_case(needle)
                || gp_proto::params::normalize_server(&gateway.address)
                    .eq_ignore_ascii_case(normalized)
        })
        .collect();

    match matches.as_slice() {
        [gateway] => Ok((*gateway).clone()),
        [] => {
            let available = format_gateway_list(gateways);
            anyhow::bail!(
                "`--gateway {needle}` did not match any portal gateways; available: {available}"
            );
        }
        many => {
            let available = many
                .iter()
                .map(|gateway| format!("{} ({})", gateway_name(gateway), gateway.address))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "`--gateway {needle}` matched multiple gateways; use an address instead: {available}"
            );
        }
    }
}

fn format_gateway_list(gateways: &[Gateway]) -> String {
    gateways
        .iter()
        .map(|gateway| format!("{} ({})", gateway_name(gateway), gateway.address))
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_ranked_gateway_table(ranked: &[RankedGateway]) {
    if !tracing::enabled!(tracing::Level::DEBUG) || ranked.is_empty() {
        return;
    }

    eprintln!("Gateway latency ranking:");
    eprintln!("{:<28} {:<40} {:>10}", "Name", "Address", "RTT");
    for entry in ranked {
        eprintln!(
            "{:<28} {:<40} {:>10}",
            gateway_name(&entry.gateway),
            entry.gateway.address,
            entry.probe.display_rtt()
        );
    }
}

fn print_gateway_connect_line(selection: &GatewaySelection) {
    let name = gateway_name(&selection.gateway);
    let address = &selection.gateway.address;
    match selection.reason {
        GatewaySelectionReason::Probed => {
            let rtt_ms = selection.rtt.map(|rtt| rtt.as_millis()).unwrap_or_default();
            eprintln!("Connecting to {name} ({address}) — {rtt_ms}ms");
        }
        GatewaySelectionReason::Forced => {
            eprintln!("Connecting to {name} ({address}) — forced by --gateway");
        }
        GatewaySelectionReason::Fallback => {
            eprintln!("Connecting to {name} ({address}) — probe unavailable");
        }
    }
}

/// Outcome of one `run_tunnel_attempt` iteration. The reconnect loop
/// reads this + the watch-channel disconnect flag to decide whether
/// to retry, break cleanly, or surface an error.
enum AttemptOutcome {
    /// User cancelled (Ctrl-C, SIGTERM, or `opc disconnect`). Always
    /// breaks the outer loop — no retry.
    UserCancel,
    /// Tunnel mainloop returned cleanly. Treated as a clean exit:
    /// no retry, no error.
    Ok,
    /// The gateway or authcookie state said "don't come back" —
    /// `TunnelError::MainloopTerminated` (remote `-EPIPE`).
    /// The reconnect loop must NOT retry: re-using the same cookie
    /// would flap. Distinct from `Err` so the loop can surface a
    /// clear "server ended the session, re-run `opc connect`"
    /// instead of spinning backoffs and eventually giving up at
    /// `MAX_RECONNECT_ATTEMPTS`.
    TerminalErr(anyhow::Error),
    /// The authcookie is no longer valid — libopenconnect returned
    /// `-EPERM` (`TunnelError::MainloopAuthExpired`). The reconnect
    /// loop should attempt a full re-auth (prelogin + SAML/password +
    /// gateway login) to obtain a fresh cookie. If re-auth fails or
    /// the re-auth budget is exhausted, the error surfaces to the user.
    AuthExpired(anyhow::Error),
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
    /// What to do when a split prefix is already routed by another
    /// interface on this host. See [`gp_route::RouteConflictPolicy`].
    route_conflict: gp_route::RouteConflictPolicy,
    hip_mode: HipMode,
    /// Optional user-supplied HIP wrapper script path. When
    /// present, `run_tunnel` registers this with libopenconnect
    /// via `openconnect_setup_csd` INSTEAD of the built-in
    /// `opc hip-report` subcommand. Already canonicalised and
    /// validated in `resolve_connect_settings`.
    hip_script: Option<String>,
    /// PEM client certificate path for mutual TLS at the
    /// libopenconnect level.
    client_cert: Option<String>,
    /// PEM private key path for `client_cert`.
    client_key: Option<String>,
    /// Pre-resolved gateway public IP, captured BEFORE gp-route /
    /// gp-dns rewrite the system's view of DNS + routing. The
    /// Windows HIP fallback pins reqwest to this IP so it can
    /// reach the gateway even after our NRPT rule has hijacked
    /// the hostname's resolution to an internal address.
    /// `None` when resolution failed at connect time (HIP will
    /// then try the hostname and best-effort).
    gateway_ip_pin: Option<std::net::Ipv4Addr>,
    /// opc instance name (`--instance` flag, default `"default"`).
    /// Scopes the NRPT rule keys we write so two parallel
    /// `opc -i NAME` invocations never delete each other's live
    /// rules on the connect-time recovery sweep.
    instance: String,
}

/// Run one tunnel attempt end-to-end: spawn the libopenconnect thread,
/// wait for the cancel handle + ready signal, publish the tun ifname
/// to the shared state, then race the mainloop against shutdown
/// signals and `opc disconnect`.
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
        route_conflict,
        hip_mode,
        hip_script,
        split_dns_zones,
        client_cert,
        client_key,
        gateway_ip_pin,
        instance,
    } = args;

    // `gateway_ip_pin` is only consumed by the Windows HIP fallback
    // below (`submit_hip_from_rust`); on Unix it stays unread, which
    // -D warnings in CI flags as dead code. The field exists in
    // `TunnelAttemptArgs` on every OS so the call site is
    // platform-uniform, so silence the lint here rather than gate
    // the field declaration.
    #[cfg(not(windows))]
    let _ = gateway_ip_pin;

    // HIP submission is delegated to libopenconnect's csd-wrapper
    // hook via `openconnect_setup_csd`. `run_tunnel` (below)
    // registers either `opc hip-report` or the user-supplied
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
    // on 2026-04-14, where a pre-CSTP HIP landed at `198.51.100.44`
    // while libopenconnect's CSTP used `198.51.100.45`, giving a
    // deterministic 60-second kick every attempt).

    // Every blocking window below is bracketed twice: an INFO
    // START/FINISH stamp (forensic timeline) and a watchdog phase
    // post (budget report). The thread receives `attempt_num` so its
    // own stamps carry the attempt ID too.
    note_phase("pre_handle_wait", PhaseKind::Auto);
    let attempt_t0 = phase_start(Some(attempt_num), "tunnel_attempt");

    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<TunnelReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<()>>();

    let gateway_owned = gateway_host.to_string();
    let cookie_owned = cookie.to_string();
    let script_owned = script.map(|s| s.to_string());
    let routes_for_thread = routes;
    let hip_script_owned = hip_script;
    let dns_zones_owned = split_dns_zones;
    let instance_owned = instance.clone();
    let tunnel_thread =
        match std::thread::Builder::new()
            .name("opc-tunnel".into())
            .spawn(move || {
                let result = run_tunnel(
                    attempt_num,
                    &gateway_owned,
                    &cookie_owned,
                    os,
                    script_owned.as_deref(),
                    routes_for_thread,
                    route_conflict,
                    reconnect_enabled,
                    enable_esp,
                    hip_mode,
                    hip_script_owned,
                    dns_zones_owned,
                    client_cert,
                    client_key,
                    instance_owned,
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
            await_handle_then_cancel_and_join(recv_task, done_rx, tunnel_thread, &instance).await;
            return AttemptOutcome::UserCancel;
        }
        _ = dr_setup.wait_for(|v| *v) => {
            tracing::info!("disconnect received before cancel handle arrived, draining tunnel thread");
            await_handle_then_cancel_and_join(recv_task, done_rx, tunnel_thread, &instance).await;
            return AttemptOutcome::UserCancel;
        }
    };
    phase_finish(Some(attempt_num), "pre_handle_wait", attempt_t0);

    // Wait for setup_tun_device. Race against shutdown signals, the
    // disconnect watch channel, and the thread's own done_rx (in
    // case it failed mid-setup).
    //
    // Watchdog phase post, NOT an await-dependency: the setup select
    // below is one of the windows the audit proved unwatched — if
    // ready_rx.recv() stalls, nothing else in this task runs, so the
    // timer lives on its own task (spawn_phase_watchdog) and only
    // reads shared state.
    note_phase("setup_tun_wait", PhaseKind::Auto);
    let setup_t0 = phase_start(Some(attempt_num), "setup_tun_wait");
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
                match drain_done_with_timeout(&mut done_rx, TUNNEL_CANCEL_WEDGE_TIMEOUT).await {
                    DrainOutcome::Resolved => {
                        let _ = tunnel_thread.join();
                    }
                    DrainOutcome::Wedged => exit_wedged(&instance),
                }
                return AttemptOutcome::UserCancel;
            }
            _ = dr.wait_for(|v| *v) => {
                tracing::info!("disconnect received during tunnel setup, cancelling...");
                if let Err(e) = cancel_handle.cancel() {
                    tracing::warn!("cancel failed: {e}");
                }
                match drain_done_with_timeout(&mut done_rx, TUNNEL_CANCEL_WEDGE_TIMEOUT).await {
                    DrainOutcome::Resolved => {
                        let _ = tunnel_thread.join();
                    }
                    DrainOutcome::Wedged => exit_wedged(&instance),
                }
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
    phase_finish(Some(attempt_num), "setup_tun_wait", setup_t0);

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
        tracing::info!("tunnel running — press Ctrl-C (or `opc disconnect`) to tear down");
    }

    // --- Windows HIP fallback ---
    // On Windows, libopenconnect's CSD wrapper path is unsupported
    // (setup_csd is a no-op). Submit HIP from the Rust side using
    // the HTTP primitives in gp-auth, after we have client_ip.
    #[cfg(windows)]
    if hip_mode != HipMode::Off {
        let client_ip = tunnel_ready
            .ip_info
            .as_ref()
            .and_then(|i| i.addr.as_deref())
            .unwrap_or("");
        if client_ip.is_empty() && hip_mode == HipMode::Force {
            return AttemptOutcome::Err(anyhow::anyhow!(
                "HIP force mode requires client_ip but none was assigned"
            ));
        }
        if !client_ip.is_empty() {
            // The select that would resume normal processing does not
            // exist yet at this point (the steady-state select is
            // below), so a stalled HIP submission previously
            // swallowed Ctrl-C/disconnect entirely — the watchdog
            // phase here is the only thing that can talk about it,
            // and it does so from its own task.
            note_phase("hip_submit", PhaseKind::Auto);
            let hip_t0 = phase_start(Some(attempt_num), "hip_submit");
            if let Err(e) = submit_hip_from_rust(
                gateway_host,
                cookie,
                client_ip,
                os,
                hip_mode,
                gateway_ip_pin,
            )
            .await
            {
                tracing::warn!("Windows HIP submission failed: {e}");
                if hip_mode == HipMode::Force {
                    phase_finish(Some(attempt_num), "hip_submit", hip_t0);
                    note_phase_clear();
                    return AttemptOutcome::Err(
                        anyhow::anyhow!(e).context("HIP submission required but failed"),
                    );
                }
            }
            phase_finish(Some(attempt_num), "hip_submit", hip_t0);
            note_phase_clear();
        } else {
            tracing::warn!("no client_ip available for HIP submission, skipping");
        }
    }

    // Steady-state: race the mainloop against shutdown, disconnect,
    // and its own exit. The watchdog is deliberately NOT armed for
    // the mainloop — a healthy session spends hours here; a budget
    // WARN every 120s would be noise that buries the real signals.
    note_phase_clear();
    tokio::select! {
        sig = shutdown_signal() => {
            tracing::info!("{sig} received, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
            match drain_done_with_timeout(&mut done_rx, TUNNEL_CANCEL_WEDGE_TIMEOUT).await {
                DrainOutcome::Resolved => {
                    let _ = tunnel_thread.join();
                }
                DrainOutcome::Wedged => exit_wedged(&instance),
            }
            AttemptOutcome::UserCancel
        }
        _ = disconnect_rx.wait_for(|v| *v) => {
            tracing::info!("disconnect request received via control socket, cancelling tunnel...");
            if let Err(e) = cancel_handle.cancel() {
                tracing::warn!("cancel failed: {e}");
            }
            match drain_done_with_timeout(&mut done_rx, TUNNEL_CANCEL_WEDGE_TIMEOUT).await {
                DrainOutcome::Resolved => {
                    let _ = tunnel_thread.join();
                }
                DrainOutcome::Wedged => exit_wedged(&instance),
            }
            AttemptOutcome::UserCancel
        }
        res = &mut done_rx => {
            let _ = tunnel_thread.join();
            // Tunnel exited on its own — clear the tun info now,
            // not in the outer loop, so a `opc status` racing the
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
/// [`gp_tunnel::TunnelError`]:
///
/// * `MainloopAuthExpired` (-EPERM) → [`AttemptOutcome::AuthExpired`]:
///   the reconnect loop should attempt a full re-auth to get a fresh
///   cookie.
/// * `MainloopTerminated` (-EPIPE) → [`AttemptOutcome::TerminalErr`]:
///   the gateway ended the session; retrying with the same cookie is
///   futile.
/// * Anything else → [`AttemptOutcome::Err`]: the reconnect loop may
///   retry if `--reconnect` is enabled.
fn classify_tunnel_err(e: anyhow::Error) -> AttemptOutcome {
    use gp_tunnel::TunnelError;

    // Walk the error chain looking for our specific tunnel error
    // variants. `MainloopAuthExpired` gets its own outcome so the
    // reconnect loop can attempt re-auth instead of giving up.
    let tunnel_err = e
        .chain()
        .find_map(|cause| cause.downcast_ref::<TunnelError>());

    match tunnel_err {
        Some(TunnelError::MainloopAuthExpired) => AttemptOutcome::AuthExpired(e),
        Some(TunnelError::MainloopTerminated) => AttemptOutcome::TerminalErr(e),
        _ => AttemptOutcome::Err(e),
    }
}

/// Helper: clear `tun_ifname` + `local_ipv4` from the shared base so
/// `opc status` and `/metrics` don't keep reporting a dead tunnel's
/// interface after the tunnel thread has exited but before the outer
/// reconnect loop has decided what to do with the failure.
fn clear_tun_info(base: &SharedBase) {
    let mut guard = base.write().expect("SharedBase RwLock poisoned");
    guard.tun_ifname = None;
    guard.local_ipv4 = None;
}

/// How long to wait for the tunnel thread to acknowledge a cancel
/// before concluding it is wedged in an uninterruptible kernel-mode
/// wait — the Windows Wintun/PnP hang documented in gp-dns's
/// `windows_nrpt` module that `taskkill /F` itself cannot interrupt.
/// Sized to comfortably cover a healthy libopenconnect teardown
/// (sub-second once the cmd-pipe cancel lands) while still bailing out
/// of a true wedge fast enough that the user isn't left staring at a
/// frozen `opc` — and, more importantly, isn't left in DNS blackout
/// with the control pipe pinned by an unkillable process.
const TUNNEL_CANCEL_WEDGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Process exit code used when we abandon a wedged tunnel thread.
/// Distinct from 0/1 so callers/scripts can tell a wedge-exit apart
/// from a clean teardown or an ordinary error.
const EXIT_TUNNEL_WEDGED: i32 = 75;

/// Outcome of waiting (with a timeout) for the tunnel thread to report
/// it has finished after we asked it to cancel.
#[derive(Debug, PartialEq, Eq)]
enum DrainOutcome {
    /// The thread reported a result (clean or error) or its sender was
    /// dropped — either way it's done and safe to `join()`.
    Resolved,
    /// The thread never acknowledged the cancel within the timeout: it
    /// is wedged in an uninterruptible kernel-mode wait and `join()`
    /// would block forever.
    Wedged,
}

/// Await the tunnel thread's `done` signal, giving up after `timeout`.
///
/// A `Resolved` outcome means the thread is exiting and the caller can
/// `join()` it without risk of blocking. `Wedged` means the cancel was
/// never serviced (the Wintun/PnP kernel hang); the caller must NOT
/// `join()` — it should clean up what it can and force-exit instead.
async fn drain_done_with_timeout(
    done_rx: &mut tokio::sync::oneshot::Receiver<Result<()>>,
    timeout: Duration,
) -> DrainOutcome {
    match tokio::time::timeout(timeout, done_rx).await {
        // Inner value (Ok result, Err result, or RecvError from a
        // dropped sender) doesn't matter here — any of them means the
        // thread is no longer blocking and can be joined.
        Ok(_) => DrainOutcome::Resolved,
        Err(_) => DrainOutcome::Wedged,
    }
}

/// Last-resort teardown when the tunnel thread is wedged. Never
/// returns.
///
/// The thread is stuck in an uninterruptible kernel wait, so we can't
/// `join()` it and we can't run the route/DNS revert that lives in its
/// stack frame. Leaving the process alive would keep the control pipe
/// held (blocking the next `opc connect` with AlreadyRunning) and —
/// far worse — leave the catch-all `.` NRPT rule hijacking ALL DNS
/// until the user figures out a manual fix. The NRPT rule lives in the
/// registry keyed by this instance's prefix, NOT in the wedged thread,
/// so we CAN sweep it from here. Do that, then force-exit so the OS
/// reclaims the wedged thread and frees the pipe.
fn exit_wedged(instance: &str) -> ! {
    tracing::error!(
        "tunnel thread wedged in an uninterruptible kernel-mode wait \
         (the Windows Wintun/PnP hang); abandoning it and force-exiting so the \
         control pipe is freed. Clearing leaked DNS state first."
    );
    #[cfg(windows)]
    match gp_dns::cleanup_stale_windows_nrpt(instance) {
        Ok(n) => tracing::info!(
            "wedge-exit: cleared {n} leaked NRPT rule(s) for instance {instance} — DNS restored"
        ),
        Err(e) => tracing::warn!("wedge-exit: NRPT cleanup failed: {e}"),
    }
    #[cfg(not(windows))]
    let _ = instance;
    // process::exit() skips destructors: the queued lines behind the
    // non-blocking tracing-appender worker — precisely the phase
    // stamps that explain this wedge — would die with the process.
    // Flush them explicitly, but on a throwaway thread with a hard
    // budget: a wedged disk must not turn the wedge-ESCAPE hatch into
    // the next hang (do not assume destructors/joins terminate).
    if !flush_tracing_bounded(Duration::from_millis(500)) {
        eprintln!(
            "opc: emergency log flush exceeded its 500ms budget; the tail              of --log-file output may be missing"
        );
    }
    tracing::error!("wedge-exit: force-exiting now (exit code {EXIT_TUNNEL_WEDGED})");
    std::process::exit(EXIT_TUNNEL_WEDGED);
}

/// How long we let the tunnel thread deliver its CancelHandle after a
/// shutdown/disconnect has already fired, before proceeding without
/// it. The old `recv_task.await` here was UNBOUNDED: a thread wedged
/// before its first send pinned Ctrl-C forever (the
/// "cannot interrupt opc" half of the hang reports). 5s matches the
/// client-side IPC request budget (gp-ipc CLIENT_REQUEST_TIMEOUT) so
/// the entire cancel path shares one coherent bound; the thread is
/// still given the bounded drain below afterwards.
const CANCEL_HANDLE_RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Await the cancel-handle spawn_blocking task with a hard deadline,
/// WARNing (never blocking) if the handle never lands.
async fn bounded_cancel_handle_recv(
    recv_task: &mut tokio::task::JoinHandle<
        Result<gp_tunnel::CancelHandle, std::sync::mpsc::RecvError>,
    >,
) -> Option<gp_tunnel::CancelHandle> {
    match tokio::time::timeout(CANCEL_HANDLE_RECV_TIMEOUT, &mut *recv_task).await {
        Ok(Ok(Ok(handle))) => Some(handle),
        // Thread died, sender dropped, or the join task panicked:
        // no handle will EVER arrive; the bounded drain covers the
        // rest of the teardown.
        Ok(Ok(Err(_))) | Ok(Err(_)) => {
            tracing::debug!("tunnel thread exited before delivering cancel handle");
            None
        }
        Err(_elapsed) => {
            tracing::warn!(
                "cancel handle not delivered within {:?} — proceeding                  without it (this await was previously unbounded and could                  swallow Ctrl-C forever)",
                CANCEL_HANDLE_RECV_TIMEOUT,
            );
            None
        }
    }
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
    mut recv_task: tokio::task::JoinHandle<
        Result<gp_tunnel::CancelHandle, std::sync::mpsc::RecvError>,
    >,
    mut done_rx: tokio::sync::oneshot::Receiver<Result<()>>,
    tunnel_thread: std::thread::JoinHandle<()>,
    instance: &str,
) {
    if let Some(handle) = bounded_cancel_handle_recv(&mut recv_task).await {
        if let Err(e) = handle.cancel() {
            tracing::warn!("cancel after pre-handle shutdown failed: {e}");
        }
    }
    // Bounded: if the thread is wedged in a kernel-mode Wintun/PnP wait
    // the cancel never lands and `join()` would hang opc forever.
    match drain_done_with_timeout(&mut done_rx, TUNNEL_CANCEL_WEDGE_TIMEOUT).await {
        DrainOutcome::Resolved => {
            let _ = tunnel_thread.join();
        }
        DrainOutcome::Wedged => exit_wedged(instance),
    }
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
                 openprotect standardised on headless SAML. Falling back to \
                 `paste` for this session. Run `opc portal add <name> \
                 --auth-mode paste …` (or edit \
                 `~/.config/openprotect/config.toml`) to silence this warning."
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
    gateway: Option<String>,
    os: Option<String>,
    insecure: Option<bool>,
    vpnc_script: Option<String>,
    auth_mode: Option<SamlAuthMode>,
    saml_port: Option<u16>,
    only: Option<String>,
    route_conflict: Option<RouteConflictArg>,
    dns_zone: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    pkcs12: Option<String>,
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
    gateway: Option<String>,
    os: String,
    auth_mode: SamlAuthMode,
    saml_port: u16,
    vpnc_script: Option<String>,
    only: Option<String>,
    /// Policy for a `--only` prefix another interface already routes.
    route_conflict: gp_route::RouteConflictPolicy,
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
    cert: Option<String>,
    key: Option<String>,
    pkcs12: Option<String>,
    hip: HipMode,
    /// Absolute path to an external HIP wrapper script, when the
    /// user has asked to replace the built-in `opc hip-report`
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
    config: &gp_config::OpenProtectConfig,
) -> Result<ResolvedConnectSettings> {
    // --- Resolve the portal argument to a profile, if any. ---
    let portal_arg: Option<String> = match cli.portal {
        Some(p) => Some(p),
        None => config.default.portal.clone(),
    };
    let portal_arg = portal_arg.ok_or_else(|| {
        anyhow::anyhow!(
            "no portal given and no default profile set — pass a portal URL or \
             run `opc portal use <name>` first"
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
        .unwrap_or(0);
    let vpnc_script: Option<String> = cli
        .vpnc_script
        .or_else(|| profile.as_ref().and_then(|p| p.vpnc_script.clone()));
    let only: Option<String> = cli
        .only
        .or_else(|| profile.as_ref().and_then(|p| p.only.clone()));
    let gateway: Option<String> = cli
        .gateway
        .or_else(|| profile.as_ref().and_then(|p| p.gateway.clone()));
    let cert: Option<String> = cli
        .cert
        .or_else(|| profile.as_ref().and_then(|p| p.client_cert.clone()));
    let key: Option<String> = cli
        .key
        .or_else(|| profile.as_ref().and_then(|p| p.client_key.clone()));
    let pkcs12: Option<String> = cli
        .pkcs12
        .or_else(|| profile.as_ref().and_then(|p| p.client_pkcs12.clone()));
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
    // is NOT the shell the user invoked opc from.
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

    // Route-conflict policy. CLI/env only for now — there is no
    // profile field yet, so a profile cannot pin it.
    let route_conflict: gp_route::RouteConflictPolicy =
        cli.route_conflict.map(Into::into).unwrap_or_default();

    Ok(ResolvedConnectSettings {
        route_conflict,
        portal_url,
        cfg_user,
        user,
        gateway,
        os,
        auth_mode,
        saml_port,
        vpnc_script,
        only,
        dns_zones_override,
        cert,
        key,
        pkcs12,
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
/// whose CWD is not the shell the user ran `opc connect` from
/// (systemd units run with `WorkingDirectory=/`, for example).
/// Relative paths would resolve against that CWD and silently
/// miss. `fs::canonicalize` turns them into absolute paths while
/// simultaneously confirming the file exists.
#[cfg(unix)]
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

#[cfg(not(unix))]
fn resolve_hip_script_path(raw: &str) -> Result<String> {
    let path = std::fs::canonicalize(raw)
        .with_context(|| format!("`--hip-script {raw}`: file not found"))?;
    Ok(path.to_string_lossy().into_owned())
}

/// Submit a HIP report from Rust (bypassing libopenconnect's CSD
/// wrapper). Used on Windows where `openconnect_setup_csd` is a
/// no-op.
///
/// Flow: compute md5 → hipreportcheck → build XML → hipreport.esp.
///
/// `gateway_ip_pin` is the public IP we resolved for `gateway` BEFORE
/// any route / NRPT install. Once gp-dns has applied NRPT, resolving
/// the gateway hostname through the system resolver typically returns
/// an internal IP whose TLS cert doesn't match — so HIP has to keep
/// using the pre-NRPT IP. When set, it's plumbed through reqwest's
/// `resolve()` override so TLS / SNI still uses the hostname (cert
/// validation unaffected) while the connection goes to the pinned IP.
#[cfg(windows)]
async fn submit_hip_from_rust(
    gateway: &str,
    cookie: &str,
    client_ip: &str,
    client_os: &str,
    hip_mode: HipMode,
    gateway_ip_pin: Option<std::net::Ipv4Addr>,
) -> Result<()> {
    use gp_auth::hip::compute_csd_md5;

    let os_enum: ClientOs = client_os.parse().unwrap_or_default();
    let mut gp_params = GpParams::new(os_enum);
    // Inherit TLS permissiveness from the connect flow — HIP
    // endpoints live on the same gateway with the same cert.
    // TODO: thread --insecure from TunnelAttemptArgs so HIP inherits
    // TLS permissiveness. Conservative default for valid-cert gateways.
    gp_params.ignore_tls_errors = false;
    // Issue #43: pre-NRPT gateway IP pin + advertised port, via the
    // extracted pure helper (single splitter behind it).
    gp_params.resolve_override = hip_resolve_override(gateway, gateway_ip_pin);
    let client = GpClient::new(gp_params).context("creating HIP HTTP client")?;

    let md5 = compute_csd_md5(cookie);

    // Auto mode: check if the gateway actually wants a report.
    if hip_mode == HipMode::Auto {
        let t0 = phase_start(None, "hip_report_check");
        let check = client
            .hip_report_check(gateway, cookie, client_ip, &md5)
            .await
            .context("hipreportcheck")?;
        phase_finish(None, "hip_report_check", t0);
        if !check.needed {
            tracing::info!("HIP: gateway says report not needed, skipping");
            return Ok(());
        }
        tracing::info!("HIP: gateway requests report (md5={md5})");
    } else {
        tracing::info!("HIP: force mode, submitting report (md5={md5})");
    }

    // Extract username from cookie for the HIP XML.
    let user_name: String = serde_urlencoded::from_str::<Vec<(String, String)>>(cookie)
        .unwrap_or_default()
        .into_iter()
        .find_map(|(k, v)| if k == "user" { Some(v) } else { None })
        .unwrap_or_else(|| "openprotect".to_string());

    // Build HIP XML.
    let host = gp_hip::HostInfo::detect();
    let profile = gp_hip::HostProfile::from_client_os(Some(client_os));
    let generate_time = gp_hip_generate_time();
    let report = gp_hip::build_report(
        &md5,
        user_name,
        client_ip.to_string(),
        host,
        profile,
        generate_time,
    );
    let xml = report.to_xml();

    tracing::debug!("HIP: submitting {} bytes of XML", xml.len());

    let t0 = phase_start(None, "hip_report_post");
    client
        .submit_hip_report(gateway, cookie, client_ip, &xml)
        .await
        .context("hipreport submission")?;
    phase_finish(None, "hip_report_post", t0);

    tracing::info!("HIP: report submitted successfully");
    Ok(())
}

/// Build reqwest's `resolve()` override entry for the Windows HIP
/// lane (issue #43 seam S3): key on the BARE hostname (reqwest
/// matches the override against the request URL authority's host,
/// which for a bracketed IPv6 literal is `[addr]` — brackets kept,
/// matching `url::Url::host_str()`), pin it to the pre-NRPT public
/// IP on the ADVERTISED TLS port (default 443). `None` when there
/// is no pin (HIP then falls back to system DNS).
///
/// Extracted from the body of `submit_hip_from_rust` so the pin
/// contract is unit-testable; the `gateway_ip_pin = None` case
/// (the second-order #43 casualty: the broken exclude resolution
/// silently disabled this override for `host:port` gateways) is
/// pinned explicitly.
#[cfg(windows)]
fn hip_resolve_override(
    gateway: &str,
    pin: Option<std::net::Ipv4Addr>,
) -> Option<(String, SocketAddr)> {
    let ip = pin?;
    let port = parse_gateway_port(gateway).unwrap_or(443);
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    Some((gateway_hostname(gateway).to_string(), addr))
}

/// Reduce a `gateway` label — bare `host`, `host:port`, or the
/// historic profile shape `https://host:port/...` — to its URL
/// authority component (scheme and path stripped). Shared front-end
/// for the HIP pin helpers so both halves agree on one parse.
#[cfg(windows)]
fn gateway_authority(gateway: &str) -> &str {
    gp_proto::params::normalize_server(gateway)
        .split('/')
        .next()
        .unwrap_or("")
}

/// Pull the TCP port out of a `gateway` string (see
/// [`gateway_authority`]). Delegates to the single bracket-aware
/// splitter (issue #43): the pre-#43 `rsplit_once(':')` here had a
/// dead guard (`port.contains(':')` can never fire after the split)
/// and mangled a bare IPv6 label into `Some(1)`; `split_host_port`
/// treats an unbracketed multi-colon head as an address, not a port.
/// Returns `None` when no explicit, in-range port is present.
#[cfg(windows)]
fn parse_gateway_port(gateway: &str) -> Option<u16> {
    gp_proto::params::service_port(gateway_authority(gateway))
}

/// Host half of a gateway label (see [`gateway_authority`]), for use
/// as the lookup key in reqwest's resolve override map: reqwest
/// matches the key against the request URL authority's host string
/// (`url::Url::host_str()`), so a bracketed IPv6 keeps its brackets
/// and an unbracketed one is returned whole (issue #43 — the old
/// naive rsplit produced mangled keys like `"fd00:"` that never
/// matched, silently losing the pin). Delegates to the shared
/// `server_field`/`split_host_port` rule.
#[cfg(windows)]
fn gateway_hostname(gateway: &str) -> &str {
    gp_proto::params::server_field(gateway_authority(gateway))
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
/// fields and md5s those bytes. Our [`gp_auth::hip::compute_csd_md5`]
/// parses the cookie via `serde_urlencoded::from_str` and re-serializes
/// through `serde_urlencoded::to_string` before md5 — i.e. it produces
/// md5 over the *canonical form-urlencoded* representation.
///
/// For both md5s to agree, the cookie bytes handed to libopenconnect and
/// the cookie bytes we md5 over must be byte-identical **after** any
/// encoding normalization. Practically, that means the builder itself
/// must emit canonical serde_urlencoded output. If we emit raw (e.g.
/// `user=alice@ad.example.edu`), libopenconnect md5s `@` bytes while
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
#[cfg(unix)]
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
    // flag on their next `wait_for`, so `opc disconnect` correctly
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
#[cfg(unix)]
const IPC_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle one client connection: one request, one response, close.
#[cfg(unix)]
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

// ---------------------------------------------------------------------------
// Windows Named Pipe IPC server
// ---------------------------------------------------------------------------

#[cfg(windows)]
const IPC_PIPE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(windows)]
async fn spawn_ipc_server_pipe(
    pipe_name: String,
    base: SharedBase,
    started_at: Instant,
    disconnect_tx: tokio::sync::watch::Sender<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    use gp_ipc::{bind_server_pipe, create_pipe_instance};

    // Create the first pipe instance — fails if another server exists.
    let first = bind_server_pipe(&pipe_name)
        .await
        .with_context(|| format!("binding named pipe {pipe_name}"))?;
    tracing::info!("control pipe listening on {pipe_name}");

    let disconnect_tx = Arc::new(disconnect_tx);

    Ok(tokio::spawn(async move {
        let mut server = first;
        loop {
            // Wait for a client to connect to this pipe instance.
            if let Err(e) = server.connect().await {
                tracing::debug!("named pipe connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                // Try creating a fresh instance.
                match create_pipe_instance(&pipe_name) {
                    Ok(s) => server = s,
                    Err(e) => {
                        tracing::warn!("named pipe create failed: {e}");
                        return;
                    }
                }
                continue;
            }

            // Swap: hand the connected instance to a handler, then
            // create a new instance for the next client. Serve the
            // current client even if next-instance creation fails.
            let connected = server;

            let base = Arc::clone(&base);
            let disconnect_tx = Arc::clone(&disconnect_tx);
            tokio::spawn(async move {
                if let Err(e) =
                    handle_ipc_client_pipe(connected, base, started_at, disconnect_tx).await
                {
                    tracing::debug!("pipe client error: {e}");
                }
            });

            match create_pipe_instance(&pipe_name) {
                Ok(next) => server = next,
                Err(e) => {
                    tracing::warn!("named pipe create (next instance) failed: {e}");
                    // Can't accept more clients, but the in-flight handler
                    // will still complete. Break out of the loop.
                    return;
                }
            }
        }
    }))
}

#[cfg(windows)]
async fn handle_ipc_client_pipe(
    mut server: gp_ipc::NamedPipeServer,
    base: SharedBase,
    started_at: Instant,
    disconnect_tx: Arc<tokio::sync::watch::Sender<bool>>,
) -> Result<(), IpcError> {
    use gp_ipc::{read_request_pipe, write_response_pipe};

    let req =
        match tokio::time::timeout(IPC_PIPE_READ_TIMEOUT, read_request_pipe(&mut server)).await {
            Ok(Ok(req)) => req,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(IpcError::Protocol(
                    "pipe client did not send a request within the timeout".into(),
                ))
            }
        };
    let resp = match req {
        IpcRequest::Status => {
            let snapshot_base = {
                let guard = base.read().expect("SharedBase RwLock poisoned");
                guard.clone()
            };
            IpcResponse::Status(build_snapshot(&snapshot_base, started_at))
        }
        IpcRequest::Disconnect => {
            let _ = disconnect_tx.send(true);
            IpcResponse::Ok
        }
    };
    write_response_pipe(&mut server, &resp).await?;
    Ok(())
}

fn default_vpnc_script() -> Option<String> {
    for path in [
        "/etc/vpnc/vpnc-script",
        "/usr/share/vpnc-scripts/vpnc-script",
        "/opt/homebrew/etc/vpnc/vpnc-script",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

// The bundled vpnc-script shim that earlier releases installed under
// `$XDG_RUNTIME_DIR/openprotect-vpnc-*.sh` is gone. Native route
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
///   is sorted for stable `opc status` / log output.
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
/// `opc connect` / `opc portal add` rather than hours later via
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
///   `opc status` / `opc disconnect`.
///
/// If `split_routes` is non-empty, the thread uses `gp-route` to
/// install those routes natively on the tun interface after
/// `setup_tun_device` returns — no shell script involvement. Routes
/// are reverted on the way out.
/// The session-config prelude of [`run_tunnel`], generic over the
/// gp-tunnel [`gp_tunnel::SessionHandle`] seam (issue #43, mirrors
/// gp-route's injectable `CommandRunner` precedent): production
/// passes the real `OpenConnectSession`; unit tests pass a
/// recording double and pin exactly which hostname/port values are
/// handed to libopenconnect — without faking FFI.
///
/// The gateway address is split here (via
/// [`gp_tunnel::parse_tunnel_target`] + `configure_target`), NOT
/// upstream: `Gateway::address` and every display / `--gateway` /
/// auth-URL consumer keep the verbatim `host:port` label (issue #42
/// contract), and only the CSTP-side primitives get halves.
fn configure_tunnel_session<S: gp_tunnel::SessionHandle + ?Sized>(
    session: &mut S,
    gateway_host: &str,
    os: &str,
    cookie: &str,
    client_cert: Option<&str>,
    client_key: Option<&str>,
) -> Result<()> {
    session.set_protocol_gp().context("set_protocol_gp")?;
    let target = gp_tunnel::parse_tunnel_target(gateway_host).context("parse_tunnel_target")?;
    session
        .configure_target(&target)
        .context("configure_target")?;
    session.set_os_spoof(os).context("set_os_spoof")?;
    session.set_cookie(cookie).context("set_cookie")?;
    if let (Some(cert), Some(key)) = (client_cert, client_key) {
        session
            .set_client_cert(cert, key)
            .context("set_client_cert")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tunnel(
    attempt: u32,
    gateway_host: &str,
    cookie: &str,
    os: &str,
    vpnc_script: Option<&str>,
    split_routes: Vec<String>,
    route_conflict: gp_route::RouteConflictPolicy,
    reconnect_enabled: bool,
    enable_esp: bool,
    hip_mode: HipMode,
    hip_script: Option<String>,
    split_dns_zones: Vec<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
    instance: String,
    cancel_tx: std::sync::mpsc::Sender<gp_tunnel::CancelHandle>,
    ready_tx: std::sync::mpsc::Sender<TunnelReady>,
) -> Result<()> {
    let t0 = phase_start(Some(attempt), "session_create");
    let mut session =
        OpenConnectSession::new("PAN GlobalProtect").context("creating openconnect session")?;
    phase_finish(Some(attempt), "session_create", t0);

    configure_tunnel_session(
        &mut session,
        gateway_host,
        os,
        cookie,
        client_cert.as_deref(),
        client_key.as_deref(),
    )?;

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
            // If we're not under sudo, keep the current effective uid
            // instead of forcing uid 0; otherwise libopenconnect tries
            // `setgid(0)` / `setuid(0)` from an already-unprivileged
            // process and HIP wrapper exec fails.
            let uid = resolve_csd_wrapper_uid();
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

    // CSTP handshake. The "uncancellable once entered" wording is
    // load-bearing for users reading a hang report: between the
    // START stamp and the FINISH stamp, the only escape is the
    // cmd-pipe poll already armed by the cancel handle (sent above,
    // before any blocking work) or libopenconnect's own timeouts —
    // Ctrl-C will not land until one of those fires.
    let make_cstp_t0 = phase_start_with(
        Some(attempt),
        "make_cstp",
        "uncancellable once entered (cmd-pipe cancel is the only interrupt)",
    );
    session
        .make_cstp_connection()
        .context("make_cstp_connection")?;
    phase_finish(Some(attempt), "make_cstp", make_cstp_t0);

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

    // Wintun device creation + (non-native path) script hook. Same
    // honesty note as make_cstp: the kernel-mode PnP wait documented
    // in the gp-dns windows_nrpt module lives HERE, and nothing we
    // own can interrupt it once entered.
    let setup_tun_t0 = phase_start_with(
        Some(attempt),
        "setup_tun",
        "uncancellable once entered (Wintun/PnP kernel wait)",
    );
    session
        .setup_tun_device(vpnc_script)
        .context("setup_tun_device")?;
    phase_finish(Some(attempt), "setup_tun", setup_tun_t0);

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
    // `opc status` reports `Connecting` until the routes are fully
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
        // The nameservers we are about to hand to gp-dns usually sit in
        // the tunnel's own subnet, which the user's `--only` prefixes do
        // not cover. Without a route they are unreachable, and the
        // split-DNS config below then points every matching query at a
        // dead address. Pin them here so the existing route install and
        // revert paths carry them.
        let pushed_dns: Vec<std::net::IpAddr> = ip_info
            .as_ref()
            .map(|i| &i.dns)
            .into_iter()
            .flatten()
            .filter_map(|s| s.parse().ok())
            .collect();
        let mut routes = split_routes.clone();
        let tunnel_net = ipv4.zip(
            ip_info
                .as_ref()
                .and_then(|i| i.netmask.as_deref())
                .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()),
        );
        let dns_plan = gp_route::dns_pin_routes(&routes, &pushed_dns, tunnel_net);
        if !dns_plan.pins.is_empty() {
            tracing::info!(
                "gp-route: pinning {} pushed nameserver(s) into the tunnel — {}",
                dns_plan.pins.len(),
                dns_plan.pins.join(" ")
            );
            routes.extend(dns_plan.pins.iter().cloned());
        }
        // Say what was left out. A resolver the gateway pushed but we
        // did not route is the exact shape of issue #23, so it must be
        // visible in the log rather than inferred from silence.
        if !dns_plan.skipped_global.is_empty() {
            tracing::warn!(
                "gp-route: NOT routing {} globally-routable pushed nameserver(s) into the \
                 tunnel — {}. Forcing a public resolver through a split tunnel breaks DNS \
                 for the whole host when the gateway does not forward it. Add it to --only \
                 if your gateway really does own that address.",
                dns_plan.skipped_global.len(),
                dns_plan
                    .skipped_global
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        if !dns_plan.skipped_ipv6.is_empty() {
            tracing::warn!(
                "gp-route: {} pushed IPv6 nameserver(s) cannot be routed into the tunnel \
                 (gp-route is IPv4-only) — {}. Queries to them will leave via the physical \
                 interface.",
                dns_plan.skipped_ipv6.len(),
                dns_plan
                    .skipped_ipv6
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        let config = gp_route::TunConfig {
            ifname,
            ipv4,
            mtu,
            gateway_exclude: resolve_gateway_for_exclude(gateway_host),
            routes,
            route_conflict,
        };
        tracing::info!(
            "gp-route: applying {} route(s) natively on {}",
            config.routes.len(),
            config.ifname
        );
        // opc-side banner bracketing the route-owner's subprocess
        // INFO lines (gp-route adds its own per-command lines).
        note_phase("gp_route_apply", PhaseKind::Auto);
        let route_t0 = phase_start(Some(attempt), "gp_route_apply");
        let state = gp_route::apply(&config).context("gp-route apply")?;
        phase_finish(Some(attempt), "gp_route_apply", route_t0);
        note_phase("tunnel_setup_between_apply_steps", PhaseKind::Auto);
        // One summary line, so a user whose containers stop answering
        // mid-session can connect the two events without reading back
        // through per-route warnings.
        let displaced: Vec<&str> = state.displaced_cidrs().collect();
        if !displaced.is_empty() {
            tracing::warn!(
                "gp-route: {} prefix(es) taken over from other interfaces (Docker bridges, \
                 another VPN): {} — host traffic to these goes through the tunnel until \
                 disconnect, when the previous routes are restored. Pass \
                 `--route-conflict fail` or `skip` to change this.",
                displaced.len(),
                displaced.join(" ")
            );
        }
        Some(state)
    } else {
        None
    };

    // Native DNS configuration — runs only when we also took the
    // native route path. Any vpnc-script the user pointed `opc` at
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
            instance: instance.clone(),
        };
        if !config.servers.is_empty() {
            tracing::info!(
                "gp-dns: applying {} nameserver(s) on {} (search={:?}, split={:?})",
                config.servers.len(),
                config.ifname,
                config.search_domains,
                config.split_domains
            );
            // NRPT apply: the registry write + DnsIndex paramchange.
            // Bracketed at INFO because the SCM can serialise the
            // paramchange behind other service traffic (the same
            // serialization that makes exit_wedged's cleanup slow —
            // so a phase here can legitimately sit for tens of
            // seconds; the watchdog report keeps it visible).
            note_phase("nrpt_apply", PhaseKind::Auto);
            let nrpt_t0 = phase_start(Some(attempt), "nrpt_apply");
            match gp_dns::apply(&config) {
                Ok(state) => {
                    phase_finish(Some(attempt), "nrpt_apply", nrpt_t0);
                    note_phase_clear();
                    // NRPT is now live in the registry. Arm crash
                    // cleanup so an abrupt death (console close, logoff,
                    // shutdown, panic) before the normal revert still
                    // clears it. Disarmed on the revert path below.
                    #[cfg(windows)]
                    crash_cleanup::arm(&instance);
                    Some(state)
                }
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
                        let rb_t0 = phase_start(Some(attempt), "rollback_gp_route_after_dns_fail");
                        for rev_err in gp_route::revert(route_state) {
                            tracing::warn!("gp-route revert (on dns failure): {rev_err}");
                        }
                        phase_finish(Some(attempt), "rollback_gp_route_after_dns_fail", rb_t0);
                    }
                    phase_finish(Some(attempt), "nrpt_apply", nrpt_t0);
                    note_phase_clear();
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
    let ready_t0 = phase_start(Some(attempt), "tunnel_ready_publish");
    let _ = ready_tx.send(TunnelReady {
        ifname: ifname.clone(),
        ip_info: ip_info.clone(),
    });
    phase_finish(Some(attempt), "tunnel_ready_publish", ready_t0);

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
    note_phase("teardown_dns_revert", PhaseKind::Auto);
    let dns_rev_t0 = phase_start(Some(attempt), "teardown_dns_revert");
    if let Some(state) = native_dns_state {
        for err in gp_dns::revert(&state) {
            tracing::warn!("gp-dns revert: {err}");
        }
        // NRPT is reverted — nothing left for the crash handlers to
        // sweep, so disarm to avoid a redundant (harmless but noisy)
        // sweep if the process dies abruptly during the rest of
        // teardown or a between-attempts reconnect gap.
        #[cfg(windows)]
        crash_cleanup::disarm();
    }
    phase_finish(Some(attempt), "teardown_dns_revert", dns_rev_t0);
    note_phase("teardown_route_revert", PhaseKind::Auto);
    let route_rev_t0 = phase_start(Some(attempt), "teardown_route_revert");
    if let Some(state) = native_route_state {
        for err in gp_route::revert(&state) {
            tracing::warn!("gp-route revert: {err}");
        }
    }
    phase_finish(Some(attempt), "teardown_route_revert", route_rev_t0);
    note_phase_clear();

    run_res.context("openconnect mainloop")?;
    tracing::info!(
        "{}",
        phase_line(
            PhaseEvent::Finish,
            Some(attempt),
            "session_destruction",
            process_elapsed(),
            Some("final teardown complete; returning to attempt loop")
        )
    );
    Ok(())
}

/// Mask a file path for display — show only the filename, not the full path.
fn mask_path(s: &str) -> String {
    std::path::Path::new(s)
        .file_name()
        .map(|f| format!(".../{}", f.to_string_lossy()))
        .unwrap_or_else(|| "***".to_string())
}

#[cfg(all(test, unix))]
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
            gateway: None,
            os: None,
            insecure: None,
            vpnc_script: None,
            auth_mode: None,
            saml_port: None,
            only: None,
            route_conflict: None,
            dns_zone: None,
            cert: None,
            key: None,
            pkcs12: None,
            hip: None,
            hip_script: None,
            reconnect: None,
            metrics_port: None,
            okta_url: None,
            esp: None,
        }
    }

    fn config_with_profile() -> gp_config::OpenProtectConfig {
        let mut c = gp_config::OpenProtectConfig::default();
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

    fn sample_gateway(name: &str, address: &str) -> Gateway {
        Gateway {
            address: address.into(),
            description: name.into(),
            priority: 0,
            priority_rules: Vec::new(),
        }
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
        let cfg = gp_config::OpenProtectConfig::default();
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
        assert_eq!(r.saml_port, 0);
        assert!(!r.insecure);
    }

    #[test]
    fn resolve_unknown_auth_mode_in_profile_falls_back() {
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        // consume the next token, so `opc connect --insecure
        // vpn.example.com` parsed `vpn.example.com` as the
        // --insecure value and blew up with a bool parse error.
        // Now that `require_equals` is set, only `--insecure=…`
        // syntax can supply a value.
        use clap::Parser;
        let cli = Cli::try_parse_from(["opc", "connect", "--insecure", "vpn.example.com"])
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
        let cli = Cli::try_parse_from(["opc", "connect", "--insecure=false", "vpn.example.com"])
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
        let result = Cli::try_parse_from(["opc", "connect", "--insecure", "true"]);
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
        let cfg = gp_config::OpenProtectConfig::default();
        let overrides = CliConnectOverrides {
            portal: Some("vpn.example.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert!(!r.reconnect, "default should be off (opt-in)");
    }

    #[test]
    fn resolve_reconnect_inherits_from_profile() {
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let cli = Cli::try_parse_from(["opc", "connect", "--reconnect", "vpn.example.com"])
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        // accepts it as an input value. That lets opc emit a
        // custom migration error at connect time instead of
        // clap's generic "invalid value" response. This is a
        // one-shot UX improvement for users who run the old
        // flag after upgrading.
        let cli = Cli::try_parse_from([
            "opc",
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
        // opc — they should log a migration warning and return
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
            "opc",
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let cli = Cli::try_parse_from(["opc", "connect", "--instance", "work", "vpn.example.com"])
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
    fn connect_accepts_gateway_flag() {
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["opc", "connect", "--gateway", "US East", "vpn.example.com"])
                .expect("--gateway must parse");
        match cli.command {
            Some(Commands::Connect {
                gateway, portal, ..
            }) => {
                assert_eq!(gateway.as_deref(), Some("US East"));
                assert_eq!(portal.as_deref(), Some("vpn.example.com"));
            }
            _ => panic!("expected Commands::Connect"),
        }
    }

    #[test]
    fn match_gateway_override_accepts_name_or_address() {
        let gateways = vec![
            sample_gateway("US East", "gw1.example.com"),
            sample_gateway("EU West", "gw2.example.com"),
        ];

        let by_name = match_gateway_override(&gateways, "us east").unwrap();
        assert_eq!(by_name.address, "gw1.example.com");

        let by_address = match_gateway_override(&gateways, "https://gw2.example.com/").unwrap();
        assert_eq!(by_address.description, "EU West");
    }

    #[test]
    fn match_gateway_override_rejects_missing_name() {
        let gateways = vec![sample_gateway("US East", "gw1.example.com")];
        let err = match_gateway_override(&gateways, "missing").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("did not match any portal gateways"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("US East (gw1.example.com)"),
            "available gateways missing from error: {msg}"
        );
    }

    #[test]
    fn match_gateway_override_rejects_ambiguous_name() {
        let gateways = vec![
            sample_gateway("Shared Name", "gw1.example.com"),
            sample_gateway("Shared Name", "gw2.example.com"),
        ];
        let err = match_gateway_override(&gateways, "shared name").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("matched multiple gateways"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("gw1.example.com"),
            "missing first gateway: {msg}"
        );
        assert!(
            msg.contains("gw2.example.com"),
            "missing second gateway: {msg}"
        );
    }

    #[test]
    fn gateway_latency_sort_puts_failures_last() {
        let mut ranked = [
            RankedGateway {
                gateway: sample_gateway("Slow", "gw3.example.com"),
                probe: GatewayProbe::Reachable(Duration::from_millis(90)),
            },
            RankedGateway {
                gateway: sample_gateway("Timeout", "gw4.example.com"),
                probe: GatewayProbe::TimedOut,
            },
            RankedGateway {
                gateway: sample_gateway("Fast", "gw1.example.com"),
                probe: GatewayProbe::Reachable(Duration::from_millis(12)),
            },
            RankedGateway {
                gateway: sample_gateway("Error", "gw2.example.com"),
                probe: GatewayProbe::Failed("dns".into()),
            },
        ];

        ranked.sort_by(|a, b| {
            gateway_probe_sort_key(&a.probe)
                .cmp(&gateway_probe_sort_key(&b.probe))
                .then_with(|| gateway_name(&a.gateway).cmp(gateway_name(&b.gateway)))
                .then_with(|| a.gateway.address.cmp(&b.gateway.address))
        });

        let order: Vec<_> = ranked
            .iter()
            .map(|entry| entry.gateway.address.as_str())
            .collect();
        assert_eq!(
            order,
            vec![
                "gw1.example.com",
                "gw3.example.com",
                "gw2.example.com",
                "gw4.example.com",
            ]
        );
    }

    #[test]
    fn resolve_gateway_cli_overrides_profile() {
        let mut cfg = gp_config::OpenProtectConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                gateway: Some("profile-gw".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        // CLI wins
        let overrides = CliConnectOverrides {
            gateway: Some("cli-gw".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.gateway.as_deref(), Some("cli-gw"));
    }

    #[test]
    fn resolve_gateway_inherits_from_profile() {
        let mut cfg = gp_config::OpenProtectConfig::default();
        cfg.default.portal = Some("work".into());
        cfg.set_portal(
            "work",
            gp_config::PortalProfile {
                url: "vpn.example.com".into(),
                gateway: Some("saved-gw".into()),
                ..gp_config::PortalProfile::default()
            },
        );
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert_eq!(r.gateway.as_deref(), Some("saved-gw"));
    }

    #[test]
    fn resolve_gateway_none_when_neither_set() {
        let cfg = config_with_profile();
        let r = resolve_connect_settings(empty_overrides(), &cfg).unwrap();
        assert!(r.gateway.is_none());
    }

    #[test]
    fn disconnect_accepts_instance_and_all_but_not_together() {
        use clap::Parser;
        // Just --instance.
        let cli = Cli::try_parse_from(["opc", "disconnect", "-i", "work"]).unwrap();
        matches!(cli.command, Some(Commands::Disconnect { .. }));

        // Just --all.
        let cli = Cli::try_parse_from(["opc", "disconnect", "--all"]).unwrap();
        matches!(cli.command, Some(Commands::Disconnect { all: true, .. }));

        // Both together → clap should error (conflicts_with).
        let result = Cli::try_parse_from(["opc", "disconnect", "-i", "work", "--all"]);
        assert!(
            result.is_err(),
            "--instance and --all must conflict (parsed OK unexpectedly)"
        );
    }

    #[test]
    fn status_accepts_instance_and_all() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opc", "status", "--instance", "work"]).unwrap();
        match cli.command {
            Some(Commands::Status { instance, all }) => {
                assert_eq!(instance.as_deref(), Some("work"));
                assert!(!all);
            }
            _ => panic!("expected Commands::Status"),
        }
        let cli = Cli::try_parse_from(["opc", "status", "--all"]).unwrap();
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
        let cfg = gp_config::OpenProtectConfig::default();
        let overrides = CliConnectOverrides {
            portal: Some("vpn.example.com".into()),
            ..empty_overrides()
        };
        let r = resolve_connect_settings(overrides, &cfg).unwrap();
        assert_eq!(r.os, "linux");
        assert_eq!(r.auth_mode, SamlAuthMode::Paste);
        assert_eq!(r.saml_port, 0);
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
            "opc",
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
            "opc-hip-script-test-{}-{}-{name}",
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let mut cfg = gp_config::OpenProtectConfig::default();
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
            "opc",
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
        let mut cfg = gp_config::OpenProtectConfig::default();
        cfg.set_portal("work", profile.clone());

        // Round-trip through `OpenProtectConfig::save_to` + `load_from`
        // rather than `toml::to_string` directly — this crate has
        // no direct `toml` dep (it goes through gp-config), and the
        // save/load path is the real persistence surface anyway.
        let tmp = std::env::temp_dir().join(format!(
            "opc-dns-zones-roundtrip-{}.toml",
            std::process::id()
        ));
        cfg.save_to(&tmp).expect("save");
        let on_disk = std::fs::read_to_string(&tmp).expect("read back");
        assert!(
            on_disk.contains("dns_zones"),
            "serialised TOML must contain dns_zones field:\n{on_disk}"
        );
        let round = gp_config::OpenProtectConfig::load_from(&tmp).expect("load");
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
            "opc-hip-script-does-not-exist-{}",
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
        let cfg = gp_config::OpenProtectConfig::default();
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
        let cfg = gp_config::OpenProtectConfig::default();
        let resolved = resolve_connect_settings(overrides, &cfg).unwrap();
        let hip_script = resolved.hip_script.expect("hip_script must be set");
        assert!(std::path::Path::new(&hip_script).is_absolute());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_hip_script_falls_back_to_profile_and_cli_overrides() {
        let profile_path = tmp_file_with_mode("prof", 0o755);
        let cli_path = tmp_file_with_mode("cli", 0o755);

        let mut cfg = gp_config::OpenProtectConfig::default();
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
        let rel = format!("opc-hip-rel-test-{}.sh", std::process::id());
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
            "opc",
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
        let cookie = build_openconnect_cookie(&cookie_with_username("alice@ad.example.edu"));
        assert!(
            cookie.contains("user=alice%40ad.example.edu"),
            "expected percent-encoded @, got: {cookie}"
        );
        assert!(
            !cookie.contains("user=alice@ad.example.edu"),
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

    #[cfg(unix)]
    #[test]
    fn resolve_csd_wrapper_uid_prefers_sudo_uid() {
        assert_eq!(resolve_csd_wrapper_uid_impl(Some("501"), 0), 501);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_csd_wrapper_uid_falls_back_to_current_euid() {
        assert_eq!(resolve_csd_wrapper_uid_impl(None, 501), 501);
        assert_eq!(resolve_csd_wrapper_uid_impl(Some("not-a-number"), 501), 501);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_macos_connect_privileges_requires_root() {
        assert!(ensure_macos_connect_privileges_impl(0).is_ok());
        assert!(ensure_macos_connect_privileges_impl(501).is_err());
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

// CLI-parse tests that must run on EVERY platform — the `recover` /
// `doctor` recovery commands are Windows-first, so gating them behind
// the Unix-only `mod tests` above would leave them unexercised on the
// platform they exist for.
#[cfg(test)]
mod recover_cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn recover_accepts_instance_and_all_but_not_together() {
        // Bare `opc recover` → default instance, no --all.
        let cli = Cli::try_parse_from(["opc", "recover"]).unwrap();
        match cli.command {
            Some(Commands::Recover { instance, all }) => {
                assert!(instance.is_none());
                assert!(!all);
            }
            _ => panic!("expected Commands::Recover"),
        }

        // `opc recover -i work`.
        let cli = Cli::try_parse_from(["opc", "recover", "-i", "work"]).unwrap();
        match cli.command {
            Some(Commands::Recover { instance, all }) => {
                assert_eq!(instance.as_deref(), Some("work"));
                assert!(!all);
            }
            _ => panic!("expected Commands::Recover"),
        }

        // `opc recover --all`.
        let cli = Cli::try_parse_from(["opc", "recover", "--all"]).unwrap();
        match cli.command {
            Some(Commands::Recover { all: true, .. }) => {}
            _ => panic!("expected Commands::Recover with --all"),
        }

        // --instance and --all conflict.
        let result = Cli::try_parse_from(["opc", "recover", "-i", "work", "--all"]);
        assert!(
            result.is_err(),
            "recover --instance and --all must conflict"
        );
    }

    // Doctor verdict table — per-instance attribution (replaces the
    // old count-vs-sessions heuristic; every cell from the
    // pre-rewrite table is preserved below in scan form, plus the
    // cells the audit proved wrong).
    fn inst(name: &str, liveness: LivenessProbe, rules: Option<usize>) -> DoctorInstance {
        DoctorInstance {
            name: name.to_string(),
            liveness,
            rules,
        }
    }
    fn scan(
        elevated: bool,
        total: Option<usize>,
        instances: Vec<DoctorInstance>,
        adapters: usize,
    ) -> DoctorScan {
        DoctorScan {
            elevated,
            total_rules: total,
            instances,
            adapters,
        }
    }

    #[test]
    fn doctor_verdict_distinguishes_leaked_live_and_inconclusive() {
        use DoctorVerdict::*;
        // ---- cells preserved verbatim from the pre-rewrite table ----
        // Nothing present at all is unambiguously clean, even non-elevated.
        assert_eq!(doctor_verdict_scan(&scan(true, Some(0), vec![], 0)), NoLeak);
        assert_eq!(
            doctor_verdict_scan(&scan(false, Some(0), vec![], 0)),
            NoLeak
        );
        // A rule owned by a live session is NOT a leak.
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(1),
                vec![inst("default", LivenessProbe::Responsive, Some(1))],
                0
            )),
            NoLeak
        );
        // A rule with no live owner IS a leak.
        assert_eq!(doctor_verdict_scan(&scan(true, Some(1), vec![], 0)), Leaked);
        // Orphan adapter with no live session is a leak.
        assert_eq!(doctor_verdict_scan(&scan(true, Some(0), vec![], 1)), Leaked);
        // Non-elevated with something present: can't confirm ownership.
        assert_eq!(
            doctor_verdict_scan(&scan(false, Some(1), vec![], 0)),
            Inconclusive
        );
        assert_eq!(
            doctor_verdict_scan(&scan(false, Some(0), vec![], 1)),
            Inconclusive
        );
    }

    #[test]
    fn doctor_multi_namespace_session_is_not_a_leak() {
        // THE false positive the old heuristic produced: one healthy
        // session, three DNS namespaces => three rules, one session.
        // Old code: nrpt_count(3) > live_sessions(1) => Leaked
        // (watched failing as doctor_verdict(true,3,1,0)==Leaked on
        // 2026-09-28). Per-instance attribution: all rules owned by
        // the responsive instance, residue zero => NoLeak.
        use DoctorVerdict::*;
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(3),
                vec![inst("work", LivenessProbe::Responsive, Some(3))],
                1
            )),
            NoLeak,
            "a healthy multi-namespace session must never flag a leak"
        );
    }

    #[test]
    fn doctor_adapter_count_beyond_live_sessions_flags() {
        // New cell (live=1, adapters=2): the live session owns one
        // node; a second OpenConnect/OpenProtect node with no owner
        // is a leak. The old (live==0 && adapters>0) condition let
        // this slip (watched failing as doctor_verdict(true,0,1,2)==NoLeak
        // before the rework). Comparison stays inside the
        // snapshot_closed set (see DoctorScan::adapters doc):
        // foreign Wintun devices are invisible to report AND removal
        // — one closed set, deliberately blind (do not widen).
        use DoctorVerdict::*;
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(1),
                vec![inst("default", LivenessProbe::Responsive, Some(1))],
                2
            )),
            Leaked
        );
        // Exactly one node per live session stays clean.
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(1),
                vec![inst("default", LivenessProbe::Responsive, Some(1))],
                1
            )),
            NoLeak
        );
    }

    #[test]
    fn doctor_failed_probes_yield_unknown_never_absent() {
        use DoctorVerdict::*;
        // A busy/unanswerable pipe (wedged-live session) must NOT
        // have its rules counted as leak evidence...
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(2),
                vec![inst("work", LivenessProbe::Unknown, Some(2))],
                1
            )),
            Unknown,
            "busy probe must yield UNKNOWN, never a Leaked verdict"
        );
        // ...and a failed RULE COUNT on a responsive instance is
        // UNKNOWN too (not silently zero).
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(0),
                vec![inst("work", LivenessProbe::Responsive, None)],
                0
            )),
            Unknown
        );
        // A failed TOTAL enumeration is UNKNOWN even when nothing
        // else is present.
        assert_eq!(doctor_verdict_scan(&scan(true, None, vec![], 0)), Unknown);
        assert_eq!(doctor_verdict_scan(&scan(false, None, vec![], 3)), Unknown);
        // Rules parked under a provably-absent name are still leaks.
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(1),
                vec![inst("dead", LivenessProbe::Absent, Some(1))],
                0
            )),
            Leaked
        );
        // Attribution racing the enumeration (more owned than total)
        // is UNKNOWN, not a guess.
        assert_eq!(
            doctor_verdict_scan(&scan(
                true,
                Some(1),
                vec![inst("work", LivenessProbe::Responsive, Some(2))],
                1
            )),
            Unknown
        );
    }

    #[test]
    fn liveness_classification_never_launders_failure_into_absence() {
        // Decision-logic seam for the busy-pipe class of hang
        // reports: only ERROR_FILE_NOT_FOUND (IpcError::NotRunning)
        // may classify as Absent. The client-open busy-pipe mapping is
        // now the dedicated `IpcError::PipeBusy` variant (post the ipc
        // owner's gp-ipc lib.rs:622 fix), which — like the server-side
        // `AlreadyRunning` shape and permission-denied, protocol and io
        // errors — must yield UNKNOWN, never absence. Both busy-shape
        // variants are pinned: `PipeBusy` is what `client_roundtrip`
        // actually returns on a busy pipe today; `AlreadyRunning` is
        // kept as the server-create-shape guard so a future refactor
        // cannot launder a busy pipe into a leak verdict. Integration
        // gap: a REAL wedged pipe cannot be spun up in a unit test, so
        // this pins the decision over the enum; the end-to-end busy-
        // pipe probe is covered by gp-ipc's own suite plus manual
        // doctor runs.
        use LivenessProbe::*;
        let ok = Ok(IpcResponse::Status(gp_ipc::StateSnapshot {
            instance: "x".into(),
            portal: "p".into(),
            gateway: "g".into(),
            user: "u".into(),
            reported_os: "win".into(),
            uptime_seconds: 0,
            started_at_unix: 0,
            routes: vec![],
            tun_ifname: None,
            local_ipv4: None,
            state: SessionState::Connected,
        }));
        assert_eq!(classify_liveness(&ok), Responsive);
        assert_eq!(
            classify_liveness(&Err(IpcError::NotRunning(std::path::PathBuf::from("p")))),
            Absent
        );
        assert_eq!(
            classify_liveness(&Err(IpcError::AlreadyRunning(std::path::PathBuf::from(
                "p"
            )))),
            Unknown,
            "AlreadyRunning (server-create shape) must not be absent"
        );
        assert_eq!(
            classify_liveness(&Err(IpcError::PipeBusy(std::path::PathBuf::from("p")))),
            Unknown,
            "PipeBusy is the post-fix client busy-pipe mapping — the exact wedge case; \
             must be Unknown, never laundered into Absent"
        );
        assert_eq!(
            classify_liveness(&Err(IpcError::PermissionDenied(std::path::PathBuf::from(
                "p"
            )))),
            Unknown
        );
        assert_eq!(
            classify_liveness(&Err(IpcError::Protocol("timeout talking to pipe".into()))),
            Unknown
        );
        assert_eq!(
            classify_liveness(&Err(IpcError::Io(std::io::Error::other("boom")))),
            Unknown
        );
    }

    #[test]
    fn preconnect_blanket_sweep_only_when_no_sibling_is_possibly_alive() {
        // The safety invariant (liveness, not responsiveness): a blanket
        // cross-instance sweep is allowed ONLY when every lingering
        // control pipe is provably `Absent`. Any sibling that is `Alive`
        // OR `Unknown` must force the narrow, instance-scoped path so a
        // live-but-busy / wedged-but-listening sibling's live NRPT rule
        // is NEVER deleted. The old responsiveness-only gate counted a
        // busy sibling (Status roundtrip → Err, dropped) as absent and
        // swept it; that cell is what this now pins.
        use gp_ipc::Liveness::*;
        // Empty candidate set: post-crash clean box (no pipe survived)
        // → blanket safe.
        assert!(preconnect_sweep_is_blanket(&[]));
        // All-provably-dead siblings → blanket safe.
        assert!(preconnect_sweep_is_blanket(&[Absent, Absent]));
        // A live sibling → narrow.
        assert!(!preconnect_sweep_is_blanket(&[Alive]));
        assert!(!preconnect_sweep_is_blanket(&[Absent, Alive]));
        // THE busy/wedged cell the false comment claimed was safe:
        // a possibly-alive (Unknown: busy/denied/parked) sibling must
        // block the blanket sweep.
        assert!(!preconnect_sweep_is_blanket(&[Unknown]));
        assert!(
            !preconnect_sweep_is_blanket(&[Absent, Unknown, Absent]),
            "a single unknown pipe among dead ones must not license deleting \
             a possibly-live sibling's rule"
        );
    }

    #[test]
    fn possibly_alive_instances_names_only_non_absent_rows() {
        // The operator-facing helper behind the recover --all refusal
        // and the narrowed-sweep log line: it must surface exactly the
        // Alive/Unknown instances (in enumeration order) and drop the
        // provably-dead ones, so the refusal message names who we
        // would-not-sweep rather than a bare count.
        use gp_ipc::Liveness::*;
        let row = |n: &str, l| {
            (
                n.to_string(),
                std::path::PathBuf::from(format!(r"\\.\pipe\openprotect-{n}")),
                l,
            )
        };
        let rows = vec![row("work", Alive), row("home", Absent), row("lab", Unknown)];
        assert_eq!(
            possibly_alive_instances(&rows),
            vec!["work".to_string(), "lab".to_string()]
        );
        assert!(possibly_alive_instances(&[row("dead", Absent)]).is_empty());
    }

    #[test]
    fn doctor_accepts_instance() {
        let cli = Cli::try_parse_from(["opc", "doctor"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Doctor { .. })));

        let cli = Cli::try_parse_from(["opc", "doctor", "--instance", "work"]).unwrap();
        match cli.command {
            Some(Commands::Doctor { instance }) => {
                assert_eq!(instance.as_deref(), Some("work"));
            }
            _ => panic!("expected Commands::Doctor"),
        }
    }
}

// Bounded tunnel-teardown drain: a wedged Wintun/PnP kernel wait must
// not be able to hang `opc` forever on `done_rx.await`/`join()`.
#[cfg(test)]
mod drain_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn drain_reports_wedged_when_thread_never_acks() {
        // _tx kept alive (channel open) but never sends → models a
        // tunnel thread stuck in an uninterruptible kernel-mode wait
        // that never acknowledges the cancel.
        let (_tx, mut rx) = tokio::sync::oneshot::channel::<anyhow::Result<()>>();
        let outcome = drain_done_with_timeout(&mut rx, Duration::from_millis(50)).await;
        assert_eq!(outcome, DrainOutcome::Wedged);
    }

    #[tokio::test]
    async fn drain_reports_resolved_when_thread_finishes() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<anyhow::Result<()>>();
        tx.send(Ok(())).unwrap();
        let outcome = drain_done_with_timeout(&mut rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, DrainOutcome::Resolved);
    }

    #[tokio::test]
    async fn drain_reports_resolved_when_thread_dropped_sender() {
        // Sender dropped without sending (thread panicked) → the
        // receiver resolves with an error, which still counts as
        // "done, not wedged" so teardown proceeds to join the thread.
        let (tx, mut rx) = tokio::sync::oneshot::channel::<anyhow::Result<()>>();
        drop(tx);
        let outcome = drain_done_with_timeout(&mut rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, DrainOutcome::Resolved);
    }
}

// Connect-phase observability: file sink (opt-in), phase stamps,
// report-only watchdog budget. Written RED first (2026-09-28): the
// sink/stamp/watchdog symbols did not exist and the suite failed to
// compile against them; then GREEN with the implementations above.
#[cfg(test)]
mod observability_tests {
    use super::*;

    /// Issue #36 review: the exit-code script/systemd contract (see
    /// [`classify_exit_code`]'s doc) must not regress now that login
    /// failures carry diagnostics. A transient 5xx portal/gateway
    /// reject without an auth-engine header stays
    /// `GATEWAY_UNREACHABLE` (exit 3), like the legacy
    /// `.error_for_status()` → `AuthError::Http` path, while real
    /// credential rejects remain `AUTH_FAILED` (exit 2).
    #[test]
    fn classify_exit_code_keeps_transient_server_rejects_unreachable() {
        let transient = anyhow::Error::from(gp_auth::AuthError::Server(
            "gateway login rejected: HTTP 503".into(),
        ));
        assert_eq!(
            classify_exit_code(&transient),
            exit_code::GATEWAY_UNREACHABLE,
            "5xx without auth-failed must not page as a credential problem"
        );
        let auth = anyhow::Error::from(gp_auth::AuthError::Failed("auth-failed".into()));
        assert_eq!(classify_exit_code(&auth), exit_code::AUTH_FAILED);
        let cancelled = anyhow::Error::from(gp_auth::AuthError::Cancelled);
        assert_eq!(classify_exit_code(&cancelled), exit_code::AUTH_FAILED);
    }

    // ---------- budget env parsing ----------

    #[test]
    fn phase_budget_defaults_and_env_override() {
        assert_eq!(parse_phase_budget(None), DEFAULT_PHASE_BUDGET);
        assert_eq!(parse_phase_budget(Some("")), DEFAULT_PHASE_BUDGET);
        assert_eq!(parse_phase_budget(Some("  ")), DEFAULT_PHASE_BUDGET);
        assert_eq!(parse_phase_budget(Some("45")), Duration::from_secs(45));
        assert_eq!(parse_phase_budget(Some(" 90 ")), Duration::from_secs(90));
        // Garbage / sub-second fall back to the DEFAULT rather than
        // silently disabling the watchdog — a typo'd budget must not
        // recreate the unwatched-stall problem this exists for.
        assert_eq!(parse_phase_budget(Some("nope")), DEFAULT_PHASE_BUDGET);
        assert_eq!(parse_phase_budget(Some("0")), DEFAULT_PHASE_BUDGET);
        assert_eq!(DEFAULT_PHASE_BUDGET, Duration::from_secs(120));
    }

    // ---------- watchdog tick decision ----------

    fn entry(name: &str, kind: PhaseKind, ago: Duration) -> PhaseEntry {
        PhaseEntry {
            name: name.to_string(),
            kind,
            entered: Instant::now() - ago,
        }
    }

    #[test]
    fn watchdog_warns_once_past_budget_and_latches() {
        let budget = Duration::from_secs(120);
        let mut latch = WatchdogLatch::default();
        let now = Instant::now();

        // Under budget: silence.
        let fresh = entry("setup_tun", PhaseKind::Auto, Duration::from_secs(5));
        assert_eq!(latch.tick(now, Some(&fresh), budget), None);

        // Past budget: exactly one report. (The clock for `now` is
        // taken AFTER the entry is constructed at -200s, and the
        // assertion keeps 1s of slack for scheduling between the
        // two Instant::now() reads — the previous strict 200s
        // compare tripped its own epsilon, watched failing.)
        let stale = entry("setup_tun", PhaseKind::Auto, Duration::from_secs(200));
        let warn_now = Instant::now();
        let warn = latch
            .tick(warn_now, Some(&stale), budget)
            .expect("200s-old Auto phase must report past a 120s budget");
        assert_eq!(warn.phase, "setup_tun");
        assert!(warn.elapsed >= Duration::from_secs(199));
        // Latched: repeated ticks on the SAME phase do not spam.
        assert_eq!(latch.tick(now, Some(&stale), budget), None);
        assert_eq!(latch.tick(now, Some(&stale), budget), None);

        // Phase change re-arms the latch on the new name.
        let other = entry("hip_submit", PhaseKind::Auto, Duration::from_secs(300));
        let warn2 = latch
            .tick(now, Some(&other), budget)
            .expect("a new late phase must report once too");
        assert_eq!(warn2.phase, "hip_submit");
        assert_eq!(latch.tick(now, Some(&other), budget), None);

        // Returning to no-phase disarms entirely (never watch the
        // steady mainloop).
        assert_eq!(latch.tick(now, None, budget), None);
        assert_eq!(latch.tick(now, Some(&other), budget).map(|w| w.phase), Some("hip_submit".into()),
            "latch cleared by None-phase => a stale same-name phase may re-report once (safe: reports, never exits)");

        // REPORT-ONLY contract: tick() is a pure decision with no
        // process access at all — there is no path from it to
        // process::exit. (Structural, asserted by construction; the
        // exit_wedged flush test pins the only exit-adjacent use of
        // the flush helper.)
    }

    #[test]
    fn human_bound_phases_are_budget_exempt() {
        // The saml paste wait is budget-EXEMPT: the human is the
        // slow part, the real bound is the gateway's
        // <saml-request-timeout> (auth agent's area). The watchdog
        // must stay silent for hours here.
        let budget = Duration::from_secs(120);
        let mut latch = WatchdogLatch::default();
        let now = Instant::now();
        let waiting = entry(
            "saml_paste_wait",
            PhaseKind::HumanBound,
            Duration::from_secs(30 * 60),
        );
        assert_eq!(latch.tick(now, Some(&waiting), budget), None);
    }

    // ---------- stamp rendering ----------

    #[test]
    fn phase_line_is_stable_and_grep_friendly() {
        let t = Duration::from_millis(4123);
        assert_eq!(
            phase_line(PhaseEvent::Start, Some(2), "make_cstp", t, None),
            "phase=make_cstp START attempt=2 t+4123ms"
        );
        assert_eq!(
            phase_line(PhaseEvent::Finish, None, "hip_submit", t, Some("dur=17ms")),
            "phase=hip_submit FINISH attempt=pre t+4123ms dur=17ms"
        );
    }

    // ---------- emergency flush bound ----------

    #[test]
    fn run_bounded_returns_true_when_work_completes() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = Arc::clone(&flag);
        assert!(run_bounded(
            move || f.store(true, std::sync::atomic::Ordering::SeqCst),
            Duration::from_secs(5)
        ));
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn run_bounded_abandons_slow_work_at_the_deadline() {
        // exit_wedged must NOT assume destructors/flush joins run:
        // a 10s "wedged disk" flush is abandoned at 100ms.
        let started = Instant::now();
        let done = run_bounded(
            || std::thread::sleep(Duration::from_secs(10)),
            Duration::from_millis(100),
        );
        assert!(!done, "slow flush must report deadline-exceeded");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "bounded flush returned after {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn flush_without_file_sink_is_an_immediate_success() {
        // DEFAULT OFF corollary: with no guards armed, nothing to
        // flush, no thread spawned, no delay.
        assert!(flush_tracing_bounded(Duration::from_millis(50)));
    }

    // ---------- opt-in rolling file sink ----------

    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn emit_probe_line(marker: &str) {
        tracing::info!("{marker}");
    }

    #[test]
    fn log_file_sink_off_by_default_writes_no_file_and_keeps_console() {
        // RED first (compile-fail on build_tracing_subscriber); the
        // "zero behavior change without --log-file" requirement: the
        // console layer still receives everything and NOTHING
        // touches the filesystem.
        let cap = CaptureWriter::default();
        let (sub, guards) = build_tracing_subscriber("info", cap.clone(), None).unwrap();
        let dir = std::env::temp_dir().join(format!("opc-nosink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        tracing::subscriber::with_default(sub, || emit_probe_line("no-sink-probe"));
        drop(guards);
        let seen = String::from_utf8_lossy(&cap.0.lock().unwrap().clone()).into_owned();
        assert!(
            seen.contains("no-sink-probe"),
            "console sink lost the event: {seen:?}"
        );
        assert!(
            !dir.exists(),
            "default-off file sink must not create anything"
        );
    }

    #[test]
    fn log_file_sink_writes_alongside_console_when_enabled() {
        let dir = std::env::temp_dir().join(format!("opc-filesink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log_path = dir.join("opc.log");

        let cap = CaptureWriter::default();
        let (sub, guards) = build_tracing_subscriber("info", cap.clone(), Some(&log_path)).unwrap();
        tracing::subscriber::with_default(sub, || emit_probe_line("dual-sink-probe"));
        // Dropping the worker guards joins the non-blocking writer
        // thread — guarantees the line is on disk before we assert.
        drop(guards);

        let seen_console = String::from_utf8_lossy(&cap.0.lock().unwrap().clone()).into_owned();
        assert!(
            seen_console.contains("dual-sink-probe"),
            "console layer must keep receiving events when the file sink is on: {seen_console:?}"
        );

        let files: Vec<String> = std::fs::read_dir(&dir)
            .expect("sink dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !files.is_empty(),
            "hourly appender produced no file in {dir:?}"
        );
        let body = files
            .iter()
            .map(|f| std::fs::read_to_string(dir.join(f)).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("");
        assert!(
            body.contains("dual-sink-probe"),
            "rolling file sink missing the event; files={files:?}"
        );
        assert!(
            !body.contains('\u{1b}'),
            "file layer must be ANSI-free, got {body:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hip_report_path_skips_all_tracing_init() {
        // HIP wrapper stdout isolation: the csd-wrapper invocation
        // dup2's stdout to libopenconnect's XML pipe, so tracing init
        // must never run there — not even with --log-file set (a
        // regression that armed the hourly rolling file sink for
        // wrappers would leak a handle per fork and corrupt the XML).
        // Pinned at the DECISION level via the exact predicate run()
        // gates on, and at the clap surface: wrapper-shaped argv still
        // yields HipReport (the argv-sniff shim), and the init
        // predicate returns false for it.
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "opc",
            "--log-file",
            "/tmp/x.log",
            "hip-report",
            "--cookie",
            "c",
            "--md5",
            "m",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Commands::HipReport { .. })));
        assert_eq!(cli.log_file.as_deref(), Some("/tmp/x.log"));
        // The real gate (run(): `if tracing_init_needed(&cli.command)`)
        // must say NO-INIT for hip-report even with --log-file set.
        assert!(
            !tracing_init_needed(&cli.command),
            "hip-report must skip ALL tracing init (console AND file sink)"
        );
        // …and the predicate must still bring tracing up for every
        // other form, so the isolation is scoped to the wrapper path
        // and does not silently disable logging everywhere.
        let connect = Cli::try_parse_from(["opc", "--log-file", "a.log", "connect", "p"])
            .unwrap()
            .command;
        assert!(tracing_init_needed(&connect), "connect must init tracing");
        assert!(
            tracing_init_needed(&None),
            "the bare no-subcommand form must init tracing"
        );
    }

    #[test]
    fn connect_accepts_log_file_flag_and_defaults_off() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opc", "connect", "vpn.example.com"]).unwrap();
        assert_eq!(cli.log_file, None, "file sink MUST default off");
        let cli = Cli::try_parse_from([
            "opc",
            "connect",
            "--log-file",
            "D:\\logs\\opc.log",
            "vpn.example.com",
        ])
        .unwrap();
        assert_eq!(cli.log_file.as_deref(), Some("D:\\logs\\opc.log"));
        let cli = Cli::try_parse_from(["opc", "--log-file", "a.log", "status"]).unwrap();
        assert_eq!(
            cli.log_file.as_deref(),
            Some("a.log"),
            "flag is global like --log"
        );
    }

    // ---------- bounded cancel-handle await (item 4) ----------

    #[tokio::test]
    async fn bounded_cancel_handle_recv_gives_up_on_a_never_arriving_handle() {
        // RED first as a compile-fail on bounded_cancel_handle_recv;
        // the behavior being pinned is the old main.rs:3584 defect:
        // `recv_task.await` without a deadline could swallow
        // Ctrl-C forever when the tunnel thread wedged before its
        // first send.
        //
        // Integration gap: the Some(handle) path needs a real
        // gp_tunnel::CancelHandle (FFI ctor, not constructible in a
        // unit test), so only the timeout and Err arms are exercised
        // here; the Some arm is the pre-existing happy path already
        // covered by the live connect flow + the drain tests.
        // A never-completing task models the thread wedged before
        // its first send. NOT a leaked spawn_blocking: the runtime's
        // Drop joins blocking threads, so a parked recv() would hang
        // the whole test binary (watched it do exactly that).
        let mut task = tokio::task::spawn(std::future::pending::<
            Result<gp_tunnel::CancelHandle, std::sync::mpsc::RecvError>,
        >());
        let started = Instant::now();
        let got = tokio::time::timeout(
            CANCEL_HANDLE_RECV_TIMEOUT + Duration::from_secs(2),
            bounded_cancel_handle_recv(&mut task),
        )
        .await
        .expect("the bounded recv must return well before its 7s outer guard");
        assert!(
            got.is_none(),
            "wedged thread must NOT pin the await forever"
        );
        assert!(started.elapsed() >= CANCEL_HANDLE_RECV_TIMEOUT);
    }

    #[tokio::test]
    async fn bounded_cancel_handle_recv_resolves_dropped_sender_as_none() {
        // Thread died before the send: recv returns Err(Disconnected)
        // immediately; no warn, no wait.
        let (tx, rx) = std::sync::mpsc::channel::<gp_tunnel::CancelHandle>();
        drop(tx);
        let mut task = tokio::task::spawn_blocking(move || rx.recv());
        let started = Instant::now();
        let got = bounded_cancel_handle_recv(&mut task).await;
        assert!(got.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

// ---------------------------------------------------------------------------
// Issue #43 — portal-advertised gateway entries carrying a service port
// (`"203.0.113.7:11443"`) broke tunnel START: the whole label reached
// getaddrinfo-style consumers (gateway-exclude resolution, the
// libopenconnect set_hostname lane, the latency probe). Cross-platform
// module deliberately (the historical `mod tests` is unix-only); every
// test here is pure-unit, injected-resolver, or 127.0.0.1 loopback —
// no real resolver, no real tunnel (PID 21216), no outbound network.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod issue43_tests {
    use super::*;

    fn gw(name: &str, address: &str) -> Gateway {
        Gateway {
            address: address.into(),
            description: name.into(),
            priority: 0,
            priority_rules: Vec::new(),
        }
    }

    #[derive(Clone, Default)]
    struct LogCap(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for LogCap {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCap {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_text(cap: &LogCap) -> String {
        String::from_utf8_lossy(&cap.0.lock().unwrap().clone()).into_owned()
    }

    // ---------- (a) forced selection identity (characterization) ----------

    /// The `--gateway` force path must keep resolving a port-bearing
    /// entry by its advertised verbatim name (probes-skipped branch;
    /// `match_gateway_override`'s normalize_server-vs-normalize_server
    /// comparison is untouched by the #43 fix).
    #[test]
    fn match_gateway_override_resolves_port_bearing_entry_by_advertised_name() {
        let gateways = vec![gw("GW", "203.0.113.7:11443")];
        let by_address = match_gateway_override(&gateways, "203.0.113.7:11443").unwrap();
        assert_eq!(by_address.address, "203.0.113.7:11443");
        let by_name = match_gateway_override(&gateways, "GW").unwrap();
        assert_eq!(by_name.address, "203.0.113.7:11443");
    }

    // ---------- (b) the run_tunnel session-config seam ----------

    /// Recording double for the `gp_tunnel::SessionHandle` seam:
    /// pins exactly which hostname/port values would reach
    /// libopenconnect, without faking FFI (the local build is the
    /// OPENCONNECT_DIR-unset stub).
    #[derive(Default)]
    struct RecordingSession {
        calls: Vec<String>,
        hostnames: Vec<String>,
        urls: Vec<String>,
    }

    impl RecordingSession {
        /// The port libopenconnect would use after this sequence:
        /// a parse_url call carries it explicitly; the
        /// set_hostname-only lane keeps the library default 443.
        fn effective_port(&self) -> Option<u16> {
            match self.urls.last() {
                Some(u) => u
                    .strip_prefix("https://")
                    .unwrap_or(u)
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse().ok()),
                None => Some(443),
            }
        }
    }

    impl gp_tunnel::SessionHandle for RecordingSession {
        fn set_protocol_gp(&mut self) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push("set_protocol_gp".into());
            Ok(())
        }
        fn set_hostname(
            &mut self,
            hostname: &str,
        ) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push(format!("set_hostname:{hostname}"));
            self.hostnames.push(hostname.to_string());
            Ok(())
        }
        fn parse_url(&mut self, url: &str) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push(format!("parse_url:{url}"));
            self.urls.push(url.to_string());
            Ok(())
        }
        fn set_os_spoof(&mut self, os: &str) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push(format!("set_os_spoof:{os}"));
            Ok(())
        }
        fn set_cookie(&mut self, cookie: &str) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push(format!("set_cookie:{cookie}"));
            Ok(())
        }
        fn set_client_cert(
            &mut self,
            cert: &str,
            key: &str,
        ) -> std::result::Result<(), gp_tunnel::TunnelError> {
            self.calls.push(format!("set_client_cert:{cert}:{key}"));
            Ok(())
        }
    }

    /// RED today: `session.set_hostname(gateway_host)` hands the
    /// WHOLE `"203.0.113.7:11443"` to libopenconnect (STRDUPed
    /// verbatim into vpninfo->hostname), so its own getaddrinfo
    /// fails — the reporter's `ERROR openconnect: getaddrinfo
    /// failed for host` + `rc=-5` pair. Post-fix: no colon-bearing
    /// host outside brackets may reach set_hostname, and the
    /// advertised port must actually be applied (v9.21 has no
    /// public set_port; the canonical lane is openconnect_parse_url).
    #[test]
    fn run_tunnel_hands_no_port_bearing_host_to_set_hostname() {
        let mut s = RecordingSession::default();
        configure_tunnel_session(
            &mut s,
            "203.0.113.7:11443",
            "win",
            "authcookie=MOCK-cookie",
            None,
            None,
        )
        .expect("configure_tunnel_session");
        for h in &s.hostnames {
            let colon_bearing = h.contains(':') && !(h.starts_with('[') && h.ends_with(']'));
            assert!(
                !colon_bearing,
                "issue #43: whole host:port reached set_hostname ({h:?}); \
                 libopenconnect getaddrinfo would fail rc=-5. calls={:?}",
                s.calls
            );
        }
        assert_eq!(
            s.effective_port(),
            Some(11443),
            "advertised port must reach libopenconnect, calls={:?}",
            s.calls
        );
    }

    /// UNSW daily-connect no-regression pin: with no port in the
    /// label, the recorded sequence must be byte-identical to the
    /// pre-#43 flow — set_protocol_gp, verbatim set_hostname,
    /// set_os_spoof, set_cookie — and ZERO parse_url calls
    /// (vpninfo->port stays at the library default 443).
    #[test]
    fn run_tunnel_no_port_configures_hostname_verbatim_without_any_port_call() {
        let mut s = RecordingSession::default();
        configure_tunnel_session(
            &mut s,
            "ra.vpn.unsw.edu.au",
            "win",
            "authcookie=MOCK-cookie",
            None,
            None,
        )
        .expect("configure_tunnel_session");
        assert_eq!(
            s.calls,
            vec![
                "set_protocol_gp",
                "set_hostname:ra.vpn.unsw.edu.au",
                "set_os_spoof:win",
                "set_cookie:authcookie=MOCK-cookie",
            ]
        );
        assert!(s.urls.is_empty(), "port-less lane must not call parse_url");
    }

    // ---------- (c) gateway-exclude / HIP-pin resolution (site A) ----------

    #[test]
    fn resolve_gateway_for_exclude_ipv4_literal_with_port_pins_bare_ip() {
        // The reporter's exact shape: a numeric gateway advertised
        // with its port. Today this returns None (11001 WARN at the
        // site-A failure); post-fix it must pin the bare IPv4 with
        // the resolver never invoked (numeric fast path) and no WARN.
        let cap = LogCap::default();
        let (sub, guards) = build_tracing_subscriber("info", cap.clone(), None).unwrap();
        let mut calls: Vec<(String, u16)> = Vec::new();
        let out = tracing::subscriber::with_default(sub, || {
            resolve_gateway_for_exclude_with("203.0.113.7:11443", &mut |host, port| {
                calls.push((host.to_string(), port));
                let ip = host
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| Ipv4Addr::new(198, 51, 100, 7));
                Ok(vec![SocketAddr::from((ip, port))])
            })
        });
        drop(guards);
        assert_eq!(out, Some("203.0.113.7".parse().unwrap()));
        assert!(
            calls.is_empty(),
            "numeric literal must not invoke the resolver at all: {calls:?}"
        );
        let seen = captured_text(&cap);
        assert!(
            !seen.contains("gateway exclude skipped"),
            "no WARN on the numeric fast path: {seen}"
        );
    }

    #[test]
    fn resolve_gateway_for_exclude_hostname_resolves_bare_host() {
        // RED today: `(gateway_host, 443).to_socket_addrs()` feeds
        // the WHOLE colon-bearing string to getaddrinfo as the node
        // (WSAHOST_NOT_FOUND 11001 — the #43 WARN). The injected
        // resolver must see the bare host and the ADVERTISED port as
        // service.
        let mut calls: Vec<(String, u16)> = Vec::new();
        let out = resolve_gateway_for_exclude_with("gw.example.com:11443", &mut |host, port| {
            calls.push((host.to_string(), port));
            Ok(vec![SocketAddr::from((
                Ipv4Addr::new(198, 51, 100, 7),
                port,
            ))])
        });
        assert_eq!(
            calls,
            vec![("gw.example.com".to_string(), 11443u16)],
            "resolver node must be the bare host at the advertised port"
        );
        assert_eq!(out, Some(Ipv4Addr::new(198, 51, 100, 7)));
    }

    #[test]
    fn resolve_gateway_for_exclude_no_port_resolves_with_443() {
        // UNSW-shape pin: port-less hosts keep resolving with
        // service 443 exactly as before the #43 change.
        let mut calls: Vec<(String, u16)> = Vec::new();
        let out = resolve_gateway_for_exclude_with("ra.vpn.unsw.edu.au", &mut |host, port| {
            calls.push((host.to_string(), port));
            Ok(vec![SocketAddr::from((
                Ipv4Addr::new(129, 93, 30, 10),
                port,
            ))])
        });
        assert_eq!(calls, vec![("ra.vpn.unsw.edu.au".to_string(), 443u16)]);
        assert_eq!(out, Some(Ipv4Addr::new(129, 93, 30, 10)));
    }

    #[test]
    fn resolve_gateway_for_exclude_ipv6_literal_returns_none_without_resolve_failure_warning() {
        // gp-route's gateway_exclude is IPv4-only
        // (TunConfig::gateway_exclude: Option<Ipv4Addr>) — an IPv6
        // gateway is a KNOWN no-IPv4-to-exclude case and must be
        // classified at debug, not via the resolver-failure WARN the
        // reporter saw (today every `[v6]:port` label falls into the
        // Err arm and emits it).
        let cap = LogCap::default();
        let (sub, guards) = build_tracing_subscriber("info", cap.clone(), None).unwrap();
        let mut called = false;
        let out = tracing::subscriber::with_default(sub, || {
            resolve_gateway_for_exclude_with("[fd00::1]:11443", &mut |_host, _port| {
                called = true;
                Ok(vec![])
            })
        });
        drop(guards);
        assert_eq!(out, None, "IPv4-only consumers get None for v6 literals");
        assert!(!called, "bracketed IPv6 must not reach the resolver");
        let seen = captured_text(&cap);
        assert!(
            !seen.contains("failed to resolve IPv4 address"),
            "IPv6 literal must not trip the resolver-failure WARN: {seen}"
        );
        assert!(
            !seen.contains("resolver returned no IPv4"),
            "IPv6 literal must not trip the no-IPv4 WARN either: {seen}"
        );
    }

    #[test]
    fn resolve_gateway_for_exclude_dns_failure_still_warns() {
        // Guards the #43 fix from blanket-silencing: a genuine DNS
        // failure must keep the #40 diagnostics WARN.
        let cap = LogCap::default();
        let (sub, guards) = build_tracing_subscriber("info", cap.clone(), None).unwrap();
        let out = tracing::subscriber::with_default(sub, || {
            resolve_gateway_for_exclude_with("gw.example.com", &mut |_host, _port| {
                Err(std::io::Error::other("simulated resolver failure"))
            })
        });
        drop(guards);
        assert_eq!(out, None);
        let seen = captured_text(&cap);
        assert!(
            seen.contains("gp-route: gateway exclude skipped")
                && seen.contains("failed to resolve IPv4 address")
                && seen.contains("simulated resolver failure"),
            "DNS-failure WARN lost in the #43 refactor: {seen}"
        );
    }

    // ---------- (d) HIP lane helpers (Windows-only code) ----------

    #[cfg(windows)]
    #[test]
    fn parse_gateway_port_rejects_unbracketed_ipv6() {
        // RED today: the naive `rsplit_once(':')` chops `fd00::1`
        // into host `fd00:` + port `1` — the `contains(':')` guard
        // after rsplit_once can never fire.
        assert_eq!(parse_gateway_port("fd00::1"), None);
        assert_eq!(parse_gateway_port("2001:db8::1"), None);
    }

    #[cfg(windows)]
    #[test]
    fn gateway_hostname_keeps_unbracketed_ipv6() {
        // RED today (returns "fd00:").
        assert_eq!(gateway_hostname("fd00::1"), "fd00::1");
        assert_eq!(gateway_hostname("2001:db8::1"), "2001:db8::1");
    }

    #[cfg(windows)]
    #[test]
    fn gateway_hostname_strips_ipv4_port() {
        // GREEN companion pinning today's correct halves (must stay).
        assert_eq!(gateway_hostname("203.0.113.7:11443"), "203.0.113.7");
        assert_eq!(gateway_hostname("gw.example.com"), "gw.example.com");
    }

    #[cfg(windows)]
    #[test]
    fn parse_gateway_port_keeps_advertised_port() {
        assert_eq!(parse_gateway_port("203.0.113.7:11443"), Some(11443));
        assert_eq!(parse_gateway_port("ra.vpn.unsw.edu.au"), None);
    }

    #[cfg(windows)]
    #[test]
    fn parse_gateway_port_accepts_historic_url_profile() {
        // Unix-csd-era profile strings may carry scheme + trailing
        // slash; the delegation must preserve that leniency.
        assert_eq!(
            parse_gateway_port("https://gw.example.com:11443/"),
            Some(11443)
        );
    }

    #[cfg(windows)]
    #[test]
    fn hip_resolve_override_uses_advertised_port() {
        // Issue #43 secondary casualty: with a port-bearing gateway
        // the exclude resolution returned None, so the NRPT-proof
        // HIP pin silently degraded to system DNS. Key on the bare
        // host, pin to the public IP on the ADVERTISED port.
        let pin: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let (key, addr) = hip_resolve_override("203.0.113.7:11443", Some(pin)).expect("pin");
        assert_eq!(key, "203.0.113.7");
        assert_eq!(addr.to_string(), "203.0.113.7:11443");
        let (key, addr) = hip_resolve_override("ra.vpn.unsw.edu.au", Some(pin)).expect("pin");
        assert_eq!(key, "ra.vpn.unsw.edu.au");
        assert_eq!(addr.port(), 443, "no-port gateway defaults 443");
        assert!(
            hip_resolve_override("203.0.113.7:11443", None).is_none(),
            "no pin -> no override (HIP falls back to system DNS, best effort)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn hip_resolve_override_key_survives_ipv6_labels() {
        // Bracketed: key keeps the brackets (reqwest matches the
        // override against url::Url::host_str(), which is bracketed
        // for IPv6 authorities). Unbracketed: today the naive rsplit
        // mangles the key to "fd00:" (RED) — the override would
        // never match and HIP would silently lose the pin.
        let pin: Ipv4Addr = "198.51.100.9".parse().unwrap();
        let (key, addr) = hip_resolve_override("[fd00::1]:11443", Some(pin)).expect("pin");
        assert_eq!(key, "[fd00::1]");
        assert_eq!(addr.port(), 11443);
        let (key, _) = hip_resolve_override("fd00::1", Some(pin)).expect("pin");
        assert_eq!(key, "fd00::1", "unbracketed IPv6 must not be chopped");
    }

    // ---------- (e) latency probe (third same-class site) ----------

    #[test]
    fn probe_target_uses_advertised_port() {
        // RED today: TcpStream::connect((normalize_server(addr), 443))
        // — colon-bearing node AND hardcoded port, so a custom-port
        // gateway can NEVER rank Reachable (masked in the #43 repro
        // by --gateway's probe skip).
        let (h, p) = probe_target("203.0.113.7:11443");
        assert_eq!(h, "203.0.113.7");
        assert_eq!(p, 11443);
    }

    #[test]
    fn probe_target_no_port_defaults_443() {
        // UNSW-shape pin.
        let (h, p) = probe_target("ra.vpn.unsw.edu.au");
        assert_eq!(h, "ra.vpn.unsw.edu.au");
        assert_eq!(p, 443);
    }

    #[tokio::test]
    async fn probe_gateway_reaches_custom_port_on_loopback() {
        // Wire-level proof of (e): a listener on 127.0.0.1:<ephemeral>
        // (the kernel backlog completes the handshake without
        // accept()). Today the probe dials the colon-bearing node at
        // :443 and can never connect; post-fix it reaches the
        // advertised port.
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback probe target");
        let port = listener.local_addr().expect("local_addr").port();
        let probe = probe_gateway(&format!("127.0.0.1:{port}")).await;
        drop(listener);
        assert!(
            matches!(probe, GatewayProbe::Reachable(_)),
            "advertised-port gateway must rank Reachable, got {probe:?}"
        );
    }
}
