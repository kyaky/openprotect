//! Native route / address / link management for the openprotect tun device.
//!
//! # Backends
//!
//! * **Linux** — shells out to `ip(8)` for link, addr, and route ops.
//! * **macOS** — shells out to `ifconfig(8)` and `route(8)` for
//!   utun address / MTU setup plus split-route installation.
//! * **Windows** — shells out to `netsh` for address/route management
//!   and `route.exe` for both gateway-exclude pinning and
//!   default-gateway discovery (parsing `route.exe print -4 0.0.0.0`).
//!   The discovery used to go through `Get-NetRoute` in PowerShell,
//!   but PowerShell cold-starts cost 5-15 s and routinely tripped the
//!   subprocess timeout; route.exe finishes in under 100 ms.
//! * Fallback — returns [`RouteError::InvalidConfig`] on other platforms.
//!
//! The [`CommandRunner`] trait keeps all call sites testable against a
//! mock.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default per-command timeout.
pub const DEFAULT_IP_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Description of how a tun interface should be configured.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (`tun0`, `OpenProtect`, etc.).
    pub ifname: String,
    /// IPv4 address to assign.
    pub ipv4: Option<Ipv4Addr>,
    /// MTU. `None` means leave the kernel/driver default.
    pub mtu: Option<u16>,
    /// IPv4 gateway host to pin outside the tunnel so broad split
    /// routes don't capture it.
    pub gateway_exclude: Option<Ipv4Addr>,
    /// Routes to install (CIDR strings like `"10.0.0.0/8"`).
    pub routes: Vec<String>,
    /// What to do when a route's prefix is already claimed by another
    /// interface.
    pub route_conflict: RouteConflictPolicy,
}

/// What [`apply`] does when the routing table already has an entry for
/// a split prefix, so installing ours would displace it.
///
/// Split prefixes collide more often than one would hope: Docker's
/// default address pool (`172.17.0.0/16` .. `172.31.0.0/16`) overlaps
/// the RFC1918 space corporate gateways hand out, and a second VPN or a
/// hypervisor host-only network can claim the same prefix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RouteConflictPolicy {
    /// Take the prefix over for the tunnel and hand it back on
    /// disconnect. The default: the prefix is one the caller asked to
    /// route through the tunnel, so honouring that is the least
    /// surprising outcome — but it is announced at WARN, naming the
    /// interface that loses it.
    #[default]
    TakeOver,
    /// Refuse to connect, naming what owns the prefix.
    Fail,
    /// Leave the existing route alone and carry on without ours.
    /// Traffic to the prefix keeps its current path — a deliberate
    /// hole in the split tunnel, so it is announced at WARN too.
    Skip,
}

/// Saved state for a temporary gateway `/32` host-route pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPinState {
    pub ip: Ipv4Addr,
    /// On Linux: the prior `ip route show` entry.
    /// On macOS / Windows: the default gateway nexthop used for the pin.
    pub prior_entry: Option<String>,
}

/// One split route installed by [`apply`], together with whatever the
/// routing table already held for that exact prefix.
///
/// Split prefixes collide with existing routes more often than one
/// would hope — Docker's default address pool (`172.17.0.0/16` ..
/// `172.31.0.0/16`) overlaps the RFC1918 space corporate gateways hand
/// out, and a second VPN or a hypervisor host-only network can claim
/// the same prefix. The tunnel has to win while it is up, so `apply`
/// takes the prefix over; `prior` is what [`revert`] puts back
/// afterwards so the takeover lasts exactly as long as the session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstalledRoute {
    /// CIDR as installed.
    pub cidr: String,
    /// Verbatim routing-table entries for this exact prefix that the
    /// install displaced, in a form the platform's restore command
    /// accepts. Empty when the prefix was unclaimed.
    ///
    /// Linux only — the macOS and Windows backends never populate it
    /// (see their `platform_apply` for why).
    pub prior: Vec<String>,
}

impl InstalledRoute {
    /// A route that displaced nothing.
    pub fn new(cidr: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            prior: Vec::new(),
        }
    }

    /// True when installing this route took the prefix over from
    /// another interface.
    pub fn displaced(&self) -> bool {
        !self.prior.is_empty()
    }
}

impl From<&str> for InstalledRoute {
    fn from(cidr: &str) -> Self {
        Self::new(cidr)
    }
}

impl From<String> for InstalledRoute {
    fn from(cidr: String) -> Self {
        Self::new(cidr)
    }
}

/// Lets `assert_eq!(state.installed_routes, vec!["10.0.0.0/8"])` keep
/// working: `Vec<T>: PartialEq<Vec<U>>` forwards to `T: PartialEq<U>`.
impl PartialEq<&str> for InstalledRoute {
    fn eq(&self, other: &&str) -> bool {
        self.cidr == *other
    }
}

/// State produced by [`apply`] — hand back to [`revert`] to undo.
#[derive(Debug, Clone, Default)]
pub struct AppliedState {
    pub ifname: String,
    pub installed_routes: Vec<InstalledRoute>,
    pub installed_addr: Option<Ipv4Addr>,
    pub installed_gateway_exclude: Option<GatewayPinState>,
}

impl AppliedState {
    /// The CIDRs installed, in install order.
    pub fn route_cidrs(&self) -> impl Iterator<Item = &str> {
        self.installed_routes.iter().map(|r| r.cidr.as_str())
    }

    /// The CIDRs whose prefix was taken over from another interface.
    pub fn displaced_cidrs(&self) -> impl Iterator<Item = &str> {
        self.installed_routes
            .iter()
            .filter(|r| r.displaced())
            .map(|r| r.cidr.as_str())
    }
}

/// Errors produced by the `gp-route` API.
#[derive(Debug, Error)]
pub enum RouteError {
    #[error("ip command failed: {op}: {stderr}")]
    IpCommand { op: &'static str, stderr: String },

    #[error("{program} failed: {op}: {detail}")]
    UnixCommand {
        program: &'static str,
        op: &'static str,
        detail: String,
    },

    #[error("{program} failed: {op}: {detail}")]
    WinCommand {
        program: &'static str,
        op: &'static str,
        detail: String,
    },

    #[error(
        "{cidr} is already routed via {owner} on this host, so the tunnel cannot claim it{detail}\n\
         \n\
         Fix it in one of these ways:\n\
         \x20 - narrow the split-tunnel spec so it no longer covers {cidr}\n\
         \x20 - move whatever owns the prefix (for Docker: `default-address-pools` in \
         /etc/docker/daemon.json, then recreate the affected networks)\n\
         \x20 - pass `--route-conflict take-over` to hand the prefix to the tunnel for the \
         session (restored on disconnect), or `--route-conflict skip` to leave it alone"
    )]
    RouteConflict {
        cidr: String,
        owner: String,
        detail: String,
    },

    #[error("spawning subprocess: {0}")]
    Spawn(#[from] io::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Abstraction over "run a command and inspect its output."
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error>;
}

/// Default implementation: spawn + try_wait-poll with timeout.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
        run_with_timeout(program, args, DEFAULT_IP_COMMAND_TIMEOUT)
    }
}

fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                return child.wait_with_output().map(|o| Output {
                    status,
                    stdout: o.stdout,
                    stderr: o.stderr,
                });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "`{program} {}` did not exit within {:?}",
                            args.join(" "),
                            timeout
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply a [`TunConfig`] to the live system. All-or-nothing: on any
/// failure, everything installed so far is rolled back.
pub fn apply(config: &TunConfig) -> Result<AppliedState, RouteError> {
    apply_with(&SystemCommandRunner, config)
}

/// Like [`apply`] but uses the given [`CommandRunner`].
pub fn apply_with<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    if config.ifname.is_empty() {
        return Err(RouteError::InvalidConfig(
            "tun interface name is empty".into(),
        ));
    }
    let deduped = dedupe_routes(&config.routes);
    if deduped.len() == config.routes.len() {
        platform_apply(runner, config)
    } else {
        tracing::debug!(
            "gp-route: {} duplicate route(s) collapsed before install",
            config.routes.len() - deduped.len()
        );
        platform_apply(
            runner,
            &TunConfig {
                routes: deduped,
                ..config.clone()
            },
        )
    }
}

/// Canonical form of a route for duplicate detection: an IPv4 CIDR with
/// its host bits masked off, so `10.0.0.1/8` and `10.0.0.0/8` are seen
/// as the same prefix. Anything that does not parse as an IPv4 CIDR
/// (IPv6, malformed input) is returned unchanged — [`apply`] still
/// reports it, via whatever the platform's install command says.
fn normalize_route(route: &str) -> String {
    match parse_ipv4_cidr(route) {
        Ok((network, netmask)) => {
            let masked = Ipv4Addr::from(u32::from(network) & u32::from(netmask));
            let prefix = route.split_once('/').map(|(_, p)| p).unwrap_or("32");
            format!("{masked}/{prefix}")
        }
        Err(_) => route.to_string(),
    }
}

/// Collapse duplicate prefixes, keeping the first occurrence and the
/// original ordering.
///
/// `resolve_only_spec` in `opc` emits one `/32` per resolved address
/// with no de-duplication, so `--only a.corp.com,b.corp.com` where both
/// names resolve to the same IP produces the same prefix twice. On
/// Linux that used to abort the connect outright (`ip route add` is
/// `NLM_F_EXCL`, so the second add returns `EEXIST`); now that the
/// install is a `replace`, an un-deduplicated list would be worse still
/// — the second pass would record *our own* tun route as the prefix's
/// prior entry and [`revert`] would faithfully reinstate a route
/// pointing at a dead device.
fn dedupe_routes(routes: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::with_capacity(routes.len());
    let mut out: Vec<String> = Vec::with_capacity(routes.len());
    for route in routes {
        let key = normalize_route(route);
        if !seen.contains(&key) {
            seen.push(key);
            out.push(route.clone());
        }
    }
    out
}

/// Reverse an [`AppliedState`]. Best-effort: collects errors.
pub fn revert(state: &AppliedState) -> Vec<String> {
    revert_with(&SystemCommandRunner, state)
}

/// Like [`revert`] but uses the given [`CommandRunner`].
pub fn revert_with<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    platform_revert(runner, state)
}

/// Narrow [`IpAddr`] to [`Ipv4Addr`].
pub fn as_ipv4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(_) => None,
    }
}

/// What [`dns_pin_routes`] decided about the gateway-pushed
/// nameservers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsPinPlan {
    /// `/32` routes to append to [`TunConfig::routes`].
    pub pins: Vec<String>,
    /// Globally-routable servers deliberately left alone. Reported so
    /// the decision is visible in the log rather than silent.
    pub skipped_global: Vec<Ipv4Addr>,
    /// IPv6 servers, which this crate cannot route.
    pub skipped_ipv6: Vec<IpAddr>,
}

/// Extra `/32` routes needed so the gateway-pushed `servers` are
/// reachable through the tunnel, given the split `routes` already
/// scheduled for installation and the tunnel's own subnet.
///
/// In split-tunnel mode the pushed nameserver usually lives in the
/// tunnel's own subnet, which the caller's `--only` prefixes do not
/// cover. Nothing then routes it into the tun device, so the split-DNS
/// configuration that points at it resolves nothing: queries leave via
/// the physical interface and are dropped or answered by whatever holds
/// that address on the local network. Appending these routes to
/// [`TunConfig::routes`] keeps the fix inside the existing install and
/// revert paths.
///
/// The pin is deliberately *not* unconditional. The resolvers it exists
/// to serve are consumed in a scoped way — systemd-resolved `~domain`,
/// Windows NRPT, macOS `/etc/resolver` — but the route it installs is
/// global. A gateway that pushes a public resolver alongside its
/// internal one (`8.8.8.8`, say) would otherwise have that resolver
/// forced through the corporate tunnel for every process on the
/// machine; on a split-tunnel gateway that does not forward
/// non-corporate destinations, the host looks like it lost DNS the
/// moment the VPN came up. So a server is pinned only when it is
/// plausibly *behind* the tunnel: inside the tunnel's own subnet, or in
/// RFC1918 / CGNAT space. Anything globally routable is reported in
/// [`DnsPinPlan::skipped_global`] and left alone.
///
/// `tunnel_net` is the tunnel's `(address, netmask)` when known.
/// Servers already covered by a scheduled route are skipped too, so a
/// full-tunnel `0.0.0.0/0` adds nothing. IPv6 servers are reported in
/// [`DnsPinPlan::skipped_ipv6`] — this crate manages IPv4 routes only.
/// Unparsable entries in `routes` are treated as covering nothing;
/// `apply` reports them.
pub fn dns_pin_routes(
    routes: &[String],
    servers: &[IpAddr],
    tunnel_net: Option<(Ipv4Addr, Ipv4Addr)>,
) -> DnsPinPlan {
    let parsed: Vec<(Ipv4Addr, Ipv4Addr)> = routes
        .iter()
        .filter_map(|r| parse_ipv4_cidr(r).ok())
        .collect();

    let mut plan = DnsPinPlan::default();
    for server in servers.iter().copied() {
        let Some(server) = as_ipv4(server) else {
            if !plan.skipped_ipv6.contains(&server) {
                plan.skipped_ipv6.push(server);
            }
            continue;
        };

        let covered = parsed.iter().any(|(network, netmask)| {
            let mask = u32::from(*netmask);
            u32::from(server) & mask == u32::from(*network) & mask
        });
        let pin = format!("{server}/32");
        if covered || routes.contains(&pin) || plan.pins.contains(&pin) {
            continue;
        }

        if !reachable_only_behind_tunnel(server, tunnel_net) {
            if !plan.skipped_global.contains(&server) {
                plan.skipped_global.push(server);
            }
            continue;
        }

        plan.pins.push(pin);
    }
    plan
}

/// Whether pinning `server` into the tunnel is plausibly what the
/// gateway meant.
///
/// True when the address sits in the tunnel's own subnet, or in space
/// that cannot be reached over the public internet anyway (RFC1918,
/// CGNAT 100.64.0.0/10). Loopback, link-local, multicast and broadcast
/// are never pinned — routing those into a tunnel is meaningless.
fn reachable_only_behind_tunnel(
    server: Ipv4Addr,
    tunnel_net: Option<(Ipv4Addr, Ipv4Addr)>,
) -> bool {
    if server.is_loopback()
        || server.is_link_local()
        || server.is_multicast()
        || server.is_broadcast()
        || server.is_unspecified()
    {
        return false;
    }
    if let Some((addr, netmask)) = tunnel_net {
        let mask = u32::from(netmask);
        if u32::from(server) & mask == u32::from(addr) & mask {
            return true;
        }
    }
    // CGNAT — 100.64.0.0/10. `Ipv4Addr::is_shared` is still unstable.
    let octets = server.octets();
    let cgnat = octets[0] == 100 && (64..128).contains(&octets[1]);
    server.is_private() || cgnat
}

// ---------------------------------------------------------------------------
// Linux backend (ip(8))
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn platform_apply<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    let mut state = AppliedState {
        ifname: config.ifname.clone(),
        ..AppliedState::default()
    };

    let rollback_and_fail = |runner: &R, state: &AppliedState, err: RouteError| -> RouteError {
        if !state.installed_routes.is_empty()
            || state.installed_addr.is_some()
            || state.installed_gateway_exclude.is_some()
        {
            for rev_err in platform_revert(runner, state) {
                tracing::warn!("gp-route apply-rollback: {rev_err}");
            }
        }
        err
    };

    // 1. Bring the link up.
    run_ip(
        runner,
        "link up",
        &["link", "set", "dev", &config.ifname, "up"],
    )?;

    // 2. Set MTU if requested.
    if let Some(mtu) = config.mtu {
        let mtu_str = mtu.to_string();
        run_ip(
            runner,
            "set mtu",
            &["link", "set", "dev", &config.ifname, "mtu", &mtu_str],
        )?;
    }

    // 3. Assign IPv4 address.
    if let Some(addr) = config.ipv4 {
        let addr_cidr = format!("{addr}/32");
        run_ip(
            runner,
            "addr add",
            &["addr", "add", &addr_cidr, "dev", &config.ifname],
        )?;
        state.installed_addr = Some(addr);
    }

    // 4. Pin gateway outside the tunnel.
    if let Some(gateway_exclude) = config.gateway_exclude {
        if let Err(e) = install_gateway_exclude_linux(runner, &mut state, gateway_exclude) {
            tracing::warn!(
                "gp-route: gateway exclude {gateway_exclude}/32 failed ({e}); rolling back"
            );
            return Err(rollback_and_fail(runner, &state, e));
        }
    }

    // 5. Install routes.
    //
    // `ip route add` is NLM_F_CREATE|NLM_F_EXCL, so it returns EEXIST
    // ("RTNETLINK answers: File exists") the moment something else
    // holds the *exact* same key — same prefix, same metric, same
    // table. That is not hypothetical: Docker's default address pool
    // (172.17.0.0/16 .. 172.31.0.0/16) collides head-on with the
    // RFC1918 ranges corporate gateways hand out, and until this the
    // collision aborted the whole connect.
    //
    // `add` stays the fast path rather than switching everything to
    // `replace`, and that choice is load-bearing rather than
    // conservative. It makes the kernel — not a heuristic — the thing
    // that decides whether a real displacement is happening, so
    // `prior` is populated only when a takeover genuinely occurred.
    // Capturing unconditionally would be actively harmful: with a
    // `default via <gw> metric 100` in the table, `ip route add
    // 0.0.0.0/0 dev tun0` *succeeds* (metric 0 is a different key and
    // both routes coexist), so a blind capture would record a default
    // route we never displaced and `revert` would faithfully resurrect
    // it hours later, possibly onto an interface the machine has since
    // roamed off.
    for route in &config.routes {
        let family = family_flag(route);
        match run_ip(
            runner,
            "route add",
            &[family, "route", "add", route, "dev", &config.ifname],
        ) {
            Ok(()) => state
                .installed_routes
                .push(InstalledRoute::new(route.clone())),
            Err(e) if is_route_exists_error(&e) => {
                match resolve_route_conflict_linux(runner, config, route, family) {
                    Ok(Some(installed)) => state.installed_routes.push(installed),
                    // Skip policy: no route of ours, nothing to revert.
                    Ok(None) => {}
                    Err(e) => return Err(rollback_and_fail(runner, &state, e)),
                }
            }
            Err(e) => {
                tracing::warn!(
                    "gp-route: route add {route} on {} failed ({e}); rolling back",
                    config.ifname
                );
                return Err(rollback_and_fail(runner, &state, e));
            }
        }
    }

    Ok(state)
}

/// Handle an `ip route add` that came back EEXIST.
///
/// Returns the installed route on takeover, `None` when the policy says
/// to skip, and an error when the connect should fail.
#[cfg(target_os = "linux")]
fn resolve_route_conflict_linux<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
    route: &str,
    family: &'static str,
) -> Result<Option<InstalledRoute>, RouteError> {
    let prior = capture_prior_routes_linux(runner, route, family, &config.ifname);
    let owner = prior
        .first()
        .and_then(|entry| route_entry_dev(entry))
        .unwrap_or("another interface")
        .to_string();

    match config.route_conflict {
        RouteConflictPolicy::Fail => {
            return Err(RouteError::RouteConflict {
                cidr: route.to_string(),
                owner,
                detail: match prior.first() {
                    Some(entry) => format!(" ({entry})"),
                    None => String::new(),
                },
            })
        }
        RouteConflictPolicy::Skip => {
            tracing::warn!(
                "gp-route: {route} is already routed via {owner}; leaving it alone as asked. \
                 Traffic to {route} will NOT go through the tunnel."
            );
            return Ok(None);
        }
        RouteConflictPolicy::TakeOver => {}
    }

    // More than one entry shares this key (IPv6 makes this reachable —
    // the route key there excludes the device, so a prefix can hold
    // several same-metric entries). `ip route replace` collapses them
    // into one, and replaying them one at a time on revert would
    // restore only the last. Refusing is the honest outcome.
    if prior.len() > 1 {
        return Err(RouteError::RouteConflict {
            cidr: route.to_string(),
            owner,
            detail: format!(
                " — {} entries share this prefix, which cannot be restored faithfully \
                 after a takeover",
                prior.len()
            ),
        });
    }

    match prior.first() {
        Some(entry) => tracing::warn!(
            "gp-route: {route} is currently routed via {owner} ({entry}) — taking it over \
             for {} until disconnect, when the original entry is restored. Host traffic to \
             {route} goes through the tunnel meanwhile.",
            config.ifname
        ),
        // The only entry was on our own interface: a leftover from a
        // session that died before revert. Reclaim it silently — there
        // is nothing of anyone else's to preserve.
        None => tracing::debug!(
            "gp-route: reclaiming a stale {route} entry on {}",
            config.ifname
        ),
    }

    run_ip(
        runner,
        "route replace",
        &[family, "route", "replace", route, "dev", &config.ifname],
    )?;

    Ok(Some(InstalledRoute {
        cidr: route.to_string(),
        prior,
    }))
}

/// True when a route command failed because the entry already exists.
///
/// Linux says `RTNETLINK answers: File exists`; BSD/macOS says
/// `route: writing to routing socket: File exists`. Matching on the
/// shared tail keeps both backends on one predicate. A localized or
/// reworded message simply falls through to the original error, which
/// is the pre-existing behaviour.
fn is_route_exists_error(err: &RouteError) -> bool {
    let text = match err {
        RouteError::IpCommand { stderr, .. } => stderr.as_str(),
        RouteError::UnixCommand { detail, .. } => detail.as_str(),
        RouteError::WinCommand { detail, .. } => detail.as_str(),
        _ => return false,
    };
    let lowered = text.to_ascii_lowercase();
    lowered.contains("file exists") || lowered.contains("object already exists")
}

/// `-4` or `-6` for an `ip` invocation about `cidr`.
///
/// The flag is not cosmetic. `ip route show exact fe80::/64` with no
/// family flag prints nothing and exits 0 — a silent capture loss — and
/// `ip -4 route show exact fe80::/64` is a hard parse error. Since
/// `resolve_only_spec` already emits `/128` entries from AAAA records,
/// the family has to be derived per route rather than hardcoded.
/// Malformed input falls through to `-4` so the install command
/// produces the authoritative error, exactly as before.
#[cfg(target_os = "linux")]
fn family_flag(cidr: &str) -> &'static str {
    if cidr.split('/').next().unwrap_or(cidr).contains(':') {
        "-6"
    } else {
        "-4"
    }
}

/// Tokens `ip route show` prints that `ip route replace` rejects.
///
/// Feeding a captured line back verbatim is a hard failure whenever the
/// route sits on an interface with no carrier:
///
/// ```text
/// $ ip -4 route show exact 172.17.0.0/16
/// 172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
/// $ ip -4 route replace 172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
/// Error: either "to" is duplicate, or "linkdown" is a garbage.
/// ```
#[cfg(target_os = "linux")]
const SHOW_ONLY_FLAGS: &[&str] = &[
    "linkdown",
    "dead",
    "offload",
    "offload_failed",
    "trap",
    "notify",
    "rt_offload",
    "rt_trap",
];

/// Show-only tokens that carry a value, so the value has to go too.
#[cfg(target_os = "linux")]
const SHOW_ONLY_KV: &[&str] = &["expires", "error"];

/// Strip [`SHOW_ONLY_FLAGS`] / [`SHOW_ONLY_KV`] from an `ip route show`
/// entry so it can be fed back to `ip route replace`.
///
/// Returns `None` when what remains names neither a device nor a
/// nexthop — such an entry cannot be reinstalled and is better dropped
/// than issued as a malformed command.
#[cfg(target_os = "linux")]
fn sanitize_route_entry(entry: &str) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    let mut tokens = entry.split_whitespace();
    while let Some(token) = tokens.next() {
        if SHOW_ONLY_FLAGS.contains(&token) {
            continue;
        }
        if SHOW_ONLY_KV.contains(&token) {
            let _ = tokens.next();
            continue;
        }
        out.push(token);
    }
    if !out
        .iter()
        .any(|t| *t == "dev" || *t == "via" || *t == "nexthop")
    {
        return None;
    }
    Some(out.join(" "))
}

/// The word after the first `dev` token, if any.
#[cfg(target_os = "linux")]
fn route_entry_dev(entry: &str) -> Option<&str> {
    let mut tokens = entry.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next();
        }
    }
    None
}

/// Split `ip route show` output into one string per route.
///
/// A record starts at a line with no leading whitespace; indented
/// `nexthop ...` continuation lines belong to the record above them and
/// are folded into it, so a multipath route stays a single entry.
#[cfg(target_os = "linux")]
fn split_route_entries(stdout: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let continuation = line.starts_with(char::is_whitespace);
        match entries.last_mut() {
            Some(last) if continuation => {
                last.push(' ');
                last.push_str(line.trim());
            }
            _ => entries.push(line.trim().to_string()),
        }
    }
    entries
}

/// What the routing table holds for `cidr` right now, ready to be
/// restored later.
///
/// Best-effort by design: a failing `ip` here is logged and treated as
/// "nothing to preserve" so that the install command below stays the
/// sole authority on whether `apply` succeeds — a malformed `--only`
/// CIDR must still fail with the platform's own message, not with a
/// capture error. Entries already pointing at our own interface are
/// dropped: they are leftovers from a session that died before revert,
/// and restoring them would reinstate a route on a dead device.
#[cfg(target_os = "linux")]
fn capture_prior_routes_linux<R: CommandRunner>(
    runner: &R,
    cidr: &str,
    family: &str,
    ifname: &str,
) -> Vec<String> {
    let stdout = match run_ip_stdout(
        runner,
        "route show exact",
        &[family, "route", "show", "exact", cidr],
    ) {
        Ok(out) => out,
        Err(e) => {
            tracing::debug!("gp-route: could not read prior route for {cidr} ({e})");
            return Vec::new();
        }
    };

    split_route_entries(&stdout)
        .iter()
        .filter(|entry| route_entry_dev(entry) != Some(ifname))
        .filter_map(|entry| sanitize_route_entry(entry))
        .collect()
}

#[cfg(target_os = "linux")]
fn platform_revert<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    // LIFO: undo in the reverse of the order `platform_apply` installed.
    for route in state.installed_routes.iter().rev() {
        let family = family_flag(&route.cidr);

        // Delete ours first, scoped by `dev` so it can only ever match
        // the route we installed. This matters when the displaced entry
        // carried a different metric: `ip route replace` keys on
        // dst+metric+table, so restoring alone would leave our own
        // metric-0 record in place beside the restored one and quietly
        // keep the prefix in the tunnel after disconnect.
        let deleted = run_ip(
            runner,
            "route del",
            &[family, "route", "del", &route.cidr, "dev", &state.ifname],
        );
        match deleted {
            Ok(()) => {}
            // Nothing to restore, so a failed delete is a real leak.
            Err(e) if route.prior.is_empty() => {
                errors.push(format!("route del {}: {e}", route.cidr));
            }
            // libopenconnect routinely tears the tun device down before
            // we get here, and the kernel drops device routes with it —
            // so this is expected noise. The restore below is the step
            // that actually matters, and it runs either way.
            Err(e) => {
                tracing::debug!("gp-route: route del {} before restore: {e}", route.cidr);
            }
        }

        for prior in &route.prior {
            let mut args = vec![
                family.to_string(),
                "route".to_string(),
                "replace".to_string(),
            ];
            args.extend(prior.split_whitespace().map(str::to_string));
            if let Err(e) = run_ip_owned(runner, "route replace", &args) {
                errors.push(format!("route restore {} ({prior}): {e}", route.cidr));
            }
        }
    }

    if let Some(addr) = state.installed_addr {
        let addr_cidr = format!("{addr}/32");
        if let Err(e) = run_ip(
            runner,
            "addr del",
            &["addr", "del", &addr_cidr, "dev", &state.ifname],
        ) {
            errors.push(format!("addr del {addr_cidr}: {e}"));
        }
    }

    if let Some(pin) = &state.installed_gateway_exclude {
        let gw_cidr = format!("{}/32", pin.ip);
        let result = if let Some(prior_entry) = pin.prior_entry.as_deref() {
            let mut args = vec!["-4".to_string(), "route".to_string(), "replace".to_string()];
            args.extend(prior_entry.split_whitespace().map(str::to_string));
            run_ip_owned(runner, "route replace", &args)
        } else {
            run_ip(runner, "route del", &["-4", "route", "del", &gw_cidr])
        };
        if let Err(e) = result {
            if pin.prior_entry.is_some() {
                errors.push(format!("route replace {gw_cidr}: {e}"));
            } else {
                errors.push(format!("route del {gw_cidr}: {e}"));
            }
        }
    }

    errors
}

#[cfg(target_os = "linux")]
fn install_gateway_exclude_linux<R: CommandRunner>(
    runner: &R,
    state: &mut AppliedState,
    gateway: Ipv4Addr,
) -> Result<(), RouteError> {
    let gw_cidr = format!("{gateway}/32");
    // `sanitize_route_entry` is load-bearing, not tidying: if the
    // gateway's prior route sits on an interface with no carrier, the
    // captured line ends in `linkdown`, and `ip route replace` rejects
    // that token outright — the restore on disconnect would fail with
    // `Error: either "to" is duplicate, or "linkdown" is a garbage.`
    let prior_entry = split_route_entries(&run_ip_stdout(
        runner,
        "route show exact",
        &["-4", "route", "show", "exact", &gw_cidr],
    )?)
    .first()
    .and_then(|entry| sanitize_route_entry(entry));

    let route_get = run_ip_stdout(
        runner,
        "route get",
        &["-4", "route", "get", &gateway.to_string()],
    )?;
    let lookup = parse_route_get(&route_get, gateway)?;

    let mut args = vec![
        "-4".to_string(),
        "route".to_string(),
        "replace".to_string(),
        gw_cidr.clone(),
    ];
    if let Some(via) = lookup.via {
        args.push("via".to_string());
        args.push(via);
    }
    args.push("dev".to_string());
    args.push(lookup.dev);
    if let Some(src) = lookup.src {
        args.push("src".to_string());
        args.push(src);
    }
    run_ip_owned(runner, "route replace", &args)?;

    state.installed_gateway_exclude = Some(GatewayPinState {
        ip: gateway,
        prior_entry,
    });
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteLookup {
    via: Option<String>,
    dev: String,
    src: Option<String>,
}

#[cfg(target_os = "linux")]
fn parse_route_get(output: &str, gateway: Ipv4Addr) -> Result<RouteLookup, RouteError> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(RouteError::InvalidConfig(format!(
            "ip -4 route get {gateway} returned no output"
        )));
    }

    let mut via = None;
    let mut dev = None;
    let mut src = None;
    let mut tokens = trimmed.split_whitespace();

    while let Some(token) = tokens.next() {
        match token {
            "via" => {
                via = Some(next_route_token(&mut tokens, "via", gateway, trimmed)?);
            }
            "dev" => {
                dev = Some(next_route_token(&mut tokens, "dev", gateway, trimmed)?);
            }
            "src" => {
                src = Some(next_route_token(&mut tokens, "src", gateway, trimmed)?);
            }
            _ => {}
        }
    }

    let dev = dev.ok_or_else(|| {
        RouteError::InvalidConfig(format!(
            "ip -4 route get {gateway} output missing `dev`: {trimmed:?}"
        ))
    })?;

    Ok(RouteLookup { via, dev, src })
}

#[cfg(target_os = "linux")]
fn next_route_token<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    keyword: &str,
    gateway: Ipv4Addr,
    output: &str,
) -> Result<String, RouteError> {
    tokens.next().map(str::to_string).ok_or_else(|| {
        RouteError::InvalidConfig(format!(
            "ip -4 route get {gateway} output missing value after `{keyword}`: {output:?}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn run_ip<R: CommandRunner>(runner: &R, op: &'static str, args: &[&str]) -> Result<(), RouteError> {
    run_ip_checked(runner, op, args).map(|_| ())
}

#[cfg(target_os = "linux")]
fn run_ip_owned<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[String],
) -> Result<(), RouteError> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(runner, op, &refs)
}

#[cfg(target_os = "linux")]
fn run_ip_stdout<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<String, RouteError> {
    run_ip_checked(runner, op, args).map(|out| String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(target_os = "linux")]
fn run_ip_checked<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<Output, RouteError> {
    tracing::debug!("gp-route: ip {}", args.join(" "));
    let out = runner.run("ip", args)?;
    if out.status.success() {
        Ok(out)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(RouteError::IpCommand { op, stderr })
    }
}

// ---------------------------------------------------------------------------
// macOS backend (ifconfig + route)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn platform_apply<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    let mut state = AppliedState {
        ifname: config.ifname.clone(),
        ..AppliedState::default()
    };

    let rollback_and_fail = |runner: &R, state: &AppliedState, err: RouteError| -> RouteError {
        if !state.installed_routes.is_empty()
            || state.installed_addr.is_some()
            || state.installed_gateway_exclude.is_some()
        {
            for rev_err in platform_revert(runner, state) {
                tracing::warn!("gp-route apply-rollback: {rev_err}");
            }
        }
        err
    };

    let route_gateway = if config.routes.is_empty() {
        None
    } else {
        Some(config.ipv4.ok_or_else(|| {
            RouteError::InvalidConfig(
                "macOS split-route installation requires a tunnel IPv4 address".into(),
            )
        })?)
    };

    configure_iface_macos(runner, config)?;
    state.installed_addr = config.ipv4;

    if let Some(gateway) = config.gateway_exclude {
        if let Err(e) = install_gateway_exclude_macos(runner, &mut state, gateway) {
            tracing::warn!("gp-route: gateway exclude {gateway} failed ({e}); rolling back");
            return Err(rollback_and_fail(runner, &state, e));
        }
    }

    if let Some(route_gateway) = route_gateway {
        let route_gateway = route_gateway.to_string();
        for route in &config.routes {
            let (network, netmask) = parse_ipv4_cidr(route)?;
            let network = network.to_string();
            let netmask = netmask.to_string();
            let add = run_unix(
                runner,
                "route",
                "add route",
                &[
                    "-n",
                    "add",
                    "-net",
                    &network,
                    "-netmask",
                    &netmask,
                    &route_gateway,
                ],
            );
            // BSD `route add` is EEXIST-on-conflict just like Linux's,
            // so a prefix already claimed by another VPN's utun or a
            // hypervisor host-only network aborted the connect.
            // `route change` is the documented way to repoint an
            // existing route, and it can only succeed in exactly the
            // case `add` just failed for.
            //
            // Unlike the Linux backend this does NOT preserve what it
            // displaced: recovering the prior entry means parsing
            // `route -n get` output, which no CI runner here can
            // exercise (they are all Linux), and shipping unverified
            // route-mutation logic is worse than a documented gap. The
            // warning says so plainly.
            match add {
                Ok(()) => {}
                Err(add_err) if is_route_exists_error(&add_err) => {
                    match config.route_conflict {
                        RouteConflictPolicy::Fail => {
                            return Err(rollback_and_fail(
                                runner,
                                &state,
                                RouteError::RouteConflict {
                                    cidr: route.clone(),
                                    owner: "another interface".into(),
                                    detail: String::new(),
                                },
                            ))
                        }
                        RouteConflictPolicy::Skip => {
                            tracing::warn!(
                                "gp-route: {route} is already routed on this host; leaving it \
                                 alone as asked. Traffic to {route} will NOT go through the \
                                 tunnel."
                            );
                            continue;
                        }
                        RouteConflictPolicy::TakeOver => {}
                    }
                    tracing::warn!(
                        "gp-route: {route} is already routed on this host — repointing it at \
                         {} for the session. Unlike Linux, the macOS backend cannot restore \
                         the previous entry on disconnect; it may need re-creating by hand.",
                        config.ifname
                    );
                    if let Err(e) = run_unix(
                        runner,
                        "route",
                        "change route",
                        &[
                            "-n",
                            "change",
                            "-net",
                            &network,
                            "-netmask",
                            &netmask,
                            &route_gateway,
                        ],
                    ) {
                        tracing::warn!(
                            "gp-route: route change {route} on {} failed ({e}); rolling back",
                            config.ifname
                        );
                        return Err(rollback_and_fail(runner, &state, e));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "gp-route: route add {route} on {} failed ({e}); rolling back",
                        config.ifname
                    );
                    return Err(rollback_and_fail(runner, &state, e));
                }
            }
            state
                .installed_routes
                .push(InstalledRoute::new(route.clone()));
        }
    }

    Ok(state)
}

#[cfg(target_os = "macos")]
fn platform_revert<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    for route in state.installed_routes.iter().rev() {
        let cidr = &route.cidr;
        match parse_ipv4_cidr(cidr) {
            Ok((network, netmask)) => {
                if let Err(e) = run_unix(
                    runner,
                    "route",
                    "delete route",
                    &[
                        "-n",
                        "delete",
                        "-net",
                        &network.to_string(),
                        "-netmask",
                        &netmask.to_string(),
                    ],
                ) {
                    errors.push(format!("route delete {cidr}: {e}"));
                }
            }
            Err(e) => errors.push(format!("route delete {cidr}: {e}")),
        }
    }

    if let Some(addr) = state.installed_addr {
        let addr_str = addr.to_string();
        if let Err(e) = run_unix(
            runner,
            "ifconfig",
            "addr del",
            &[&state.ifname, &addr_str, "delete"],
        ) {
            errors.push(format!("addr del {addr}: {e}"));
        }
    }

    if let Some(pin) = &state.installed_gateway_exclude {
        let pin_ip = pin.ip.to_string();
        let result = if let Some(gateway) = pin.prior_entry.as_deref() {
            run_unix(
                runner,
                "route",
                "delete gateway pin",
                &["-n", "delete", "-host", &pin_ip, gateway],
            )
        } else {
            run_unix(
                runner,
                "route",
                "delete gateway pin",
                &["-n", "delete", "-host", &pin_ip],
            )
        };
        if let Err(e) = result {
            errors.push(format!("route delete {pin_ip}/32: {e}"));
        }
    }

    errors
}

#[cfg(target_os = "macos")]
fn configure_iface_macos<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<(), RouteError> {
    let mut args = vec![config.ifname.clone()];
    match config.ipv4 {
        Some(addr) => {
            let addr = addr.to_string();
            args.extend([
                "inet".to_string(),
                addr.clone(),
                addr,
                "netmask".to_string(),
                "255.255.255.255".to_string(),
            ]);
        }
        None => args.push("up".to_string()),
    }
    if let Some(mtu) = config.mtu {
        args.push("mtu".to_string());
        args.push(mtu.to_string());
    }
    if config.ipv4.is_some() {
        args.push("up".to_string());
    }
    run_unix_owned(runner, "ifconfig", "configure interface", &args)
}

#[cfg(target_os = "macos")]
fn install_gateway_exclude_macos<R: CommandRunner>(
    runner: &R,
    state: &mut AppliedState,
    gateway: Ipv4Addr,
) -> Result<(), RouteError> {
    let route_get = run_unix_stdout(runner, "route", "get default", &["-n", "get", "default"])?;
    let default_gw = parse_default_gateway_macos(&route_get)?;
    run_unix(
        runner,
        "route",
        "add gateway pin",
        &["-n", "add", "-host", &gateway.to_string(), &default_gw],
    )?;

    state.installed_gateway_exclude = Some(GatewayPinState {
        ip: gateway,
        prior_entry: Some(default_gw),
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn parse_default_gateway_macos(output: &str) -> Result<String, RouteError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(gateway) = trimmed.strip_prefix("gateway:") {
            let gateway = gateway.trim();
            if !gateway.is_empty() {
                return Ok(gateway.to_string());
            }
        }
    }
    Err(RouteError::InvalidConfig(format!(
        "route -n get default output missing gateway: {output:?}"
    )))
}

fn parse_ipv4_cidr(route: &str) -> Result<(Ipv4Addr, Ipv4Addr), RouteError> {
    let (network, prefix) = route.split_once('/').ok_or_else(|| {
        RouteError::InvalidConfig(format!("expected a CIDR route, got {route:?}"))
    })?;
    let network = network
        .parse::<Ipv4Addr>()
        .map_err(|e| RouteError::InvalidConfig(format!("invalid IPv4 network {network:?}: {e}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| RouteError::InvalidConfig(format!("invalid IPv4 prefix in {route:?}: {e}")))?;
    if prefix > 32 {
        return Err(RouteError::InvalidConfig(format!(
            "invalid IPv4 prefix length {prefix} in {route:?}"
        )));
    }
    Ok((network, ipv4_netmask(prefix)))
}

fn ipv4_netmask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(bits)
}

#[cfg(target_os = "macos")]
fn run_unix<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[&str],
) -> Result<(), RouteError> {
    run_unix_checked(runner, program, op, args).map(|_| ())
}

#[cfg(target_os = "macos")]
fn run_unix_owned<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[String],
) -> Result<(), RouteError> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_unix(runner, program, op, &refs)
}

#[cfg(target_os = "macos")]
fn run_unix_stdout<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[&str],
) -> Result<String, RouteError> {
    run_unix_checked(runner, program, op, args)
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn run_unix_checked<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[&str],
) -> Result<Output, RouteError> {
    tracing::debug!("gp-route: {program} {}", args.join(" "));
    let out = runner.run(program, args)?;
    if out.status.success() {
        Ok(out)
    } else {
        let detail = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        })
        .trim()
        .to_string();
        Err(RouteError::UnixCommand {
            program,
            op,
            detail,
        })
    }
}

// ---------------------------------------------------------------------------
// Windows backend (netsh + route.exe — including default-gateway parsing)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn platform_apply<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    let mut state = AppliedState {
        ifname: config.ifname.clone(),
        ..AppliedState::default()
    };

    let rollback = |runner: &R, state: &AppliedState, err: RouteError| -> RouteError {
        for rev_err in platform_revert(runner, state) {
            tracing::warn!("gp-route apply-rollback: {rev_err}");
        }
        err
    };

    // 1. Set MTU (no link-up needed — Wintun auto-activates).
    if let Some(mtu) = config.mtu {
        let mtu_str = format!("mtu={mtu}");
        run_netsh(
            runner,
            "set mtu",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &config.ifname,
                &mtu_str,
                "store=active",
            ],
        )?;
    }

    // 2. Assign IPv4 address.
    if let Some(addr) = config.ipv4 {
        run_netsh(
            runner,
            "add address",
            &[
                "interface",
                "ipv4",
                "add",
                "address",
                &config.ifname,
                &addr.to_string(),
                "255.255.255.255",
                "store=active",
            ],
        )?;
        state.installed_addr = Some(addr);
    }

    // 3. Pin gateway outside the tunnel.
    if let Some(gateway) = config.gateway_exclude {
        if let Err(e) = install_gateway_exclude_windows(runner, &mut state, gateway) {
            tracing::warn!("gp-route: gateway exclude {gateway} failed ({e}); rolling back");
            return Err(rollback(runner, &state, e));
        }
    }

    // 4. Install split routes via netsh.
    //
    // Windows keys routing-table entries on (prefix, interface,
    // nexthop), so a Docker Desktop / WSL2 `vEthernet (WSL)` route to
    // the same 172.x prefix on another adapter does not block ours —
    // and must not be displaced. `add route` only reports "The object
    // already exists" for the same prefix on the *same* interface,
    // i.e. a leftover from a session that died before revert on a
    // recycled Wintun adapter of the same name. Deleting that and
    // retrying is self-scoped: it can only ever remove our own stale
    // entry, so there is nothing here to capture and restore.
    for route in &config.routes {
        let add_args = [
            "interface",
            "ipv4",
            "add",
            "route",
            route,
            &config.ifname,
            "store=active",
        ];
        if let Err(first) = run_netsh(runner, "add route", &add_args) {
            // Only "the object already exists" earns a retry, and only
            // then is the delete safe: it names our own interface, so
            // the entry it removes can only be a leftover of ours on a
            // recycled Wintun adapter of the same name. Any other
            // failure propagates untouched, as before.
            if !is_route_exists_error(&first) {
                tracing::warn!(
                    "gp-route: route add {route} on {} failed ({first}); rolling back",
                    config.ifname
                );
                return Err(rollback(runner, &state, first));
            }
            tracing::warn!(
                "gp-route: route add {route} on {} reports the route already exists; \
                 clearing our stale entry for that prefix and retrying",
                config.ifname
            );
            let _ = run_netsh(
                runner,
                "delete route",
                &[
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    route,
                    &config.ifname,
                ],
            );
            if let Err(e) = run_netsh(runner, "add route", &add_args) {
                tracing::warn!(
                    "gp-route: route add {route} on {} failed again ({e}); rolling back",
                    config.ifname
                );
                return Err(rollback(runner, &state, e));
            }
        }
        state
            .installed_routes
            .push(InstalledRoute::new(route.clone()));
    }

    Ok(state)
}

#[cfg(windows)]
fn platform_revert<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    // Routes first, LIFO.
    for route in state.installed_routes.iter().rev() {
        let cidr = &route.cidr;
        if let Err(e) = run_netsh(
            runner,
            "delete route",
            &["interface", "ipv4", "delete", "route", cidr, &state.ifname],
        ) {
            errors.push(format!("delete route {cidr}: {e}"));
        }
    }

    // Then address.
    if let Some(addr) = state.installed_addr {
        if let Err(e) = run_netsh(
            runner,
            "delete address",
            &[
                "interface",
                "ipv4",
                "delete",
                "address",
                &state.ifname,
                &addr.to_string(),
            ],
        ) {
            errors.push(format!("delete address {addr}: {e}"));
        }
    }

    // Gateway pin — include the nexthop so we only remove the
    // exact route we added, not a broader match.
    if let Some(pin) = &state.installed_gateway_exclude {
        let ip_str = pin.ip.to_string();
        let mut args: Vec<&str> = vec!["delete", &ip_str, "mask", "255.255.255.255"];
        // prior_entry holds the default gateway nexthop we pinned through.
        // Include it so we only remove the exact route we added.
        if let Some(ref gw) = pin.prior_entry {
            args.push(gw);
        }
        if let Err(e) = run_checked(runner, "route.exe", "delete gateway pin", &args) {
            errors.push(format!("delete gateway pin {}: {e}", pin.ip));
        }
    }

    errors
}

/// Pin the VPN gateway through the physical default route so split
/// routes don't capture it.
#[cfg(windows)]
fn install_gateway_exclude_windows<R: CommandRunner>(
    runner: &R,
    state: &mut AppliedState,
    gateway: Ipv4Addr,
) -> Result<(), RouteError> {
    // Discover the default gateway. We used to shell out to PowerShell
    // (`Get-NetRoute … | Sort-Object …`) which gave us the correct
    // multi-homed preference (InterfaceMetric + RouteMetric) — but the
    // cold-start cost of PowerShell + CIM is 5-15s on real Windows
    // boxes, which kept tripping the 10s subprocess timeout and
    // failing every `opc connect`. `route.exe print -4 0.0.0.0` is a
    // native Win32 binary, returns in <100 ms, and exposes RouteMetric
    // directly. We lose InterfaceMetric, but the common single-NIC
    // case is correct: the lowest-RouteMetric default route is the one
    // the kernel will actually use.
    let default_gw = discover_default_gateway_win(runner)?;

    // Pin the VPN gateway through the physical default route.
    run_checked(
        runner,
        "route.exe",
        "add gateway pin",
        &[
            "add",
            &gateway.to_string(),
            "mask",
            "255.255.255.255",
            &default_gw,
        ],
    )?;

    state.installed_gateway_exclude = Some(GatewayPinState {
        ip: gateway,
        prior_entry: Some(default_gw),
    });
    Ok(())
}

#[cfg(windows)]
fn run_netsh<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<(), RouteError> {
    run_checked(runner, "netsh", op, args)
}

/// Discover the active IPv4 default gateway by parsing `route.exe print`.
///
/// We pick the row with the lowest `Metric` column among `0.0.0.0 / 0.0.0.0`
/// entries. That matches the kernel's tiebreaker for routes of identical
/// destination, so we land on the same nexthop the OS would actually use
/// for a fresh connection to the VPN gateway.
///
/// route.exe output (locale-independent, columns are whitespace-separated):
///
/// ```text
/// IPv4 Route Table
/// ===========================================================================
/// Active Routes:
/// Network Destination        Netmask          Gateway       Interface  Metric
///           0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
///           0.0.0.0          0.0.0.0      10.0.0.1     10.0.0.42        50
/// ===========================================================================
/// ```
#[cfg(windows)]
fn discover_default_gateway_win<R: CommandRunner>(runner: &R) -> Result<String, RouteError> {
    let out = runner.run("route.exe", &["print", "-4", "0.0.0.0"])?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(RouteError::WinCommand {
            program: "route",
            op: "discover default gateway",
            detail: stderr,
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let best = parse_default_gateway(&stdout);
    best.ok_or(RouteError::WinCommand {
        program: "route",
        op: "discover default gateway",
        detail: "no default route in `route.exe print -4 0.0.0.0` output".into(),
    })
}

/// Parse the lowest-metric default gateway out of `route.exe print` text.
///
/// Split out from `discover_default_gateway_win` so tests can drive it
/// against fixture strings without spawning route.exe. The route table
/// rows themselves are not localized (the column headers are, but we
/// never look at them) — we key off the literal `0.0.0.0` destination
/// and netmask plus a strict IPv4 parse on the gateway column, so a
/// localized `On-link` rendering (or any other non-IP token) cannot
/// slip through and end up as an argument to `route.exe add`.
#[cfg(windows)]
fn parse_default_gateway(stdout: &str) -> Option<String> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // `Network Destination / Netmask / Gateway / Interface / Metric`
        // — always 5 columns for the route rows we care about.
        if cols.len() < 5 {
            continue;
        }
        if cols[0] != "0.0.0.0" || cols[1] != "0.0.0.0" {
            continue;
        }
        // Strict IPv4 parse. This naturally rejects `On-link` (any
        // language), `*`, or anything else route.exe might emit for
        // a directly-attached / interface-bound default route.
        let gw: Ipv4Addr = match cols[2].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let metric: u32 = match cols[4].parse() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((metric, gw));
        }
    }
    best.map(|(_, gw)| gw.to_string())
}

/// Run a command and check exit status.
#[cfg(windows)]
fn run_checked<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[&str],
) -> Result<(), RouteError> {
    tracing::debug!("gp-route: {program} {}", args.join(" "));
    let out = runner.run(program, args)?;
    if out.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(RouteError::WinCommand {
            program,
            op,
            detail,
        })
    }
}

// Unsupported platform fallback.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_apply<R: CommandRunner>(
    _runner: &R,
    _config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    Err(RouteError::InvalidConfig("unsupported platform".into()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_revert<R: CommandRunner>(_runner: &R, _state: &AppliedState) -> Vec<String> {
    vec!["unsupported platform".into()]
}

// ---------------------------------------------------------------------------
// Tests — platform independent
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_dns_pins {
    use super::*;

    fn routes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// The tunnel subnet from the reported case: 172.20.196.199/24.
    fn tunnel() -> Option<(Ipv4Addr, Ipv4Addr)> {
        Some((
            Ipv4Addr::new(172, 20, 196, 199),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
    }

    #[test]
    fn pins_a_nameserver_outside_the_split_prefixes() {
        // The reported case: gateway hands out 172.20.196.1 as DNS while
        // the user only routed the two campus prefixes.
        let plan = dns_pin_routes(
            &routes(&["128.112.0.0/16", "140.180.0.0/16"]),
            &ips(&["172.20.196.1"]),
            tunnel(),
        );
        assert_eq!(plan.pins, vec!["172.20.196.1/32"]);
    }

    #[test]
    fn skips_a_nameserver_already_inside_a_split_prefix() {
        let plan = dns_pin_routes(&routes(&["10.0.0.0/8"]), &ips(&["10.1.2.3"]), tunnel());
        assert!(plan.pins.is_empty(), "got {:?}", plan.pins);
    }

    #[test]
    fn skips_everything_under_a_default_route() {
        let plan = dns_pin_routes(
            &routes(&["0.0.0.0/0"]),
            &ips(&["172.20.196.1", "8.8.8.8"]),
            tunnel(),
        );
        assert!(plan.pins.is_empty(), "got {:?}", plan.pins);
        // Covered by a route, so not "skipped as global" either.
        assert!(plan.skipped_global.is_empty());
    }

    #[test]
    fn skips_a_pin_the_caller_already_listed() {
        let plan = dns_pin_routes(
            &routes(&["172.20.196.1/32"]),
            &ips(&["172.20.196.1"]),
            tunnel(),
        );
        assert!(plan.pins.is_empty(), "got {:?}", plan.pins);
    }

    #[test]
    fn deduplicates_repeated_servers() {
        let plan = dns_pin_routes(
            &routes(&["128.112.0.0/16"]),
            &ips(&["172.20.196.1", "172.20.196.1", "172.20.196.2"]),
            tunnel(),
        );
        assert_eq!(plan.pins, vec!["172.20.196.1/32", "172.20.196.2/32"]);
    }

    #[test]
    fn reports_ipv6_servers_instead_of_dropping_them_silently() {
        let plan = dns_pin_routes(
            &routes(&["128.112.0.0/16"]),
            &ips(&["2001:db8::1"]),
            tunnel(),
        );
        assert!(plan.pins.is_empty(), "got {:?}", plan.pins);
        assert_eq!(plan.skipped_ipv6, ips(&["2001:db8::1"]));
    }

    #[test]
    fn treats_unparsable_routes_as_covering_nothing() {
        // `apply` is what reports the bad route; this must not panic or
        // silently swallow the pin it would otherwise emit.
        let plan = dns_pin_routes(&routes(&["not-a-cidr"]), &ips(&["172.20.196.1"]), tunnel());
        assert_eq!(plan.pins, vec!["172.20.196.1/32"]);
    }

    #[test]
    fn boundary_addresses_of_a_prefix_are_covered() {
        let list = routes(&["128.112.0.0/16"]);
        assert!(dns_pin_routes(&list, &ips(&["128.112.0.0"]), None)
            .pins
            .is_empty());
        assert!(dns_pin_routes(&list, &ips(&["128.112.255.255"]), None)
            .pins
            .is_empty());
        // 128.113.0.0 is outside the prefix but globally routable, so
        // it is reported rather than pinned.
        let plan = dns_pin_routes(&list, &ips(&["128.113.0.0"]), None);
        assert!(plan.pins.is_empty());
        assert_eq!(plan.skipped_global, vec![Ipv4Addr::new(128, 113, 0, 0)]);
    }

    /// A gateway that pushes a public resolver alongside its internal
    /// one must not have that resolver dragged into the tunnel: on a
    /// split-tunnel gateway that does not forward it, the host loses
    /// DNS entirely the moment the VPN comes up.
    #[test]
    fn does_not_pin_a_globally_routable_resolver() {
        let plan = dns_pin_routes(
            &routes(&["10.0.0.0/8"]),
            &ips(&["10.1.1.1", "8.8.8.8"]),
            None,
        );
        assert!(plan.pins.is_empty(), "10.1.1.1 is covered by 10.0.0.0/8");
        assert_eq!(plan.skipped_global, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn pins_private_and_cgnat_resolvers_without_a_known_tunnel_subnet() {
        let plan = dns_pin_routes(
            &routes(&["203.0.113.0/24"]),
            &ips(&["10.1.1.1", "172.16.0.1", "192.168.5.5", "100.100.100.100"]),
            None,
        );
        assert_eq!(
            plan.pins,
            vec![
                "10.1.1.1/32",
                "172.16.0.1/32",
                "192.168.5.5/32",
                "100.100.100.100/32"
            ]
        );
        assert!(plan.skipped_global.is_empty());
    }

    /// A resolver on a globally-routable address is still pinned when
    /// it demonstrably lives in the tunnel's own subnet.
    #[test]
    fn pins_a_public_address_that_sits_in_the_tunnel_subnet() {
        let net = Some((
            Ipv4Addr::new(203, 0, 113, 9),
            Ipv4Addr::new(255, 255, 255, 0),
        ));
        let plan = dns_pin_routes(&routes(&["10.0.0.0/8"]), &ips(&["203.0.113.1"]), net);
        assert_eq!(plan.pins, vec!["203.0.113.1/32"]);
    }

    #[test]
    fn never_pins_loopback_or_link_local() {
        let plan = dns_pin_routes(
            &routes(&["10.0.0.0/8"]),
            &ips(&["127.0.0.53", "169.254.1.1"]),
            None,
        );
        assert!(plan.pins.is_empty(), "got {:?}", plan.pins);
    }
}

#[cfg(test)]
mod tests_route_dedupe {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn identical_prefixes_collapse_to_one() {
        // `resolve_only_spec` emits one /32 per resolved address with
        // no de-duplication, so `--only a.corp,b.corp` behind a single
        // IP produced the same prefix twice — and `ip route add` fails
        // EEXIST on the second.
        assert_eq!(
            dedupe_routes(&v(&["10.1.1.1/32", "10.1.1.1/32"])),
            v(&["10.1.1.1/32"])
        );
    }

    #[test]
    fn host_bits_do_not_hide_a_duplicate() {
        assert_eq!(
            dedupe_routes(&v(&["10.0.0.0/8", "10.99.99.99/8"])),
            v(&["10.0.0.0/8"])
        );
    }

    #[test]
    fn order_is_preserved_and_first_spelling_wins() {
        assert_eq!(
            dedupe_routes(&v(&["10.99.99.99/8", "192.168.0.0/16", "10.0.0.0/8"])),
            v(&["10.99.99.99/8", "192.168.0.0/16"])
        );
    }

    #[test]
    fn ipv6_and_malformed_entries_pass_through_and_dedupe_textually() {
        assert_eq!(
            dedupe_routes(&v(&[
                "2001:db8::/64",
                "2001:db8::/64",
                "nonsense",
                "nonsense"
            ])),
            v(&["2001:db8::/64", "nonsense"])
        );
    }

    #[test]
    fn normalize_masks_host_bits_only_for_parseable_ipv4() {
        assert_eq!(normalize_route("10.99.99.99/8"), "10.0.0.0/8");
        assert_eq!(normalize_route("10.0.0.0/8"), "10.0.0.0/8");
        assert_eq!(normalize_route("1.2.3.4/32"), "1.2.3.4/32");
        assert_eq!(normalize_route("0.0.0.0/0"), "0.0.0.0/0");
        assert_eq!(normalize_route("2001:db8::/64"), "2001:db8::/64");
        assert_eq!(normalize_route("nonsense"), "nonsense");
    }
}

// ---------------------------------------------------------------------------
// Tests — Linux
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests_linux {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok() -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn ok_stdout(stdout: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            }
        }

        fn err(stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(1 << 8),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        fn new(outcomes: Vec<Result<Output, io::Error>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }

        fn all_ok(n: usize) -> Self {
            let outcomes = (0..n).map(|_| Ok(Self::ok())).collect();
            Self::new(outcomes)
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(full);
            let mut outcomes = self.outcomes.borrow_mut();
            if outcomes.is_empty() {
                panic!("FakeRunner: no more outcomes queued (unexpected call)");
            }
            outcomes.remove(0)
        }
    }

    fn cfg(routes: Vec<&str>) -> TunConfig {
        cfg_with_gateway(routes, None)
    }

    fn cfg_with_gateway(routes: Vec<&str>, gateway_exclude: Option<Ipv4Addr>) -> TunConfig {
        TunConfig {
            ifname: "tun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1422),
            gateway_exclude,
            routes: routes.into_iter().map(String::from).collect(),
            route_conflict: RouteConflictPolicy::default(),
        }
    }

    #[test]
    fn apply_issues_expected_commands_in_order() {
        // The happy path is still one call per route: `add` succeeds,
        // so nothing is captured and nothing is displaced.
        let runner = FakeRunner::all_ok(5);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap();

        assert_eq!(state.ifname, "tun7");
        assert_eq!(state.installed_addr, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        assert!(state.installed_routes.iter().all(|r| !r.displaced()));

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0], vec!["ip", "link", "set", "dev", "tun7", "up"]);
        assert_eq!(
            calls[1],
            vec!["ip", "link", "set", "dev", "tun7", "mtu", "1422"]
        );
        assert_eq!(
            calls[2],
            vec!["ip", "addr", "add", "10.1.2.3/32", "dev", "tun7"]
        );
        assert_eq!(
            calls[3],
            vec!["ip", "-4", "route", "add", "10.0.0.0/8", "dev", "tun7"]
        );
        assert_eq!(
            calls[4],
            vec!["ip", "-4", "route", "add", "172.16.0.0/12", "dev", "tun7"]
        );
    }

    #[test]
    fn apply_skips_mtu_and_addr_when_not_set() {
        let config = TunConfig {
            ifname: "tun0".into(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::all_ok(2);
        apply_with(&runner, &config).unwrap();
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1..4], ["link", "set", "dev"]);
        assert_eq!(calls[1][1..4], ["-4", "route", "add"]);
    }

    #[test]
    fn apply_fails_fast_on_link_up() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::err("boom"))]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(matches!(err, RouteError::IpCommand { op: "link up", .. }));
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn apply_auto_rolls_back_on_route_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),              // link up
            Ok(FakeRunner::ok()),              // mtu
            Ok(FakeRunner::ok()),              // addr add
            Ok(FakeRunner::ok()),              // route add 10.0.0.0/8
            Ok(FakeRunner::err("route2 bad")), // route add 172.16.0.0/12 FAILS
            Ok(FakeRunner::ok()),              // route del 10.0.0.0/8 (rollback)
            Ok(FakeRunner::ok()),              // addr del (rollback)
        ]);
        let err = apply_with(
            &runner,
            &cfg(vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
        )
        .unwrap_err();
        match err {
            RouteError::IpCommand { op, stderr } => {
                assert_eq!(op, "route add");
                assert!(stderr.contains("route2 bad"), "got: {stderr}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 7, "call sequence: {:#?}", calls);
        // Rollback deletes only what was actually installed.
        assert_eq!(
            calls[5],
            vec!["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "tun7"]
        );
    }

    #[test]
    fn apply_rolls_back_address_on_first_route_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),        // link up
            Ok(FakeRunner::ok()),        // mtu
            Ok(FakeRunner::ok()),        // addr add
            Ok(FakeRunner::err("nope")), // route add FAILS
            Ok(FakeRunner::ok()),        // addr del (rollback)
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(matches!(
            err,
            RouteError::IpCommand {
                op: "route add",
                ..
            }
        ));
    }

    /// The reported bug: a Docker bridge owns 172.20.0.0/16, so
    /// `ip route add` returns EEXIST and the whole connect used to
    /// abort. The prefix is now taken over and the bridge's entry is
    /// recorded for restoration.
    #[test]
    fn takes_over_a_prefix_a_docker_bridge_already_owns() {
        const DOCKER: &str =
            "172.20.0.0/16 dev br-81f0638ae4fb proto kernel scope link src 172.20.0.1";
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                                  // link up
            Ok(FakeRunner::ok()),                                  // mtu
            Ok(FakeRunner::ok()),                                  // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")), // route add
            Ok(FakeRunner::ok_stdout(&format!("{DOCKER}\n"))),     // route show exact
            Ok(FakeRunner::ok()),                                  // route replace
        ]);

        let state = apply_with(&runner, &cfg(vec!["172.20.0.0/16"])).unwrap();

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[3],
            vec!["ip", "-4", "route", "add", "172.20.0.0/16", "dev", "tun7"]
        );
        assert_eq!(
            calls[4],
            vec!["ip", "-4", "route", "show", "exact", "172.20.0.0/16"]
        );
        assert_eq!(
            calls[5],
            vec![
                "ip",
                "-4",
                "route",
                "replace",
                "172.20.0.0/16",
                "dev",
                "tun7"
            ]
        );
        assert_eq!(state.installed_routes.len(), 1);
        assert_eq!(state.installed_routes[0].prior, vec![DOCKER.to_string()]);
        assert!(state.installed_routes[0].displaced());
        assert_eq!(
            state.displaced_cidrs().collect::<Vec<_>>(),
            ["172.20.0.0/16"]
        );
    }

    /// The other half of the takeover: disconnect must hand the prefix
    /// back, or the user's containers stay unreachable from the host.
    #[test]
    fn revert_restores_a_displaced_route() {
        const DOCKER: &str =
            "172.20.0.0/16 dev br-81f0638ae4fb proto kernel scope link src 172.20.0.1";
        let state = AppliedState {
            ifname: "tun7".into(),
            installed_routes: vec![InstalledRoute {
                cidr: "172.20.0.0/16".into(),
                prior: vec![DOCKER.into()],
            }],
            installed_addr: None,
            installed_gateway_exclude: None,
        };
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok()), Ok(FakeRunner::ok())]);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0],
            vec!["ip", "-4", "route", "del", "172.20.0.0/16", "dev", "tun7"]
        );
        let mut expected = vec!["ip", "-4", "route", "replace"];
        expected.extend(DOCKER.split_whitespace());
        assert_eq!(calls[1], expected);
    }

    /// libopenconnect usually tears the tun device down before revert
    /// runs, so the delete fails with "Cannot find device". The restore
    /// is the step that matters and must still happen — and a delete
    /// failure must not be reported as an error when there is
    /// something to put back.
    #[test]
    fn revert_restores_even_when_the_delete_fails() {
        const PRIOR: &str = "172.20.0.0/16 dev br-x proto kernel scope link src 172.20.0.1";
        let state = AppliedState {
            ifname: "tun7".into(),
            installed_routes: vec![InstalledRoute {
                cidr: "172.20.0.0/16".into(),
                prior: vec![PRIOR.into()],
            }],
            installed_addr: None,
            installed_gateway_exclude: None,
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::err("Cannot find device \"tun7\"")),
            Ok(FakeRunner::ok()),
        ]);
        let errors = revert_with(&runner, &state);
        assert!(
            errors.is_empty(),
            "delete failure must not surface: {errors:?}"
        );
        assert_eq!(runner.calls.borrow().len(), 2, "restore must still run");
    }

    /// `--route-conflict fail` keeps the old refuse-to-connect
    /// behaviour but explains itself.
    #[test]
    fn fail_policy_reports_what_owns_the_prefix() {
        let mut config = cfg(vec!["172.20.0.0/16"]);
        config.route_conflict = RouteConflictPolicy::Fail;
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")),
            Ok(FakeRunner::ok_stdout(
                "172.20.0.0/16 dev br-81f0638ae4fb proto kernel scope link src 172.20.0.1\n",
            )),
            Ok(FakeRunner::ok()), // addr del (rollback)
        ]);
        let err = apply_with(&runner, &config).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("172.20.0.0/16"), "{rendered}");
        assert!(rendered.contains("br-81f0638ae4fb"), "{rendered}");
        assert!(
            rendered.contains("--route-conflict take-over"),
            "{rendered}"
        );
    }

    /// `--route-conflict skip` installs everything else and leaves the
    /// contested prefix alone — so it must not end up in the state
    /// that revert replays.
    #[test]
    fn skip_policy_installs_nothing_for_the_contested_prefix() {
        let mut config = cfg(vec!["172.20.0.0/16", "10.0.0.0/8"]);
        config.route_conflict = RouteConflictPolicy::Skip;
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")),
            Ok(FakeRunner::ok_stdout("172.20.0.0/16 dev br-x scope link\n")),
            Ok(FakeRunner::ok()), // route add 10.0.0.0/8
        ]);
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8"]);
    }

    /// An EEXIST whose only claimant is our own interface is a
    /// leftover from a session that died before revert. Reclaim it,
    /// but do not record it as someone else's route to restore.
    #[test]
    fn reclaims_a_stale_entry_on_our_own_interface_without_recording_it() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")),
            Ok(FakeRunner::ok_stdout("10.0.0.0/8 dev tun7 scope link\n")),
            Ok(FakeRunner::ok()), // route replace
        ]);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap();
        assert_eq!(state.installed_routes.len(), 1);
        assert!(state.installed_routes[0].prior.is_empty());
        assert!(!state.installed_routes[0].displaced());
    }

    /// Several entries share the key, so `replace` would collapse them
    /// and revert could only put one back. Refuse rather than lose the
    /// others.
    #[test]
    fn refuses_takeover_when_several_entries_share_the_prefix() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")),
            Ok(FakeRunner::ok_stdout(
                "10.0.0.0/8 dev eth0 metric 256\n10.0.0.0/8 dev eth1 metric 256\n",
            )),
            Ok(FakeRunner::ok()), // addr del (rollback)
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(
            err.to_string().contains("2 entries share this prefix"),
            "{err}"
        );
    }

    /// A route failure that is not a conflict keeps the old behaviour:
    /// no capture attempt, straight to rollback.
    #[test]
    fn a_non_conflict_route_failure_does_not_try_to_take_over() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::err("Network is unreachable")),
            Ok(FakeRunner::ok()), // addr del (rollback)
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(matches!(
            err,
            RouteError::IpCommand {
                op: "route add",
                ..
            }
        ));
        assert_eq!(runner.calls.borrow().len(), 5);
    }

    /// IPv6 split routes exist (`resolve_only_spec` emits `/128` from
    /// AAAA records) and every `ip` call about them needs `-6`:
    /// `ip -4 route show exact fe80::/64` is a hard parse error, and
    /// omitting the flag returns nothing at all.
    #[test]
    fn ipv6_routes_use_the_v6_family_flag() {
        let config = TunConfig {
            ifname: "tun7".into(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec!["2001:db8::/64".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::all_ok(2);
        apply_with(&runner, &config).unwrap();
        assert_eq!(
            runner.calls.borrow()[1],
            vec!["ip", "-6", "route", "add", "2001:db8::/64", "dev", "tun7"]
        );
    }

    #[test]
    fn family_flag_picks_the_right_family() {
        assert_eq!(family_flag("10.0.0.0/8"), "-4");
        assert_eq!(family_flag("1.2.3.4/32"), "-4");
        assert_eq!(family_flag("2001:db8::/64"), "-6");
        assert_eq!(family_flag("fe80::1/128"), "-6");
        // Malformed input falls through to -4 so the install command
        // produces the authoritative error.
        assert_eq!(family_flag("not-a-cidr"), "-4");
    }

    /// `ip route show` prints tokens `ip route replace` refuses.
    /// Verified against iproute2: replaying the docker0 line verbatim
    /// gives `Error: either "to" is duplicate, or "linkdown" is a
    /// garbage.` and exits 255.
    #[test]
    fn sanitize_strips_show_only_tokens() {
        assert_eq!(
            sanitize_route_entry(
                "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown"
            )
            .unwrap(),
            "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1"
        );
        assert_eq!(
            sanitize_route_entry("10.0.0.0/8 via 192.0.2.1 dev eth0 expires 300sec").unwrap(),
            "10.0.0.0/8 via 192.0.2.1 dev eth0"
        );
        assert_eq!(
            sanitize_route_entry("10.0.0.0/8 dev eth0 error -101 dead").unwrap(),
            "10.0.0.0/8 dev eth0"
        );
        // Preserved: everything `replace` accepts.
        assert_eq!(
            sanitize_route_entry("10.0.0.0/8 via 192.0.2.1 dev eth0 metric 100 onlink").unwrap(),
            "10.0.0.0/8 via 192.0.2.1 dev eth0 metric 100 onlink"
        );
        // Nothing left to reinstall.
        assert!(sanitize_route_entry("blackhole 10.0.0.0/8").is_none());
    }

    #[test]
    fn split_route_entries_folds_multipath_continuations() {
        assert_eq!(split_route_entries(""), Vec::<String>::new());
        assert_eq!(
            split_route_entries("10.0.0.0/8 dev eth0\n192.168.0.0/16 dev eth1\n"),
            vec!["10.0.0.0/8 dev eth0", "192.168.0.0/16 dev eth1"]
        );
        assert_eq!(
            split_route_entries(
                "10.0.0.0/8 proto static\n\tnexthop via 192.0.2.1 dev eth0 weight 1\n\tnexthop via 192.0.2.2 dev eth1 weight 1\n"
            ),
            vec![concat!(
                "10.0.0.0/8 proto static ",
                "nexthop via 192.0.2.1 dev eth0 weight 1 ",
                "nexthop via 192.0.2.2 dev eth1 weight 1"
            )]
        );
    }

    #[test]
    fn route_entry_dev_finds_the_interface() {
        assert_eq!(
            route_entry_dev("172.20.0.0/16 dev br-x proto kernel"),
            Some("br-x")
        );
        assert_eq!(route_entry_dev("10.0.0.0/8 via 192.0.2.1"), None);
    }

    /// The gateway pin has always captured and restored a prior entry;
    /// it just never sanitized it, so a pin whose prior route sat on a
    /// carrier-less interface failed to restore on disconnect.
    #[test]
    fn gateway_pin_capture_is_sanitized() {
        let gateway = Ipv4Addr::new(198, 51, 100, 230);
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // link up
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr add
            Ok(FakeRunner::ok_stdout(
                "198.51.100.230 via 192.0.2.1 dev eth0 linkdown\n",
            )), // route show exact
            Ok(FakeRunner::ok_stdout(
                "198.51.100.230 via 192.0.2.1 dev eth0\n",
            )), // route get
            Ok(FakeRunner::ok()), // route replace
            Ok(FakeRunner::ok()), // route add split
        ]);
        let state = apply_with(
            &runner,
            &cfg_with_gateway(vec!["198.51.100.0/16"], Some(gateway)),
        )
        .unwrap();
        assert_eq!(
            state
                .installed_gateway_exclude
                .unwrap()
                .prior_entry
                .unwrap(),
            "198.51.100.230 via 192.0.2.1 dev eth0",
            "linkdown must be stripped or the restore fails"
        );
    }

    #[test]
    fn revert_removes_routes_and_address() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            installed_addr: Some(Ipv4Addr::new(172, 17, 0, 2)),
            installed_gateway_exclude: None,
        };
        let runner = FakeRunner::all_ok(3);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn revert_is_best_effort_on_per_item_failure() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            installed_addr: None,
            installed_gateway_exclude: None,
        };
        // Revert is LIFO, so the first delete issued is the
        // last-installed route.
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::err("first gone")),
            Ok(FakeRunner::ok()),
        ]);
        let errors = revert_with(&runner, &state);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("192.168.1.0/24"), "{errors:?}");
    }

    #[test]
    fn empty_ifname_is_rejected() {
        let config = TunConfig {
            ifname: String::new(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec![],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::all_ok(0);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, RouteError::InvalidConfig(_)));
    }

    #[test]
    fn apply_pins_gateway_exclude_before_split_routes() {
        let gateway = Ipv4Addr::new(198, 51, 100, 230);
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),          // link up
            Ok(FakeRunner::ok()),          // mtu
            Ok(FakeRunner::ok()),          // addr add
            Ok(FakeRunner::ok_stdout("")), // route show exact
            Ok(FakeRunner::ok_stdout(
                "198.51.100.230 via 192.0.2.1 dev eth0 src 192.0.2.10\n    cache\n",
            )), // route get
            Ok(FakeRunner::ok()),          // route replace (gateway pin)
            Ok(FakeRunner::ok()),          // route add 198.51.100.0/16
        ]);

        let state = apply_with(
            &runner,
            &cfg_with_gateway(vec!["198.51.100.0/16"], Some(gateway)),
        )
        .unwrap();

        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: gateway,
                prior_entry: None,
            })
        );
    }

    #[test]
    fn revert_deletes_gateway_exclude_after_split_routes() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec!["198.51.100.0/16".into(), "10.0.0.0/8".into()],
            installed_addr: Some(Ipv4Addr::new(172, 17, 0, 2)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: None,
            }),
        };
        let runner = FakeRunner::all_ok(4);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[3],
            vec!["ip", "-4", "route", "del", "198.51.100.230/32"]
        );
    }

    #[test]
    fn revert_restores_prior_gateway_entry_verbatim() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec![],
            installed_addr: None,
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some(
                    "198.51.100.230 via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100"
                        .into(),
                ),
            }),
        };
        let runner = FakeRunner::all_ok(1);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn apply_skips_gateway_exclude_when_not_requested() {
        let gateway = "198.51.100.230";
        let runner = FakeRunner::all_ok(4);
        apply_with(&runner, &cfg(vec!["198.51.100.0/16"])).unwrap();
        let calls = runner.calls.borrow();
        // The split route itself legitimately issues `show exact` and
        // `replace` now, so the invariant is narrower: nothing mentions
        // the gateway address, and no `route get` happens at all.
        assert!(
            calls
                .iter()
                .all(|call| call.iter().all(|arg| !arg.contains(gateway))),
            "gateway leaked into a call: {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .all(|call| !(call.len() >= 4 && call[2] == "route" && call[3] == "get")),
            "unexpected route get: {calls:#?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — macOS
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "macos"))]
mod tests_macos {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok() -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn ok_stdout(stdout: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            }
        }

        fn err(stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(1 << 8),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        fn new(outcomes: Vec<Result<Output, io::Error>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }

        fn all_ok(n: usize) -> Self {
            let outcomes = (0..n).map(|_| Ok(Self::ok())).collect();
            Self::new(outcomes)
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(full);
            let mut outcomes = self.outcomes.borrow_mut();
            if outcomes.is_empty() {
                panic!("FakeRunner: no more outcomes queued (unexpected call)");
            }
            outcomes.remove(0)
        }
    }

    fn cfg(routes: Vec<&str>) -> TunConfig {
        cfg_with_gateway(routes, None)
    }

    fn cfg_with_gateway(routes: Vec<&str>, gateway_exclude: Option<Ipv4Addr>) -> TunConfig {
        TunConfig {
            ifname: "utun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1380),
            gateway_exclude,
            routes: routes.into_iter().map(String::from).collect(),
            route_conflict: RouteConflictPolicy::default(),
        }
    }

    #[test]
    fn apply_macos_issues_ifconfig_and_route_commands() {
        let runner = FakeRunner::all_ok(3);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap();

        assert_eq!(state.ifname, "utun7");
        assert_eq!(state.installed_addr, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0],
            vec![
                "ifconfig",
                "utun7",
                "inet",
                "10.1.2.3",
                "10.1.2.3",
                "netmask",
                "255.255.255.255",
                "mtu",
                "1380",
                "up",
            ]
        );
        assert_eq!(
            calls[1],
            vec![
                "route",
                "-n",
                "add",
                "-net",
                "10.0.0.0",
                "-netmask",
                "255.0.0.0",
                "10.1.2.3",
            ]
        );
        assert_eq!(
            calls[2],
            vec![
                "route",
                "-n",
                "add",
                "-net",
                "172.16.0.0",
                "-netmask",
                "255.240.0.0",
                "10.1.2.3",
            ]
        );
    }

    #[test]
    fn apply_macos_gateway_exclude_uses_default_gateway() {
        let gateway = Ipv4Addr::new(198, 51, 100, 230);
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // ifconfig
            Ok(FakeRunner::ok_stdout(
                "   route to: default\n   gateway: 192.0.2.1\ninterface: en0\n",
            )),
            Ok(FakeRunner::ok()), // host route pin
            Ok(FakeRunner::ok()), // split route
        ]);

        let state = apply_with(
            &runner,
            &cfg_with_gateway(vec!["198.51.100.0/16"], Some(gateway)),
        )
        .unwrap();

        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: gateway,
                prior_entry: Some("192.0.2.1".into()),
            })
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls[1], vec!["route", "-n", "get", "default"]);
        assert_eq!(
            calls[2],
            vec!["route", "-n", "add", "-host", "198.51.100.230", "192.0.2.1"]
        );
    }

    #[test]
    fn apply_macos_rejects_routes_without_tunnel_ip() {
        let config = TunConfig {
            ifname: "utun0".into(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::new(vec![]);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, RouteError::InvalidConfig(_)));
    }

    #[test]
    fn revert_macos_removes_routes_and_gateway_pin() {
        let state = AppliedState {
            ifname: "utun7".into(),
            installed_routes: vec!["10.0.0.0/8".into()],
            installed_addr: Some(Ipv4Addr::new(10, 1, 2, 3)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.0.2.1".into()),
            }),
        };
        let runner = FakeRunner::all_ok(3);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0],
            vec![
                "route",
                "-n",
                "delete",
                "-net",
                "10.0.0.0",
                "-netmask",
                "255.0.0.0",
            ]
        );
        assert_eq!(calls[1], vec!["ifconfig", "utun7", "10.1.2.3", "delete"]);
        assert_eq!(
            calls[2],
            vec![
                "route",
                "-n",
                "delete",
                "-host",
                "198.51.100.230",
                "192.0.2.1"
            ]
        );
    }

    #[test]
    fn apply_macos_rollback_runs_on_route_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),        // ifconfig
            Ok(FakeRunner::ok()),        // first route
            Ok(FakeRunner::err("nope")), // second route fails
            Ok(FakeRunner::ok()),        // rollback route delete
            Ok(FakeRunner::ok()),        // rollback addr delete
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap_err();
        assert!(matches!(
            err,
            RouteError::UnixCommand {
                program: "route",
                op: "add route",
                ..
            }
        ));
    }
}

// ---------------------------------------------------------------------------
// Tests — Windows
// ---------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests_windows {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn parse_default_gateway_picks_lowest_metric() {
        // Two default routes, one via 192.168.1.1 (metric 35), one via 10.0.0.1
        // (metric 50). The 192.168.1.1 one should win.
        let stdout = "\
===========================================================================
Interface List
 14...01 23 45 67 89 ab ......Realtek Ethernet
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
          0.0.0.0          0.0.0.0      10.0.0.1     10.0.0.42        50
        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331
===========================================================================
";
        assert_eq!(parse_default_gateway(stdout), Some("192.168.1.1".into()));
    }

    #[test]
    fn parse_default_gateway_returns_none_for_no_default_route() {
        // No 0.0.0.0/0 row anywhere — laptop with WiFi off.
        let stdout = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331
";
        assert_eq!(parse_default_gateway(stdout), None);
    }

    #[test]
    fn parse_default_gateway_skips_on_link_gateway() {
        // `On-link` means no nexthop; we can't pin through it.
        let stdout = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link       10.0.0.42     50
";
        assert_eq!(parse_default_gateway(stdout), None);
    }
    use std::os::windows::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok() -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn ok_stdout(stdout: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            }
        }

        fn fail(stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        fn new(outcomes: Vec<Result<Output, io::Error>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(full);
            let mut outcomes = self.outcomes.borrow_mut();
            if outcomes.is_empty() {
                panic!("FakeRunner: no more outcomes queued");
            }
            outcomes.remove(0)
        }
    }

    fn cfg(routes: Vec<&str>) -> TunConfig {
        TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1400),
            gateway_exclude: None,
            routes: routes.into_iter().map(String::from).collect(),
            route_conflict: RouteConflictPolicy::default(),
        }
    }

    #[test]
    fn apply_windows_issues_netsh_commands() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // set mtu
            Ok(FakeRunner::ok()), // add address
            Ok(FakeRunner::ok()), // add route 1
            Ok(FakeRunner::ok()), // add route 2
        ]);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap();
        assert_eq!(state.ifname, "OpenProtect");
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0][0], "netsh");
        assert!(calls[0].contains(&"mtu=1400".to_string()));
        assert_eq!(calls[1][0], "netsh");
        assert!(calls[1].contains(&"10.1.2.3".to_string()));
        assert_eq!(calls[2][0], "netsh");
        assert!(calls[2].contains(&"10.0.0.0/8".to_string()));
        assert_eq!(calls[3][0], "netsh");
        assert!(calls[3].contains(&"172.16.0.0/12".to_string()));
    }

    #[test]
    fn apply_windows_rolls_back_on_route_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),         // mtu
            Ok(FakeRunner::ok()),         // addr
            Ok(FakeRunner::ok()),         // route 1
            Ok(FakeRunner::fail("nope")), // route 2 FAILS
            Ok(FakeRunner::ok()),         // rollback route 1
            Ok(FakeRunner::ok()),         // rollback addr
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap_err();
        assert!(matches!(err, RouteError::WinCommand { .. }));
        assert_eq!(runner.calls.borrow().len(), 6);
    }

    #[test]
    fn apply_windows_gateway_exclude() {
        let config = TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: None,
            gateway_exclude: Some(Ipv4Addr::new(198, 51, 100, 230)),
            routes: vec!["198.51.100.0/16".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let route_print_stdout = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
===========================================================================
";
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                          // addr
            Ok(FakeRunner::ok_stdout(route_print_stdout)), // route.exe print -4 0.0.0.0
            Ok(FakeRunner::ok()),                          // route add pin
            Ok(FakeRunner::ok()),                          // add route
        ]);
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.168.1.1".into()),
            })
        );
        let calls = runner.calls.borrow();
        // Second call (index 1) is `route.exe print` for default-gateway
        // discovery — the fast replacement for the old PowerShell call.
        assert_eq!(calls[1][0], "route.exe");
        assert_eq!(calls[1][1..], ["print", "-4", "0.0.0.0"]);
        // Third call is route.exe again to install the pin.
        assert_eq!(calls[2][0], "route.exe");
        assert!(calls[2].contains(&"198.51.100.230".to_string()));
        assert!(calls[2].contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn revert_windows_removes_routes_and_gateway() {
        let state = AppliedState {
            ifname: "OpenProtect".into(),
            installed_routes: vec!["10.0.0.0/8".into()],
            installed_addr: Some(Ipv4Addr::new(10, 1, 2, 3)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.168.1.1".into()),
            }),
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // delete route
            Ok(FakeRunner::ok()), // delete addr
            Ok(FakeRunner::ok()), // delete gateway pin
        ]);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0][0], "netsh"); // route
        assert_eq!(calls[1][0], "netsh"); // addr
        assert_eq!(calls[2][0], "route.exe"); // gateway
    }
}
