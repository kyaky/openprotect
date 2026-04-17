//! Native route / address / link management for the openprotect tun device.
//!
//! # Backends
//!
//! * **Linux** — shells out to `ip(8)` for link, addr, and route ops.
//! * **Windows** — shells out to `netsh` for address/route management
//!   and `route.exe` for gateway-exclude pinning. PowerShell is used
//!   only for default-gateway discovery (one-shot during setup).
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
}

/// Saved state for a temporary gateway `/32` host-route pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPinState {
    pub ip: Ipv4Addr,
    /// On Linux: the prior `ip route show` entry.
    /// On Windows: the default gateway nexthop used for the pin.
    pub prior_entry: Option<String>,
}

/// State produced by [`apply`] — hand back to [`revert`] to undo.
#[derive(Debug, Clone, Default)]
pub struct AppliedState {
    pub ifname: String,
    pub installed_routes: Vec<String>,
    pub installed_addr: Option<Ipv4Addr>,
    pub installed_gateway_exclude: Option<GatewayPinState>,
}

/// Errors produced by the `gp-route` API.
#[derive(Debug, Error)]
pub enum RouteError {
    #[error("ip command failed: {op}: {stderr}")]
    IpCommand { op: &'static str, stderr: String },

    #[error("{program} failed: {op}: {detail}")]
    WinCommand {
        program: &'static str,
        op: &'static str,
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
    platform_apply(runner, config)
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

// ---------------------------------------------------------------------------
// Linux backend (ip(8))
// ---------------------------------------------------------------------------

#[cfg(unix)]
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
    for route in &config.routes {
        if let Err(e) = run_ip(
            runner,
            "route add",
            &["route", "add", route, "dev", &config.ifname],
        ) {
            tracing::warn!(
                "gp-route: route add {route} on {} failed ({e}); rolling back",
                config.ifname
            );
            return Err(rollback_and_fail(runner, &state, e));
        }
        state.installed_routes.push(route.clone());
    }

    Ok(state)
}

#[cfg(unix)]
fn platform_revert<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    for route in &state.installed_routes {
        if let Err(e) = run_ip(
            runner,
            "route del",
            &["route", "del", route, "dev", &state.ifname],
        ) {
            errors.push(format!("route del {route}: {e}"));
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

#[cfg(unix)]
fn install_gateway_exclude_linux<R: CommandRunner>(
    runner: &R,
    state: &mut AppliedState,
    gateway: Ipv4Addr,
) -> Result<(), RouteError> {
    let gw_cidr = format!("{gateway}/32");
    let prior_entry = run_ip_stdout(
        runner,
        "route show exact",
        &["-4", "route", "show", "exact", &gw_cidr],
    )?
    .lines()
    .map(str::trim)
    .find(|line| !line.is_empty())
    .map(str::to_string);

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

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteLookup {
    via: Option<String>,
    dev: String,
    src: Option<String>,
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn run_ip<R: CommandRunner>(runner: &R, op: &'static str, args: &[&str]) -> Result<(), RouteError> {
    run_ip_checked(runner, op, args).map(|_| ())
}

#[cfg(unix)]
fn run_ip_owned<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[String],
) -> Result<(), RouteError> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(runner, op, &refs)
}

#[cfg(unix)]
fn run_ip_stdout<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<String, RouteError> {
    run_ip_checked(runner, op, args).map(|out| String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(unix)]
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
// Windows backend (netsh + route.exe + PowerShell for gateway discovery)
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
    for route in &config.routes {
        if let Err(e) = run_netsh(
            runner,
            "add route",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                route,
                &config.ifname,
                "store=active",
            ],
        ) {
            tracing::warn!(
                "gp-route: route add {route} on {} failed ({e}); rolling back",
                config.ifname
            );
            return Err(rollback(runner, &state, e));
        }
        state.installed_routes.push(route.clone());
    }

    Ok(state)
}

#[cfg(windows)]
fn platform_revert<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    // Routes first.
    for route in &state.installed_routes {
        if let Err(e) = run_netsh(
            runner,
            "delete route",
            &["interface", "ipv4", "delete", "route", route, &state.ifname],
        ) {
            errors.push(format!("delete route {route}: {e}"));
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
    // Discover default gateway via PowerShell.
    // Sort by InterfaceMetric + RouteMetric to match Windows
    // effective route preference on multi-homed systems.
    let cmd = "$ErrorActionPreference = 'Stop'; \
               (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | \
               Sort-Object { $_.InterfaceMetric + $_.RouteMetric } | \
               Select-Object -First 1).NextHop";
    let out = runner.run(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", cmd],
    )?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(RouteError::WinCommand {
            program: "powershell",
            op: "discover default gateway",
            detail: stderr,
        });
    }
    let default_gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if default_gw.is_empty() {
        return Err(RouteError::WinCommand {
            program: "powershell",
            op: "discover default gateway",
            detail: "no default route found".into(),
        });
    }

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
#[cfg(not(any(unix, windows)))]
fn platform_apply<R: CommandRunner>(
    _runner: &R,
    _config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    Err(RouteError::InvalidConfig("unsupported platform".into()))
}

#[cfg(not(any(unix, windows)))]
fn platform_revert<R: CommandRunner>(_runner: &R, _state: &AppliedState) -> Vec<String> {
    vec!["unsupported platform".into()]
}

// ---------------------------------------------------------------------------
// Tests — Linux
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests_unix {
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
        }
    }

    #[test]
    fn apply_issues_expected_commands_in_order() {
        let runner = FakeRunner::all_ok(5);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap();

        assert_eq!(state.ifname, "tun7");
        assert_eq!(state.installed_addr, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);

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
            vec!["ip", "route", "add", "10.0.0.0/8", "dev", "tun7"]
        );
        assert_eq!(
            calls[4],
            vec!["ip", "route", "add", "172.16.0.0/12", "dev", "tun7"]
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
        };
        let runner = FakeRunner::all_ok(2);
        apply_with(&runner, &config).unwrap();
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1..4], ["link", "set", "dev"]);
        assert_eq!(calls[1][1..3], ["route", "add"]);
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
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::err("first gone")),
            Ok(FakeRunner::ok()),
        ]);
        let errors = revert_with(&runner, &state);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("10.0.0.0/8"), "{errors:?}");
    }

    #[test]
    fn empty_ifname_is_rejected() {
        let config = TunConfig {
            ifname: String::new(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec![],
        };
        let runner = FakeRunner::all_ok(0);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, RouteError::InvalidConfig(_)));
    }

    #[test]
    fn apply_pins_gateway_exclude_before_split_routes() {
        let gateway = Ipv4Addr::new(129, 94, 0, 230);
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),          // link up
            Ok(FakeRunner::ok()),          // mtu
            Ok(FakeRunner::ok()),          // addr add
            Ok(FakeRunner::ok_stdout("")), // route show exact
            Ok(FakeRunner::ok_stdout(
                "129.94.0.230 via 192.0.2.1 dev eth0 src 192.0.2.10\n    cache\n",
            )), // route get
            Ok(FakeRunner::ok()),          // route replace
            Ok(FakeRunner::ok()),          // route add
        ]);

        let state = apply_with(
            &runner,
            &cfg_with_gateway(vec!["129.94.0.0/16"], Some(gateway)),
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
            installed_routes: vec!["129.94.0.0/16".into(), "10.0.0.0/8".into()],
            installed_addr: Some(Ipv4Addr::new(172, 17, 0, 2)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(129, 94, 0, 230),
                prior_entry: None,
            }),
        };
        let runner = FakeRunner::all_ok(4);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[3],
            vec!["ip", "-4", "route", "del", "129.94.0.230/32"]
        );
    }

    #[test]
    fn revert_restores_prior_gateway_entry_verbatim() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec![],
            installed_addr: None,
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(129, 94, 0, 230),
                prior_entry: Some(
                    "129.94.0.230 via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100"
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
        let runner = FakeRunner::all_ok(4);
        apply_with(&runner, &cfg(vec!["129.94.0.0/16"])).unwrap();
        let calls = runner.calls.borrow();
        assert!(calls.iter().all(|call| {
            !(call.len() >= 4
                && call[0] == "ip"
                && call[1] == "-4"
                && call[2] == "route"
                && matches!(call[3].as_str(), "show" | "get" | "replace"))
        }));
    }
}

// ---------------------------------------------------------------------------
// Tests — Windows
// ---------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests_windows {
    use super::*;
    use std::cell::RefCell;
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
            gateway_exclude: Some(Ipv4Addr::new(129, 94, 0, 230)),
            routes: vec!["129.94.0.0/16".into()],
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                       // addr
            Ok(FakeRunner::ok_stdout("192.168.1.1\n")), // PS default gw
            Ok(FakeRunner::ok()),                       // route add pin
            Ok(FakeRunner::ok()),                       // add route
        ]);
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: Ipv4Addr::new(129, 94, 0, 230),
                prior_entry: Some("192.168.1.1".into()),
            })
        );
        let calls = runner.calls.borrow();
        // Second call is PowerShell for default gateway discovery.
        assert_eq!(calls[1][0], "powershell.exe");
        // Third call is route.exe for the pin.
        assert_eq!(calls[2][0], "route.exe");
        assert!(calls[2].contains(&"129.94.0.230".to_string()));
        assert!(calls[2].contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn revert_windows_removes_routes_and_gateway() {
        let state = AppliedState {
            ifname: "OpenProtect".into(),
            installed_routes: vec!["10.0.0.0/8".into()],
            installed_addr: Some(Ipv4Addr::new(10, 1, 2, 3)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(129, 94, 0, 230),
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
