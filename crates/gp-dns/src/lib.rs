//! DNS configuration for the VPN tunnel lifetime.
//!
//! # Backends
//!
//! * **Linux** — `systemd-resolved` via `resolvectl`. Per-interface DNS
//!   with split-DNS routing (`~domain`) so only matching queries go
//!   through the VPN resolver.
//!
//! * **Windows** — NRPT (Name Resolution Policy Table) written directly
//!   to the registry, with a `SERVICE_CONTROL_PARAMCHANGE` ping to
//!   the `DnsCache` service. Used to shell out to PowerShell
//!   `Add-DnsClientNrptRule`, but cold-starting `powershell.exe` plus
//!   the `DnsClient` PSModule costs 5-15 s on a quiet box and tens of
//!   seconds with EDR scanning. See `windows_nrpt` for the schema and
//!   reload mechanics. This still achieves the same split-DNS routing
//!   that `systemd-resolved` provides on Linux.
//!
//! * **macOS** — `networksetup` against the currently active network
//!   service. This is a pragmatic compatibility backend: it swaps the
//!   service's DNS servers globally for the tunnel lifetime rather than
//!   installing fully scoped split-DNS resolvers.
//!
//! * Fallback — [`Backend::None`]: log a warning and leave DNS alone.
//!
//! # API shape
//!
//! The crate mirrors `gp-route`'s shell-out + injectable runner
//! pattern so tests can assert the exact argv without touching
//! real system state.
//!
//! * [`DnsConfig`] — what the caller wants.
//! * [`apply`] / [`revert`] — commit or roll back.
//! * [`AppliedDnsState`] — returned by `apply` for later cleanup.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

#[cfg(windows)]
mod windows_nrpt;

/// Sweep stale NRPT rule keys owned by the named opc `instance`,
/// then signal `DnsCache` to reload. Returns the count of rules
/// removed. Windows-only.
///
/// Called from `opc connect` before portal prelogin: if a previous
/// session of THIS instance left a catch-all NRPT rule routing `.`
/// through the VPN's internal DNS server (which is unreachable
/// until the new tunnel is up), portal prelogin would hang forever
/// trying to resolve the portal hostname. Cleaning the stale rule
/// first restores normal DNS until the new connect has a chance to
/// reinstall its own.
///
/// The `instance` parameter scopes the cleanup so two
/// `opc -i NAME` invocations running side-by-side never delete
/// each other's live rules. Pass the same string you'd pass to
/// `apply` for the connect-DNS step.
#[cfg(windows)]
pub fn cleanup_stale_windows_nrpt(instance: &str) -> Result<usize, DnsError> {
    windows_nrpt::cleanup_stale_native(instance).map_err(|e| DnsError::Nrpt {
        op: "cleanup-stale-nrpt",
        detail: e.to_string(),
    })
}

/// Default per-command timeout.
///
/// Used to be 10s. Real Windows boxes routinely take 5-15s just to
/// **launch** a fresh `powershell.exe` (.NET runtime cold-load plus
/// the `DnsClient` module's first-use load). Every NRPT call ships
/// through a brand-new PowerShell process — there is no native Win32
/// API for NRPT that bypasses it, and we don't want to chain cmdlets
/// into a single megascript just to dodge cold-start. 60s gives the
/// slowest realistic startup plenty of headroom while still failing
/// fast on a genuinely wedged subprocess. Wall-clock impact on the
/// happy path is unchanged: warm-cache PowerShell finishes in <1s.
pub const DEFAULT_DNS_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// What the caller wants DNS to look like.
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// Tun interface the nameservers should be scoped to.
    pub ifname: String,
    /// Nameservers pushed by the VPN server.
    pub servers: Vec<IpAddr>,
    /// Search domains pushed by the VPN server. These become
    /// regular (non-routing) `resolvectl domain` entries on Linux.
    /// On Windows, search domains are not currently applied by the
    /// NRPT backend (NRPT handles routing, not suffix search);
    /// they are stored here for future DNS suffix search list support.
    pub search_domains: Vec<String>,
    /// Split-DNS domains — only these domains get resolved via the
    /// VPN resolver; everything else stays on the system DNS.
    pub split_domains: Vec<String>,
    /// opc instance name. Windows uses it to scope NRPT rule key
    /// names (`openprotect-<instance>-<random>`) so two parallel
    /// `opc -i NAME` invocations never delete each other's live
    /// rules on the recovery sweep. Defaults to `"default"` when
    /// unset, matching opc's default-instance name.
    pub instance: String,
}

/// Backend that was (or was not) used to apply a [`DnsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `resolvectl` invoked on a live `systemd-resolved` instance.
    SystemdResolved,
    /// Windows NRPT rules written directly to the registry and
    /// loaded via a `DnsCache` `SERVICE_CONTROL_PARAMCHANGE`. See
    /// the `windows_nrpt` submodule.
    Nrpt,
    /// macOS `networksetup` on the active service.
    MacosNetworkSetup,
    /// No backend detected on the host. Apply was a no-op.
    None,
}

/// Tracks what `apply` actually did, so `revert` can undo only
/// what was done.
#[derive(Debug, Clone)]
pub struct AppliedDnsState {
    pub ifname: String,
    pub backend: Backend,
    /// NRPT rule names (GUIDs) created by `apply`. Empty on non-NRPT
    /// backends. Used by `revert` to remove exactly the rules we added.
    pub nrpt_rule_names: Vec<String>,
    /// macOS active network service that had its DNS overridden.
    pub macos_service: Option<String>,
    /// macOS DNS servers present before `apply`.
    pub macos_prior_servers: Vec<String>,
    /// macOS search domains present before `apply`.
    pub macos_prior_search_domains: Vec<String>,
    /// Whether `apply` changed macOS search domains.
    pub macos_search_domains_changed: bool,
}

/// Errors produced by the `gp-dns` API.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolvectl failed: {op}: {stderr}")]
    Resolvectl { op: &'static str, stderr: String },

    #[error("NRPT operation failed: {op}: {detail}")]
    Nrpt { op: &'static str, detail: String },

    #[error("macOS DNS operation failed: {op}: {detail}")]
    MacosDns { op: &'static str, detail: String },

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
        run_with_timeout(program, args, DEFAULT_DNS_COMMAND_TIMEOUT)
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

/// Detect which DNS backend is live on this host.
pub fn detect_backend() -> Backend {
    detect_backend_with(&SystemCommandRunner)
}

/// Like [`detect_backend`] but uses the given [`CommandRunner`].
pub fn detect_backend_with<R: CommandRunner>(runner: &R) -> Backend {
    #[cfg(target_os = "linux")]
    {
        match runner.run("systemctl", &["is-active", "systemd-resolved"]) {
            Ok(out) => {
                let trimmed = String::from_utf8_lossy(&out.stdout);
                if trimmed.trim() == "active" {
                    Backend::SystemdResolved
                } else {
                    Backend::None
                }
            }
            Err(_) => Backend::None,
        }
    }
    #[cfg(target_os = "macos")]
    {
        match runner.run("networksetup", &["-listallnetworkservices"]) {
            Ok(out) if out.status.success() => Backend::MacosNetworkSetup,
            _ => Backend::None,
        }
    }
    #[cfg(windows)]
    {
        // NRPT is the only Windows backend. We used to probe for the
        // `Add-DnsClientNrptRule` cmdlet by spawning powershell.exe,
        // which paid the same 5-15 s cold-start cost as the apply path
        // — for every connect attempt, just to confirm a cmdlet we
        // no longer use exists. The native registry/SCM path runs on
        // every supported Windows (8+, and the only realistic targets
        // for OpenProtect are 10/11) so we just declare the backend.
        let _ = runner;
        Backend::Nrpt
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = runner;
        Backend::None
    }
}

/// Apply a [`DnsConfig`] to the live system.
pub fn apply(config: &DnsConfig) -> Result<AppliedDnsState, DnsError> {
    apply_with(&SystemCommandRunner, config)
}

/// Like [`apply`] but uses the given [`CommandRunner`].
pub fn apply_with<R: CommandRunner>(
    runner: &R,
    config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    if config.ifname.is_empty() {
        return Err(DnsError::InvalidConfig(
            "tun interface name is empty".into(),
        ));
    }
    if config.servers.is_empty() {
        tracing::debug!(
            "gp-dns: no server-pushed DNS for {}, leaving resolver alone",
            config.ifname
        );
        return Ok(AppliedDnsState {
            ifname: config.ifname.clone(),
            backend: Backend::None,
            nrpt_rule_names: Vec::new(),
            macos_service: None,
            macos_prior_servers: Vec::new(),
            macos_prior_search_domains: Vec::new(),
            macos_search_domains_changed: false,
        });
    }

    let backend = detect_backend_with(runner);
    match backend {
        Backend::SystemdResolved => apply_systemd_resolved(runner, config),
        Backend::Nrpt => apply_nrpt(runner, config),
        Backend::MacosNetworkSetup => {
            #[cfg(target_os = "macos")]
            {
                apply_macos_networksetup(runner, config)
            }
            #[cfg(not(target_os = "macos"))]
            {
                unreachable!("macOS DNS backend selected on non-macOS host")
            }
        }
        Backend::None => {
            tracing::warn!(
                "gp-dns: no supported DNS backend detected — skipping DNS \
                 configuration. Set `--vpnc-script` for external DNS handling."
            );
            Ok(AppliedDnsState {
                ifname: config.ifname.clone(),
                backend: Backend::None,
                nrpt_rule_names: Vec::new(),
                macos_service: None,
                macos_prior_servers: Vec::new(),
                macos_prior_search_domains: Vec::new(),
                macos_search_domains_changed: false,
            })
        }
    }
}

/// Reverse an [`AppliedDnsState`]. Best-effort; per-command errors
/// are collected and returned rather than stopping the cleanup.
pub fn revert(state: &AppliedDnsState) -> Vec<String> {
    revert_with(&SystemCommandRunner, state)
}

/// Like [`revert`] but uses the given [`CommandRunner`].
pub fn revert_with<R: CommandRunner>(runner: &R, state: &AppliedDnsState) -> Vec<String> {
    let mut errors = Vec::new();
    match state.backend {
        Backend::SystemdResolved => {
            if let Err(e) = run_resolvectl(runner, "revert", &["revert", &state.ifname]) {
                errors.push(format!("resolvectl revert {}: {e}", state.ifname));
            }
        }
        Backend::Nrpt => {
            // Remove the specific rules we created (tracked by GUID).
            for name in &state.nrpt_rule_names {
                if let Err(e) = remove_nrpt_rule(runner, name) {
                    errors.push(format!("removing NRPT rule {name}: {e}"));
                }
            }
            // No blanket safety sweep here — see the comment near the
            // (now removed) `cleanup_stale_nrpt_rules` for why an
            // instance-agnostic sweep is unsafe with multi-instance
            // opc. Each rule key was deleted above by its exact
            // registry name; that's already canonical cleanup.
            if let Err(e) = flush_dns_cache(runner) {
                errors.push(format!("flushing DNS cache: {e}"));
            }
        }
        Backend::MacosNetworkSetup => {
            #[cfg(target_os = "macos")]
            {
                if let Some(service) = state.macos_service.as_deref() {
                    if let Err(e) = set_networksetup_list(
                        runner,
                        "setdnsservers",
                        service,
                        &state.macos_prior_servers,
                    ) {
                        errors.push(format!("restoring macOS DNS servers on {service}: {e}"));
                    }
                    if state.macos_search_domains_changed {
                        if let Err(e) = set_networksetup_list(
                            runner,
                            "setsearchdomains",
                            service,
                            &state.macos_prior_search_domains,
                        ) {
                            errors
                                .push(format!("restoring macOS search domains on {service}: {e}"));
                        }
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = state;
            }
        }
        Backend::None => {}
    }
    errors
}

// ---------------------------------------------------------------------------
// systemd-resolved backend (Linux)
// ---------------------------------------------------------------------------

fn apply_systemd_resolved<R: CommandRunner>(
    runner: &R,
    config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    let servers_strs: Vec<String> = config.servers.iter().map(|ip| ip.to_string()).collect();
    let mut dns_args: Vec<&str> = vec!["dns", &config.ifname];
    dns_args.extend(servers_strs.iter().map(|s| s.as_str()));
    run_resolvectl(runner, "dns", &dns_args)?;

    let state = AppliedDnsState {
        ifname: config.ifname.clone(),
        backend: Backend::SystemdResolved,
        nrpt_rule_names: Vec::new(),
        macos_service: None,
        macos_prior_servers: Vec::new(),
        macos_prior_search_domains: Vec::new(),
        macos_search_domains_changed: false,
    };

    let mut domain_strs: Vec<String> = config.search_domains.clone();
    domain_strs.extend(config.split_domains.iter().map(|d| format!("~{d}")));

    if !domain_strs.is_empty() {
        let mut domain_args: Vec<&str> = vec!["domain", &config.ifname];
        domain_args.extend(domain_strs.iter().map(|s| s.as_str()));
        if let Err(err) = run_resolvectl(runner, "domain", &domain_args) {
            for rev_err in revert_with(runner, &state) {
                tracing::warn!("gp-dns apply-rollback: {rev_err}");
            }
            return Err(err);
        }
    }

    Ok(state)
}

fn run_resolvectl<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<(), DnsError> {
    tracing::debug!("gp-dns: resolvectl {}", args.join(" "));
    let out = runner.run("resolvectl", args)?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(DnsError::Resolvectl { op, stderr })
    }
}

// ---------------------------------------------------------------------------
// macOS networksetup backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn apply_macos_networksetup<R: CommandRunner>(
    runner: &R,
    config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    let active_interface = macos_default_interface(runner)?;
    let active_service = macos_service_for_interface(runner, &active_interface)?;
    let prior_servers = read_networksetup_list(runner, "getdnsservers", &active_service)?;
    let prior_search_domains = read_networksetup_list(runner, "getsearchdomains", &active_service)?;

    let server_values: Vec<String> = config.servers.iter().map(ToString::to_string).collect();
    set_networksetup_list(runner, "setdnsservers", &active_service, &server_values)?;

    let search_domains_changed = !config.search_domains.is_empty();
    if search_domains_changed {
        set_networksetup_list(
            runner,
            "setsearchdomains",
            &active_service,
            &config.search_domains,
        )?;
    }

    if !config.split_domains.is_empty() {
        tracing::warn!(
            "gp-dns: macOS backend currently applies VPN DNS globally on {} \
             and does not scope lookups to split domains {:?}",
            active_service,
            config.split_domains
        );
    }

    Ok(AppliedDnsState {
        ifname: config.ifname.clone(),
        backend: Backend::MacosNetworkSetup,
        nrpt_rule_names: Vec::new(),
        macos_service: Some(active_service),
        macos_prior_servers: prior_servers,
        macos_prior_search_domains: prior_search_domains,
        macos_search_domains_changed: search_domains_changed,
    })
}

#[cfg(target_os = "macos")]
fn macos_default_interface<R: CommandRunner>(runner: &R) -> Result<String, DnsError> {
    let out = runner.run("route", &["-n", "get", "default"])?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(DnsError::MacosDns {
            op: "route -n get default",
            detail,
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(iface) = trimmed.strip_prefix("interface:") {
            let iface = iface.trim();
            if !iface.is_empty() {
                return Ok(iface.to_string());
            }
        }
    }
    Err(DnsError::InvalidConfig(format!(
        "route -n get default output missing interface: {stdout:?}"
    )))
}

#[cfg(target_os = "macos")]
fn macos_service_for_interface<R: CommandRunner>(
    runner: &R,
    interface: &str,
) -> Result<String, DnsError> {
    let out = runner.run("networksetup", &["-listnetworkserviceorder"])?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(DnsError::MacosDns {
            op: "networksetup -listnetworkserviceorder",
            detail,
        });
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut current_service: Option<String> = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('(') && trimmed.contains(") ") && !trimmed.starts_with("(*)") {
            if let Some((_, service)) = trimmed.split_once(") ") {
                current_service = Some(service.to_string());
            }
            continue;
        }
        if let Some(device) = parse_networksetup_device(trimmed) {
            if device == interface {
                if let Some(service) = current_service {
                    return Ok(service);
                }
            }
        }
    }

    Err(DnsError::InvalidConfig(format!(
        "no active network service maps to interface {interface}"
    )))
}

#[cfg(target_os = "macos")]
fn parse_networksetup_device(line: &str) -> Option<&str> {
    let device_pos = line.find("Device: ")?;
    let after = &line[device_pos + "Device: ".len()..];
    let device = after.split(')').next()?.trim();
    if device.is_empty() {
        None
    } else {
        Some(device)
    }
}

#[cfg(target_os = "macos")]
fn read_networksetup_list<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    service: &str,
) -> Result<Vec<String>, DnsError> {
    let flag = match op {
        "getdnsservers" => "-getdnsservers",
        "getsearchdomains" => "-getsearchdomains",
        _ => {
            return Err(DnsError::InvalidConfig(format!(
                "unsupported networksetup read op: {op}"
            )))
        }
    };
    let out = runner.run("networksetup", &[flag, service])?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(DnsError::MacosDns { op, detail });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    if trimmed.contains("There aren't any") {
        return Ok(Vec::new());
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(target_os = "macos")]
fn set_networksetup_list<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    service: &str,
    values: &[String],
) -> Result<(), DnsError> {
    let flag = match op {
        "setdnsservers" => "-setdnsservers",
        "setsearchdomains" => "-setsearchdomains",
        _ => {
            return Err(DnsError::InvalidConfig(format!(
                "unsupported networksetup write op: {op}"
            )))
        }
    };

    let mut owned = vec![flag.to_string(), service.to_string()];
    if values.is_empty() {
        owned.push("Empty".to_string());
    } else {
        owned.extend(values.iter().cloned());
    }
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    let out = runner.run("networksetup", &args)?;
    if out.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(DnsError::MacosDns { op, detail })
    }
}

// ---------------------------------------------------------------------------
// NRPT backend (Windows)
// ---------------------------------------------------------------------------

/// Validate that a domain name contains only characters we're
/// willing to write into the `Name` REG_MULTI_SZ value of an NRPT
/// rule key. The native path doesn't interpolate strings into a
/// shell, but we still reject quotes / semicolons / backticks / $
/// so a future code path that does shell out (e.g. an `opc dns
/// dump` debug helper or PowerShell-driven cleanup script) can't
/// be fed an injection payload from an untrusted profile config.
fn validate_nrpt_domain(domain: &str) -> Result<(), DnsError> {
    if domain.is_empty() {
        return Err(DnsError::InvalidConfig("empty domain name".into()));
    }
    let valid = domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !valid {
        return Err(DnsError::InvalidConfig(format!(
            "domain {domain:?} contains characters not safe for NRPT"
        )));
    }
    Ok(())
}

/// Format a domain for NRPT namespace (must start with a dot).
fn nrpt_namespace(domain: &str) -> String {
    let d = domain.trim_start_matches('.');
    format!(".{d}")
}

#[cfg(windows)]
fn apply_nrpt<R: CommandRunner>(
    _runner: &R,
    config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    // Validate ALL inputs before touching any system state.
    for d in &config.split_domains {
        if d.trim().is_empty() {
            return Err(DnsError::InvalidConfig(
                "split_domains contains an empty entry".into(),
            ));
        }
        validate_nrpt_domain(&nrpt_namespace(d))?;
    }

    let instance = if config.instance.is_empty() {
        "default"
    } else {
        config.instance.as_str()
    };

    // 1. Sweep this instance's stale rule keys from a previous crash.
    //    Best-effort — failure here doesn't block fresh installs.
    match windows_nrpt::cleanup_stale_native(instance) {
        Ok(n) if n > 0 => tracing::info!(
            "gp-dns: cleaned {n} stale openprotect NRPT rule(s) for instance {instance}"
        ),
        Ok(_) => tracing::debug!("gp-dns: no stale NRPT rules to clean for instance {instance}"),
        Err(e) => tracing::warn!("gp-dns: stale-rule cleanup failed: {e}"),
    }

    // 2. Build namespace list. Empty split-domains = `.` catch-all so
    //    *all* DNS goes through the VPN resolver.
    let namespaces: Vec<String> = if config.split_domains.is_empty() {
        vec![".".to_string()]
    } else {
        config
            .split_domains
            .iter()
            .map(|d| nrpt_namespace(d))
            .collect()
    };

    // 3. One rule per namespace. Same shape PowerShell would have
    //    produced, just written through the registry instead.
    let rules: Vec<windows_nrpt::NrptRule> = namespaces
        .iter()
        .map(|ns| windows_nrpt::NrptRule {
            namespace: ns.clone(),
            servers: config.servers.clone(),
        })
        .collect();

    let applied = windows_nrpt::apply_native(instance, &rules).map_err(|e| match e {
        windows_nrpt::NrptError::GpoConflict(_) => DnsError::Nrpt {
            op: "apply NRPT (GP conflict)",
            detail: e.to_string(),
        },
        _ => DnsError::Nrpt {
            op: "apply NRPT",
            detail: e.to_string(),
        },
    })?;

    tracing::info!(
        "gp-dns: installed {} NRPT rule(s) for {} namespace(s) via registry",
        applied.rule_key_names.len(),
        namespaces.len()
    );

    Ok(AppliedDnsState {
        ifname: config.ifname.clone(),
        backend: Backend::Nrpt,
        nrpt_rule_names: applied.rule_key_names,
        macos_service: None,
        macos_prior_servers: Vec::new(),
        macos_prior_search_domains: Vec::new(),
        macos_search_domains_changed: false,
    })
}

/// Non-Windows builds still need this symbol for `apply_with`'s match
/// arms to compile, but the body is unreachable in practice.
#[cfg(not(windows))]
fn apply_nrpt<R: CommandRunner>(
    _runner: &R,
    _config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    Err(DnsError::InvalidConfig(
        "NRPT backend only exists on Windows".into(),
    ))
}

/// Remove a single NRPT rule key. Native registry path; no PowerShell.
#[cfg(windows)]
fn remove_nrpt_rule<R: CommandRunner>(_runner: &R, name: &str) -> Result<(), DnsError> {
    // Defence in depth: refuse keys that don't carry our prefix so
    // even if `AppliedDnsState` were corrupted with an unrelated
    // adapter's GUID, we couldn't delete it.
    if !name.starts_with(windows_nrpt::RULE_KEY_PREFIX) {
        return Err(DnsError::Nrpt {
            op: "remove NRPT rule",
            detail: format!("refusing to remove rule without openprotect prefix: {name:?}"),
        });
    }
    windows_nrpt::remove_native(name).map_err(|e| DnsError::Nrpt {
        op: "remove NRPT rule",
        detail: e.to_string(),
    })
}

#[cfg(not(windows))]
fn remove_nrpt_rule<R: CommandRunner>(_runner: &R, _name: &str) -> Result<(), DnsError> {
    Err(DnsError::InvalidConfig(
        "NRPT backend only exists on Windows".into(),
    ))
}

// `cleanup_stale_nrpt_rules` used to do an instance-agnostic
// "any openprotect-prefixed rule" sweep here as a belt-and-suspenders
// extra during revert. The new design scopes rule keys by instance
// name (`openprotect-<instance>-<random>`), so an undirected sweep
// could nuke a sibling `opc -i NAME` instance's live rules. The
// connect-time recovery sweep in `connect()` is already instance-
// scoped and runs against the live rules; revert deletes its own
// rules by exact name, so the extra blanket sweep is no longer
// needed.

/// Trigger a `DnsCache` reload so deleted NRPT rules actually leave
/// the kernel's in-memory cache. `revert_with`'s Nrpt branch deletes
/// each registry key but the kernel keeps its prior policy snapshot
/// in memory until something pings `SERVICE_CONTROL_PARAMCHANGE`.
/// Without this call a clean disconnect would silently leave
/// DnsCache hijacking DNS for our namespaces until the next connect
/// (or a manual `Clear-DnsClientCache` / reboot).
#[cfg(windows)]
fn flush_dns_cache<R: CommandRunner>(_runner: &R) -> Result<(), DnsError> {
    windows_nrpt::paramchange_public().map_err(|e| DnsError::Nrpt {
        op: "paramchange after revert",
        detail: e.to_string(),
    })
}

#[cfg(not(windows))]
fn flush_dns_cache<R: CommandRunner>(_runner: &R) -> Result<(), DnsError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests_unix {
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok_with_stdout(stdout: &str) -> Output {
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

        fn ok_active() -> Output {
            Self::ok_with_stdout("active\n")
        }

        fn ok_inactive() -> Output {
            Self::ok_with_stdout("inactive\n")
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
                panic!("FakeRunner: no more outcomes queued (unexpected call)");
            }
            outcomes.remove(0)
        }
    }

    fn cfg(servers: Vec<&str>, search: Vec<&str>, split: Vec<&str>) -> DnsConfig {
        DnsConfig {
            ifname: "tun0".into(),
            servers: servers
                .into_iter()
                .map(|s| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()))
                .collect(),
            search_domains: search.into_iter().map(String::from).collect(),
            split_domains: split.into_iter().map(String::from).collect(),
            instance: "default".into(),
        }
    }

    #[test]
    fn detect_backend_reads_systemctl_output() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok_active())]);
        assert_eq!(detect_backend_with(&runner), Backend::SystemdResolved);

        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok_inactive())]);
        assert_eq!(detect_backend_with(&runner), Backend::None);

        let runner = FakeRunner::new(vec![Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no systemctl",
        ))]);
        assert_eq!(detect_backend_with(&runner), Backend::None);
    }

    #[test]
    fn apply_issues_dns_and_domain_commands() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok_active()),        // detect
            Ok(FakeRunner::ok_with_stdout("")), // resolvectl dns
            Ok(FakeRunner::ok_with_stdout("")), // resolvectl domain
        ]);
        let state = apply_with(
            &runner,
            &cfg(
                vec!["10.0.0.53", "10.0.0.54"],
                vec!["example.com"],
                vec!["intranet.example.com", "staff.example.com"],
            ),
        )
        .unwrap();
        assert_eq!(state.backend, Backend::SystemdResolved);
        assert_eq!(state.ifname, "tun0");
        assert!(state.nrpt_rule_names.is_empty());

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], vec!["systemctl", "is-active", "systemd-resolved"]);
        assert_eq!(
            calls[1],
            vec!["resolvectl", "dns", "tun0", "10.0.0.53", "10.0.0.54"]
        );
        assert_eq!(
            calls[2],
            vec![
                "resolvectl",
                "domain",
                "tun0",
                "example.com",
                "~intranet.example.com",
                "~staff.example.com"
            ]
        );
    }

    #[test]
    fn apply_skips_domain_call_when_no_domains() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok_active()),
            Ok(FakeRunner::ok_with_stdout("")),
        ]);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec![], vec![])).unwrap();
        assert_eq!(state.backend, Backend::SystemdResolved);
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1], vec!["resolvectl", "dns", "tun0", "10.0.0.53"]);
    }

    #[test]
    fn apply_no_servers_is_noop() {
        let runner = FakeRunner::new(vec![]);
        let state = apply_with(&runner, &cfg(vec![], vec!["x.com"], vec!["y.com"])).unwrap();
        assert_eq!(state.backend, Backend::None);
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn apply_without_resolved_falls_back_to_none() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok_inactive())]);
        let state = apply_with(
            &runner,
            &cfg(vec!["10.0.0.53"], vec![], vec!["intranet.example.com"]),
        )
        .unwrap();
        assert_eq!(state.backend, Backend::None);
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn apply_rolls_back_on_domain_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok_active()),        // detect
            Ok(FakeRunner::ok_with_stdout("")), // dns (ok)
            Ok(FakeRunner::err("nope")),        // domain (fails)
            Ok(FakeRunner::ok_with_stdout("")), // revert (ok)
        ]);
        let err = apply_with(
            &runner,
            &cfg(vec!["10.0.0.53"], vec![], vec!["intranet.example.com"]),
        )
        .unwrap_err();
        assert!(matches!(err, DnsError::Resolvectl { op: "domain", .. }));
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3], vec!["resolvectl", "revert", "tun0"]);
    }

    #[test]
    fn revert_issues_resolvectl_revert() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok_with_stdout(""))]);
        let state = AppliedDnsState {
            ifname: "tun0".into(),
            backend: Backend::SystemdResolved,
            nrpt_rule_names: Vec::new(),
            macos_service: None,
            macos_prior_servers: Vec::new(),
            macos_prior_search_domains: Vec::new(),
            macos_search_domains_changed: false,
        };
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], vec!["resolvectl", "revert", "tun0"]);
    }

    #[test]
    fn revert_noop_for_none_backend() {
        let runner = FakeRunner::new(vec![]);
        let state = AppliedDnsState {
            ifname: "tun0".into(),
            backend: Backend::None,
            nrpt_rule_names: Vec::new(),
            macos_service: None,
            macos_prior_servers: Vec::new(),
            macos_prior_search_domains: Vec::new(),
            macos_search_domains_changed: false,
        };
        assert!(revert_with(&runner, &state).is_empty());
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn empty_ifname_is_rejected() {
        let runner = FakeRunner::new(vec![]);
        let config = DnsConfig {
            ifname: String::new(),
            servers: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            ..Default::default()
        };
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, DnsError::InvalidConfig(_)));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests_macos {
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok(stdout: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            }
        }

        fn fail(stderr: &str) -> Output {
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

    fn cfg(servers: Vec<&str>, search: Vec<&str>, split: Vec<&str>) -> DnsConfig {
        DnsConfig {
            ifname: "utun7".into(),
            servers: servers
                .into_iter()
                .map(|s| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()))
                .collect(),
            search_domains: search.into_iter().map(String::from).collect(),
            split_domains: split.into_iter().map(String::from).collect(),
            instance: "default".into(),
        }
    }

    #[test]
    fn detect_backend_macos_networksetup_available() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok("Wi-Fi\n"))]);
        assert_eq!(detect_backend_with(&runner), Backend::MacosNetworkSetup);
    }

    #[test]
    fn apply_macos_sets_and_restores_dns_servers() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("USB LAN\n")), // detect
            Ok(FakeRunner::ok(
                "   route to: default\n  interface: en5\n    gateway: 192.0.2.1\n",
            )),
            Ok(FakeRunner::ok(
                "An asterisk (*) denotes that a network service is disabled.\n(1) USB LAN\n(Hardware Port: USB LAN, Device: en5)\n",
            )),
            Ok(FakeRunner::ok("1.1.1.1\n8.8.8.8\n")), // prior dns
            Ok(FakeRunner::ok("corp.example.com\n")), // prior search
            Ok(FakeRunner::ok("")),                   // set dns
            Ok(FakeRunner::ok("")),                   // set search
            Ok(FakeRunner::ok("")),                   // restore dns
            Ok(FakeRunner::ok("")),                   // restore search
        ]);
        let state = apply_with(
            &runner,
            &cfg(
                vec!["10.0.0.53", "10.0.0.54"],
                vec!["corp.example.com"],
                vec!["intranet.example.com"],
            ),
        )
        .unwrap();
        assert_eq!(state.backend, Backend::MacosNetworkSetup);
        assert_eq!(state.macos_service.as_deref(), Some("USB LAN"));
        assert_eq!(state.macos_prior_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(state.macos_prior_search_domains, vec!["corp.example.com"]);
        assert!(state.macos_search_domains_changed);

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[5],
            vec![
                "networksetup",
                "-setdnsservers",
                "USB LAN",
                "10.0.0.53",
                "10.0.0.54"
            ]
        );
        assert_eq!(
            calls[6],
            vec![
                "networksetup",
                "-setsearchdomains",
                "USB LAN",
                "corp.example.com"
            ]
        );
        drop(calls);

        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[7],
            vec![
                "networksetup",
                "-setdnsservers",
                "USB LAN",
                "1.1.1.1",
                "8.8.8.8"
            ]
        );
        assert_eq!(
            calls[8],
            vec![
                "networksetup",
                "-setsearchdomains",
                "USB LAN",
                "corp.example.com"
            ]
        );
    }

    #[test]
    fn apply_macos_uses_empty_when_no_prior_dns_exists() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("Wi-Fi\n")), // detect
            Ok(FakeRunner::ok(
                "   route to: default\n  interface: en0\n    gateway: 192.0.2.1\n",
            )),
            Ok(FakeRunner::ok(
                "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
            )),
            Ok(FakeRunner::ok("There aren't any DNS Servers set on Wi-Fi.\n")),
            Ok(FakeRunner::ok("There aren't any Search Domains set on Wi-Fi.\n")),
            Ok(FakeRunner::ok("")), // set dns
            Ok(FakeRunner::ok("")), // restore dns
        ]);

        let state = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec![], vec![])).unwrap();
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[6],
            vec!["networksetup", "-setdnsservers", "Wi-Fi", "Empty"]
        );
    }

    #[test]
    fn apply_macos_surfaces_networksetup_failures() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("Wi-Fi\n")), // detect
            Ok(FakeRunner::ok(
                "   route to: default\n  interface: en0\n    gateway: 192.0.2.1\n",
            )),
            Ok(FakeRunner::ok(
                "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
            )),
            Ok(FakeRunner::ok("1.1.1.1\n")),
            Ok(FakeRunner::ok("There aren't any Search Domains set on Wi-Fi.\n")),
            Ok(FakeRunner::fail("permission denied")),
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec![], vec![])).unwrap_err();
        assert!(matches!(
            err,
            DnsError::MacosDns {
                op: "setdnsservers",
                ..
            }
        ));
    }
}

#[cfg(test)]
mod tests_cross_platform {
    use super::*;

    #[test]
    fn nrpt_namespace_normalizes_dots() {
        assert_eq!(nrpt_namespace("corp.example.com"), ".corp.example.com");
        assert_eq!(nrpt_namespace(".corp.example.com"), ".corp.example.com");
        assert_eq!(nrpt_namespace("example.com"), ".example.com");
    }

    #[test]
    fn validate_nrpt_domain_rejects_injection() {
        assert!(validate_nrpt_domain(".corp.example.com").is_ok());
        assert!(validate_nrpt_domain("example.com").is_ok());
        assert!(validate_nrpt_domain("a-b.example.com").is_ok());

        // Injection attempts
        assert!(validate_nrpt_domain("'; Remove-Item C:\\*;'").is_err());
        assert!(validate_nrpt_domain("x$(evil)").is_err());
        assert!(validate_nrpt_domain("x`whoami`").is_err());
        assert!(validate_nrpt_domain("").is_err());
    }

    #[test]
    fn validate_nrpt_domain_rejects_semicolons_and_quotes() {
        assert!(validate_nrpt_domain("test;evil").is_err());
        assert!(validate_nrpt_domain("test'evil").is_err());
        assert!(validate_nrpt_domain("test\"evil").is_err());
    }
}

#[cfg(all(test, windows))]
mod tests_windows {
    //! Windows-specific NRPT tests.
    //!
    //! The legacy PowerShell-based tests in this module relied on a
    //! `FakeRunner` to mock cmdlet exit status — they exercised the
    //! *shape* of the PowerShell commands we used to emit. The new
    //! native backend talks to the registry and SCM directly, so
    //! those mocks no longer apply.
    //!
    //! Coverage now splits two ways:
    //!
    //! * Pure unit tests for the registry encoding (`encode_multi_sz`)
    //!   and key naming (`generate_rule_key_name`) live next to the
    //!   code in `windows_nrpt::tests`.
    //!
    //! * The integration-level tests here exercise the public
    //!   `apply_with` / `remove_nrpt_rule` envelope without touching
    //!   the registry. Anything that needs a live `HKLM` write is
    //!   left for manual / CI-on-Windows verification.

    use super::*;

    #[test]
    fn detect_backend_always_returns_nrpt_on_windows() {
        // We no longer probe for cmdlets — NRPT is the only backend
        // and it's always available.
        struct NoopRunner;
        impl CommandRunner for NoopRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Result<Output, io::Error> {
                unreachable!("Windows detect_backend should not shell out");
            }
        }
        assert_eq!(detect_backend_with(&NoopRunner), Backend::Nrpt);
    }

    #[test]
    fn remove_nrpt_rule_rejects_names_without_openprotect_prefix() {
        // Defence in depth: never delete a registry key we didn't
        // create, even if `AppliedDnsState` were tampered with.
        struct NoopRunner;
        impl CommandRunner for NoopRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Result<Output, io::Error> {
                unreachable!("remove_nrpt_rule should not shell out on the validation path");
            }
        }
        assert!(remove_nrpt_rule(&NoopRunner, "{12345678-1234-1234-1234-123456789abc}").is_err());
        assert!(remove_nrpt_rule(&NoopRunner, "").is_err());
        assert!(remove_nrpt_rule(&NoopRunner, "tailscale-rule").is_err());
    }

    #[test]
    fn apply_nrpt_rejects_empty_split_domain_before_touching_registry() {
        // Input validation must run before any registry write.
        struct NoopRunner;
        impl CommandRunner for NoopRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Result<Output, io::Error> {
                unreachable!("validation failure should short-circuit before any subprocess");
            }
        }
        let config = DnsConfig {
            ifname: "tun0".into(),
            servers: vec![IpAddr::V4("10.0.0.1".parse().unwrap())],
            search_domains: Vec::new(),
            split_domains: vec!["good.com".into(), "".into()],
            instance: "default".into(),
        };
        let err = apply_with(&NoopRunner, &config).unwrap_err();
        assert!(matches!(err, DnsError::InvalidConfig(_)));
    }
}
