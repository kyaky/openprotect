//! DNS configuration for the VPN tunnel lifetime.
//!
//! # Backends
//!
//! * **Linux** — `systemd-resolved` via `resolvectl`. Per-interface DNS
//!   with split-DNS routing (`~domain`) so only matching queries go
//!   through the VPN resolver.
//!
//! * **Windows** — NRPT (Name Resolution Policy Table) via PowerShell
//!   `Add-DnsClientNrptRule`. Achieves the same split-DNS routing that
//!   `systemd-resolved` provides on Linux. This is a differentiator:
//!   no other open-source GP client uses NRPT — they all fall back to
//!   per-interface DNS via `netsh`, which breaks split tunnel.
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

/// Default per-command timeout.
pub const DEFAULT_DNS_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Comment tag stamped on every NRPT rule we create so we can
/// identify (and clean up) our own rules without touching others.
const NRPT_COMMENT: &str = "openprotect-vpn";

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
}

/// Backend that was (or was not) used to apply a [`DnsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `resolvectl` invoked on a live `systemd-resolved` instance.
    SystemdResolved,
    /// Windows NRPT rules created via PowerShell.
    Nrpt,
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
}

/// Errors produced by the `gp-dns` API.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolvectl failed: {op}: {stderr}")]
    Resolvectl { op: &'static str, stderr: String },

    #[error("NRPT operation failed: {op}: {detail}")]
    Nrpt { op: &'static str, detail: String },

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
    #[cfg(unix)]
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
    #[cfg(windows)]
    {
        // NRPT cmdlets are built into Windows PowerShell 5.1+ (Windows 8+).
        // Probe for the cmdlet rather than assuming availability.
        match runner.run(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (Get-Command Add-DnsClientNrptRule -EA SilentlyContinue) { 'ok' } else { 'no' }",
            ],
        ) {
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "ok" => Backend::Nrpt,
            _ => Backend::None,
        }
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
        });
    }

    let backend = detect_backend_with(runner);
    match backend {
        Backend::SystemdResolved => apply_systemd_resolved(runner, config),
        Backend::Nrpt => apply_nrpt(runner, config),
        Backend::None => {
            tracing::warn!(
                "gp-dns: no supported DNS backend detected — skipping DNS \
                 configuration. Set `--vpnc-script` for external DNS handling."
            );
            Ok(AppliedDnsState {
                ifname: config.ifname.clone(),
                backend: Backend::None,
                nrpt_rule_names: Vec::new(),
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
            // Safety sweep: also remove any stale openprotect-tagged rules
            // that might have survived a crash.
            if let Err(e) = cleanup_stale_nrpt_rules(runner) {
                errors.push(format!("cleaning stale NRPT rules: {e}"));
            }
            if let Err(e) = flush_dns_cache(runner) {
                errors.push(format!("flushing DNS cache: {e}"));
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
// NRPT backend (Windows)
// ---------------------------------------------------------------------------

/// Validate a domain name for safe interpolation into PowerShell.
/// Rejects anything that could be command injection.
fn validate_nrpt_domain(domain: &str) -> Result<(), DnsError> {
    if domain.is_empty() {
        return Err(DnsError::InvalidConfig("empty domain name".into()));
    }
    // Allow only: alphanumeric, dots, hyphens, and the leading dot that
    // NRPT namespaces require. Reject quotes, semicolons, backticks, $,
    // and anything else that could confuse PowerShell.
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

fn apply_nrpt<R: CommandRunner>(
    runner: &R,
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

    // 1. Clean up stale openprotect rules from a previous crash.
    if let Err(e) = cleanup_stale_nrpt_rules(runner) {
        tracing::warn!("gp-dns: failed to clean stale NRPT rules: {e}");
    }

    // 2. Check for GPO-managed NRPT rules (informational warning).
    check_gpo_nrpt_conflicts(runner);

    // 3. Build NRPT namespace list.
    let namespaces: Vec<String> = if config.split_domains.is_empty() {
        // No split domains: route ALL DNS through VPN (full tunnel).
        vec![".".to_string()]
    } else {
        config
            .split_domains
            .iter()
            .map(|d| nrpt_namespace(d))
            .collect()
    };

    // 4. Build the NameServers argument: '10.0.0.1','10.0.0.2'
    let servers_ps: String = config
        .servers
        .iter()
        .map(|ip| format!("'{ip}'"))
        .collect::<Vec<_>>()
        .join(",");

    // 5. Create one NRPT rule per namespace.
    let mut rule_names: Vec<String> = Vec::new();
    for ns in &namespaces {
        let cmd = format!(
            "$r = Add-DnsClientNrptRule -Namespace '{ns}' \
             -NameServers {servers_ps} \
             -Comment '{NRPT_COMMENT}' -PassThru; \
             $r.Name"
        );
        tracing::debug!("gp-dns: NRPT add rule for {ns}");
        let out = run_powershell(runner, &cmd)?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            // Roll back rules we already created; collect rollback
            // failures so the caller gets the full picture.
            let mut detail = format!("namespace {ns}: {stderr}");
            for name in &rule_names {
                if let Err(e) = remove_nrpt_rule(runner, name) {
                    detail.push_str(&format!("; rollback {name}: {e}"));
                }
            }
            return Err(DnsError::Nrpt {
                op: "Add-DnsClientNrptRule",
                detail,
            });
        }
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !name.is_empty() {
            rule_names.push(name);
        }
    }

    // 6. Flush DNS cache so the new rules take effect immediately.
    if let Err(e) = flush_dns_cache(runner) {
        tracing::warn!("gp-dns: failed to flush DNS cache: {e}");
    }

    tracing::info!(
        "gp-dns: created {} NRPT rule(s) for {} namespace(s)",
        rule_names.len(),
        namespaces.len()
    );

    Ok(AppliedDnsState {
        ifname: config.ifname.clone(),
        backend: Backend::Nrpt,
        nrpt_rule_names: rule_names,
    })
}

/// Remove a single NRPT rule by its GUID name.
fn remove_nrpt_rule<R: CommandRunner>(runner: &R, name: &str) -> Result<(), DnsError> {
    // Validate the name looks like a GUID to prevent injection.
    let safe = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '{' || c == '}');
    if !safe || name.is_empty() {
        return Err(DnsError::Nrpt {
            op: "Remove-DnsClientNrptRule",
            detail: format!("refusing to remove rule with suspicious name: {name:?}"),
        });
    }
    let cmd = format!("Remove-DnsClientNrptRule -Name '{name}' -Force");
    tracing::debug!("gp-dns: NRPT remove rule {name}");
    let out = run_powershell(runner, &cmd)?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(DnsError::Nrpt {
            op: "Remove-DnsClientNrptRule",
            detail: format!("{name}: {stderr}"),
        })
    }
}

/// Remove all NRPT rules tagged with our comment. Called on startup
/// (to clean up after a crash) and during revert (as a safety net).
fn cleanup_stale_nrpt_rules<R: CommandRunner>(runner: &R) -> Result<(), DnsError> {
    let cmd = format!(
        "Get-DnsClientNrptRule | \
         Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}"
    );
    tracing::debug!("gp-dns: cleaning stale NRPT rules");
    let out = run_powershell(runner, &cmd)?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(DnsError::Nrpt {
            op: "cleanup-stale",
            detail: stderr,
        })
    }
}

/// Warn if Group Policy has its own NRPT rules. GPO-managed rules
/// override all local rules on domain-joined machines — our rules
/// might be silently ignored.
fn check_gpo_nrpt_conflicts<R: CommandRunner>(runner: &R) {
    let cmd = "Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | \
               Measure-Object | Select-Object -ExpandProperty Count";
    match run_powershell(runner, cmd) {
        Ok(out) if out.status.success() => {
            let count_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(count) = count_str.parse::<u32>() {
                if count > 0 {
                    tracing::warn!(
                        "gp-dns: Group Policy has {count} NRPT rule(s) — on domain-joined \
                         machines these override local NRPT rules. If split DNS doesn't \
                         work, check with your IT admin."
                    );
                }
            }
        }
        _ => {
            // Detection failed silently — not critical.
        }
    }
}

/// Flush the Windows DNS client cache so new NRPT rules take
/// effect without waiting for TTL expiry.
fn flush_dns_cache<R: CommandRunner>(runner: &R) -> Result<(), DnsError> {
    tracing::debug!("gp-dns: flushing DNS cache");
    let out = run_powershell(runner, "Clear-DnsClientCache")?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(DnsError::Nrpt {
            op: "Clear-DnsClientCache",
            detail: stderr,
        })
    }
}

/// Run a PowerShell command and return its output.
///
/// Wraps the command with `$ErrorActionPreference = 'Stop'` so
/// non-terminating cmdlet errors become terminating and produce a
/// non-zero exit code rather than silently succeeding.
fn run_powershell<R: CommandRunner>(runner: &R, command: &str) -> Result<Output, DnsError> {
    let wrapped = format!("$ErrorActionPreference = 'Stop'; {command}");
    Ok(runner.run(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &wrapped],
    )?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
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
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::os::windows::process::ExitStatusExt;
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

    fn cfg(servers: Vec<&str>, split: Vec<&str>) -> DnsConfig {
        DnsConfig {
            ifname: "tun0".into(),
            servers: servers
                .into_iter()
                .map(|s| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()))
                .collect(),
            search_domains: Vec::new(),
            split_domains: split.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn detect_backend_nrpt_available() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok("ok\n"))]);
        assert_eq!(detect_backend_with(&runner), Backend::Nrpt);
    }

    #[test]
    fn detect_backend_nrpt_unavailable() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok("no\n"))]);
        assert_eq!(detect_backend_with(&runner), Backend::None);
    }

    #[test]
    fn apply_nrpt_creates_rules_for_split_domains() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")),       // detect NRPT
            Ok(FakeRunner::ok("")),           // cleanup stale
            Ok(FakeRunner::ok("0\n")),        // GPO check (0 policies)
            Ok(FakeRunner::ok("{GUID-1}\n")), // add rule 1
            Ok(FakeRunner::ok("{GUID-2}\n")), // add rule 2
            Ok(FakeRunner::ok("")),           // flush cache
        ]);
        let state = apply_with(
            &runner,
            &cfg(
                vec!["10.0.0.53"],
                vec!["corp.example.com", "intranet.example.com"],
            ),
        )
        .unwrap();
        assert_eq!(state.backend, Backend::Nrpt);
        assert_eq!(state.nrpt_rule_names, vec!["{GUID-1}", "{GUID-2}"]);

        let calls = runner.calls.borrow();
        // All calls go through powershell.exe
        assert!(calls.iter().all(|c| c[0] == "powershell.exe"));
        // Verify the add commands contain the right namespaces
        assert!(calls[3].last().unwrap().contains(".corp.example.com"));
        assert!(calls[4].last().unwrap().contains(".intranet.example.com"));
    }

    #[test]
    fn apply_nrpt_full_tunnel_uses_dot_namespace() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")),         // detect
            Ok(FakeRunner::ok("")),             // cleanup
            Ok(FakeRunner::ok("0\n")),          // GPO
            Ok(FakeRunner::ok("{GUID-ALL}\n")), // add rule for "."
            Ok(FakeRunner::ok("")),             // flush
        ]);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec![])).unwrap();
        assert_eq!(state.backend, Backend::Nrpt);
        assert_eq!(state.nrpt_rule_names, vec!["{GUID-ALL}"]);

        let calls = runner.calls.borrow();
        // The add command should contain "." namespace
        let add_cmd = calls[3].last().unwrap();
        assert!(add_cmd.contains("-Namespace '.'"), "got: {add_cmd}");
    }

    #[test]
    fn apply_nrpt_rolls_back_on_second_rule_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")),            // detect
            Ok(FakeRunner::ok("")),                // cleanup
            Ok(FakeRunner::ok("0\n")),             // GPO
            Ok(FakeRunner::ok("{GUID-1}\n")),      // add rule 1 (ok)
            Ok(FakeRunner::fail("access denied")), // add rule 2 (fails)
            Ok(FakeRunner::ok("")),                // rollback: remove rule 1
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec!["a.com", "b.com"])).unwrap_err();
        assert!(matches!(err, DnsError::Nrpt { .. }));

        let calls = runner.calls.borrow();
        // Last call should be removing the first rule
        let last = calls.last().unwrap().last().unwrap();
        assert!(
            last.contains("{GUID-1}"),
            "rollback should remove first rule"
        );
    }

    #[test]
    fn revert_nrpt_removes_rules_and_sweeps() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("")), // remove rule 1
            Ok(FakeRunner::ok("")), // remove rule 2
            Ok(FakeRunner::ok("")), // cleanup stale
            Ok(FakeRunner::ok("")), // flush cache
        ]);
        let state = AppliedDnsState {
            ifname: "tun0".into(),
            backend: Backend::Nrpt,
            nrpt_rule_names: vec!["{GUID-1}".into(), "{GUID-2}".into()],
        };
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(runner.calls.borrow().len(), 4);
    }

    #[test]
    fn remove_nrpt_rule_rejects_suspicious_names() {
        let runner = FakeRunner::new(vec![]);
        assert!(remove_nrpt_rule(&runner, "'; evil;'").is_err());
        assert!(remove_nrpt_rule(&runner, "").is_err());
    }

    #[test]
    fn apply_nrpt_rejects_empty_split_domain() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")), // detect
        ]);
        let config = DnsConfig {
            ifname: "tun0".into(),
            servers: vec![IpAddr::V4("10.0.0.1".parse().unwrap())],
            search_domains: Vec::new(),
            split_domains: vec!["good.com".into(), "".into()],
        };
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, DnsError::InvalidConfig(_)));
    }

    #[test]
    fn apply_nrpt_rollback_collects_remove_failures() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")),            // detect
            Ok(FakeRunner::ok("")),                // cleanup
            Ok(FakeRunner::ok("0\n")),             // GPO
            Ok(FakeRunner::ok("{GUID-1}\n")),      // add rule 1 (ok)
            Ok(FakeRunner::fail("denied")),        // add rule 2 (fails)
            Ok(FakeRunner::fail("remove failed")), // rollback rule 1 (also fails)
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.53"], vec!["a.com", "b.com"])).unwrap_err();
        // Error should mention both the add failure and the rollback failure.
        let msg = format!("{err}");
        assert!(msg.contains("denied"), "should contain add error: {msg}");
        assert!(
            msg.contains("rollback"),
            "should contain rollback info: {msg}"
        );
    }

    #[test]
    fn apply_nrpt_ignores_search_domains() {
        // search_domains are not used by the NRPT backend today.
        // Verify they don't cause extra commands or failures.
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok("ok\n")),       // detect
            Ok(FakeRunner::ok("")),           // cleanup
            Ok(FakeRunner::ok("0\n")),        // GPO
            Ok(FakeRunner::ok("{GUID-1}\n")), // add rule
            Ok(FakeRunner::ok("")),           // flush
        ]);
        let config = DnsConfig {
            ifname: "tun0".into(),
            servers: vec![IpAddr::V4("10.0.0.53".parse().unwrap())],
            search_domains: vec!["corp.example.com".into()],
            split_domains: vec!["corp.example.com".into()],
        };
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(state.backend, Backend::Nrpt);
        // Only 5 calls (detect, cleanup, gpo, add, flush) — no extra
        // call for search_domains.
        assert_eq!(runner.calls.borrow().len(), 5);
    }
}
