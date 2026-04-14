//! DNS configuration for the VPN tunnel lifetime.
//!
//! # Scope (MVP)
//!
//! Only the `systemd-resolved` backend is implemented today. Its
//! per-interface `resolvectl` model is the only one on Linux that
//! cleanly supports split DNS — routing queries for specific
//! domains through the VPN-assigned resolver while leaving the rest
//! on the normal system DNS. That's the experience we want for
//! `pgn connect --only …`.
//!
//! On systems without `systemd-resolved` (detected via `systemctl
//! is-active systemd-resolved`), the crate falls back to
//! [`Backend::None`]: it logs a one-line warning and leaves DNS
//! alone. Users who need DNS reconfiguration on those systems
//! should point `pgn connect --vpnc-script` at a real vpnc-script
//! that handles DNS itself.
//!
//! Adding `resolvconf(8)` and direct-`/etc/resolv.conf` backends is
//! tracked in the roadmap but deliberately out of scope for this
//! first cut — per-interface DNS on those backends requires extra
//! plumbing (resolvconf suffix files, manual /etc backup/restore)
//! that isn't worth the complexity before we've confirmed
//! systemd-resolved covers the 95% case.
//!
//! # API shape
//!
//! The crate mirrors `gp-route`'s shell-out + injectable runner
//! pattern so tests can assert the exact argv without touching
//! `resolvectl(1)` on the host.
//!
//! * [`DnsConfig`] — what the caller wants: interface name,
//!   nameservers, search/split domains.
//! * [`apply`] / [`revert`] — commit or roll back.
//! * [`AppliedDnsState`] — handed back from `apply` so cleanup can
//!   tell the difference between "we actually touched resolved"
//!   and "we were a no-op".
//! * [`Backend`] — the detected backend in effect; currently just
//!   `SystemdResolved` or `None`.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default per-`resolvectl` timeout. `resolvectl` talks to the
/// resolved daemon over dbus and should complete in milliseconds.
pub const DEFAULT_DNS_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// What the caller wants DNS to look like.
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// Tun interface the nameservers should be scoped to.
    pub ifname: String,
    /// Nameservers pushed by the VPN server.
    pub servers: Vec<IpAddr>,
    /// Search domains pushed by the VPN server. These become
    /// regular (non-routing) `resolvctl domain` entries.
    pub search_domains: Vec<String>,
    /// Split-DNS domains — only these domains get resolved via the
    /// per-interface resolver; everything else stays on the system
    /// DNS. Maps to `resolvectl domain <iface> ~domain`.
    pub split_domains: Vec<String>,
}

/// Backend that was (or was not) used to apply a [`DnsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `resolvectl` invoked on a live `systemd-resolved` instance.
    SystemdResolved,
    /// No backend detected on the host. Apply was a no-op.
    None,
}

/// Tracks what `apply` actually did, so `revert` can undo only
/// what was done.
#[derive(Debug, Clone)]
pub struct AppliedDnsState {
    pub ifname: String,
    pub backend: Backend,
}

/// Errors produced by the `gp-dns` API.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolvectl failed: {op}: {stderr}")]
    Resolvectl {
        op: &'static str,
        stderr: String,
    },

    #[error("spawning subprocess: {0}")]
    Spawn(#[from] io::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Abstraction over "run a command and inspect its output."
/// Matches the trait of the same name in `gp-route` so tests can
/// share the mock shape.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error>;
}

/// Default implementation: spawn + try_wait-poll with a 10 second
/// timeout, same shape as `gp-route`'s `SystemCommandRunner`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
        run_with_timeout(program, args, DEFAULT_DNS_COMMAND_TIMEOUT)
    }
}

fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<Output> {
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

/// Detect which DNS backend is live on this host.
///
/// Currently: runs `systemctl is-active systemd-resolved` and
/// returns [`Backend::SystemdResolved`] iff the output (after trim)
/// is the literal string `"active"`. Anything else falls back to
/// [`Backend::None`].
pub fn detect_backend() -> Backend {
    detect_backend_with(&SystemCommandRunner)
}

/// Like [`detect_backend`] but uses the given [`CommandRunner`].
pub fn detect_backend_with<R: CommandRunner>(runner: &R) -> Backend {
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

/// Apply a [`DnsConfig`] to the live system. Returns an
/// [`AppliedDnsState`] that tells the caller which backend handled
/// the request so `revert` can undo it later.
pub fn apply(config: &DnsConfig) -> Result<AppliedDnsState, DnsError> {
    apply_with(&SystemCommandRunner, config)
}

/// Like [`apply`] but uses the given [`CommandRunner`]. Intended
/// for tests; production callers should use [`apply`].
///
/// Behaviour is all-or-nothing per backend: if the `resolvectl
/// dns` call succeeds but a subsequent `resolvectl domain` call
/// fails, we [`revert`] what we'd done so far before returning the
/// triggering error — so the caller never has to deal with a
/// partially-applied DNS state.
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
        });
    }

    let backend = detect_backend_with(runner);
    match backend {
        Backend::SystemdResolved => apply_systemd_resolved(runner, config),
        Backend::None => {
            tracing::warn!(
                "gp-dns: systemd-resolved not detected on this host — skipping DNS \
                 configuration. Traffic will continue using the system resolver; \
                 set `--vpnc-script` to an external script if you need DNS."
            );
            Ok(AppliedDnsState {
                ifname: config.ifname.clone(),
                backend: Backend::None,
            })
        }
    }
}

fn apply_systemd_resolved<R: CommandRunner>(
    runner: &R,
    config: &DnsConfig,
) -> Result<AppliedDnsState, DnsError> {
    // `resolvectl dns <iface> <ip> [<ip> ...]`
    let servers_strs: Vec<String> = config.servers.iter().map(|ip| ip.to_string()).collect();
    let mut dns_args: Vec<&str> = vec!["dns", &config.ifname];
    dns_args.extend(servers_strs.iter().map(|s| s.as_str()));
    run_resolvectl(runner, "dns", &dns_args)?;

    let state = AppliedDnsState {
        ifname: config.ifname.clone(),
        backend: Backend::SystemdResolved,
    };

    // Build the combined search/split domain list. Split domains get
    // a `~` prefix so resolved treats them as routing-only (not also
    // a search suffix for unqualified names).
    let mut domain_strs: Vec<String> = config.search_domains.clone();
    domain_strs.extend(config.split_domains.iter().map(|d| format!("~{d}")));

    if !domain_strs.is_empty() {
        let mut domain_args: Vec<&str> = vec!["domain", &config.ifname];
        domain_args.extend(domain_strs.iter().map(|s| s.as_str()));
        if let Err(err) = run_resolvectl(runner, "domain", &domain_args) {
            // Roll back the dns setup we just did so we don't leave
            // resolved in a half-configured state.
            for rev_err in revert_with(runner, &state) {
                tracing::warn!("gp-dns apply-rollback: {rev_err}");
            }
            return Err(err);
        }
    }

    Ok(state)
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
            // `resolvectl revert <iface>` drops all configuration
            // we pushed via `resolvectl dns` and `resolvectl domain`.
            if let Err(e) =
                run_resolvectl(runner, "revert", &["revert", &state.ifname])
            {
                errors.push(format!("resolvectl revert {}: {e}", state.ifname));
            }
        }
        Backend::None => {
            // Nothing to undo.
        }
    }
    errors
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

#[cfg(test)]
mod tests {
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
            Ok(FakeRunner::ok_active()),          // detect
            Ok(FakeRunner::ok_with_stdout("")),   // resolvectl dns
            Ok(FakeRunner::ok_with_stdout("")),   // resolvectl domain
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

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            vec!["systemctl", "is-active", "systemd-resolved"]
        );
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
        assert_eq!(calls.len(), 2); // detect + dns; no domain
        assert_eq!(
            calls[1],
            vec!["resolvectl", "dns", "tun0", "10.0.0.53"]
        );
    }

    #[test]
    fn apply_no_servers_is_noop() {
        let runner = FakeRunner::new(vec![]);
        let state = apply_with(&runner, &cfg(vec![], vec!["x.com"], vec!["y.com"])).unwrap();
        assert_eq!(state.backend, Backend::None);
        // No commands should have been attempted — detection is
        // skipped when there are no servers to install.
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn apply_without_resolved_falls_back_to_none() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::ok_inactive())]);
        let state =
            apply_with(&runner, &cfg(vec!["10.0.0.53"], vec![], vec!["intranet.example.com"])).unwrap();
        assert_eq!(state.backend, Backend::None);
        // Only the detection call ran.
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn apply_rolls_back_on_domain_failure() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok_active()),            // detect
            Ok(FakeRunner::ok_with_stdout("")),     // dns (ok)
            Ok(FakeRunner::err("nope")),            // domain (fails)
            Ok(FakeRunner::ok_with_stdout("")),     // revert (ok)
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
