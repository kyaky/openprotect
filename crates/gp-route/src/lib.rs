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

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
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

/// How the `/32` gateway pin got into the routing table, decided by a
/// numeric probe at install time. Governs what teardown may delete.
///
/// The pre-fix Windows path issued a bare `route.exe add` with no
/// exists-branch, trusted the (always-zero) exit code, recorded the
/// pin unconditionally as ours, and `platform_revert` then DELETED it —
/// so a pre-existing (adopted) route could be claimed and destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinOwnership {
    /// We ran `route.exe add` for it and the numeric probe confirms
    /// the row is present. Only this class may be deleted on teardown.
    #[default]
    Created,
    /// The exact `(dest, mask, nexthop)` triple was already in the
    /// table before our add (a crashed prior session's leftover, or a
    /// third-party route we cannot distinguish from ours by the triple
    /// alone). Teardown must NOT delete it.
    Adopted,
}

/// Saved state for a temporary gateway `/32` host-route pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPinState {
    pub ip: Ipv4Addr,
    /// On Linux: the prior `ip route show` entry.
    /// On macOS / Windows: the default gateway nexthop used for the pin.
    pub prior_entry: Option<String>,
    /// Windows: whether teardown created the row (may delete) or found
    /// it already there (must not delete). Linux/macOS do not currently
    /// distinguish and leave this at [`PinOwnership::Created`].
    pub ownership: PinOwnership,
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

    /// A runner command hit its timeout, we killed the child, and the
    /// child did not confirm exit within `KILL_GRACE` after the kill
    /// — so a possibly-live process may still be mutating the routing
    /// table. gp-route then REFUSES every further route mutation,
    /// delete, retry or rollback for that call, because issuing one
    /// could interleave with the live process. Callers must treat this
    /// as "state unknown", surface it to the operator, and must not
    /// assume the earlier commands were cleaned up.
    #[error(
        "route mutation aborted: `{program}` ({op}) was killed after its command timeout but \
         did not confirm exit within the post-kill grace (pid {pid}). gp-route will NOT delete, \
         retry or roll back routes while a possibly-live process may still be mutating the \
         table — run `taskkill /PID {pid} /F` (or reboot) and check the route table before \
         reconnecting; some earlier changes may need manual cleanup."
    )]
    UnconfirmedTermination {
        op: &'static str,
        program: String,
        pid: u32,
    },

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

impl RouteError {
    /// True when this error means a killed child's death is
    /// unconfirmed: a live `route.exe`/`netsh`/`ip` may still hold the
    /// routing table. Rollback, retry and removal paths must gate on
    /// this and refuse to proceed while it holds.
    pub fn blocks_further_mutation(&self) -> bool {
        matches!(self, RouteError::UnconfirmedTermination { .. })
    }
}

/// Terminal payload carried inside the [`io::Error`] a runner returns
/// when its timed-out child was killed but did not confirm exit within
/// `KILL_GRACE`.
///
/// The distinction from a plain timeout is deliberate and load-bearing:
/// a *confirmed* kill means no child is mutating routes any more, so
/// rollback/removal may proceed. An *unconfirmed* kill means a process
/// may still be live and mutating routes, so it must not. Callers can
/// test the payload with [`is_unconfirmed_termination`] without
/// downcasting by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnconfirmedTermination {
    pub program: String,
    pub args: String,
    pub pid: u32,
}

impl std::fmt::Display for UnconfirmedTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`{} {}` (pid {}) was killed after its timeout but did not confirm exit within \
             the post-kill grace",
            self.program, self.args, self.pid
        )
    }
}

impl std::error::Error for UnconfirmedTermination {}

/// True when `err` is the [`io::Error`] wrapper of an
/// [`UnconfirmedTermination`] payload from a runner.
pub fn is_unconfirmed_termination(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|r| r.downcast_ref::<UnconfirmedTermination>())
        .is_some()
}

/// Map an [`io::Error`] from [`CommandRunner::run`] onto a
/// [`RouteError`], preserving the distinct unconfirmed-termination
/// signal instead of blending it into [`RouteError::Spawn`].
fn map_run_error(err: io::Error, op: &'static str, program: &str) -> RouteError {
    if let Some(t) = err
        .get_ref()
        .and_then(|r| r.downcast_ref::<UnconfirmedTermination>())
    {
        // `program` is what the caller actually invoked — preferred
        // over the payload's copy, which a custom runner may label
        // however it likes. The pid travels from the payload.
        return RouteError::UnconfirmedTermination {
            op,
            program: program.to_string(),
            pid: t.pid,
        };
    }
    RouteError::Spawn(err)
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

/// Poll interval while waiting for a child to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Grace allowed for a killed child to confirm exit after `kill()`.
///
/// The pre-fix code called `child.wait()` here, which is INFINITE: a
/// child wedged in a driver call (uninterruptible pending termination)
/// blocked the dedicated `run_tunnel` thread forever — an unbounded
/// hang behind an allegedly-bounded runner. Expiry is not an error to
/// swallow: it produces [`UnconfirmedTermination`] so callers can
/// refuse further route mutations.
const KILL_GRACE: Duration = Duration::from_millis(2_000);

/// Grace allowed for the stdout/stderr drainer threads to reach EOF
/// once the child itself has exited (or been confirmed dead).
///
/// The pre-fix code called `wait_with_output()` after `try_wait` had
/// already observed exit — so a surviving grandchild holding an
/// inherited write handle left the pipe without EOF and the read
/// blocked forever. Draining happens concurrently from child start
/// (see [`run_with_timeout`]); this bound only covers collecting the
/// last bytes, and expiry returns what was drained with a WARN rather
/// than blocking.
const EOF_GRACE: Duration = Duration::from_millis(1_000);

/// Outcome of the post-kill confirmation wait.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Termination {
    /// The child reported exit within the grace — nothing of ours is
    /// mutating routes any more, so rollback/retry/removal may proceed.
    Confirmed,
    /// The child did not confirm exit within the grace. A live process
    /// may still be mutating the table: every mutation-authorising
    /// caller must refuse to proceed.
    Unconfirmed { pid: u32 },
}

/// Poll `try_wait` until the child confirms exit or the grace expires.
///
/// Factored out of [`run_with_timeout`] with the child access behind a
/// closure so the grace decision is testable without an unkillable
/// process. A poll error means the child's exit state cannot be read,
/// which is deliberately NOT a lie about cleanup: it yields
/// [`Termination::Unconfirmed`].
fn confirm_child_exit(
    mut try_wait: impl FnMut() -> io::Result<Option<()>>,
    pid: u32,
    grace: Duration,
    poll: Duration,
) -> Termination {
    let start = Instant::now();
    loop {
        match try_wait() {
            Ok(Some(())) => return Termination::Confirmed,
            Ok(None) => {}
            Err(_) => return Termination::Unconfirmed { pid },
        }
        if start.elapsed() >= grace {
            return Termination::Unconfirmed { pid };
        }
        std::thread::sleep(poll);
    }
}

/// Spawn a pipe-drainer thread.
///
/// Each stream gets its own thread appending chunks into `buf` as they
/// arrive, so a child producing more output than the OS pipe buffer
/// cannot wedge: the pre-fix runner only collected pipes AFTER the
/// child exited (`wait_with_output` at old :233), so such a child
/// blocked on a full pipe, `try_wait` never observed exit, and the
/// command died on its timeout with all output lost. The thread is
/// detached: if a grandchild inherits the write handle and never
/// closes it, the drainer parks in `read` and the shared buffer stays
/// readable; joining them unboundedly is the wedge this rewrite removes.
fn spawn_drain<R>(
    name: &'static str,
    mut stream: R,
    buf: Arc<Mutex<Vec<u8>>>,
    done_tx: std::sync::mpsc::Sender<()>,
) -> io::Result<()>
where
    R: Read + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut chunk = [0u8; 8 * 1024];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .extend_from_slice(&chunk[..n]);
                    }
                    // A failed read is EOF-equivalent for our purposes: we
                    // keep whatever drained and stop.
                    Err(_) => break,
                }
            }
            let _ = done_tx.send(());
        })?;
    Ok(())
}

/// Drain `buf` under its mutex, tolerating a panicked/unreachable
/// drainer thread by reading the guarded data anyway (poison).
fn take_drained(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    buf.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    // The deadline is accounted from BEFORE `Command::spawn`, not after
    // it: the pre-fix clock started at old :229, after spawn returned,
    // so a wedged `CreateProcess` (AV filter, hung child-process
    // manager) cost the caller an unbounded amount of time that no
    // timeout ever covered.
    //
    // Honesty note: `spawn()` itself cannot be interrupted once we are
    // inside `CreateProcessW`. We therefore run it on a supervising
    // thread and wait for its result with `recv_timeout`: the CALLER
    // always stays bounded (and kills any child the late thread
    // eventually produces, since by then nobody will reap it). The
    // thread itself leaks while the wedged syscall is in flight — that
    // residue is bounded-by-OS and announced at WARN below.
    let deadline = Instant::now() + timeout;
    let (spawn_tx, spawn_rx) = std::sync::mpsc::channel();
    let spawn_program = program.to_string();
    let spawn_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    std::thread::Builder::new()
        .name("gp-route-spawn".into())
        .spawn(move || {
            let mut cmd = Command::new(&spawn_program);
            cmd.args(&spawn_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            match cmd.spawn() {
                Ok(child) => {
                    // If the caller abandoned us (its recv_timeout
                    // expired while CreateProcess was wedged), nobody
                    // owns this child: kill it rather than leak a live
                    // process mutating routes behind our back.
                    if let Err(send_err) = spawn_tx.send(Ok(child)) {
                        if let Ok(mut orphan) = send_err.0 {
                            let _ = orphan.kill();
                            let _ = orphan.wait();
                        }
                    }
                }
                Err(e) => {
                    let _ = spawn_tx.send(Err(e));
                }
            }
        })?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    let child = match spawn_rx.recv_timeout(remaining) {
        Ok(result) => result?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            tracing::warn!(
                "gp-route: spawning `{program} {}` did not return within {timeout:?} — \
                 CreateProcess itself is wedged; the supervising spawn thread is abandoned \
                 (bounded-by-OS, it will kill any child it eventually yields)",
                args.join(" ")
            );
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "`{program} {}` did not spawn within {timeout:?}",
                    args.join(" ")
                ),
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err(io::Error::other(format!(
                "spawn supervisor for `{program}` died before reporting"
            )));
        }
    };
    let mut child = child;

    // Drain stdout/stderr CONCURRENTLY from child start: the pre-fix
    // code polled `try_wait` first and only then called
    // `wait_with_output()`, so (a) a child producing more than the OS
    // pipe buffer blocked on write and the command "timed out" alive,
    // and (b) a surviving grandchild holding the inherited write handle
    // left the post-exit drain without EOF — an infinite read while the
    // exit code was already known (old :233).
    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let (eof_tx, eof_rx) = std::sync::mpsc::channel::<()>();
    let mut eof_expected = 0usize;
    if let Some(stdout) = child.stdout.take() {
        spawn_drain(
            "gp-route-drain-stdout",
            stdout,
            Arc::clone(&stdout_buf),
            eof_tx.clone(),
        )?;
        eof_expected += 1;
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_drain(
            "gp-route-drain-stderr",
            stderr,
            Arc::clone(&stderr_buf),
            eof_tx.clone(),
        )?;
        eof_expected += 1;
    }
    drop(eof_tx);

    // Poll for exit until the deadline. try_wait errors are not swallowed.
    let pid = child.id();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let term = confirm_child_exit(
                        || child.try_wait().map(|s| s.map(|_| ())),
                        pid,
                        KILL_GRACE,
                        POLL_INTERVAL,
                    );
                    match term {
                        Termination::Unconfirmed { pid } => {
                            // Do NOT lie about cleanup: a distinct
                            // terminal result, propagated so callers
                            // gate rollback/retry/removal on it.
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                UnconfirmedTermination {
                                    program: program.to_string(),
                                    args: args.join(" "),
                                    pid,
                                },
                            ));
                        }
                        Termination::Confirmed => {
                            // Dead and confirmed: collect what drained
                            // (bounded), then report the timeout.
                            collect_eofs(&eof_rx, eof_expected, program, args);
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "`{program} {}` did not exit within {timeout:?}",
                                    args.join(" ")
                                ),
                            ));
                        }
                    }
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    };

    // The child exited; give the drainers bounded time to see EOF, then
    // take the buffers. If EOF never arrives (grandchild inherited the
    // write handle), we return the bytes drained so far with a WARN —
    // the exit status is trustworthy, the capture is best-effort
    // bounded, and an unbounded read here was the old wedge.
    collect_eofs(&eof_rx, eof_expected, program, args);
    Ok(Output {
        status,
        stdout: take_drained(&stdout_buf),
        stderr: take_drained(&stderr_buf),
    })
}

/// Wait for the drainer threads to report EOF, bounded by
/// [`EOF_GRACE`] in total, and WARN if any stream never closed.
fn collect_eofs(
    eof_rx: &std::sync::mpsc::Receiver<()>,
    expected: usize,
    program: &str,
    args: &[&str],
) {
    let eof_deadline = Instant::now() + EOF_GRACE;
    let mut got = 0usize;
    while got < expected {
        let budget = eof_deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            break;
        }
        match eof_rx.recv_timeout(budget) {
            Ok(()) => got += 1,
            Err(_) => break,
        }
    }
    if got < expected {
        tracing::warn!(
            "gp-route: `{program} {}` pipes did not reach EOF within {EOF_GRACE:?} (a \
             surviving grandchild likely holds an inherited write handle); returning only the \
             bytes drained so far",
            args.join(" ")
        );
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
        // A killed-unconfirmed child may still be live and mutating
        // routes: refuse the rollback rather than interleave with it,
        // and let the error text tell the operator cleanup was
        // deliberately skipped.
        if err.blocks_further_mutation() {
            tracing::warn!(
                "gp-route: NOT rolling back — a killed command did not confirm its exit \
                 and may still be mutating the table: {err}"
            );
            return err;
        }
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
                if e.blocks_further_mutation() {
                    return errors;
                }
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
                // Unconfirmed child: a live `ip` may still be mutating
                // — stop issuing restores/replacements.
                if e.blocks_further_mutation() {
                    return errors;
                }
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
            if e.blocks_further_mutation() {
                return errors;
            }
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
            if e.blocks_further_mutation() {
                return errors;
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
        // Linux restores a captured prior entry rather than deleting,
        // so the created/adopted distinction (a Windows tooling hazard)
        // does not apply: the pin we replace is unambiguously ours to
        // put back.
        ownership: PinOwnership::Created,
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
    // map_run_error keeps a killed-unconfirmed child DISTINCT from an
    // ordinary spawn failure, so rollback/retry/removal paths can gate
    // on RouteError::blocks_further_mutation().
    let out = match runner.run("ip", args) {
        Ok(out) => out,
        Err(e) => return Err(map_run_error(e, op, "ip")),
    };
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
        // A killed-unconfirmed child may still be live and mutating
        // routes: refuse the rollback rather than interleave with it,
        // and let the error text tell the operator cleanup was
        // deliberately skipped.
        if err.blocks_further_mutation() {
            tracing::warn!(
                "gp-route: NOT rolling back — a killed command did not confirm its exit \
                 and may still be mutating the table: {err}"
            );
            return err;
        }
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
                    // Unconfirmed kill: a live `route(8)` may still be
                    // mutating the table — do not interleave with it.
                    if e.blocks_further_mutation() {
                        return errors;
                    }
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
            if e.blocks_further_mutation() {
                return errors;
            }
        }
    }

    if let Some(pin) = &state.installed_gateway_exclude {
        if pin.ownership == PinOwnership::Adopted {
            tracing::warn!(
                "gp-route: gateway pin {} was ADOPTED at install time; leaving it in place",
                pin.ip
            );
            return errors;
        }
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
            if e.blocks_further_mutation() {
                return errors;
            }
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

    // Probe-before-add, mirroring the Windows `/32` pin path and closing
    // the same hazard the cross-platform ownership contract states:
    // teardown deletes only pins we PROVED we created (`Created`), never
    // a row that already existed (`Adopted`). BSD `route(8)` — unlike
    // Windows `route.exe` — returns an honest exit code, so
    // `route -n get -host <gateway>` exiting 0 IS the existence proof
    // (a crashed prior session's leftover, or a static admin route). In
    // that case we leave the row in place and mark it ADOPTED; a
    // `route -n delete` of the (dest, default-gw) pair would otherwise
    // tear out a route this session never installed.
    //
    // The probe is deliberately conservative: we only ever *downgrade*
    // to Adopted on a positive existence proof, and never skip the add
    // we actually need. If the probe itself cannot classify (the probe
    // command errors for an unrelated reason) we fall through to the
    // add exactly as before, so a misparse can never leave the gateway
    // unpinned (which would let the split routes capture it — a worse
    // failure than an over-eager teardown).
    let pre_existing = probe_gateway_pin_present_macos(runner, gateway);
    if pre_existing {
        tracing::warn!(
            "gp-route: gateway pin {gateway}/32 via {default_gw} is ALREADY in the route \
             table — adopting it for this session; it will NOT be deleted on disconnect \
             (we cannot prove our add created it)"
        );
        state.installed_gateway_exclude = Some(GatewayPinState {
            ip: gateway,
            prior_entry: Some(default_gw),
            ownership: PinOwnership::Adopted,
        });
        return Ok(());
    }

    run_unix(
        runner,
        "route",
        "add gateway pin",
        &["-n", "add", "-host", &gateway.to_string(), &default_gw],
    )?;

    state.installed_gateway_exclude = Some(GatewayPinState {
        ip: gateway,
        prior_entry: Some(default_gw),
        // BSD `route -n get` gave an honest "absent" verdict above, so
        // our add is the proven creator of the row: it may be deleted
        // on teardown (contract: only `Created` pins are deleted).
        ownership: PinOwnership::Created,
    });
    Ok(())
}

/// Existence probe for the macOS gateway pin. Returns `true` ONLY on a
/// positive `route -n get -host` (exit 0); any probe error is folded to
/// `false` so the caller proceeds with the add (never skips a needed
/// pin). Split out so the install decision is table-testable against an
/// injected `CommandRunner`.
#[cfg(target_os = "macos")]
fn probe_gateway_pin_present_macos<R: CommandRunner>(runner: &R, gateway: Ipv4Addr) -> bool {
    match run_unix_stdout(
        runner,
        "route",
        "probe gateway pin",
        &["-n", "get", "-host", &gateway.to_string()],
    ) {
        Ok(out) => !out.trim().is_empty(),
        Err(_) => false,
    }
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
    // See run_ip_checked: an unconfirmed kill must stay distinguishable.
    let out = match runner.run(program, args) {
        Ok(out) => out,
        Err(e) => return Err(map_run_error(e, op, program)),
    };
    if out.status.success() {
        Ok(out)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Same fallback the pre-fix code had (stderr, else stdout) —
        // expressed once so all backends share it.
        let detail = first_non_empty(&[stderr.as_str(), stdout.as_str()])
            .unwrap_or_else(|| "process exited with failure status".into());
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
        // A killed-unconfirmed child may still be live and mutating
        // the route table. Rolling back now could interleave with it,
        // so refuse — the error text tells the operator the state is
        // unknown and cleanup was deliberately NOT attempted.
        if err.blocks_further_mutation() {
            tracing::warn!(
                "gp-route: NOT rolling back installed routes — a killed command did not \
                 confirm its exit and may still be mutating the table: {err}"
            );
            return err;
        }
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
            // Reaching here means `first` carried exists-text from a
            // COMPLETED command: an unconfirmed kill surfaces as
            // RouteError::UnconfirmedTermination, is_route_exists_error
            // is false for it, and the branch above bails to the (now
            // gated) rollback. The delete+add retry below can therefore
            // never interleave with a possibly-live netsh.
            tracing::warn!(
                "gp-route: route add {route} on {} reports the route already exists; \
                 clearing our stale entry for that prefix and retrying",
                config.ifname
            );
            if let Err(e) = run_netsh(
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
            ) {
                // A stale-entry delete failing loudly is only fatal if
                // the child's death is unconfirmed (the retry could
                // interleave with it); other failures stay tolerated
                // pre-existing behaviour and the re-add decides anyway.
                if e.blocks_further_mutation() {
                    return Err(rollback(runner, &state, e));
                }
            }
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
            // A netsh delete that was killed without confirming its
            // death means a live process may still be mutating routes:
            // STOP. Issuing the next delete/retry could interleave with
            // it. Report the partial teardown instead of pressing on.
            if e.blocks_further_mutation() {
                return errors;
            }
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
            if e.blocks_further_mutation() {
                return errors;
            }
        }
    }

    // Gateway pin. Only pins we PROVED we created are deleted, and the
    // delete keys on (dest, mask, nexthop) — the exact route we added.
    //
    // (dest, mask, nexthop) names no interface: `route.exe` resolves
    // the outbound adapter itself, so the triple cannot by itself tell
    // our row from a third party's identical row. That is precisely why
    // install probes first and classifies Adopted rows as untouchable.
    if let Some(pin) = &state.installed_gateway_exclude {
        if pin.ownership == PinOwnership::Adopted {
            tracing::warn!(
                "gp-route: gateway pin {} via {} was ADOPTED (already in the table at \
                 install time); leaving it in place — deleting a (dest, mask, nexthop) \
                 match we cannot prove we created would tear out someone else's route",
                pin.ip,
                pin.prior_entry.as_deref().unwrap_or("unknown nexthop"),
            );
        } else {
            let ip_str = pin.ip.to_string();
            let mut args: Vec<&str> = vec!["delete", &ip_str, "mask", "255.255.255.255"];
            // prior_entry holds the default gateway nexthop we pinned
            // through. Include it so we only remove the exact route we
            // added; without it the delete is an even broader match, so
            // verification below only runs when we can name the triple.
            if let Some(ref gw) = pin.prior_entry {
                args.push(gw);
            }
            match run_checked(runner, "route.exe", "delete gateway pin", &args) {
                Ok(_) => {
                    if let Some(ref gw) = pin.prior_entry {
                        // The delete's exit code means nothing (Win11
                        // 26100: always 0); the numeric probe decides
                        // whether the pin is actually gone.
                        match route_row_present(runner, &ip_str, "255.255.255.255", gw) {
                            Ok(true) => errors.push(format!(
                                "delete gateway pin {}: reported success but the /32 route is \
                                 still present (numeric postcondition failed)",
                                pin.ip
                            )),
                            Ok(false) => {}
                            Err(e) => {
                                errors.push(format!(
                                    "verify deletion of gateway pin {}: {e}",
                                    pin.ip
                                ));
                                if e.blocks_further_mutation() {
                                    return errors;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("delete gateway pin {}: {e}", pin.ip));
                    if e.blocks_further_mutation() {
                        return errors;
                    }
                }
            }
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

    let dest = gateway.to_string();
    let mask = "255.255.255.255";

    // HAZARD, documented in code because it drives everything below:
    // `route.exe add/delete <dest> mask <mask> <nexthop>` identifies a
    // row by (dest, mask, nexthop) ONLY — the interface is resolved by
    // the kernel at add time and is not part of the key we can express.
    // A matching triple can therefore belong to another adapter's
    // route or a third party, and a blind `delete` on teardown would
    // remove something we never created. We consequently (1) probe
    // before acting, (2) never issue `route.exe change` against a
    // matching destination without this same verified-triple check,
    // and (3) only delete rows we proved we CREATED.

    // Check-then-change/adopt: probe first.
    let pre_existing = route_row_present(runner, &dest, mask, &default_gw)?;
    if pre_existing {
        // ADOPTED. Present before we touched anything: reuse it, record
        // it, and mark it NOT ours — teardown must not delete a route
        // we cannot prove we installed.
        tracing::warn!(
            "gp-route: gateway pin {gateway}/32 via {default_gw} is ALREADY in the route \
             table — adopting it for this session; it will NOT be deleted on disconnect \
             ((dest, mask, nexthop) names no interface, so we cannot prove we own it)"
        );
        state.installed_gateway_exclude = Some(GatewayPinState {
            ip: gateway,
            prior_entry: Some(default_gw),
            ownership: PinOwnership::Adopted,
        });
        return Ok(());
    }

    // Keep the add's raw text: on a localized Windows the English-only
    // WIN_FAILURE_TEXTS scan in run_checked cannot read a third party's
    // (or our own) "object already exists" line, so an exit-0 add with
    // such output passes as success here. We still trust the NUMERIC
    // post-probe for existence, but we surface the unclassified-output
    // case so a disappearing third-party /32 can be attributed in the
    // field (see the WARN below).
    let add_out = run_checked(
        runner,
        "route.exe",
        "add gateway pin",
        &["add", &dest, "mask", mask, &default_gw],
    );
    let add_unclassified_output = add_out.as_ref().ok().and_then(localised_add_text_residual);
    let add_err = add_out.err();

    // Postcondition by NUMERIC probe, never by success text or exit
    // code: route.exe exits 0 on every failure (live-proven, Win11
    // 26100) and its failure strings are localized, so only the
    // printed table tells the truth.
    let present = route_row_present(runner, &dest, mask, &default_gw)?;
    match (add_err, present) {
        (None, true) => {
            if let Some(text) = &add_unclassified_output {
                // The add exited 0 and the row is present, so we record
                // it as CREATED (and tear it down). But route.exe printed
                // a line our English failure table could not classify —
                // on a localized build this is indistinguishable from a
                // third party's "already exists", and the (dest, mask,
                // nexthop) triple names no interface. If the row actually
                // predated us (installed in the probe→add window by
                // another VPN / DHCP-pushed script), this disconnect will
                // delete a route we never created. Name the residual so
                // field reports of a vanishing third-party gateway route
                // point here rather than reading as an unexplained leak.
                tracing::warn!(
                    "gp-route: gateway pin {gateway}/32 via {default_gw}: `route.exe add` exited \
                     0 with output the localized-failure table could not classify ({text:?}); the \
                     numeric post-probe alone vouched for it and it is recorded as CREATED (will \
                     be deleted on disconnect). On a non-English locale this can mask a pre-\
                     existing third-party (dest,mask,nexthop) row — if that route disappears \
                     after disconnect, attribute it to this probe→add window."
                );
            }
            state.installed_gateway_exclude = Some(GatewayPinState {
                ip: gateway,
                prior_entry: Some(default_gw),
                ownership: PinOwnership::Created,
            });
            Ok(())
        }
        // add claimed success (or was believed) but the row is not
        // there: the exit code lied and there is nothing to tear down.
        (None, false) => Err(RouteError::WinCommand {
            program: "route",
            op: "add gateway pin",
            detail: format!(
                "`route.exe add {gateway} mask {mask} {default_gw}` exited 0 but the /32 pin \
                 is not in the routing table (numeric postcondition failed — route.exe \
                 exits 0 on every failure on this OS build)"
            ),
        }),
        // add failed with an already-exists shape, yet the (identical)
        // triple is now present: someone installed it between probes,
        // or our view raced. Cannot prove we created it → ADOPTED, and
        // NOT deleted on teardown.
        (Some(e), true) if is_route_exists_error(&e) => {
            tracing::warn!(
                "gp-route: gateway pin {gateway}/32 via {default_gw} reported as existing \
                 during add and the probe confirms it — classifying as ADOPTED; teardown \
                 will leave it in place. ({e})"
            );
            state.installed_gateway_exclude = Some(GatewayPinState {
                ip: gateway,
                prior_entry: Some(default_gw),
                ownership: PinOwnership::Adopted,
            });
            Ok(())
        }
        (Some(e), _) => Err(e),
    }
}

#[cfg(windows)]
fn run_netsh<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<(), RouteError> {
    run_checked(runner, "netsh", op, args).map(|_| ())
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
    // Audit finding: this used to call `runner.run` directly, bypassing
    // every rule `run_checked` enforces (exit-0-with-failure-text,
    // distinct unconfirmed-kill propagation). Discovery is a read, but
    // it still goes through the checked path so a wedged or lying
    // route.exe is reported the same way a mutation would be — and a
    // killed-unconfirmed child here blocks the pin install below, as it
    // must.
    let out = run_checked(
        runner,
        "route.exe",
        "discover default gateway",
        &["print", "-4", "0.0.0.0"],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_default_gateway(&stdout).ok_or(RouteError::WinCommand {
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

/// Run a command, check its exit status, and — because on Windows the
/// exit status is not trustworthy — check its output text too.
///
/// LIVE-PROVEN fact (Windows 11 26100): `route.exe` returns EXIT CODE 0
/// on every failure — "The route addition failed: The object already
/// exists." is printed with exit 0. The pre-fix version of this function
/// (old :1748-1766) keyed only on `status.success()` and read stderr
/// only, so every such failure passed as success: adopted pre-existing
/// pins were claimed as ours and later DELETED by teardown, and
/// `is_route_exists_error` never fired because the error never existed.
/// For mutating commands we now scan BOTH streams for known failure
/// text and only then consult success; and pin install/revert add a
/// numeric route-table probe on top (locale cannot defeat a number).
#[cfg(windows)]
fn run_checked<R: CommandRunner>(
    runner: &R,
    program: &'static str,
    op: &'static str,
    args: &[&str],
) -> Result<Output, RouteError> {
    tracing::debug!("gp-route: {program} {}", args.join(" "));
    let out = match runner.run(program, args) {
        Ok(out) => out,
        Err(e) => return Err(map_run_error(e, op, program)),
    };
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        // Pre-fix read stderr only; netsh (and some route.exe paths)
        // print the reason on stdout, so fall back to it.
        let detail = first_non_empty(&[stderr.trim(), stdout.trim()])
            .unwrap_or("process exited with failure status".into());
        return Err(RouteError::WinCommand {
            program,
            op,
            detail,
        });
    }
    // Exit 0 does not mean success for the Windows route/netsh tooling
    // (see doc comment). Read-only `print` output is legitimately full
    // of words like "failed" inside interface descriptions, so the text
    // scan is scoped to mutating subcommands; the pin paths additionally
    // verify a numeric postcondition, which is what actually vouches
    // for them on a localized box.
    if is_mutating_command(program, args) {
        if let Some(failure) = command_failure_text(&stderr, &stdout) {
            return Err(RouteError::WinCommand {
                program,
                op,
                detail: failure,
            });
        }
    }
    Ok(out)
}

#[cfg(any(windows, target_os = "macos"))]
fn first_non_empty(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|s| !s.is_empty())
        .map(|s| (*s).to_string())
}

/// English failure lines `route.exe`/`netsh` print while still exiting
/// 0 (or on a stream nobody consulted). Matching is on the lowercased
/// text; the phrase table is deliberately narrow so ordinary informational
/// output cannot be misread as a failure (false positives would block a
/// good connect — worse than the localized false negatives, which the
/// numeric probes cover).
#[cfg(windows)]
const WIN_FAILURE_TEXTS: &[&str] = &[
    "route addition failed",
    "route deletion failed",
    "route change failed",
    "object already exists",
    "access is denied",
    "requires elevation",
];

#[cfg(windows)]
fn command_failure_text(stderr: &str, stdout: &str) -> Option<String> {
    for stream in [stderr, stdout] {
        for line in stream.lines() {
            let lowered = line.to_ascii_lowercase();
            if WIN_FAILURE_TEXTS.iter().any(|p| lowered.contains(p)) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

/// The combined trimmed stdout+stderr of a `route.exe add` that
/// `run_checked` accepted (exit 0, no English failure text matched) but
/// that still PRINTED something. Returns `Some(text)` for that
/// unclassified output and `None` for a clean silent success (the normal
/// English case, where `route.exe add` emits nothing on success).
///
/// A `Some` is the localized-text residual: on a non-English build
/// route.exe writes its "already exists" reason in the UI language,
/// which [`WIN_FAILURE_TEXTS`] cannot match, so a pre-existing
/// (possibly third-party) `/32` row passes as our own creation. The pin
/// install turns this into a WARN so the disappearing-route class is
/// attributable in field reports. Pure so the WARN decision is unit-
/// testable without a tracing subscriber (the subscriber emission
/// itself is a documented no-seam residual, like the heartbeat asserts).
#[cfg(windows)]
fn localised_add_text_residual(out: &Output) -> Option<String> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}\n{stderr}");
    let trimmed = combined.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// True for commands that change the routing table — the ones whose
/// exit code we refuse to believe without consulting output.
#[cfg(windows)]
fn is_mutating_command(program: &str, args: &[&str]) -> bool {
    let verb = |i: usize| args.get(i).map(|s| s.to_ascii_lowercase());
    match program.to_ascii_lowercase().as_str() {
        // `route.exe add|delete|change …` (print is read-only)
        "route.exe" | "route" => matches!(
            verb(0).as_deref(),
            Some("add") | Some("delete") | Some("change")
        ),
        // `netsh interface ipv4 add|delete|set …`
        "netsh" => {
            verb(0).as_deref() == Some("interface")
                && matches!(
                    verb(2).as_deref(),
                    Some("add") | Some("delete") | Some("set")
                )
        }
        _ => false,
    }
}

/// One numeric row of `route.exe print` output.
///
/// Parsed positionally from the five whitespace columns
/// (`Network Destination / Netmask / Gateway / Interface / Metric`).
/// Every column is a strict IPv4/u32 parse, so this is
/// LOCALE-INDEPENDENT: headers and `On-link` renderings translate, the
/// numbers do not, and a row that cannot parse is not a row.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteRow {
    destination: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    iface: Ipv4Addr,
    metric: u32,
}

#[cfg(windows)]
fn parse_route_rows(stdout: &str) -> Vec<RouteRow> {
    let mut rows = Vec::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() != 5 {
            continue;
        }
        let (Ok(destination), Ok(netmask), Ok(gateway), Ok(iface), Ok(metric)) = (
            cols[0].parse::<Ipv4Addr>(),
            cols[1].parse::<Ipv4Addr>(),
            cols[2].parse::<Ipv4Addr>(),
            cols[3].parse::<Ipv4Addr>(),
            cols[4].parse::<u32>(),
        ) else {
            continue;
        };
        rows.push(RouteRow {
            destination,
            netmask,
            gateway,
            iface,
            metric,
        });
    }
    rows
}

/// Numeric route-table probe: does the table contain the exact
/// `(dest, mask, nexthop)` triple right now?
///
/// This is how gp-route verifies a pin's intended postcondition instead
/// of trusting `route.exe`'s word for it — live-proven exit-code 0 on
/// failure makes both the code and (on localized hosts) the text
/// unusable as sole evidence. `Err` (including
/// [`RouteError::UnconfirmedTermination`]) means the table could not be
/// read: callers must treat the postcondition as UNKNOWN, not false.
#[cfg(windows)]
fn route_row_present<R: CommandRunner>(
    runner: &R,
    dest: &str,
    mask: &str,
    gateway: &str,
) -> Result<bool, RouteError> {
    let (Some(destination), Some(netmask), Some(gw)) = (
        dest.parse::<Ipv4Addr>().ok(),
        mask.parse::<Ipv4Addr>().ok(),
        gateway.parse::<Ipv4Addr>().ok(),
    ) else {
        return Err(RouteError::InvalidConfig(format!(
            "probe args not numeric IPv4: dest={dest:?} mask={mask:?} gateway={gateway:?}"
        )));
    };
    // A *filtered read* through the same checked path, never a blind
    // runner.run: audit item 4 (the old discovery bypass) is closed for
    // every route.exe invocation, reads included.
    let out = run_checked(
        runner,
        "route.exe",
        "verify route pin",
        &["print", "-4", dest],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_route_rows(&stdout)
        .into_iter()
        .any(|r| r.destination == destination && r.netmask == netmask && r.gateway == gw))
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
                ownership: PinOwnership::Created,
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
                ownership: PinOwnership::Created,
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
                ownership: PinOwnership::Created,
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
        // Probe-before-add: get default → probe `get -host` (EXIT NONZERO
        // = absent) → our `add -host` → Created.
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // ifconfig
            Ok(FakeRunner::ok_stdout(
                "   route to: default\n   gateway: 192.0.2.1\ninterface: en0\n",
            )),
            Ok(FakeRunner::err("route: not in table")), // probe: absent
            Ok(FakeRunner::ok()),                       // host route pin (our add)
            Ok(FakeRunner::ok()),                       // split route
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
                ownership: PinOwnership::Created,
            })
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls[1], vec!["route", "-n", "get", "default"]);
        // Index 2 is now the existence probe we must run before claiming
        // ownership of the row.
        assert_eq!(
            calls[2],
            vec!["route", "-n", "get", "-host", "198.51.100.230"]
        );
        assert_eq!(
            calls[3],
            vec!["route", "-n", "add", "-host", "198.51.100.230", "192.0.2.1"]
        );
    }

    /// Contract: a macOS `/32` gateway pin that is ALREADY in the table
    /// (BSD `route -n get -host` exits 0) is adopted — never claimed as
    /// ours, and therefore NEVER deleted on teardown. This closes the gap
    /// the Windows (dest,mask,nexthop) probe was written for: a
    /// pre-existing (crashed-session / admin-static) host route must
    /// survive disconnect.
    #[test]
    fn apply_macos_existing_gateway_pin_is_adopted_and_never_added() {
        let gateway = Ipv4Addr::new(198, 51, 100, 230);
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // ifconfig
            Ok(FakeRunner::ok_stdout(
                "   route to: default\n   gateway: 192.0.2.1\ninterface: en0\n",
            )),
            Ok(FakeRunner::ok_stdout(
                "   route to: 198.51.100.230\ndestination: 198.51.100.230\n\
                 gateway: 192.0.2.1\ninterface: en0\n",
            )), // probe: PRESENT (exit 0)
            // NO `add -host` outcome queued — the adopted path must skip
            // the add (if it added, FakeRunner panics "no more outcomes").
            // The split `-net` route below still runs.
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
                ownership: PinOwnership::Adopted,
            }),
            "a present macOS host route must be adopted, not claimed Created"
        );
        let calls = runner.calls.borrow();
        // The probe ran…
        assert_eq!(
            calls[2],
            vec!["route", "-n", "get", "-host", "198.51.100.230"]
        );
        // …and NO `route -n add -host` was issued: calls[3] is the split
        // `-net` route, not a host add.
        assert_eq!(calls[3][1], "add");
        assert_eq!(calls[3][2], "-net");
    }

    /// An Adopted pin survives teardown: `platform_revert_macos` must
    /// issue NO `route -n delete -host` for it (the Windows gate, now
    /// honoured on macOS too).
    #[test]
    fn revert_macos_leaves_adopted_gateway_pin_in_place() {
        let state = AppliedState {
            ifname: "utun7".into(),
            installed_routes: vec![],
            installed_addr: None,
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.0.2.1".into()),
                ownership: PinOwnership::Adopted,
            }),
        };
        // Zero command outcomes available: ANY delete attempt panics the
        // FakeRunner, proving the adopted branch issues no mutations.
        let runner = FakeRunner::all_ok(0);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            runner.calls.borrow().is_empty(),
            "adopted pin must mutate nothing"
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
                ownership: PinOwnership::Created,
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
// Tests — command runner bounds & termination (platform independent)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_runner {
    use super::*;

    type PollSeq = Vec<io::Result<Option<()>>>;

    fn seq(values: PollSeq) -> impl FnMut() -> io::Result<Option<()>> {
        let mut values = Some(values.into_iter());
        move || {
            let iter = values.as_mut().unwrap();
            iter.next().unwrap_or(Ok(None))
        }
    }

    /// The post-kill confirmation wait must be BOUNDED and must never
    /// misreport: `child.wait()` after `kill()` was INFINITE pre-fix
    /// (old :241-242), hanging the dedicated run_tunnel thread when a
    /// child wedged in a driver call.
    #[test]
    fn confirm_child_exit_table() {
        let grace = Duration::from_millis(100);
        let poll = Duration::from_millis(1);

        let cases: Vec<(&str, PollSeq, Termination)> = vec![
            (
                "exits immediately",
                vec![Ok(Some(()))],
                Termination::Confirmed,
            ),
            (
                "exits after a few polls",
                vec![Ok(None), Ok(None), Ok(Some(()))],
                Termination::Confirmed,
            ),
            (
                // The kill that never lands: the ONLY honest answer is
                // Unconfirmed — reporting success here would let
                // rollback issue deletes beside a live route mutator.
                "never confirms within the grace",
                (0..64).map(|_| Ok(None)).collect(),
                Termination::Unconfirmed { pid: 4242 },
            ),
            (
                // A poll error means we cannot READ the exit state,
                // which is not evidence of death either.
                "poll errors out",
                vec![Err(io::Error::other("wait failed"))],
                Termination::Unconfirmed { pid: 4242 },
            ),
            (
                // Empty stream = perpetual Ok(None): same as the
                // never-exit row, must terminate by grace, not hang.
                "grace expiry dominates the poll count",
                vec![],
                Termination::Unconfirmed { pid: 9 },
            ),
        ];
        for (name, values, want) in cases {
            let got = confirm_child_exit(seq(values), want_pid(&want), grace, poll);
            assert_eq!(got, want, "case `{name}`");
        }
    }

    fn want_pid(t: &Termination) -> u32 {
        match t {
            Termination::Confirmed => 4242,
            Termination::Unconfirmed { pid } => *pid,
        }
    }

    /// The unconfirmed payload must survive the io::Error round trip —
    /// it is what every rollback/retry/removal site gates on.
    #[test]
    fn unconfirmed_payload_is_detectable_and_maps_to_a_distinct_error() {
        let payload = UnconfirmedTermination {
            program: "route.exe".into(),
            args: "add 198.51.100.230 mask 255.255.255.255 192.168.1.1".into(),
            pid: 31337,
        };
        let err = io::Error::new(io::ErrorKind::TimedOut, payload.clone());
        assert!(is_unconfirmed_termination(&err));

        let mapped = map_run_error(err, "add gateway pin", "route.exe");
        match &mapped {
            RouteError::UnconfirmedTermination { op, program, pid } => {
                assert_eq!(*op, "add gateway pin");
                // program names the binary the CALLER ran, not whatever
                // a custom runner stamped into the payload.
                assert_eq!(program, "route.exe");
                assert_eq!(*pid, 31337);
            }
            other => panic!("must map to UnconfirmedTermination, got {other:?}"),
        }
        assert!(mapped.blocks_further_mutation());

        // An ordinary spawn failure must NOT map to the unconfirmed
        // class — it is a different (pre-spawn, nothing-ran) situation.
        let plain = io::Error::new(io::ErrorKind::NotFound, "no such program");
        assert!(!is_unconfirmed_termination(&plain));
        assert!(matches!(
            map_run_error(plain, "add route", "netsh"),
            RouteError::Spawn(_)
        ));
    }
}

// ---------------------------------------------------------------------------
// Tests — is_route_exists_error predicate
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_route_exists {
    use super::*;

    /// Table-driven regression for the predicate that gates every
    /// exists-retry / adopt branch. The EN strings are the live-proven
    /// route.exe wording (printed with exit code 0 on Win11 26100) and
    /// the iproute2 wording from commit 467bf28's Linux path; the
    /// negatives are what must NEVER be retried-and-deleted.
    #[test]
    fn exists_predicate_table() {
        let cases: Vec<(RouteError, bool, &str)> = vec![
            (
                RouteError::WinCommand {
                    program: "route",
                    op: "add gateway pin",
                    detail: "The route addition failed: The object already exists.".into(),
                },
                true,
                "route.exe exit-0 stdout line (live-proven class)",
            ),
            (
                RouteError::WinCommand {
                    program: "netsh",
                    op: "add route",
                    detail: "The object already exists.".into(),
                },
                true,
                "netsh same-interface duplicate",
            ),
            (
                RouteError::IpCommand {
                    op: "route add",
                    stderr: "RTNETLINK answers: File exists".into(),
                },
                true,
                "Linux EEXIST (467bf28 path)",
            ),
            (
                RouteError::UnixCommand {
                    program: "route",
                    op: "add route",
                    detail: "route: writing to routing socket: File exists".into(),
                },
                true,
                "BSD/macOS EEXIST",
            ),
            (
                // Mixed case: the predicate lowercases before matching.
                RouteError::WinCommand {
                    program: "route",
                    op: "add gateway pin",
                    detail: "THE OBJECT ALREADY EXISTS.".into(),
                },
                true,
                "case-insensitive",
            ),
            (
                // Not-a-conflict failures must fall through to the
                // original error — a delete/retry beside these is the
                // hazard the retry scoping guards against.
                RouteError::WinCommand {
                    program: "route",
                    op: "add gateway pin",
                    detail: "The route addition failed: Access is denied.".into(),
                },
                false,
                "access denied is NOT an exists",
            ),
            (
                RouteError::IpCommand {
                    op: "route add",
                    stderr: "Network is unreachable".into(),
                },
                false,
                "ordinary failure is NOT an exists",
            ),
            (
                RouteError::Spawn(io::Error::other("boom")),
                false,
                "spawn errors never classify as exists",
            ),
            (
                // LOCALIZED NEGATIVE (documented limitation, not a
                // regression): a zh-CN route.exe prints
                // "添加路由失败: 对象已存在。". The text predicate
                // cannot match it, so it falls through to the original
                // error — which is why pin install/revert additionally
                // verify a NUMERIC postcondition (locale cannot lie
                // about digits).
                RouteError::WinCommand {
                    program: "route",
                    op: "add gateway pin",
                    detail: "添加路由失败: 对象已存在。".into(),
                },
                false,
                "localized text intentionally unmatched; numeric probe covers it",
            ),
        ];
        for (err, want, why) in cases {
            assert_eq!(is_route_exists_error(&err), want, "case `{why}`: {err}");
        }
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

        /// Exit 0 but non-empty stderr — exactly the shape route.exe
        /// produces on Windows 11 26100, where *every* failure mode
        /// exits 0 and prints the reason (live-proven: "The route
        /// addition failed: The object already exists." with exit 0).
        fn ok_stderr(stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        /// Route-table `print` output holding no rows — what
        /// `route.exe print -4 <dest>` returns when the destination
        /// has no route (headers only, exit 0).
        fn print_empty() -> Output {
            FakeRunner::ok_stdout(
                "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
===========================================================================
",
            )
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
        // install_gateway_exclude_windows is check-then-act now:
        // discover → numeric pre-probe (absent) → add → numeric
        // post-probe (present) → CREATED recorded.
        let pin_row_stdout = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
      198.51.100.230  255.255.255.255     192.168.1.1   192.168.1.42     35
===========================================================================
Persistent Routes:
  None
";
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                          // addr
            Ok(FakeRunner::ok_stdout(route_print_stdout)), // route.exe print -4 0.0.0.0 (discover)
            Ok(FakeRunner::print_empty()),                 // pre-probe: no pin yet
            Ok(FakeRunner::ok()),                          // route.exe add pin
            Ok(FakeRunner::ok_stdout(pin_row_stdout)),     // post-probe: pin present → Created
            Ok(FakeRunner::ok()),                          // netsh add split route
        ]);
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.168.1.1".into()),
                ownership: PinOwnership::Created,
            })
        );
        let calls = runner.calls.borrow();
        // Index 1 is `route.exe print -4 0.0.0.0` for default-gateway
        // discovery — the fast replacement for the old PowerShell call.
        assert_eq!(calls[1][0], "route.exe");
        assert_eq!(calls[1][1..], ["print", "-4", "0.0.0.0"]);
        // Index 2 is the numeric PRE-probe (check-then-change): the
        // intended triple must be absent before we may claim CREATED.
        assert_eq!(calls[2][1..], ["print", "-4", "198.51.100.230"]);
        // Index 3 is the actual pin install…
        assert_eq!(calls[3][0], "route.exe");
        assert_eq!(
            calls[3][1..],
            [
                "add",
                "198.51.100.230",
                "mask",
                "255.255.255.255",
                "192.168.1.1"
            ]
        );
        // …and index 4 verifies its postcondition numerically.
        assert_eq!(calls[4][1..], ["print", "-4", "198.51.100.230"]);
    }

    /// Pure seam for the localized-text WARN decision: a clean silent
    /// English success (empty output) must NOT warn; a non-English
    /// "already exists" line that `WIN_FAILURE_TEXTS` cannot match must
    /// surface as the residual so install can emit the WARN. (The actual
    /// `tracing::warn!` emission is a documented no-seam residual, like
    /// the heartbeat/INFO assertions elsewhere in this pass.)
    #[test]
    fn localised_add_text_residual_flags_unmatched_output_only() {
        use std::os::windows::process::ExitStatusExt;
        let out = |stdout: &str, stderr: &str| Output {
            status: ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        // Silent success → None → no WARN.
        assert_eq!(localised_add_text_residual(&out("", "")), None);
        assert_eq!(localised_add_text_residual(&out("   \n", "")), None);
        // A localized "already exists" (here French) is invisible to the
        // English table → the residual the WARN keys on.
        assert_eq!(
            localised_add_text_residual(&out(
                "Échec de l'ajout de l'itinéraire : objet déjà présent.",
                ""
            )),
            Some("Échec de l'ajout de l'itinéraire : objet déjà présent.".to_string()),
        );
        // stderr counts too (run_checked consults both streams).
        assert!(localised_add_text_residual(&out("", "Some localized notice")).is_some());
    }

    /// End-to-end at the classification seam: an exit-0 `route.exe add`
    /// whose only output is a localized (non-matching) line is believed
    /// as success by `run_checked` and the numeric post-probe shows the
    /// row present, so install records it CREATED — and the third-party-
    /// in-the-window class is what the WARN documents. We assert the
    /// classification (the WARN itself is subscriber-emitted, no seam).
    #[test]
    fn exit0_add_with_localized_text_is_recorded_created_and_warns() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                             // netsh add address
            Ok(FakeRunner::ok_stdout(GW_TABLE)),              // discover default gateway
            Ok(FakeRunner::print_empty()),                    // numeric pre-probe: absent
            Ok(FakeRunner::ok_stdout("Objet déjà présent.")), // exit 0 + localized failure text
            Ok(FakeRunner::ok_stdout(
                "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
      198.51.100.230  255.255.255.255     192.168.1.1   192.168.1.42     35
",
            )), // numeric post-probe: row present
            Ok(FakeRunner::ok()),                             // (no split routes in pin_config)
        ]);
        let state = apply_with(&runner, &pin_config())
            .expect("exit-0 add + present post-probe installs as Created");
        assert_eq!(
            state.installed_gateway_exclude.map(|p| p.ownership),
            Some(PinOwnership::Created),
            "the localized add is believed (numeric probe present) → Created"
        );
    }

    /// The default-gateway `print` fixture shared by the pin tests: one
    /// 0.0.0.0/0 row via 192.168.1.1 so `discover_default_gateway_win`
    /// resolves without touching a real route table.
    const GW_TABLE: &str = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
===========================================================================
";

    fn pin_config() -> TunConfig {
        TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: None,
            gateway_exclude: Some(Ipv4Addr::new(198, 51, 100, 230)),
            routes: vec![],
            route_conflict: RouteConflictPolicy::default(),
        }
    }

    /// LIVE-PROVEN Windows 11 26100 behaviour: `route.exe` exits 0 on
    /// *every* failure mode, printing e.g. "The route addition failed:
    /// The object already exists." — and it puts that line on STDOUT,
    /// not stderr. The pre-fix `run_checked` keyed only on
    /// `status.success()` and read stderr only, so the lie passed as
    /// success: a `/32` pin that was never installed got recorded and
    /// later deleted at teardown.
    #[test]
    fn exit0_route_add_failure_text_on_stdout_is_not_believed() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // netsh add address
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // route.exe print -4 0.0.0.0 (discovery)
            Ok(FakeRunner::print_empty()),       // numeric pre-probe: pin absent
            Ok(FakeRunner::ok_stdout(
                "The route addition failed: The object already exists.",
            )), // route.exe add pin — EXIT 0 + failure text on stdout
            Ok(FakeRunner::print_empty()),       // post-add probe: still absent
            Ok(FakeRunner::ok()), // rollback: delete address (confirmed error, cleanup may run)
        ]);
        let err = apply_with(&runner, &pin_config()).expect_err(
            "exit-0 + stdout failure text from `route.exe add` must not be believed as success",
        );
        let text = err.to_string();
        assert!(
            text.contains("object already exists"),
            "error must carry the route.exe failure text, got: {text}"
        );
        // And it is an exists-shaped error: the retry/adopt predicate in
        // is_route_exists_error sees it.
        assert!(
            is_route_exists_error(&err),
            "exit-0 'object already exists' must classify as a route-exists error: {text}"
        );
    }

    /// Same class, other stream: exit 0 with the failure text on
    /// stderr. `route.exe` writes some diagnostics to stderr while
    /// still exiting 0 (e.g. `ERROR_FILE_EXISTS` rendered paths on
    /// some builds); success must not be concluded from the code alone.
    #[test]
    fn exit0_route_add_failure_text_on_stderr_is_not_believed() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // netsh add address
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discovery
            Ok(FakeRunner::print_empty()),       // numeric pre-probe
            Ok(FakeRunner::ok_stderr(
                "The route addition failed: The object already exists.",
            )), // route.exe add pin — EXIT 0 + failure text on stderr
            Ok(FakeRunner::print_empty()),       // post-add probe: still absent
            Ok(FakeRunner::ok()), // rollback: delete address (confirmed error, cleanup may run)
        ]);
        let err = apply_with(&runner, &pin_config())
            .expect_err("exit-0 + stderr failure text must not be believed either");
        assert!(is_route_exists_error(&err), "got: {err}");
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
                ownership: PinOwnership::Created,
            }),
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),          // delete route
            Ok(FakeRunner::ok()),          // delete addr
            Ok(FakeRunner::ok()),          // delete gateway pin
            Ok(FakeRunner::print_empty()), // numeric postcondition: pin gone
        ]);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        // The delete is now followed by a NUMERIC postcondition probe:
        // route.exe's exit code is worthless (always 0 on this OS), so
        // "delete gateway pin" only counts once print shows the triple
        // gone.
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0][0], "netsh"); // route
        assert_eq!(calls[1][0], "netsh"); // addr
        assert_eq!(calls[2][0], "route.exe"); // gateway delete…
        assert_eq!(
            calls[2][1..],
            [
                "delete",
                "198.51.100.230",
                "mask",
                "255.255.255.255",
                "192.168.1.1"
            ]
        );
        // …and its verification: same triple, numeric parse.
        assert_eq!(calls[3][1..], ["print", "-4", "198.51.100.230"]);
    }
}

// ---------------------------------------------------------------------------
// Tests — Windows: bounded runner, adopt-vs-create ledger, mutation gating
// ---------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests_windows_runner {
    use super::*;
    use std::cell::RefCell;
    use std::os::windows::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn new(outcomes: Vec<Result<Output, io::Error>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }

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

        fn fail(detail: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: detail.as_bytes().to_vec(),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            let outcome = {
                let mut outcomes = self.outcomes.borrow_mut();
                if outcomes.is_empty() {
                    panic!("FakeRunner: no more outcomes queued (unexpected call): {full:?}");
                }
                outcomes.remove(0)
            };
            self.calls.borrow_mut().push(full);
            outcome
        }
    }

    const GW_TABLE: &str = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
===========================================================================
";

    const PIN_ROW: &str = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
      198.51.100.230  255.255.255.255     192.168.1.1   192.168.1.42     35
===========================================================================
Persistent Routes:
  None
";

    const EMPTY_TABLE: &str = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
===========================================================================
";

    fn print_empty() -> Output {
        FakeRunner::ok_stdout(EMPTY_TABLE)
    }

    fn pin_config() -> TunConfig {
        TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: None,
            gateway_exclude: Some(Ipv4Addr::new(198, 51, 100, 230)),
            routes: vec![],
            route_conflict: RouteConflictPolicy::default(),
        }
    }

    fn unconfirmed_err(program: &str, pid: u32) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            UnconfirmedTermination {
                program: program.into(),
                args: "198.51.100.230 mask 255.255.255.255 192.168.1.1".into(),
                pid,
            },
        )
    }

    // -- numeric route-table probe parser -----------------------------------

    #[test]
    fn parse_route_rows_is_numeric_and_locale_independent() {
        // Column headers translate; the five value columns never do.
        // Only fully-numeric rows parse.
        assert_eq!(parse_route_rows(EMPTY_TABLE), Vec::new());
        let rows = parse_route_rows(PIN_ROW);
        assert_eq!(rows.len(), 1, "one numeric row: {rows:?}");
        let r = &rows[0];
        assert_eq!(r.destination, Ipv4Addr::new(198, 51, 100, 230));
        assert_eq!(r.netmask, Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(r.gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(r.iface, Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(r.metric, 35);

        // A single malformed column (localized `On-link` gateway,
        // non-numeric metric, wrong column count) rejects the row
        // entirely — it is never a partial match.
        assert!(parse_route_rows("  1.2.3.4  255.255.255.255  On-link  1.2.3.4  35").is_empty());
        assert!(
            parse_route_rows("  1.2.3.4  255.255.255.255  9.9.9.9  1.2.3.4  not-a-number")
                .is_empty()
        );
        assert!(parse_route_rows("  1.2.3.4  255.255.255.255  9.9.9.9  1.2.3.4").is_empty());
    }

    #[test]
    fn mutating_command_table() {
        assert!(is_mutating_command(
            "route.exe",
            &["add", "1.2.3.4", "mask", "255.255.255.255", "9.9.9.9"]
        ));
        assert!(is_mutating_command(
            "route.exe",
            &["delete", "1.2.3.4", "mask", "255.255.255.255"]
        ));
        assert!(is_mutating_command("ROUTE.EXE", &["Change", "1.2.3.4"]));
        // Reads are NOT mutations: print output legitimately contains
        // words like "failed" (interface descriptions) and must never
        // be failure-scanned.
        assert!(!is_mutating_command(
            "route.exe",
            &["print", "-4", "0.0.0.0"]
        ));
        assert!(!is_mutating_command(
            "netsh",
            &["interface", "ipv4", "show", "route"]
        ));
        assert!(is_mutating_command(
            "netsh",
            &["interface", "ipv4", "add", "route", "10.0.0.0/8"]
        ));
        assert!(is_mutating_command(
            "netsh",
            &["interface", "ipv4", "delete", "address", "x", "y"]
        ));
        assert!(!is_mutating_command("somebody-else.exe", &["add"]));
        assert!(!is_mutating_command("route.exe", &[]));
    }

    // -- adopt-vs-create ledger roundtrip ------------------------------------

    /// The claim-and-delete defect fixed: when the exact
    /// `(dest, mask, nexthop)` triple is ALREADY in the table, the pin
    /// is ADOPTED — no `route.exe add` is issued and teardown deletes
    /// nothing, because (dest, mask, nexthop) names no interface and a
    /// third party may own that identical row.
    #[test]
    fn pre_existing_pin_is_adopted_never_added_and_survives_teardown() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // netsh add address
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discover default gateway
            Ok(FakeRunner::ok_stdout(PIN_ROW)),  // numeric PRE-probe: already there
        ]);
        let state = apply_with(&runner, &pin_config()).unwrap();
        assert_eq!(
            state.installed_gateway_exclude,
            Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.168.1.1".into()),
                ownership: PinOwnership::Adopted,
            })
        );
        // No `add` was issued at all: exactly three calls.
        let calls = runner.calls();
        assert_eq!(calls.len(), 3, "{calls:#?}");
        assert!(
            !calls
                .iter()
                .any(|c| c.get(1).map(|s| s.as_str()) == Some("add")),
            "adopted pin must not issue route.exe add: {calls:#?}"
        );

        // Teardown of the ADOPTED state issues NO route.exe delete —
        // one queued outcome (the address delete); any extra command
        // makes FakeRunner panic, which IS the assertion.
        let teardown = FakeRunner::new(vec![Ok(FakeRunner::ok())]);
        let errors = revert_with(&teardown, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = teardown.calls();
        assert_eq!(calls.len(), 1, "only the address delete: {calls:#?}");
        assert_eq!(calls[0][0], "netsh");
    }

    /// The mirror case: absent triple → add → numeric postcondition
    /// confirms → CREATED, and teardown deletes exactly that triple
    /// once, then verifies its absence numerically.
    #[test]
    fn created_pin_is_recorded_then_deleted_with_numeric_verify() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // addr
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discover
            Ok(print_empty()),                   // pre-probe: absent
            Ok(FakeRunner::ok()),                // route.exe add pin
            Ok(FakeRunner::ok_stdout(PIN_ROW)),  // post-probe: present → CREATED
        ]);
        let state = apply_with(&runner, &pin_config()).unwrap();
        assert_eq!(
            state.installed_gateway_exclude.as_ref().unwrap().ownership,
            PinOwnership::Created
        );

        let teardown = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // netsh delete address
            Ok(FakeRunner::ok()), // route.exe delete <triple>
            Ok(print_empty()),    // numeric verify: triple gone
        ]);
        let errors = revert_with(&teardown, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = teardown.calls();
        assert_eq!(calls.len(), 3, "{calls:#?}");
        assert_eq!(calls[0][0], "netsh");
        assert_eq!(
            calls[1][1..],
            [
                "delete",
                "198.51.100.230",
                "mask",
                "255.255.255.255",
                "192.168.1.1"
            ]
        );
        assert_eq!(calls[2][1..], ["print", "-4", "198.51.100.230"]);
    }

    /// Race case: `route.exe add` comes back "already exists" (even as
    /// an exit-0 lie) and the probe now shows the triple present. We
    /// cannot prove the row is ours → ADOPTED, teardown leaves it.
    #[test]
    fn add_reports_exists_and_probe_shows_row_classifies_adopted() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // addr
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discover
            Ok(print_empty()),                   // pre-probe: absent
            Ok(FakeRunner::ok_stdout(
                "The route addition failed: The object already exists.",
            )), // add: exit 0 + exists text
            Ok(FakeRunner::ok_stdout(PIN_ROW)),  // post-probe: present
        ]);
        let state = apply_with(&runner, &pin_config()).unwrap();
        assert_eq!(
            state.installed_gateway_exclude.as_ref().unwrap().ownership,
            PinOwnership::Adopted,
            "cannot prove we created it → must not be deletable"
        );
        let teardown = FakeRunner::new(vec![Ok(FakeRunner::ok())]); // addr only
        assert!(revert_with(&teardown, &state).is_empty());
        assert_eq!(
            teardown.calls().len(),
            1,
            "no pin delete: {:?}",
            teardown.calls()
        );
    }

    /// `route.exe add` fails for real (access denied, non-zero) and the
    /// probe shows no row: hard error, and NOTHING is recorded as a pin
    /// (so teardown has nothing to delete — no phantom authority).
    #[test]
    fn hard_add_failure_records_no_pin_and_propagates() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // addr
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discover
            Ok(print_empty()),                   // pre-probe
            Ok(FakeRunner::fail(
                "The route addition failed: Access is denied.",
            )), // add fails
            Ok(print_empty()),                   // post-probe: absent → propagate the add error
            Ok(FakeRunner::ok()),                // rollback: delete address (confirmed failure)
        ]);
        let err = apply_with(&runner, &pin_config()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Access is denied"), "{text}");
        assert!(
            !is_route_exists_error(&err),
            "denied is not an exists error"
        );
    }

    /// add "succeeds" (exit 0, no matching text) but the numeric probe
    /// says the row is NOT there: the exit code lied. Refuse to record
    /// a pin we cannot see — the pre-fix code recorded and later
    /// deleted on this evidence.
    #[test]
    fn silent_success_without_postcondition_row_is_rejected() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                // addr
            Ok(FakeRunner::ok_stdout(GW_TABLE)), // discover
            Ok(print_empty()),                   // pre-probe: absent
            Ok(FakeRunner::ok()),                // add: exit 0, prints nothing
            Ok(print_empty()),                   // post-probe: STILL absent
            Ok(FakeRunner::ok()),                // rollback: delete address
        ]);
        let err = apply_with(&runner, &pin_config()).unwrap_err();
        assert!(
            err.to_string().contains("numeric postcondition"),
            "must name the failed postcondition: {err}"
        );
    }

    // -- unconfirmed-kill gating ---------------------------------------------

    /// A route command killed on timeout whose death is NOT confirmed
    /// must abort apply before rollback: deleting routes beside a live
    /// netsh would interleave with it. The pre-fix code blended the
    /// kill into RouteError::Spawn and rolled back regardless.
    #[test]
    fn unconfirmed_kill_during_apply_refuses_rollback() {
        let config = TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1400),
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // mtu
            Ok(FakeRunner::ok()), // addr
            Err(unconfirmed_err("netsh", 4321)), // route add: killed, UNCONFIRMED
                                  // If rollback were attempted (delete address / delete
                                  // route), FakeRunner panics with "no more outcomes" —
                                  // that panic IS the red this test showed pre-fix.
        ]);
        let err = apply_with(&runner, &config).unwrap_err();
        match &err {
            RouteError::UnconfirmedTermination { program, pid, op } => {
                assert_eq!(*pid, 4321);
                assert_eq!(program, "netsh");
                assert_eq!(*op, "add route");
                assert!(err.to_string().contains("NOT delete"), "{err}");
            }
            other => panic!("unconfirmed kill must surface as its own error: {other:?}"),
        }
        // Exactly the three commands issued; zero delete/retry commands.
        assert_eq!(runner.calls().len(), 3, "{:?}", runner.calls());
    }

    /// The same gate in revert: the first unconfirmed delete must stop
    /// the whole teardown walk, not be collected and plough on.
    #[test]
    fn unconfirmed_kill_during_revert_stops_the_walk() {
        let state = AppliedState {
            ifname: "OpenProtect".into(),
            installed_routes: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
            installed_addr: Some(Ipv4Addr::new(10, 1, 2, 3)),
            installed_gateway_exclude: Some(GatewayPinState {
                ip: Ipv4Addr::new(198, 51, 100, 230),
                prior_entry: Some("192.168.1.1".into()),
                ownership: PinOwnership::Created,
            }),
        };
        let runner = FakeRunner::new(vec![
            Err(unconfirmed_err("netsh", 99)), // first delete route: UNCONFIRMED
                                               // addr delete, second route delete, pin delete, pin verify
                                               // must NOT be attempted.
        ]);
        let errors = revert_with(&runner, &state);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("pid 99"), "{errors:?}");
        assert_eq!(
            runner.calls().len(),
            1,
            "walk must stop: {:?}",
            runner.calls()
        );
    }

    /// A *confirmed* timeout keeps the old contract: ordinary
    /// ErrorKind::TimedOut, no unconfirmed payload, so rollback/removal
    /// paths remain authorised to proceed.
    #[test]
    fn confirmed_timeout_keeps_ordinary_timeout_error_and_rollback_runs() {
        let config = TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: None,
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // addr
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "did not exit within …",
            )), // confirmed kill
            Ok(FakeRunner::ok()), // rollback: delete address — allowed, child is dead
        ]);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, RouteError::Spawn(_)), "{err:?}");
        assert!(!err.blocks_further_mutation());
        assert_eq!(runner.calls().len(), 3, "{:?}", runner.calls());
    }

    // -- netsh exit-0 already-exists retry (467bf28 class, Windows side) -----

    /// netsh `add route` that exits 0 while printing "The object
    /// already exists." must now be treated as the same EEXIST class
    /// the scoped-retry path was written for — the pre-fix text-blind
    /// run_checked believed it as success and never retried.
    #[test]
    fn exit0_netsh_already_exists_earns_the_scoped_retry() {
        let config = TunConfig {
            ifname: "OpenProtect".into(),
            ipv4: None,
            mtu: None,
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into()],
            route_conflict: RouteConflictPolicy::default(),
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok_stdout("The object already exists.")), // add route: exit 0 + wording
            Ok(FakeRunner::ok()), // delete stale same-interface entry
            Ok(FakeRunner::ok()), // add route, retry — succeeds
        ]);
        let state = apply_with(&runner, &config).unwrap();
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8"]);
        let calls = runner.calls();
        assert_eq!(calls.len(), 3, "add → delete → add: {calls:#?}");
        assert_eq!(calls[1][1..4], ["interface", "ipv4", "delete"]);
    }

    // -- read-only print is never failure-scanned ----------------------------

    /// Interface-list descriptions are operator-chosen strings that can
    /// contain anything, including route.exe failure wording. The text
    /// scan is scoped to MUTATING commands, so a poisoned-looking
    /// `print` still works.
    #[test]
    fn discovery_print_with_failure_looking_text_is_not_scanned() {
        let tainted = "\
===========================================================================
Interface List
 14...01 23 45 67 89 ab ......The route addition failed: The object already exists.
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.42     35
===========================================================================
";
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),               // addr
            Ok(FakeRunner::ok_stdout(tainted)), // discovery print — NOT scanned
            Ok(print_empty()),                  // pre-probe
            Ok(FakeRunner::ok()),               // add pin
            Ok(FakeRunner::ok_stdout(PIN_ROW)), // post-probe: present
        ]);
        let state = apply_with(&runner, &pin_config()).unwrap();
        assert_eq!(
            state.installed_gateway_exclude.as_ref().unwrap().ownership,
            PinOwnership::Created
        );
    }

    // -- discovery bypass closure --------------------------------------------

    /// Audit item 4: default-gateway discovery used to call
    /// `runner.run` directly. It must go through the checked path so a
    /// non-zero print or an unconfirmed kill there propagates as the
    /// same distinct errors instead of a raw io::Error through `?`.
    #[test]
    fn discovery_runs_through_the_checked_path() {
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()), // addr
            Err(unconfirmed_err("route.exe", 7)), // wedged print during DISCOVERY
                                  // install must bail BEFORE attempting the pin add:
        ]);
        let err = apply_with(&runner, &pin_config()).unwrap_err();
        assert!(
            matches!(err, RouteError::UnconfirmedTermination { pid: 7, .. }),
            "{err:?}"
        );
        assert_eq!(
            runner.calls().len(),
            2,
            "no pin add after dead discovery: {:?}",
            runner.calls()
        );
    }

    // -- run_with_timeout against real processes ------------------------------

    /// The drain fix: a child producing more than the OS pipe buffer
    /// could never exit while the pre-fix runner polled without
    /// reading (child blocked on a full pipe, `try_wait` never observed
    /// exit, the command died on its own timeout with ALL output lost).
    /// Draining concurrently from child start makes large output a
    /// success.
    #[test]
    fn run_with_timeout_drains_output_larger_than_the_pipe_buffer() {
        // 512 KiB well exceeds the ~4-8 KiB Windows pipe buffer.
        let size = 512 * 1024;
        let path = std::env::temp_dir().join(format!(
            "gp-route-drain-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&vec![b'a'; size]).unwrap();
            f.flush().unwrap();
        }
        let out = run_with_timeout(
            "cmd.exe",
            &["/c", "type", path.to_str().unwrap()],
            Duration::from_secs(5),
        );
        let _ = std::fs::remove_file(&path);
        let out = out.expect("large-output command must drain concurrently, not time out");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), size, "every byte must arrive");
    }

    /// The EOF wedge fix: the immediate child exits but a surviving
    /// grandchild holds the inherited write handle, so the pipes never
    /// reach EOF. The pre-fix `wait_with_output()` after `try_wait`
    /// (old :233) read FOREVER. The runner must return within a bounded
    /// time of the child's exit, with the status it earned.
    #[test]
    fn run_with_timeout_bounded_when_grandchild_holds_pipes_open() {
        // cmd exits promptly; the started ping lives ~20 s holding the
        // inherited stdout handle. The runner's own timeout is
        // deliberately far larger than the bound under test.
        let total = Duration::from_secs(30);
        let started = Instant::now();
        let handle = std::thread::spawn(move || {
            run_with_timeout(
                "cmd.exe",
                &[
                    "/c",
                    "start",
                    "/b",
                    "ping",
                    "-n",
                    "20",
                    "127.0.0.1",
                    "&&",
                    "exit",
                    "0",
                ],
                total,
            )
        });
        let out = handle
            .join()
            .expect("runner thread")
            .expect("cmd exits quickly and must be reported as success");
        let elapsed = started.elapsed();
        // The bound under test: EOF_GRACE (1 s) + scheduling slack —
        // NOT the ping lifetime (~20 s) the pre-fix code blocked on.
        assert!(
            elapsed < Duration::from_secs(8),
            "runner blocked {elapsed:?} — the EOF read is unbounded again"
        );
        assert!(out.status.success());
    }

    /// Confirmed-kill timeout keeps the documented contract:
    /// ErrorKind::TimedOut with the old message shape, so callers that
    /// already special-cased it keep working.
    #[test]
    fn run_with_timeout_confirms_kill_before_reporting_timed_out() {
        let out = run_with_timeout(
            "ping.exe",
            &["-n", "30", "127.0.0.1"],
            Duration::from_millis(400),
        );
        let err = out.expect_err("long-running ping must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            !is_unconfirmed_termination(&err),
            "kill confirms quickly: {err}"
        );
        assert!(err.to_string().contains("did not exit within"), "{err}");
    }

    /// A program that does not exist must fail as an ordinary spawn
    /// error — never a hang, never an unconfirmed signal.
    #[test]
    fn run_with_timeout_missing_program_is_an_error_not_a_hang() {
        let started = Instant::now();
        let err = run_with_timeout(
            "definitely-not-a-real-program-9c1f.exe",
            &[],
            Duration::from_secs(5),
        )
        .expect_err("missing program must error");
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(!is_unconfirmed_termination(&err));
    }
}

// ---------------------------------------------------------------------------
// Tests — Linux: commit 467bf28 semantics, pinned as UNCHANGED
// ---------------------------------------------------------------------------
//
// The adversarial review banned porting 467bf28's Linux semantics onto
// Windows blindly; this module is the guard rail in the other
// direction: the Linux behaviour this fix must NOT disturb. It runs on
// the Linux CI (it cannot be observed green from a Windows host — said
// so plainly in the work report, not faked).

#[cfg(all(test, target_os = "linux"))]
mod tests_linux_467bf28_unchanged {
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

    const DOCKER: &str = "172.20.0.0/16 dev br-81f0638ae4fb proto kernel scope link src 172.20.0.1";

    /// 467bf28's contract, re-pinned after this change: `ip route add`
    /// is the EXCLUSIVE fast path; EEXIST — and only EEXIST — earns the
    /// capture-prior → `replace` takeover; anything else fails fast
    /// without touching the table. `add` staying exclusive (rather than
    /// everything becoming `replace`) is what makes `prior` mean a real
    /// displacement: the kernel decides, and revert only resurrects
    /// what we actually took.
    #[test]
    fn eexist_takeover_sequence_is_unchanged() {
        let config = TunConfig {
            ifname: "tun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1422),
            gateway_exclude: None,
            routes: vec!["172.20.0.0/16".into()],
            route_conflict: RouteConflictPolicy::TakeOver,
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                                  // link up
            Ok(FakeRunner::ok()),                                  // mtu
            Ok(FakeRunner::ok()),                                  // addr add
            Ok(FakeRunner::err("RTNETLINK answers: File exists")), // route add → EEXIST
            Ok(FakeRunner::ok_stdout(&format!("{DOCKER}\n"))),     // route show exact
            Ok(FakeRunner::ok()),                                  // route replace
        ]);
        let state = apply_with(&runner, &config).unwrap();
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 6);
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
        drop(calls);
        assert_eq!(state.installed_routes[0].prior, vec![DOCKER.to_string()]);
        assert!(state.installed_routes[0].displaced());
    }

    /// A non-EEXIST route failure must NOT capture or replace
    /// (pre-existing fail-fast), and rollback must run exactly as
    /// before — i.e. the unconfirmed-gate added for Windows-shaped
    /// kills must not alter the Linux path for ordinary errors.
    #[test]
    fn ordinary_failure_fail_fast_and_rollback_are_unchanged() {
        let config = TunConfig {
            ifname: "tun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: None,
            gateway_exclude: None,
            routes: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
            route_conflict: RouteConflictPolicy::TakeOver,
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),                          // link up
            Ok(FakeRunner::ok()),                          // addr add
            Ok(FakeRunner::ok()),                          // route add 10.0.0.0/8
            Ok(FakeRunner::err("Network is unreachable")), // route add 172.16.0.0/12 fails
            Ok(FakeRunner::ok()), // rollback: route del 10.0.0.0/8 (dev-scoped)
            Ok(FakeRunner::ok()), // rollback: addr del
        ]);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(
            matches!(
                err,
                RouteError::IpCommand {
                    op: "route add",
                    ..
                }
            ),
            "{err:?}"
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 6, "no capture/replace attempts: {calls:#?}");
        assert_eq!(
            calls[3],
            vec!["ip", "-4", "route", "add", "172.16.0.0/12", "dev", "tun7"]
        );
        assert_eq!(
            calls[4],
            vec!["ip", "-4", "route", "del", "10.0.0.0/8", "dev", "tun7"]
        );
        // No "show exact"/"replace" was ever issued:
        assert!(!calls.iter().any(|c| c.iter().any(|a| a == "replace")));
        assert!(!calls.iter().any(|c| c.iter().any(|a| a == "show")));
    }
}
