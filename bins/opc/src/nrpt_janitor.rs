//! NRPT janitor: an out-of-process guard that clears this instance's
//! Windows NRPT DNS rules when `opc connect` dies *without* running any
//! of its in-process cleanup.
//!
//! ## Why in-process cleanup is not enough (issue #56)
//!
//! Every teardown path that lives inside `opc.exe` needs the process to
//! still execute code at the moment it dies:
//!
//! * cooperative cancel (Ctrl-C, `opc disconnect`) → the linear revert
//!   in `run_tunnel`;
//! * wedge after a cancel → `exit_wedged`;
//! * console close / logoff / shutdown / panic / unlistened Ctrl-C →
//!   `crash_cleanup`.
//!
//! None of them run when the process is simply *terminated*: Task
//! Manager "End task", `Stop-Process`, `taskkill /F` (the GUI's old
//! Cancel button), an access violation inside libopenconnect's C code
//! (a Rust panic hook never sees an SEH exception), a stack overflow or
//! an abort. The catch-all `.` rule installed for a `--only` session
//! with no split-DNS zones then survives in
//! `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`
//! and routes **every** DNS query on the machine to the now-unreachable
//! VPN resolvers — the "DNS resolution fails after OpenProtect exits"
//! report. Until this module the only recoveries were the next
//! `opc connect`, `opc recover`, or a manual registry edit.
//!
//! ## Mechanism
//!
//! Right after gp-dns installs an NRPT rule, `spawn_once` starts a
//! second, hidden `opc.exe nrpt-janitor …` process that:
//!
//! 1. opens a `SYNCHRONIZE` handle on the parent PID and verifies the
//!    process creation time matches the one the parent passed in (so a
//!    recycled PID is never mistaken for the parent);
//! 2. blocks in `WaitForSingleObject` until the parent exits — for ANY
//!    reason, including `TerminateProcess`;
//! 3. probes the instance's control pipe. If no session answers
//!    (`Liveness::Absent`), it runs the same instance-scoped sweep as
//!    `opc recover` — registry delete + `DnsCache` paramchange, no
//!    PowerShell. If a session *does* answer (a new `opc connect` of
//!    the same instance already took over the pipe) or the probe is
//!    inconclusive, it does nothing: uncertainty is never read as
//!    absence, and that session's own revert is responsible for its
//!    rules.
//!
//! On a clean exit the parent has already reverted its rules, so the
//! janitor's sweep deletes nothing and only re-pings `DnsCache` — the
//! same idempotent primitive the pre-connect sweep uses.
//!
//! The janitor is spawned with `CREATE_NO_WINDOW` and null stdio: it is
//! not attached to the parent's console (so Ctrl-C and the console's
//! close do not reach it) and it holds no inherited pipe the parent's
//! launcher is waiting on. It does not survive `taskkill /T` — a
//! tree-kill terminates children first — which is why the GUI's Cancel
//! no longer tree-kills (it asks for a cooperative disconnect, then
//! single-process kills, then runs `opc recover`).
//!
//! Windows-only: NRPT does not exist elsewhere, and the Unix backends
//! have no equivalent catch-all hazard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use gp_ipc::Liveness;

/// The parent's `--log` / `--log-file` so the janitor logs where the
/// session logged (a `--log-file` is the only place its "swept N
/// rules" line can ever be read: stderr is null).
static LOG_SINK: OnceLock<(String, Option<String>)> = OnceLock::new();

/// One janitor per `opc connect` process. It waits on the *process*,
/// so a reconnect loop that re-applies NRPT per attempt still needs
/// only the one guard.
static SPAWNED: AtomicBool = AtomicBool::new(false);

/// Record the logging flags the parent was started with. Called once
/// from `main` after tracing init; harmless if never called (the
/// janitor then logs at `info` to nowhere).
pub fn remember_log_sink(level: &str, file: Option<&str>) {
    let _ = LOG_SINK.set((level.to_string(), file.map(String::from)));
}

/// Spawn the janitor for `instance` if this process has not already.
/// Best-effort: a spawn failure is logged, never fatal — the in-process
/// cleanup paths still cover everything they covered before.
pub fn spawn_once(instance: &str) {
    if SPAWNED.swap(true, Ordering::SeqCst) {
        return;
    }
    match spawn(instance) {
        Ok(pid) => tracing::info!(
            "nrpt-janitor: spawned guard process PID {pid} for instance {instance} — it clears \
             this instance's NRPT rules if opc is terminated without cleanup"
        ),
        Err(e) => tracing::warn!(
            "nrpt-janitor: could not spawn guard process ({e}); a hard kill of this opc \
             will leave its NRPT rules behind until the next `opc connect` or `opc recover`"
        ),
    }
}

fn spawn(instance: &str) -> Result<u32, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let parent_pid = std::process::id();
    let parent_start = own_creation_time().ok_or("GetProcessTimes on self failed")?;
    let sink = LOG_SINK
        .get()
        .cloned()
        .unwrap_or_else(|| ("info".into(), None));
    let args = build_args(instance, parent_pid, parent_start, &sink);

    let mut cmd = Command::new(&exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Not attached to our console: the console's Ctrl-C and close
        // must not take the guard down with the session.
        .creation_flags(CREATE_NO_WINDOW);
    if let Some(dir) = exe.parent() {
        // Same reason as the GUI's launcher: libopenconnect-5.dll and
        // friends sit next to opc.exe, and our CWD may be anywhere.
        cmd.current_dir(dir);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", exe.display()))?;
    // Dropping the handle does not kill the child on Windows; the
    // janitor is meant to outlive us.
    Ok(child.id())
}

/// The argv handed to the janitor. Global flags first (`--log`,
/// `--log-file` are `global = true` on the clap tree, so they parse in
/// either position; leading keeps them visually separate from the
/// subcommand's own identity flags).
fn build_args(
    instance: &str,
    parent_pid: u32,
    parent_start: u64,
    (log_level, log_file): &(String, Option<String>),
) -> Vec<String> {
    let mut args = vec!["--log".to_string(), log_level.clone()];
    if let Some(f) = log_file {
        args.push("--log-file".to_string());
        args.push(f.clone());
    }
    args.extend([
        "nrpt-janitor".to_string(),
        "--instance".to_string(),
        instance.to_string(),
        "--parent-pid".to_string(),
        parent_pid.to_string(),
        "--parent-start".to_string(),
        parent_start.to_string(),
    ]);
    args
}

/// Our own process creation time as a FILETIME `u64` — the identity
/// token that lets the janitor tell us apart from a later process that
/// inherited our PID.
fn own_creation_time() -> Option<u64> {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: the pseudo-handle is always valid for the calling process.
    unsafe { creation_time_of(GetCurrentProcess()) }
}

/// `GetProcessTimes` creation time of `handle`, packed as `u64`.
///
/// # Safety
/// `handle` must be a valid process handle with
/// `PROCESS_QUERY_LIMITED_INFORMATION` access.
unsafe fn creation_time_of(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let mut creation: FILETIME = std::mem::zeroed();
    let mut exit: FILETIME = std::mem::zeroed();
    let mut kernel: FILETIME = std::mem::zeroed();
    let mut user: FILETIME = std::mem::zeroed();
    if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) == 0 {
        return None;
    }
    Some(filetime_to_u64(
        creation.dwHighDateTime,
        creation.dwLowDateTime,
    ))
}

fn filetime_to_u64(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

/// How the wait on the parent ended.
#[derive(Debug, PartialEq, Eq)]
enum ParentFate {
    /// We held a verified handle and it became signaled: the parent is
    /// gone.
    Exited,
    /// We never got to wait: the PID could not be opened, or it belongs
    /// to a different (newer) process. Either way the parent is gone —
    /// it died between spawning us and our first syscall.
    AlreadyGone(&'static str),
}

/// Block until the process `pid` (started at `expected_start`) exits.
fn wait_for_parent(pid: u32, expected_start: u64) -> ParentFate {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    // SAFETY: plain Win32 calls on a handle we own and close.
    unsafe {
        let handle = OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if handle.is_null() {
            return ParentFate::AlreadyGone("OpenProcess failed (no such process)");
        }
        // A `None` here (GetProcessTimes failed) is treated as "it's the
        // parent": we opened the exact PID we were handed within
        // milliseconds of being spawned, and waiting on the real parent
        // is the safe default — the failure mode of a wrong guess is a
        // guard that waits on a stranger, never a wrongful sweep (the
        // sweep is still liveness-gated).
        if let Some(actual) = creation_time_of(handle) {
            if !parent_identity_matches(expected_start, actual) {
                CloseHandle(handle);
                return ParentFate::AlreadyGone("PID reused by a newer process");
            }
        }
        // INFINITE: there is nothing else for this process to do. If
        // the parent is wedged in a kernel wait it is still *alive* and
        // its rules are still legitimately its own.
        let rc = WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
        if rc == WAIT_OBJECT_0 {
            ParentFate::Exited
        } else {
            // WAIT_FAILED / abandoned — cannot happen for a process
            // handle, but never loop on it: treat as gone and let the
            // liveness probe decide.
            ParentFate::AlreadyGone("WaitForSingleObject did not signal")
        }
    }
}

/// PID-reuse guard: the process behind the PID is our parent only if
/// its creation time is the one the parent reported about itself.
fn parent_identity_matches(expected_start: u64, actual_start: u64) -> bool {
    expected_start == actual_start
}

/// What the janitor does once the parent is gone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nobody owns the instance's rules any more: sweep them.
    Sweep,
    /// Leave the rules alone, for the given reason.
    Skip(&'static str),
}

/// The one decision this process makes. Pure so it is pinned by tests:
/// only a *confirmed-absent* control pipe licenses the sweep.
pub(crate) fn verdict(pipe: &Liveness) -> Verdict {
    match pipe {
        Liveness::Absent => Verdict::Sweep,
        Liveness::Alive => Verdict::Skip(
            "a live session answers on this instance's control pipe (a new `opc connect` \
             took over); its own revert owns the rules",
        ),
        Liveness::Unknown => Verdict::Skip(
            "the control-pipe probe was inconclusive (busy/denied/timed out); refusing to \
             sweep on uncertainty — run `opc recover` as Administrator if DNS is broken",
        ),
    }
}

/// `opc nrpt-janitor` entry point. Returns only after the parent has
/// exited and the sweep decision has been acted on.
pub async fn run(instance: String, parent_pid: u32, parent_start: u64) -> anyhow::Result<()> {
    tracing::info!(
        "nrpt-janitor: guarding instance {instance} for opc PID {parent_pid} \
         (start {parent_start})"
    );
    // The blocking wait must not sit on a tokio worker: it is the whole
    // job, so give it a plain thread and await the result.
    let fate = tokio::task::spawn_blocking(move || wait_for_parent(parent_pid, parent_start))
        .await
        .map_err(|e| anyhow::anyhow!("janitor wait task failed: {e}"))?;
    match &fate {
        ParentFate::Exited => tracing::info!("nrpt-janitor: opc PID {parent_pid} has exited"),
        ParentFate::AlreadyGone(why) => tracing::info!(
            "nrpt-janitor: opc PID {parent_pid} was already gone before the wait began ({why})"
        ),
    }

    let pipe = gp_ipc::probe_liveness(&gp_ipc::endpoint_for(&instance)).await;
    match verdict(&pipe) {
        Verdict::Skip(why) => {
            tracing::info!("nrpt-janitor: not sweeping instance {instance}: {why}");
        }
        Verdict::Sweep => match gp_dns::cleanup_stale_windows_nrpt(&instance) {
            Ok(0) => tracing::info!(
                "nrpt-janitor: instance {instance} left no NRPT rules behind (clean exit); \
                 DnsCache re-notified"
            ),
            Ok(n) => tracing::warn!(
                "nrpt-janitor: opc PID {parent_pid} died without cleanup — removed {n} leaked \
                 NRPT rule(s) for instance {instance}; DNS restored"
            ),
            Err(e) => tracing::error!(
                "nrpt-janitor: NRPT sweep for instance {instance} failed: {e}; run \
                 `opc recover` as Administrator"
            ),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_confirmed_absent_pipe_licenses_the_sweep() {
        assert_eq!(verdict(&Liveness::Absent), Verdict::Sweep);
        assert!(matches!(verdict(&Liveness::Alive), Verdict::Skip(_)));
        // The uncertainty rule shared with `opc recover` and the
        // pre-connect sweep: Unknown is never collapsed into Absent.
        assert!(matches!(verdict(&Liveness::Unknown), Verdict::Skip(_)));
    }

    #[test]
    fn argv_carries_identity_and_the_parents_log_sink() {
        let args = build_args("work", 4242, 0x1234_5678_9abc_def0, &("debug".into(), None));
        assert_eq!(
            args,
            vec![
                "--log",
                "debug",
                "nrpt-janitor",
                "--instance",
                "work",
                "--parent-pid",
                "4242",
                "--parent-start",
                "1311768467463790320",
            ]
        );
        let with_file = build_args(
            "default",
            1,
            2,
            &("info".into(), Some(r"D:\logs\opc.log".into())),
        );
        assert_eq!(
            &with_file[..4],
            ["--log", "info", "--log-file", r"D:\logs\opc.log"]
        );
        assert_eq!(with_file[4], "nrpt-janitor");
    }

    #[test]
    fn pid_reuse_is_detected_by_creation_time() {
        assert!(parent_identity_matches(100, 100));
        assert!(!parent_identity_matches(100, 101));
        assert_eq!(filetime_to_u64(1, 2), (1u64 << 32) | 2);
    }

    #[test]
    fn own_creation_time_is_readable() {
        // Exercised for real: the parent must be able to stamp itself,
        // or `spawn` can never start a guard.
        assert!(own_creation_time().is_some());
    }

    #[test]
    fn waiting_on_a_dead_pid_returns_without_blocking() {
        // A PID that cannot be opened must not hang the guard: it means
        // the parent died before we got here, and the sweep decision
        // still has to run.
        let fate = wait_for_parent(u32::MAX - 1, 0);
        assert!(matches!(fate, ParentFate::AlreadyGone(_)), "{fate:?}");
    }

    #[test]
    fn a_live_process_with_the_wrong_start_time_is_not_the_parent() {
        // Our own PID is certainly alive; with a bogus expected start
        // time the identity check must refuse to wait on it (otherwise
        // this test would block forever — INFINITE wait on ourselves).
        let fate = wait_for_parent(std::process::id(), 0);
        assert_eq!(
            fate,
            ParentFate::AlreadyGone("PID reused by a newer process")
        );
    }
}
