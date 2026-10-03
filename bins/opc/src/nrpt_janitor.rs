//! NRPT janitor: an out-of-process guard that clears the Windows NRPT
//! DNS rules *this process* wrote when `opc connect` dies without
//! running any of its in-process cleanup.
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
//! Every NRPT key this process writes carries its *incarnation token*
//! ([`session_token`]: PID + creation time, hex) in its name:
//! `openprotect-<instance>-<token>-<random>`. Right *before* gp-dns
//! writes the first one (the write precedes a DnsCache notification
//! the SCM can hold for seconds — a kill in that window must already
//! be covered), `spawn_once` starts a second, hidden
//! `opc.exe nrpt-janitor …` process that:
//!
//! 1. opens a `SYNCHRONIZE` handle on the parent PID and verifies the
//!    process creation time matches the one the parent passed in (so a
//!    recycled PID is never mistaken for the parent);
//! 2. blocks in `WaitForSingleObject` until the parent exits — for ANY
//!    reason, including `TerminateProcess`;
//! 3. sweeps `openprotect-<instance>-<token>-*` (registry delete +
//!    `DnsCache` paramchange, no PowerShell) and exits.
//!
//! The token is what makes this safe without any liveness probe or
//! snapshot timing: no other process ever writes under it. A
//! replacement `opc connect` of the same instance — started before,
//! during or after the sweep, descheduling notwithstanding — writes
//! under its own token and is never touched. The instance-scoped
//! sweeps (`opc recover`, the pre-connect sweep) still see every
//! incarnation's keys, because the instance prefix is a prefix of the
//! owner prefix.
//!
//! On a clean exit the parent has already reverted its rules, so the
//! sweep matches nothing and only re-pings `DnsCache` — the same
//! idempotent primitive the pre-connect sweep uses.
//!
//! The janitor is spawned with `CREATE_NO_WINDOW`, null stdio and with
//! the parent's own std handles marked non-inheritable first: it is
//! not attached to the parent's console (so Ctrl-C and the console's
//! close do not reach it) and it holds no inherited pipe the parent's
//! launcher (the GUI's stderr reader) is waiting on. It announces
//! itself through a named event — trusted by `wintun_cleanup`'s
//! "another opc.exe is running" check only if the event carries a High
//! mandatory integrity label, which a same-user medium-integrity
//! process cannot put on any object it creates. It does not survive `taskkill /T` — a tree-kill
//! terminates children first — which is why the GUI's Cancel no longer
//! tree-kills (it asks for a cooperative disconnect, then
//! single-process kills).
//!
//! Windows-only: NRPT does not exist elsewhere, and the Unix backends
//! have no equivalent catch-all hazard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HANDLE;

/// The parent's `--log` / `--log-file` so the janitor logs where the
/// session logged (a `--log-file` is the only place its "swept N
/// rules" line can ever be read: stderr is null).
static LOG_SINK: OnceLock<(String, Option<String>)> = OnceLock::new();

/// One janitor per `opc connect` process. It waits on the *process*,
/// so a reconnect loop that re-applies NRPT per attempt still needs
/// only the one guard. Cleared again if the spawn fails, so the next
/// attempt retries.
static SPAWNED: AtomicBool = AtomicBool::new(false);

/// This process's incarnation token, minted once.
static SESSION_TOKEN: OnceLock<String> = OnceLock::new();

/// `SYNCHRONIZE` / `READ_CONTROL` standard access rights (winnt.h).
/// Spelled out rather than imported: windows-sys scatters them across
/// feature modules.
const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;

/// Security descriptor the janitor creates its identity event with: a
/// High mandatory integrity label (`HI`), no-write-up. Only the SACL
/// label is specified, so the DACL stays the creator token's default
/// (SYSTEM, Administrators, the logon session) and every elevated opc
/// can open the event.
const JANITOR_EVENT_SDDL: &str = "S:(ML;;NW;;;HI)";
/// `SDDL_REVISION_1` (sddl.h).
const SDDL_REVISION_1: u32 = 1;

/// Record the logging flags the parent was started with. Called once
/// from `main` after tracing init; harmless if never called (the
/// janitor then logs at `info` to nowhere).
pub fn remember_log_sink(level: &str, file: Option<&str>) {
    let _ = LOG_SINK.set((level.to_string(), file.map(String::from)));
}

/// The token this process writes its NRPT keys under: PID and the low
/// 32 bits of the process creation time, lowercase hex. Unique per
/// process incarnation (a reused PID has a different creation time),
/// deterministic, and well-formed for gp-dns (`[0-9a-f]`, ≤ 32 chars).
pub fn session_token() -> &'static str {
    SESSION_TOKEN.get_or_init(|| {
        let pid = std::process::id();
        let start_lo = own_creation_time().unwrap_or(0) as u32;
        format!("{pid:x}{start_lo:08x}")
    })
}

/// Spawn the janitor for `instance` if this process has not already.
/// Best-effort: a spawn failure is logged, never fatal — the in-process
/// cleanup paths still cover everything they covered before — and the
/// next NRPT apply retries.
pub fn spawn_once(instance: &str) {
    if SPAWNED.swap(true, Ordering::SeqCst) {
        return;
    }
    match spawn(instance) {
        Ok(pid) => tracing::info!(
            "nrpt-janitor: spawned guard process PID {pid} for instance {instance} (token \
             {}) — it clears this process's NRPT rules if opc is terminated without cleanup",
            session_token()
        ),
        Err(e) => {
            SPAWNED.store(false, Ordering::SeqCst);
            tracing::warn!(
                "nrpt-janitor: could not spawn guard process ({e}); a hard kill of this opc \
                 will leave its NRPT rules behind until the next `opc connect` or `opc recover` \
                 (will retry on the next NRPT apply)"
            );
        }
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
    let args = build_args(instance, parent_pid, parent_start, session_token(), &sink);

    // `Stdio::null()` only sets the child's OWN std handles; std's
    // CreateProcessW still passes bInheritHandles=TRUE, so every
    // inheritable handle we hold leaks into the child as a stray. Our
    // stderr is one when a launcher (the GUI) gave us a pipe — the
    // launcher reads it to EOF to detect our exit, and a janitor
    // holding the write end would stall that until *it* exits. Strip
    // the flag on our std handles first; std re-duplicates them with
    // inherit=true for any later `Stdio::inherit()` child, so nothing
    // else changes. (Other inheritable handles — none known: tokio's
    // pipes, std's files and Wintun's handles are all created
    // non-inheritable.)
    make_std_handles_non_inheritable();

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

/// Clear `HANDLE_FLAG_INHERIT` on this process's stdin/stdout/stderr.
/// Best-effort; a failure (closed/invalid std handle) is simply left
/// as is.
fn make_std_handles_non_inheritable() {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle never fails in a way that matters here
        // (NULL / INVALID_HANDLE_VALUE just make SetHandleInformation
        // return FALSE, which we ignore).
        unsafe {
            let h = GetStdHandle(id);
            let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

/// The argv handed to the janitor. Global flags first (`--log`,
/// `--log-file` are `global = true` on the clap tree, so they parse in
/// either position; leading keeps them visually separate from the
/// subcommand's own identity flags).
fn build_args(
    instance: &str,
    parent_pid: u32,
    parent_start: u64,
    owner_token: &str,
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
        "--owner-token".to_string(),
        owner_token.to_string(),
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
unsafe fn creation_time_of(handle: HANDLE) -> Option<u64> {
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

// ---------------------------------------------------------------------------
// Identity event: "this opc.exe is only a janitor"
// ---------------------------------------------------------------------------

/// Name of the per-process event a running janitor holds open.
///
/// The NAME proves nothing by itself: creating a `Global\` event needs
/// no privilege (only file mappings and symbolic links do), so a
/// same-user medium-integrity process could pre-create it for a real
/// session's PID. What cannot be forged is the object's mandatory
/// integrity LABEL: Windows lets a process label an object at most at
/// its own integrity level, so only a High (elevated) or System
/// process can create an event labelled `HI`. The janitor only ever
/// runs elevated (NRPT itself needs elevation) and labels its event
/// `HI` ([`JANITOR_EVENT_SDDL`]); [`is_janitor_pid`] requires the
/// label to be High or System. (The object's OWNER is deliberately not
/// used: an elevated token's default owner is the user on some launch
/// paths and Administrators on others.)
pub(crate) fn identity_event_name(pid: u32) -> String {
    format!(r"Global\openprotect-nrpt-janitor-{pid}")
}

/// `true` if the process `pid` announces itself as an NRPT janitor:
/// its identity event exists AND carries a High/System integrity
/// label. Anything else — including a PID we cannot query, an event we
/// cannot open or read the label of, or an unlabelled/medium event a
/// medium-integrity process created — is "not a janitor", so a real
/// session is never mistaken for one.
pub fn is_janitor_pid(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::OpenEventW;
    let name = wide_z(&identity_event_name(pid));
    // SAFETY: OpenEventW on a NUL-terminated name; the handle is closed
    // right after the owner check.
    unsafe {
        let h = OpenEventW(SYNCHRONIZE | READ_CONTROL, 0, name.as_ptr());
        if h.is_null() {
            return false;
        }
        let trusted = label_is_high_or_system(h);
        CloseHandle(h);
        trusted
    }
}

/// The mandatory integrity label of the kernel object behind `handle`
/// is High or System. Read via `LABEL_SECURITY_INFORMATION` (needs only
/// `READ_CONTROL`, unlike the audit SACL) and compared in SDDL form.
///
/// # Safety
/// `handle` must be a valid handle opened with `READ_CONTROL`.
unsafe fn label_is_high_or_system(handle: HANDLE) -> bool {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{ACL, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let rc = GetSecurityInfo(
        handle,
        SE_KERNEL_OBJECT,
        LABEL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut sacl,
        &mut sd,
    );
    if rc != 0 || sd.is_null() {
        if !sd.is_null() {
            LocalFree(sd);
        }
        return false;
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd,
        SDDL_REVISION_1,
        LABEL_SECURITY_INFORMATION,
        &mut text,
        &mut len,
    ) != 0;
    let sddl = if converted && !text.is_null() {
        let n = (0..).take_while(|&i| *text.add(i) != 0).count();
        let t = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text as _);
        t
    } else {
        String::new()
    };
    LocalFree(sd);
    label_sddl_is_elevated(&sddl)
}

/// Pure half of [`label_is_high_or_system`]: the SDDL label part names
/// the High (`HI`) or System (`SI`) level. Medium (`ME`), Low (`LW`),
/// untrusted or no label at all → false.
fn label_sddl_is_elevated(sddl: &str) -> bool {
    sddl.contains(";;;HI)") || sddl.contains(";;;SI)")
}

/// Owning wrapper for the identity event handle, closed on drop. Holds
/// a `usize`, not the raw pointer, so it can live across `.await`s.
struct IdentityEvent(usize);

impl IdentityEvent {
    /// Create our identity event labelled High ([`JANITOR_EVENT_SDDL`])
    /// — exactly what [`is_janitor_pid`] checks for. `None` on failure
    /// (including "we are not High integrity"): the janitor still
    /// works, it is just indistinguishable from a session to the
    /// orphan-adapter sweep.
    fn hold() -> Option<Self> {
        Self::hold_with_sddl(JANITOR_EVENT_SDDL)
    }

    fn hold_with_sddl(sddl: &str) -> Option<Self> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name = wide_z(&identity_event_name(std::process::id()));
        let sddl_w = wide_z(sddl);
        // SAFETY: the SD is produced by the OS from SDDL and freed with
        // LocalFree after CreateEventW has copied what it needs; the
        // event is manual-reset, initially unsignaled — its state is
        // never used, only existence and label.
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };
            let h = CreateEventW(&sa, 1, 0, name.as_ptr());
            LocalFree(psd);
            if h.is_null() {
                None
            } else {
                Some(Self(h as usize))
            }
        }
    }

    /// Test-only: the event with DEFAULT security (no label at all) —
    /// what a forger gets from a plain `CreateEventW(NULL, …)`.
    #[cfg(test)]
    fn hold_unlabelled() -> Option<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name = wide_z(&identity_event_name(std::process::id()));
        // SAFETY: plain CreateEventW with NULL security attributes.
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
        if h.is_null() {
            None
        } else {
            Some(Self(h as usize))
        }
    }
}

impl Drop for IdentityEvent {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: we own the handle and close it exactly once.
        unsafe {
            CloseHandle(self.0 as HANDLE);
        }
    }
}

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Waiting on the parent
// ---------------------------------------------------------------------------

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
        // sweep is scoped to our parent's own token).
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
            // handle, but never loop on it: treat as gone and sweep.
            ParentFate::AlreadyGone("WaitForSingleObject did not signal")
        }
    }
}

/// PID-reuse guard: the process behind the PID is our parent only if
/// its creation time is the one the parent reported about itself.
fn parent_identity_matches(expected_start: u64, actual_start: u64) -> bool {
    expected_start == actual_start
}

/// `opc nrpt-janitor` entry point. Returns only after the parent has
/// exited and its keys have been swept.
pub async fn run(
    instance: String,
    parent_pid: u32,
    parent_start: u64,
    owner_token: String,
) -> anyhow::Result<()> {
    let _identity = IdentityEvent::hold();
    if _identity.is_none() {
        tracing::warn!(
            "nrpt-janitor: could not create the identity event; the orphan-adapter sweep \
             will count this guard as a running session while it lives"
        );
    }
    tracing::info!(
        "nrpt-janitor: guarding instance {instance} (token {owner_token}) for opc PID \
         {parent_pid} (start {parent_start})"
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

    match gp_dns::cleanup_windows_nrpt_owner(&instance, &owner_token) {
        Ok(0) => tracing::info!(
            "nrpt-janitor: opc PID {parent_pid} left no NRPT rules behind (clean exit); \
             DnsCache re-notified"
        ),
        Ok(n) => tracing::warn!(
            "nrpt-janitor: opc PID {parent_pid} died without cleanup — removed {n} leaked \
             NRPT rule(s) (instance {instance}, token {owner_token}); DNS restored"
        ),
        Err(e) => tracing::error!(
            "nrpt-janitor: NRPT sweep for instance {instance} (token {owner_token}) failed: \
             {e}; run `opc recover` as Administrator"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_is_hex_stable_and_derived_from_this_process() {
        let t = session_token();
        assert!(!t.is_empty() && t.len() <= 32, "{t}");
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{t}"
        );
        assert_eq!(t, session_token(), "minted once");
        assert!(
            t.starts_with(&format!("{:x}", std::process::id())),
            "token {t} must start with our PID in hex"
        );
    }

    #[test]
    fn argv_carries_identity_token_and_the_parents_log_sink() {
        let args = build_args(
            "work",
            4242,
            0x1234_5678_9abc_def0,
            "1092deadbeef",
            &("debug".into(), None),
        );
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
                "--owner-token",
                "1092deadbeef",
            ]
        );
        let with_file = build_args(
            "default",
            1,
            2,
            "a",
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
        // the parent died before we got here, and the sweep still has
        // to run.
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

    #[test]
    fn only_high_or_system_labels_are_trusted() {
        assert!(label_sddl_is_elevated("S:(ML;;NW;;;HI)"));
        assert!(label_sddl_is_elevated("S:(ML;;NW;;;SI)"));
        assert!(!label_sddl_is_elevated("S:(ML;;NW;;;ME)"));
        assert!(!label_sddl_is_elevated("S:(ML;;NW;;;LW)"));
        assert!(!label_sddl_is_elevated(""));
        assert!(!label_sddl_is_elevated("O:BAG:SYD:(A;;0x1f0003;;;SY)"));
    }

    /// The identity event is what keeps `wintun_cleanup` from counting
    /// a janitor as a live session: absent until held, trusted while
    /// held with the High label (this elevated test process plays the
    /// janitor), gone again on drop — and NOT trusted when unlabelled
    /// or labelled Medium, which is all a medium-integrity forger can
    /// produce (Windows refuses labels above the caller's own level).
    #[test]
    fn identity_event_is_trusted_only_while_held_with_a_high_label() {
        if !crate::is_elevated() {
            eprintln!("skipping: needs an elevated (High integrity) test process");
            return;
        }
        let me = std::process::id();
        assert!(!is_janitor_pid(me), "no event yet → not a janitor");
        {
            let held = IdentityEvent::hold().expect("CreateEventW with HI label");
            assert!(is_janitor_pid(me), "held with High label → janitor");
            drop(held);
        }
        assert!(!is_janitor_pid(me), "released → not a janitor");
        {
            let _plain = IdentityEvent::hold_unlabelled().expect("CreateEventW");
            assert!(!is_janitor_pid(me), "unlabelled event must NOT be trusted");
        }
        {
            let _medium =
                IdentityEvent::hold_with_sddl("S:(ML;;NW;;;ME)").expect("CreateEventW ME");
            assert!(
                !is_janitor_pid(me),
                "Medium-labelled event must NOT be trusted"
            );
        }
        assert!(!is_janitor_pid(me));
        // A PID that cannot possibly hold one.
        assert!(!is_janitor_pid(u32::MAX - 1));
    }

    #[test]
    fn std_handles_can_be_made_non_inheritable_without_error() {
        // Must never panic or disturb the handles themselves — the test
        // harness keeps writing to stdout/stderr after this.
        make_std_handles_non_inheritable();
        make_std_handles_non_inheritable();
    }
}
