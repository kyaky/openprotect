//! Best-effort sweep of orphaned OpenConnect Wintun adapters left
//! behind by a previous `opc` that didn't shut down cleanly (crash,
//! BSOD, Task Manager kill, UAC dismissal mid-connect).
//!
//! ## Status: belt-and-suspenders, not load-bearing
//!
//! libopenconnect already removes a same-named orphan automatically
//! when it goes to create a new adapter — observed in the wild:
//!
//! ```text
//! Using Wintun device 'ra.vpn.example.com1', index 61
//! Removed orphaned adapter "ra.vpn.example.com"
//! ```
//!
//! So the "happy path" is already covered by upstream. This module
//! catches the case where the leaked adapter's name *differs* from
//! what the next `opc connect` requests (e.g., user switched portals
//! between runs). It's a nice-to-have, NOT something the connect
//! flow can afford to wait on.
//!
//! ## Snapshot-then-remove: race-free design
//!
//! Earlier versions of this module enumerated adapters from a
//! background thread and removed every OpenConnect Wintun device
//! it found. That raced with libopenconnect's own adapter creation:
//! the sweep would fire ~10–15s after startup (PowerShell cold-load),
//! by which time our live adapter existed — and the sweep happily
//! removed it, killing the tunnel mid-session.
//!
//! The fix is to **snapshot** orphan-candidate InstanceIds at process
//! startup *before* libopenconnect creates the new adapter, then the
//! background thread only touches IDs in that snapshot. Anything
//! created after the snapshot — including our own live adapter —
//! cannot appear in the list and is therefore safe.
//!
//! ## Native APIs: locale-stable, no PowerShell
//!
//! Both the snapshot and the sibling-process check use Win32 APIs
//! directly via `windows-sys`:
//!
//! - SetupAPI (`SetupDiGetClassDevs` + `SetupDiEnumDeviceInfo` +
//!   `SetupDiGetDeviceRegistryProperty`) for device enumeration.
//!   The `DeviceDesc` value is the driver-INF-supplied English
//!   string (`"OpenConnect Tunnel"`) regardless of OS locale, and
//!   the InstanceId prefix `SWD\Wintun\` is structural rather than
//!   localised. So this filter holds on Chinese / Japanese / etc.
//!   Windows where `pnputil`'s text labels would be translated.
//!
//! - Toolhelp32 (`CreateToolhelp32Snapshot` + `Process32FirstW` /
//!   `Process32NextW`) for the sibling-`opc.exe` check. This is
//!   microseconds compared to PowerShell's 10–15s cold-load.
//!
//! Removal still goes through `pnputil.exe /remove-device <id>`
//! because it's the supported, documented way to uninstall a
//! software-enumerated device, and getting it wrong from raw
//! SetupAPI risks orphaning the driver INF binding.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use windows_sys::core::GUID;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW, DIGCF_PRESENT,
    SPDRP_DEVICEDESC, SP_DEVINFO_DATA,
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// `{4D36E972-E325-11CE-BFC1-08002BE10318}` — the Windows class GUID
/// for network adapters. Hard-coded because `windows-sys` doesn't
/// expose the well-known DEVCLASS constants and adding `windows` as
/// a second dependency just for one literal would be wasteful.
const GUID_DEVCLASS_NET: GUID = GUID {
    data1: 0x4d36_e972,
    data2: 0xe325,
    data3: 0x11ce,
    data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
};

/// Maximum wall time the background removal phase is allowed to
/// take across *all* candidate adapters. Sized to absorb a couple
/// of slow `pnputil /remove-device` calls; past that we assume
/// something is genuinely wedged and bail.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(45);

/// Per-removal timeout: a single `pnputil /remove-device` shouldn't
/// take more than a few seconds. If it does, the driver is wedged
/// and we'd rather skip than block the sweep.
const REMOVE_PER_DEVICE_TIMEOUT: Duration = Duration::from_secs(15);

/// Pause between consecutive `pnputil /remove-device` calls.
///
/// Same rationale as the netsh pacing in `gp-route`: each removal is
/// a PnP device-removal event that trips every NDIS filter driver's
/// interface-notification callback. On this project's reference box
/// a Bitdefender NDIS filter was dump-proven (3x bugcheck 0x133) to
/// spin on the NDIS interface lock during adapter churn, so batched
/// removals are paced to let each callback drain. The sweep is on a
/// background thread and already deadline-bound, so the extra wall
/// time costs nothing on the connect path.
#[cfg(not(test))]
const REMOVE_BATCH_PAUSE: Duration = Duration::from_millis(150);

#[cfg(test)]
const REMOVE_BATCH_PAUSE: Duration = Duration::ZERO;

/// Capture orphan-candidate Wintun InstanceIds **synchronously**.
///
/// Call this on the startup path *before* libopenconnect creates the
/// new tunnel adapter. The returned list is the closed set of devices
/// the background sweep is permitted to remove — any adapter that
/// appears later (including our own) cannot be in this list and is
/// therefore safe.
///
/// Uses SetupAPI directly: fast (microseconds), locale-stable, and
/// fails safe (empty `Vec` on any error means no removals will run).
pub fn snapshot_existing_orphans() -> Vec<String> {
    let started = Instant::now();
    let result = unsafe { enumerate_wintun_oc_devices() };
    debug!(
        "wintun-cleanup: snapshot captured {} orphan candidate(s) in {:?}",
        result.len(),
        started.elapsed()
    );
    result
}

/// Kick off a background removal sweep over the pre-captured snapshot.
///
/// Returns immediately. The actual work runs on a detached thread
/// with a hard timeout so it cannot block (or outlive) the connect
/// flow. Errors are logged at WARN; this function never panics and
/// never propagates a failure to the caller.
pub fn spawn_background_sweep(snapshot: Vec<String>) {
    if snapshot.is_empty() {
        debug!("wintun-cleanup: snapshot is empty — nothing to do");
        return;
    }
    std::thread::Builder::new()
        .name("opc-wintun-cleanup".into())
        .spawn(move || {
            let _ = run_sweep(snapshot);
        })
        .map(|_| ())
        .unwrap_or_else(|e| {
            warn!("wintun-cleanup: failed to spawn worker thread: {}", e);
        });
}

/// Snapshot orphan-candidate adapters and remove them **synchronously**,
/// returning how many were removed. Unlike [`spawn_background_sweep`]
/// this blocks the caller — it's the `opc recover` / `opc doctor`
/// entry point where the user is explicitly asking us to clean up and
/// wants a count back, not the latency-sensitive connect path.
///
/// Still race-safe: it skips entirely if another `opc.exe` is alive
/// (its adapter might be in the snapshot), exactly like the background
/// sweep — a missed cleanup is harmless, a wrongful delete tears down
/// a sibling's tunnel.
pub fn sweep_orphans_blocking() -> usize {
    let snapshot = snapshot_existing_orphans();
    if snapshot.is_empty() {
        return 0;
    }
    run_sweep(snapshot)
}

fn run_sweep(snapshot: Vec<String>) -> usize {
    let started = Instant::now();
    debug!(
        "wintun-cleanup: background sweep starting on {} snapshot ID(s) (timeout {:?})",
        snapshot.len(),
        CLEANUP_TIMEOUT
    );

    // Belt-and-suspenders: if another opc.exe started in the gap
    // between snapshot and sweep, it may have re-adopted one of the
    // snapshotted GUIDs. Skip to keep its tunnel intact.
    if other_opc_running() {
        debug!(
            "wintun-cleanup: skipped — another opc.exe is running, \
             its Wintun adapter may overlap our snapshot"
        );
        return 0;
    }

    let deadline = started + CLEANUP_TIMEOUT;
    let mut removed = 0usize;
    for (i, instance_id) in snapshot.iter().enumerate() {
        if Instant::now() >= deadline {
            warn!(
                "wintun-cleanup: overall timeout reached after {} removal(s), {} remaining",
                removed,
                snapshot.len() - removed
            );
            break;
        }
        match remove_device(instance_id, deadline) {
            Ok(()) => {
                removed += 1;
                debug!("wintun-cleanup: removed {}", instance_id);
            }
            Err(e) => {
                // Common case: the device was already removed (by
                // libopenconnect's inline cleanup, or a sibling
                // opc). That's fine — log and move on.
                debug!(
                    "wintun-cleanup: pnputil could not remove {}: {}",
                    instance_id, e
                );
            }
        }
        // NDIS filter-churn pacing (see REMOVE_BATCH_PAUSE): between
        // removals, not after the last — and the deadline break above
        // runs with no trailing sleep.
        if i + 1 < snapshot.len() {
            std::thread::sleep(REMOVE_BATCH_PAUSE);
        }
    }

    if removed > 0 {
        info!(
            "wintun-cleanup: removed {} orphaned OpenConnect adapter(s) in {:?}",
            removed,
            started.elapsed()
        );
    } else {
        debug!(
            "wintun-cleanup: no adapters removed from snapshot of {} ({:?})",
            snapshot.len(),
            started.elapsed()
        );
    }
    removed
}

fn remove_device(instance_id: &str, deadline: Instant) -> std::io::Result<()> {
    // Clamp per-device timeout to the overall remaining budget so a
    // removal started near the global cap can't push total wall time
    // past `CLEANUP_TIMEOUT + REMOVE_PER_DEVICE_TIMEOUT`. The caller
    // is expected to skip dispatching new removals once `now >= deadline`,
    // but a slow removal already in flight should still be bounded.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = remaining.min(REMOVE_PER_DEVICE_TIMEOUT);
    if timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "overall cleanup deadline reached",
        ));
    }
    let outcome = run_with_timeout(
        Command::new("pnputil.exe").args(["/remove-device", instance_id]),
        timeout,
    )?;
    // The removal AUTHORITY is unchanged: this runs only for IDs in
    // the pre-captured snapshot (the closed set), never for devices
    // enumerated after the snapshot. What the bounded-subprocess
    // rewrite adds is an honest *outcome*: a kill/abandon is
    // `Unconfirmed` and must not be reported as a completed removal.
    if removal_is_confirmed(&outcome) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "removal not confirmed ({outcome:?})"
        )))
    }
}

/// `true` only when `pnputil` ran to completion with exit 0 — i.e.
/// when the removal can honestly be counted. A kill-on-timeout is
/// never confirmed (reaped or not: the child was terminated before it
/// finished the removal), so `run_sweep` does not count it and the
/// summary reports the device as still present.
fn removal_is_confirmed(outcome: &RunOutcome) -> bool {
    matches!(outcome, RunOutcome::Completed { success: true, .. })
}

/// Enumerate `SWD\Wintun\*` devices whose driver-supplied
/// `DeviceDesc` begins with `OpenConnect` or `OpenProtect`.
///
/// Safety: the underlying SetupAPI calls are unsafe FFI. Inside this
/// function we hold the `HDEVINFO` until `SetupDiDestroyDeviceInfoList`
/// runs at the end (no early-return path can leak it).
unsafe fn enumerate_wintun_oc_devices() -> Vec<String> {
    let mut out = Vec::new();

    let h_dev_info = SetupDiGetClassDevsW(
        &GUID_DEVCLASS_NET,
        std::ptr::null(),
        std::ptr::null_mut(),
        DIGCF_PRESENT,
    );
    // windows-sys 0.59 declares HDEVINFO as `isize`; `0` is null and
    // `-1` is INVALID_HANDLE_VALUE. We compare via `as isize` so this
    // also holds if a future windows-sys revision migrates the type
    // to `*mut c_void` (the cast is a no-op at the bit level).
    if h_dev_info as isize == 0 || h_dev_info as isize == -1 {
        warn!(
            "wintun-cleanup: SetupDiGetClassDevsW failed: {}",
            std::io::Error::last_os_error()
        );
        return out;
    }

    let mut info: SP_DEVINFO_DATA = std::mem::zeroed();
    info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

    let mut idx: u32 = 0;
    loop {
        if SetupDiEnumDeviceInfo(h_dev_info, idx, &mut info) == 0 {
            break;
        }
        idx += 1;

        // 1) InstanceId — must start with SWD\Wintun\ for this device
        //    to be Wintun-class at all. 256 wide chars is generously
        //    sized for "SWD\Wintun\{GUID}" which is ~50 chars.
        let mut id_buf = [0u16; 256];
        let mut required: u32 = 0;
        if SetupDiGetDeviceInstanceIdW(
            h_dev_info,
            &info,
            id_buf.as_mut_ptr(),
            id_buf.len() as u32,
            &mut required,
        ) == 0
        {
            continue;
        }
        let instance_id = wide_z_to_string(&id_buf);
        if !instance_id_is_wintun(&instance_id) {
            continue;
        }

        // 2) DeviceDesc — driver-INF-supplied, locale-independent.
        //    SPDRP_DEVICEDESC returns REG_SZ wide data via the W
        //    variant. We cast our [u16] buffer to *mut u8 because
        //    SetupAPI's signature is byte-count-based.
        let mut desc_buf = [0u16; 256];
        let mut required_desc: u32 = 0;
        let ok = SetupDiGetDeviceRegistryPropertyW(
            h_dev_info,
            &info,
            SPDRP_DEVICEDESC,
            std::ptr::null_mut(),
            desc_buf.as_mut_ptr() as *mut u8,
            (desc_buf.len() * 2) as u32,
            &mut required_desc,
        );
        if ok == 0 {
            continue;
        }
        let desc = wide_z_to_string(&desc_buf);
        if desc.starts_with("OpenConnect") || desc.starts_with("OpenProtect") {
            out.push(instance_id);
        }
    }

    SetupDiDestroyDeviceInfoList(h_dev_info);
    out
}

/// Decode a null-terminated UTF-16 buffer into a `String`.
fn wide_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// `true` if the InstanceId is a Wintun software-device path.
///
/// Case-insensitive because SetupAPI may normalise the prefix
/// differently between OS versions; matching either spelling is
/// cheap and removes a class of subtle false-negatives.
fn instance_id_is_wintun(id: &str) -> bool {
    let id_upper = id.to_ascii_uppercase();
    id_upper.starts_with(r"SWD\WINTUN\")
}

/// `true` if any `opc.exe` other than ourselves is currently running.
///
/// Uses Toolhelp32 instead of PowerShell — microseconds vs. 10s of
/// cold-load. On detection error we conservatively return `true` so
/// cleanup is skipped (a missed cleanup is harmless; a wrongful
/// adapter delete tears down a sibling's tunnel).
fn other_opc_running() -> bool {
    unsafe { sibling_opc_present(std::process::id()) }
}

unsafe fn sibling_opc_present(my_pid: u32) -> bool {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap as isize == 0 || snap as isize == -1 {
        warn!(
            "wintun-cleanup: CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        );
        return true;
    }

    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut found = false;
    if Process32FirstW(snap, &mut entry) != 0 {
        loop {
            let name = wide_z_to_string(&entry.szExeFile);
            if entry.th32ProcessID != my_pid && name.eq_ignore_ascii_case("opc.exe") {
                found = true;
                break;
            }
            if Process32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snap);
    found
}

/// How long to wait for a killed child to be reaped before abandoning
/// it. The old runner called `child.wait()` unconditionally after
/// `kill()` — an INFINITE wait on a process that resists termination
/// (exactly the kernel-mode wedge this module exists around). With a
/// bounded wait, the worst case past the deadline is this constant.
const REAP_BUDGET: Duration = Duration::from_secs(2);

/// Honest outcome of a bounded subprocess run.
///
/// Distinct from a bare `io::Result<String>` because "we killed it and
/// could not confirm anything" must never be conflated with "it
/// finished" (or, pre-rewrite, quietly counted as done). Same defect
/// family the route owner is fixing in `gp-route`'s `run_with_timeout`
/// (crates/gp-route/src/lib.rs:222-256): clock accounting, concurrent
/// pipe drain, and kill-then-BOUNDED-wait with abandon-on-timeout.
#[derive(Debug, PartialEq, Eq)]
enum RunOutcome {
    /// The child exited on its own before the deadline.
    Completed {
        success: bool,
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// The deadline elapsed: `TerminateProcess` was requested and we
    /// waited at most [`REAP_BUDGET`] for the reap. `reaped: false`
    /// means the process was still alive when we abandoned it — the
    /// caller must treat the side effect as UNCONFIRMED either way
    /// (see [`removal_is_confirmed`]).
    TimedOut { reaped: bool },
}

/// Run a command with a hard wall-clock timeout, draining its pipes
/// concurrently and returning a [`RunOutcome`].
///
/// Used by `pnputil /remove-device`, which can occasionally hang on a
/// half-broken driver. The three bounded-subprocess invariants here
/// (each one a defect class observed in this repo's other runners):
///
/// 1. **Clock starts BEFORE spawn.** A slow `CreateProcess` (AV
///    scanning, first-use .NET load) must count against `timeout`,
///    not silently extend it.
/// 2. **Concurrent pipe drain.** A child writing more than the OS
///    pipe buffer blocks in `WriteFile` until somebody reads; the
///    old runner only touched the pipes after `try_wait()` reported
///    an exit it could therefore never observe, and killed healthy
///    children that simply had a lot to say.
/// 3. **Kill, then BOUNDED wait; abandon on timeout.** Never reap-
///    block: a child that refuses to die returns `TimedOut` after
///    `REAP_BUDGET` with `reaped: false`, and the caller decides what
///    it may or may not believe happened.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> std::io::Result<RunOutcome> {
    let started = Instant::now();
    let deadline = started + timeout;
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    // Hand the pipes to reader threads immediately — before polling
    // for exit — so a verbose child never blocks on a full buffer.
    let stdout = child.stdout.take().expect("stdout was configured piped");
    let stderr = child.stderr.take().expect("stderr was configured piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut stdout = stdout;
        let _ = std::io::Read::read_to_end(&mut stdout, &mut buf);
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut stderr = stderr;
        let _ = std::io::Read::read_to_end(&mut stderr, &mut buf);
        buf
    });

    loop {
        match child.try_wait()? {
            Some(status) => {
                // The process is gone, so both pipe handles are
                // closed on the write side and the readers are at
                // EOF; joining them cannot block in practice. If a
                // reader somehow lingers we cap the damage at the
                // reap budget rather than inheriting an INFINITE join.
                let (out, err) = join_readers_bounded(stdout_reader, stderr_reader);
                return Ok(RunOutcome::Completed {
                    success: status.success(),
                    code: status.code(),
                    stdout: String::from_utf8_lossy(&out).into_owned(),
                    stderr: String::from_utf8_lossy(&err).into_owned(),
                });
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    // BOUNDED reap (never `child.wait()` — INFINITE):
                    // poll try_wait for up to REAP_BUDGET, then
                    // abandon. Dropping `child` releases our process
                    // handle; an un-reaped child keeps running, which
                    // is precisely why the outcome is Unconfirmed and
                    // `remove_device` must not count it as done.
                    let reaped = loop {
                        match child.try_wait()? {
                            Some(_) => break true,
                            None => {
                                if started.elapsed() >= timeout + REAP_BUDGET {
                                    break false;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                    };
                    let _ = join_readers_bounded(stdout_reader, stderr_reader);
                    return Ok(RunOutcome::TimedOut { reaped });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Join the pipe-drain threads without an unbounded wait. On the
/// `Completed` path the writers are already at EOF; on the
/// abandon path the child may still hold the write ends, so we
/// detached-poll each JoinHandle with `is_finished()` and give up
/// after a short grace window. A leaked reader thread dies with the
/// process — the sweep is best-effort and must never block.
fn join_readers_bounded(
    stdout_reader: std::thread::JoinHandle<Vec<u8>>,
    stderr_reader: std::thread::JoinHandle<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>) {
    let grace = Instant::now() + Duration::from_millis(500);
    let read = |h: std::thread::JoinHandle<Vec<u8>>| {
        while !h.is_finished() && Instant::now() < grace {
            std::thread::sleep(Duration::from_millis(20));
        }
        if h.is_finished() {
            h.join().unwrap_or_default()
        } else {
            // Abandon: the handle leaks until process exit; dropping
            // the JoinHandle detaches the thread.
            drop(h);
            Vec::new()
        }
    };
    (read(stdout_reader), read(stderr_reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_z_to_string_trims_at_nul() {
        let mut buf = [0u16; 8];
        for (i, c) in "Hi".encode_utf16().enumerate() {
            buf[i] = c;
        }
        // buf[2..] is already zeroed
        assert_eq!(wide_z_to_string(&buf), "Hi");
    }

    #[test]
    fn wide_z_to_string_handles_no_nul() {
        // Full buffer of valid UTF-16 with no terminator should still
        // decode (we fall back to buf.len()).
        let buf: Vec<u16> = "AB".encode_utf16().collect();
        assert_eq!(wide_z_to_string(&buf), "AB");
    }

    #[test]
    fn wide_z_to_string_empty() {
        assert_eq!(wide_z_to_string(&[]), "");
        assert_eq!(wide_z_to_string(&[0u16; 4]), "");
    }

    #[test]
    fn instance_id_is_wintun_matches_canonical_form() {
        assert!(instance_id_is_wintun(
            r"SWD\Wintun\{AAAAAAAA-1111-2222-3333-444444444444}"
        ));
    }

    #[test]
    fn instance_id_is_wintun_is_case_insensitive() {
        assert!(instance_id_is_wintun(r"swd\wintun\{X}"));
        assert!(instance_id_is_wintun(r"SWD\WINTUN\{X}"));
    }

    #[test]
    fn instance_id_is_wintun_rejects_other_classes() {
        assert!(!instance_id_is_wintun(r"PCI\VEN_8086&DEV_15D7\0000"));
        assert!(!instance_id_is_wintun(r"SWD\Tailscale\{X}"));
        assert!(!instance_id_is_wintun(""));
        // Partial prefix must not match.
        assert!(!instance_id_is_wintun(r"SWD\Win\{X}"));
    }

    // ---- run_with_timeout bounded-subprocess discipline -------------
    //
    // RED-first anchors for the runner rewrite. The old runner only
    // touched the pipes AFTER `try_wait()` reported an exit, so a
    // child that wrote more than the OS pipe buffer blocked on
    // WriteFile forever: it never exited, the deadline fired, and we
    // killed a healthy `pnputil` instead of draining it. Same defect
    // class as gp-route's `run_with_timeout` (lib.rs:222-256, the
    // "EOF-read wedge") — the route owner fixes theirs, we fix ours.

    #[test]
    fn run_with_timeout_drains_a_pipe_blocking_child() {
        // RED before the rewrite: the old runner only read the pipes
        // after `try_wait()` reported an exit, so this child blocked
        // on WriteFile past the deadline and came back Err(TimedOut).
        // Watched failing at 2026-09-28 (5.07s timeout kill), passes
        // with concurrent drain.
        let mut path = std::env::temp_dir();
        path.push(format!("opc-wintun-drain-{}.txt", std::process::id()));
        std::fs::write(&path, "X".repeat(128 * 1024)).expect("fixture");

        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/C", "type", path.to_str().unwrap()]);
        let res = run_with_timeout(&mut cmd, Duration::from_secs(5));
        let _ = std::fs::remove_file(&path);

        match res.expect("drained child must return a Completed outcome") {
            RunOutcome::Completed {
                success, stdout, ..
            } => {
                assert!(success, "type exits 0");
                assert!(
                    stdout.len() >= 128 * 1024,
                    "128KB exceeds the OS pipe buffer; the runner must \
                     drain it concurrently, got {} bytes",
                    stdout.len()
                );
            }
            RunOutcome::TimedOut { reaped } => {
                panic!("pipe-blocking child timed out (reaped={reaped})")
            }
        }
    }

    #[test]
    fn run_with_timeout_never_outlives_its_budget_by_a_reap_wait() {
        // Kill-then-bounded-wait: a child that ignores its deadline
        // must be abandoned, not reaped-blocked. The old tail did
        // `child.kill(); child.wait()` — `wait()` is INFINITE if the
        // process resists termination (kernel-mode wait on a wedged
        // driver stack is exactly the scenario this sweep exists for).
        // Guard the wall clock: timeout 300ms, whole call bounded at
        // 3s (timeout + REAP_BUDGET + slack, not the child's 30s
        // lifetime), and the outcome is the distinct TimedOut variant
        // rather than an error conflated with ordinary failures.
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/C", "ping", "127.0.0.1", "-n", "30"]);
        let started = Instant::now();
        let res = run_with_timeout(&mut cmd, Duration::from_millis(300));
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "runner blocked {elapsed:?} on a child that was supposed to \
             be killed-and-abandoned at 300ms"
        );
        match res.expect("deadline path returns a distinguished Ok outcome") {
            RunOutcome::TimedOut { .. } => {}
            other => panic!("hung child must surface RunOutcome::TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn run_with_timeout_reports_nonzero_exit_with_code_and_streams() {
        // The old API flattened every failure into one opaque
        // io::Error string (and read stderr only post-exit). Exit
        // code and both streams must survive separately so callers
        // can distinguish "already gone" from "wedged driver".
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/C", "exit /b 3"]);
        let res = run_with_timeout(&mut cmd, Duration::from_secs(10))
            .expect("fast exit must be a Completed outcome");
        match res {
            RunOutcome::Completed { success, code, .. } => {
                assert!(!success);
                assert_eq!(code, Some(3));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn unconfirmed_timeout_is_never_counted_as_removal() {
        // The removal-authority freeze means run_sweep may only ever
        // DELETE devices from the pre-captured closed set; what the
        // bounded-runner rewrite adds is honesty about the OUTCOME.
        // A killed/abandoned pnputil is not a completed removal —
        // table pins the decision the sweep's counter keys on.
        assert!(removal_is_confirmed(&RunOutcome::Completed {
            success: true,
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }));
        assert!(!removal_is_confirmed(&RunOutcome::Completed {
            success: false,
            code: Some(5),
            stdout: String::new(),
            stderr: String::new(),
        }));
        // Even a reaped kill is unconfirmed: the child died BEFORE
        // finishing the removal — counting it would under-report
        // orphans (a later doctor would see the device still there
        // and we would have claimed it gone).
        assert!(!removal_is_confirmed(&RunOutcome::TimedOut {
            reaped: true
        }));
        assert!(!removal_is_confirmed(&RunOutcome::TimedOut {
            reaped: false
        }));
    }

    #[test]
    fn devclass_net_guid_matches_well_known_value() {
        // Canonical Microsoft class GUID for network adapters.
        // Guard against accidental edits to the constant above.
        assert_eq!(GUID_DEVCLASS_NET.data1, 0x4d36_e972);
        assert_eq!(GUID_DEVCLASS_NET.data2, 0xe325);
        assert_eq!(GUID_DEVCLASS_NET.data3, 0x11ce);
        assert_eq!(
            GUID_DEVCLASS_NET.data4,
            [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18]
        );
    }
}
