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
    for instance_id in &snapshot {
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
    let _ = run_with_timeout(
        Command::new("pnputil.exe").args(["/remove-device", instance_id]),
        timeout,
    )?;
    Ok(())
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
            &mut info,
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
            &mut info,
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

/// Run a command with a hard wall-clock timeout, returning stdout.
///
/// Used by `pnputil /remove-device`, which can occasionally hang on a
/// half-broken driver. Returns the timeout error if the deadline is
/// hit; the caller is expected to log-and-continue.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> std::io::Result<String> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                let out = child.wait_with_output()?;
                if status.success() {
                    return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "exited with {}: {}",
                        status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                ));
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("did not exit within {:?}", timeout),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
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
