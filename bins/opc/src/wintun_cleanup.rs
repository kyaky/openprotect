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
//! Using Wintun device 'ra.vpn.unsw.edu.au1', index 61
//! Removed orphaned adapter "ra.vpn.unsw.edu.au"
//! ```
//!
//! So the "happy path" is already covered by upstream. This module
//! catches the case where the leaked adapter's name *differs* from
//! what the next `opc connect` requests (e.g., user switched portals
//! between runs). It's a nice-to-have, NOT something the connect
//! flow can afford to wait on.
//!
//! ## Why we run it in the background
//!
//! Every PowerShell launch on Windows pays a 5-15s .NET / module
//! cold-load cost (we saw this break gp-route and gp-dns too). If
//! the sweep ran inline before tunnel setup, every reconnect would
//! eat that latency, and a wedged PowerShell would block the connect
//! forever. Instead we:
//!
//! 1. Spawn the sweep on a detached worker thread.
//! 2. Let `connect()` proceed immediately to libopenconnect's own
//!    adapter creation (which handles same-name orphans inline).
//! 3. Apply a hard process-side timeout so a slow PowerShell can't
//!    pin a zombie subprocess for the whole opc session.
//!
//! Misses are silent and harmless: if the sweep never finishes
//! before the next reconnect kicks off, libopenconnect will still
//! find and remove any same-named orphan when it tries to create
//! the new adapter.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// Maximum wall time the cleanup is allowed to take. Sized to absorb
/// a PowerShell + DnsClient module cold-load plus a couple of
/// `pnputil` device removals; past that we assume something is
/// genuinely wedged and bail.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(45);

/// Kick off a background sweep of orphan OpenConnect Wintun adapters.
///
/// Returns immediately. The actual work runs on a detached thread
/// with a hard timeout so it cannot block (or outlive) the connect
/// flow. Errors are logged at WARN; this function never panics and
/// never propagates a failure to the caller.
pub fn spawn_background_sweep() {
    std::thread::Builder::new()
        .name("opc-wintun-cleanup".into())
        .spawn(run_sweep)
        .map(|_| ())
        .unwrap_or_else(|e| {
            warn!("wintun-cleanup: failed to spawn worker thread: {}", e);
        });
}

fn run_sweep() {
    let started = Instant::now();
    debug!(
        "wintun-cleanup: background sweep starting (timeout {:?})",
        CLEANUP_TIMEOUT
    );

    if other_opc_running() {
        debug!(
            "wintun-cleanup: skipped — another opc.exe is running, \
             its Wintun adapter is live"
        );
        return;
    }
    if started.elapsed() >= CLEANUP_TIMEOUT {
        warn!("wintun-cleanup: timed out during sibling-process probe");
        return;
    }

    // Single round-trip PowerShell: enumerate, filter, remove, count.
    // `Write-Output $count` is the only thing on stdout — pnputil's
    // chatter goes to $null.
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$count = 0
Get-PnpDevice -Class Net |
  Where-Object {
    ($_.HardwareID -join ',') -match 'Wintun' -and
    ($_.FriendlyName -like 'OpenConnect*' -or $_.FriendlyName -like 'OpenProtect*')
  } |
  ForEach-Object {
    & pnputil.exe /remove-device $_.InstanceId *>$null
    if ($LASTEXITCODE -eq 0) { $count++ }
  }
Write-Output $count
"#;

    let remaining = CLEANUP_TIMEOUT.saturating_sub(started.elapsed());
    match run_powershell_with_timeout(script, remaining) {
        Ok(stdout) => {
            let removed: usize = stdout.trim().parse().unwrap_or(0);
            if removed > 0 {
                info!(
                    "wintun-cleanup: removed {} orphaned OpenConnect adapter(s) in {:?}",
                    removed,
                    started.elapsed()
                );
            } else {
                debug!(
                    "wintun-cleanup: no orphaned adapters found ({:?})",
                    started.elapsed()
                );
            }
        }
        Err(e) => {
            warn!(
                "wintun-cleanup: sweep failed after {:?}: {}",
                started.elapsed(),
                e
            );
        }
    }
}

/// `true` if any `opc.exe` other than ourselves is currently running.
///
/// We treat the existence of a sibling as "skip cleanup" because that
/// sibling almost certainly owns a live Wintun adapter via libopenconnect.
/// On detection error / timeout we conservatively return `true` so
/// cleanup is skipped — a missed cleanup is harmless, a wrongful
/// adapter delete would tear down the sibling's tunnel.
fn other_opc_running() -> bool {
    let my_pid = std::process::id();
    let script = format!(
        "Get-Process -Name opc -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.Id -ne {} }} | \
         Measure-Object | \
         Select-Object -ExpandProperty Count",
        my_pid
    );
    match run_powershell_with_timeout(&script, Duration::from_secs(10)) {
        Ok(out) => out.trim().parse::<u32>().unwrap_or(0) > 0,
        Err(_) => true,
    }
}

/// Run a PowerShell one-liner with a hard wall-clock timeout.
///
/// PowerShell is happy to take 10+ seconds to start cold; this
/// guards us against a wedged subprocess pinning the cleanup worker
/// (and, indirectly, the process — the worker is detached but a
/// runaway pnputil could still leak a Wintun handle).
fn run_powershell_with_timeout(script: &str, timeout: Duration) -> std::io::Result<String> {
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(_) => {
                return child
                    .wait_with_output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("powershell did not exit within {:?}", timeout),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
