//! Best-effort NRPT cleanup for abrupt process death that can still
//! run *some* code: console close (the window's X button), logoff,
//! shutdown, and Rust panics.
//!
//! ## Where this sits relative to the other teardown paths
//!
//! * Normal exit / Ctrl-C / `opc disconnect` → the cooperative cancel
//!   path in `main.rs` reverts NRPT cleanly. Nothing here fires.
//! * Kernel-mode Wintun/PnP wedge after a *cancel* → `exit_wedged` in
//!   `main.rs` clears NRPT and force-exits.
//! * **Console close / logoff / shutdown / panic** → THIS module. The
//!   user closing a frozen terminal window is exactly this case, and
//!   it is otherwise uncovered: no cancel is issued, so `exit_wedged`
//!   never runs, and the process is killed before the linear revert.
//! * Hard `taskkill /F` → runs no code at all; only the next
//!   `opc connect` or `opc recover` recovers it.
//!
//! ## Why a console-ctrl handler works even when the tunnel is wedged
//!
//! Windows delivers `CTRL_CLOSE_EVENT` etc. by spawning a **new
//! thread** in the process to run the registered handler. So even when
//! the main and tunnel threads are stuck in an uninterruptible
//! kernel-mode wait, the handler thread still runs and can delete the
//! leaked NRPT rule from the registry before the OS tears the process
//! down. The sweep is the same native, bounded primitive `opc recover`
//! uses (registry delete + `DnsCache` paramchange — milliseconds, no
//! PowerShell, cannot itself wedge).
//!
//! ## Arming
//!
//! `arm(instance)` records which instance's rules to sweep; it is
//! called once gp-dns has actually installed an NRPT rule, and
//! `disarm()` is called on the normal revert. The handlers no-op when
//! nothing is armed, so a connect that never reached NRPT install (or
//! one already cleanly torn down) triggers no sweep.

use std::sync::{Mutex, OnceLock};

/// The instance whose NRPT rules should be swept if we die abruptly.
/// `None` when nothing is installed (or it's already been reverted).
static ARMED_INSTANCE: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn cell() -> &'static Mutex<Option<String>> {
    ARMED_INSTANCE.get_or_init(|| Mutex::new(None))
}

/// Lock the cell, recovering from poison — a panicking thread must
/// still be able to read the armed instance from the panic hook.
fn lock_cell() -> std::sync::MutexGuard<'static, Option<String>> {
    cell().lock().unwrap_or_else(|e| e.into_inner())
}

/// Arm crash cleanup for `instance`. Called after gp-dns installs an
/// NRPT rule. Idempotent; the latest arm wins.
pub fn arm(instance: &str) {
    *lock_cell() = Some(instance.to_string());
}

/// Disarm — the normal teardown ran and reverted NRPT, so there is
/// nothing left to clean on an abrupt exit.
pub fn disarm() {
    *lock_cell() = None;
}

/// The currently-armed instance, if any. Read by the handlers.
pub fn armed_instance() -> Option<String> {
    lock_cell().clone()
}

/// Sweep the armed instance's leaked NRPT rules, if any. Best-effort
/// and self-contained: takes no locks beyond the cell, does no
/// allocation-heavy work, and never panics (so it is safe to call from
/// a panic hook or an OS handler thread). No-op when nothing is armed.
fn run_cleanup() {
    if let Some(instance) = armed_instance() {
        // Same native primitive as `opc recover`: registry delete +
        // DnsCache paramchange. Errors are swallowed — we're dying and
        // can't reliably log during shutdown anyway.
        let _ = gp_dns::cleanup_stale_windows_nrpt(&instance);
    }
}

/// Install a Windows console control handler that clears leaked NRPT
/// DNS on console-close / logoff / shutdown. Call once, early.
///
/// The handler returns FALSE for every event so it never swallows the
/// signal: Ctrl-C / Ctrl-Break stay with tokio's cooperative handler,
/// and close/logoff/shutdown proceed to the default terminate after we
/// have cleaned up. Best-effort — a failure to register is ignored.
pub fn install_console_handler() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe {
        // add = TRUE (1) registers our handler.
        let _ = SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// Which console events mean "this process is about to be killed by
/// the OS default handler, so sweep now".
///
/// Close / logoff / shutdown always do. Ctrl-C and Ctrl-Break do too —
/// but only in the case where this handler is *reached* for them:
///
/// Windows runs console handlers newest-first. tokio registers its
/// handler lazily on the first `ctrl_c()` / `ctrl_break()` call, which
/// in `opc connect` happens after `install_console_handler`, so tokio's
/// handler runs before this one. tokio returns TRUE (chain stops, the
/// cooperative cancel runs) whenever a listener for that event is
/// alive; it returns FALSE — and the chain reaches us — only when no
/// listener exists, in which case the next stop is the OS default:
/// `ExitProcess`. That is the "second Ctrl-C while teardown is still
/// running" window (the `shutdown_signal` future that handled the
/// first one has completed and been dropped) and, before
/// `shutdown_signal` grew a Ctrl-Break arm, every Ctrl-Break. Both
/// used to kill the process with its NRPT rule still installed.
///
/// If the registration order ever flipped (this handler reached first
/// on a plain Ctrl-C), the only effect is an early, redundant sweep
/// before the cooperative revert — `gp_dns::revert` treats a missing
/// key as already removed — never a lost cleanup.
fn event_is_terminal(ctrl_type: u32) -> bool {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    matches!(
        ctrl_type,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    )
}

// `BOOL` is `i32` in windows-sys; the `PHANDLER_ROUTINE` signature is
// `unsafe extern "system" fn(u32) -> BOOL`, so `i32` matches exactly.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    if event_is_terminal(ctrl_type) {
        run_cleanup();
    }
    // FALSE: not consumed — let the next handler / OS default run.
    // For Ctrl-C / Ctrl-Break this is what keeps tokio's cooperative
    // handling intact in the (expected) case where tokio runs first:
    // we never swallow an event, we only sweep ahead of a kill.
    0
}

/// Install a panic hook that clears leaked NRPT DNS before unwinding,
/// then delegates to the previous hook (so the panic is still printed
/// / logged as usual). Covers a panic anywhere in the process —
/// including the tunnel thread after NRPT was installed.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_cleanup();
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #56 (CLI half): an unlistened Ctrl-C / Ctrl-Break reaches
    /// this handler only when the OS is about to `ExitProcess`, so
    /// both must sweep — alongside the three events that always did.
    #[test]
    fn every_process_ending_console_event_sweeps() {
        use windows_sys::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        };
        for ev in [
            CTRL_C_EVENT,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        ] {
            assert!(event_is_terminal(ev), "event {ev} must trigger the sweep");
        }
        // Unknown/future event codes are left alone.
        assert!(!event_is_terminal(3));
        assert!(!event_is_terminal(4));
        assert!(!event_is_terminal(u32::MAX));
    }

    #[test]
    fn arm_then_disarm_tracks_instance() {
        // Serialized implicitly: this is the only test touching the
        // global, and cargo runs module tests in-process. Start clean.
        disarm();
        assert_eq!(armed_instance(), None);

        arm("work");
        assert_eq!(armed_instance(), Some("work".to_string()));

        // Latest arm wins.
        arm("home");
        assert_eq!(armed_instance(), Some("home".to_string()));

        disarm();
        assert_eq!(armed_instance(), None);
    }
}
