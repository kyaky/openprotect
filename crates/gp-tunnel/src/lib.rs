//! Tunnel management — safe Rust wrapper around `libopenconnect`.
//!
//! Provides [`OpenConnectSession`] which manages the lifecycle of a VPN
//! tunnel: session creation, protocol selection, authcookie injection,
//! CSTP/TUN setup, blocking main loop, and cancellation.

use thiserror::Error;

mod openconnect;

pub use openconnect::{CancelHandle, IpInfoSnapshot, OpenConnectSession};

/// Tunnel errors.
///
/// The mainloop-specific variants let the app-level reconnect loop
/// decide whether to back off + retry or bail out. libopenconnect's
/// `openconnect_mainloop` returns negative error codes that carry
/// very different meanings — a transient network blip should trigger
/// a retry, but a server-initiated session termination or an
/// invalid cookie should NOT, because blindly re-using the same
/// cookie would flap forever.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Generic error from libopenconnect. Caller may retry for
    /// transient cases (default policy in the reconnect loop).
    #[error("openconnect error: {0}")]
    OpenConnect(String),

    /// The remote gateway explicitly terminated the session (libopen-
    /// connect's mainloop returned `-EPIPE`). The session is done;
    /// retrying with the same cookie will either produce an immediate
    /// auth failure OR reconnect and get kicked again. The app-level
    /// reconnect loop MUST NOT retry on this error.
    #[error("gateway terminated session (mainloop returned -EPIPE)")]
    MainloopTerminated,

    /// The gateway sent a 401 Unauthorized, meaning the authcookie
    /// is no longer valid (libopenconnect's mainloop returned
    /// `-EPERM`). The only way to recover is to re-run the full
    /// portal_login + gateway_login flow, which is Phase 2c work —
    /// for now, the reconnect loop surfaces this as a terminal
    /// error and asks the user to reconnect.
    #[error("authcookie rejected by gateway (mainloop returned -EPERM) — re-authenticate")]
    MainloopAuthExpired,

    /// Mainloop exited with some other negative code. Caller may
    /// retry; the exact rc is preserved for diagnostic logging.
    #[error("openconnect mainloop exited with rc={0}")]
    MainloopOther(i32),

    #[error("tunnel not connected")]
    NotConnected,
}

impl TunnelError {
    /// Is this error terminal (don't retry) from the reconnect
    /// loop's perspective?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TunnelError::MainloopTerminated | TunnelError::MainloopAuthExpired
        )
    }
}
