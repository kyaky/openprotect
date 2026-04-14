//! Safe Rust wrapper around `libopenconnect`.
//!
//! Only the subset of the API needed for GlobalProtect tunnels is exposed:
//! session creation, protocol/cookie/OS setup, CSTP connect + TUN setup,
//! blocking main loop, and asynchronous cancellation via a pipe fd.

use std::ffi::{CStr, CString};
use std::ptr;

use gp_openconnect_sys as sys;

use crate::TunnelError;

/// `"gp"` as a NUL-terminated byte string. We avoid `CString::new("gp").unwrap()`
/// because library crates in this workspace are forbidden from using `unwrap()`,
/// and a `const` `CStr` removes the need entirely.
const GP_PROTOCOL: &CStr = c"gp";

/// Owned `libopenconnect` session.
///
/// Not `Send` or `Sync`: the underlying `openconnect_info` is not thread-safe
/// and must be used from the thread that created it. Cancellation from another
/// thread goes through the command pipe returned by
/// [`OpenConnectSession::cancel_handle`], which uses `openconnect_setup_cmd_pipe`
/// under the hood. libopenconnect owns the read end of that pipe and polls it
/// inside its main loop — writing `OC_CMD_CANCEL` to the write fd breaks the
/// loop out.
pub struct OpenConnectSession {
    inner: *mut sys::openconnect_info,
    /// Write end of libopenconnect's command pipe. `None` after
    /// `cancel_handle()` has moved ownership to a `CancelHandle`.
    cmd_write_fd: Option<libc::c_int>,
}

/// Handle usable from another thread to cancel a running main loop.
///
/// Holds the raw write fd of libopenconnect's command pipe. We deliberately
/// do **not** close this fd on drop: per `openconnect.h`, both ends of the
/// pipe created by `openconnect_setup_cmd_pipe` are owned by libopenconnect
/// and closed by `openconnect_vpninfo_free`. Closing it ourselves would
/// race vpninfo_free into a double-close (and potential UAF on fd reuse).
///
/// **Invariant:** a `CancelHandle` must not be used after its parent
/// [`OpenConnectSession`] has been dropped. The current `pgn` flow joins
/// the tunnel thread before dropping the session, which preserves this.
pub struct CancelHandle {
    write_fd: libc::c_int,
}

impl CancelHandle {
    /// Signal the session's main loop to exit.
    ///
    /// Behaviour:
    /// * Retries the `write(2)` on `EINTR`.
    /// * Requires the kernel to acknowledge that exactly one byte landed
    ///   (the OC_CMD_CANCEL byte). A `0` return is reported as a
    ///   transient error.
    /// * Treats `EPIPE` as success. The only documented way to get EPIPE
    ///   on this fd is for the read end to be closed, and per
    ///   `openconnect.h` lines 692-695 the cmd-pipe ends are closed only
    ///   inside `openconnect_vpninfo_free` — i.e. the session is already
    ///   torn down. Surfacing that as an error would be misleading; "the
    ///   tunnel is already gone" is the same outcome the caller wanted.
    pub fn cancel(&self) -> Result<(), TunnelError> {
        let buf = [sys::OC_CMD_CANCEL];
        loop {
            let rc = unsafe { libc::write(self.write_fd, buf.as_ptr() as *const libc::c_void, 1) };
            if rc == 1 {
                return Ok(());
            }
            if rc == 0 {
                // Pipe accepted no bytes — treat as a transient error.
                return Err(TunnelError::OpenConnect(
                    "cancel write returned 0 bytes".into(),
                ));
            }
            // rc < 0 — inspect errno.
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EPIPE) => {
                    // Read end already closed → tunnel already exited.
                    // Cancellation has effectively succeeded.
                    return Ok(());
                }
                _ => {
                    return Err(TunnelError::OpenConnect(format!(
                        "failed to write cancel byte: {err}"
                    )));
                }
            }
        }
    }
}

// CancelHandle has no Drop impl on purpose. See the type docstring:
// libopenconnect owns the cmd-pipe fds and frees them in
// openconnect_vpninfo_free.

impl OpenConnectSession {
    /// Create a new openconnect session with all callbacks set to `NULL`.
    ///
    /// libopenconnect tolerates null callbacks for progress/validate/auth when
    /// we provide a pre-obtained authcookie and skip internal authentication.
    pub fn new(useragent: &str) -> Result<Self, TunnelError> {
        let ua = CString::new(useragent)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid useragent: {e}")))?;

        // libopenconnect unconditionally calls the progress callback, so
        // we MUST supply a non-NULL function pointer — NULL here segfaults
        // on the first vpn_progress() in make_cstp_connection. The
        // variadic trampoline lives in gp-openconnect-sys/csrc and has
        // the exact `openconnect_progress_vfn` signature already.
        let progress: sys::openconnect_progress_vfn = Some(sys::pangolin_progress_trampoline);
        let inner = unsafe {
            sys::openconnect_vpninfo_new(ua.as_ptr(), None, None, None, progress, ptr::null_mut())
        };
        if inner.is_null() {
            return Err(TunnelError::OpenConnect(
                "openconnect_vpninfo_new returned NULL".into(),
            ));
        }

        // Ask libopenconnect to create its internal command pipe and hand
        // us the write end. It's now polled inside the main loop; writing
        // OC_CMD_CANCEL to this fd breaks the loop out cleanly.
        //
        // The read end is owned by libopenconnect and closed by
        // openconnect_vpninfo_free.
        let cmd_write_fd = unsafe { sys::openconnect_setup_cmd_pipe(inner) };
        if cmd_write_fd < 0 {
            unsafe { sys::openconnect_vpninfo_free(inner) };
            return Err(TunnelError::OpenConnect(
                "openconnect_setup_cmd_pipe returned error".into(),
            ));
        }

        Ok(Self {
            inner,
            cmd_write_fd: Some(cmd_write_fd),
        })
    }

    /// Take the cancel handle. Can only be called once per session.
    pub fn cancel_handle(&mut self) -> Option<CancelHandle> {
        self.cmd_write_fd
            .take()
            .map(|write_fd| CancelHandle { write_fd })
    }

    /// Select the GlobalProtect protocol.
    pub fn set_protocol_gp(&mut self) -> Result<(), TunnelError> {
        let rc = unsafe { sys::openconnect_set_protocol(self.inner, GP_PROTOCOL.as_ptr()) };
        ok_or_ffi(rc, "openconnect_set_protocol(gp)")
    }

    /// Set the portal/gateway hostname (e.g. `vpn.example.com`).
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), TunnelError> {
        let c = CString::new(hostname)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid hostname: {e}")))?;
        let rc = unsafe { sys::openconnect_set_hostname(self.inner, c.as_ptr()) };
        ok_or_ffi(rc, "openconnect_set_hostname")
    }

    /// Inject an authcookie obtained by the Rust auth flow.
    pub fn set_cookie(&mut self, cookie: &str) -> Result<(), TunnelError> {
        let c = CString::new(cookie)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid cookie: {e}")))?;
        let rc = unsafe { sys::openconnect_set_cookie(self.inner, c.as_ptr()) };
        ok_or_ffi(rc, "openconnect_set_cookie")
    }

    /// Set the reported client OS (`"win"`, `"mac-intel"`, `"linux"`, …).
    pub fn set_os_spoof(&mut self, os: &str) -> Result<(), TunnelError> {
        let c = CString::new(os)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid os string: {e}")))?;
        let rc = unsafe { sys::openconnect_set_reported_os(self.inner, c.as_ptr()) };
        ok_or_ffi(rc, "openconnect_set_reported_os")
    }

    /// Establish the CSTP connection (TLS control channel).
    pub fn make_cstp_connection(&mut self) -> Result<(), TunnelError> {
        let rc = unsafe { sys::openconnect_make_cstp_connection(self.inner) };
        ok_or_ffi(rc, "openconnect_make_cstp_connection")
    }

    /// Enable ESP / DTLS setup on the session.
    ///
    /// For the GlobalProtect protocol, libopenconnect's
    /// `openconnect_setup_dtls` is the gateway to `proto->udp_setup`,
    /// which in turn initialises the ESP state machine (probes,
    /// keepalives, fallback policy — see `esp.c:302-317` and
    /// `library.c:500-511` in upstream openconnect).
    ///
    /// **Skipping this call leaves `vpninfo->dtls_attempt_period = 0`**
    /// and means the initial ESP bring-up never runs. The tunnel will
    /// still work because libopenconnect falls back to the HTTPS
    /// transport, but it will run entirely over HTTPS — no ESP at
    /// all — which on networks that drop long-lived TCP connections
    /// (WSL2 NAT, aggressive corporate firewalls, home router NAT
    /// with short idle timers) gives a session lifetime of 2-3
    /// minutes instead of hours.
    ///
    /// yuezk/GlobalProtect-openconnect's `vpn.c:156` calls this
    /// unconditionally after `make_cstp_connection` and falls back
    /// to `openconnect_disable_dtls` on failure. We now do the same.
    ///
    /// `attempt_period_secs` is how long libopenconnect waits for
    /// the ESP probe to succeed before falling back to HTTPS.
    /// 60 seconds matches yuezk.
    ///
    /// Returns `true` if ESP setup succeeded (we should keep it
    /// enabled), `false` if it failed (caller should disable DTLS
    /// so mainloop runs pure-HTTPS cleanly).
    pub fn setup_esp(&mut self, attempt_period_secs: i32) -> bool {
        // Safety: `openconnect_setup_dtls` is safe to call on a
        // vpninfo that has had `openconnect_set_protocol` called
        // but has not yet entered the mainloop. It only mutates
        // vpninfo internal state.
        let rc = unsafe { sys::openconnect_setup_dtls(self.inner, attempt_period_secs) };
        rc == 0
    }

    /// Disable ESP / DTLS entirely, forcing the session to run
    /// pure HTTPS. Paired with [`Self::setup_esp`] so the caller
    /// can fall back cleanly when ESP probe fails.
    pub fn disable_esp(&mut self) {
        // openconnect_disable_dtls returns -EINVAL if DTLS is
        // already ESTABLISHED/CONNECTED; we don't care about the
        // return value on the setup-time path.
        let _ = unsafe { sys::openconnect_disable_dtls(self.inner) };
    }

    /// Create the TUN device. `vpnc_script` is the path to a vpnc-compatible
    /// script used by libopenconnect to configure routes/DNS. Pass `None` to
    /// skip (routes/DNS must then be configured externally).
    pub fn setup_tun_device(&mut self, vpnc_script: Option<&str>) -> Result<(), TunnelError> {
        let script = vpnc_script
            .map(|s| {
                CString::new(s)
                    .map_err(|e| TunnelError::OpenConnect(format!("invalid vpnc-script path: {e}")))
            })
            .transpose()?;
        let rc = unsafe {
            sys::openconnect_setup_tun_device(
                self.inner,
                script.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                ptr::null(),
            )
        };
        ok_or_ffi(rc, "openconnect_setup_tun_device")
    }

    /// Return the tun interface name libopenconnect assigned to this
    /// session (e.g. `"tun0"`), once [`setup_tun_device`] has been
    /// called successfully. Returns `None` before that, or if libopen-
    /// connect has no name to report.
    ///
    /// [`setup_tun_device`]: Self::setup_tun_device
    pub fn get_ifname(&self) -> Option<String> {
        let ptr = unsafe { sys::openconnect_get_ifname(self.inner) };
        if ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    /// Read the server-provided IP configuration (IPv4/IPv6 address,
    /// netmask, MTU, gateway) into a fully-owned [`IpInfoSnapshot`].
    ///
    /// The underlying `openconnect_get_ip_info` returns pointers into
    /// state owned by libopenconnect which become invalid on the next
    /// API call — we copy every field into Rust-owned strings before
    /// returning, so the snapshot is safe to hold across later calls.
    ///
    /// Must be called from the same OS thread as the session, per
    /// `openconnect.h`.
    pub fn get_ip_info(&self) -> Result<IpInfoSnapshot, TunnelError> {
        let mut info_ptr: *const sys::oc_ip_info = ptr::null();
        let rc = unsafe {
            sys::openconnect_get_ip_info(
                self.inner,
                &mut info_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(TunnelError::OpenConnect(format!(
                "openconnect_get_ip_info returned {rc}"
            )));
        }
        if info_ptr.is_null() {
            return Err(TunnelError::OpenConnect(
                "openconnect_get_ip_info produced a NULL info pointer".into(),
            ));
        }
        // SAFETY: libopenconnect guarantees the pointer is valid until
        // we call the next libopenconnect API. We only read fields and
        // copy strings; no pointers are retained.
        let info = unsafe { &*info_ptr };
        // oc_ip_info.dns is a fixed-size `[*const c_char; 3]` — each
        // slot is NULL when unused. Copy out the non-null ones.
        let mut dns = Vec::with_capacity(3);
        for slot in info.dns.iter() {
            if let Some(s) = cstr_to_opt_string(*slot) {
                dns.push(s);
            }
        }
        Ok(IpInfoSnapshot {
            addr: cstr_to_opt_string(info.addr),
            netmask: cstr_to_opt_string(info.netmask),
            addr6: cstr_to_opt_string(info.addr6),
            netmask6: cstr_to_opt_string(info.netmask6),
            gateway_addr: cstr_to_opt_string(info.gateway_addr),
            domain: cstr_to_opt_string(info.domain),
            mtu: if info.mtu > 0 {
                Some(info.mtu as u16)
            } else {
                None
            },
            dns,
        })
    }

    /// Run the tunnel main loop. Blocks until cancelled or the tunnel drops.
    ///
    /// `reconnect_timeout` is passed straight through to openconnect;
    /// set to 0 to disable libopenconnect's internal reconnection.
    ///
    /// # Error classification
    ///
    /// libopenconnect distinguishes several mainloop exit codes,
    /// each with very different caller semantics. Per upstream
    /// `mainloop.c:158-165`:
    ///
    /// * `0` — successful pause (the documented behaviour says the
    ///   caller may restart the loop). We treat this as `Ok(())`.
    /// * `-EINTR` — local cancel via `OC_CMD_CANCEL` (we sent it).
    ///   Treated as `Ok(())` — the caller asked for this.
    /// * `-EPIPE` — remote gateway explicitly terminated the
    ///   session. **Do not retry**: re-using the same cookie will
    ///   either be rejected immediately or get kicked again.
    ///   Mapped to [`TunnelError::MainloopTerminated`].
    /// * `-EPERM` — gateway returned 401, i.e. the authcookie is
    ///   no longer valid. **Do not retry** with the same cookie;
    ///   the caller needs to re-auth.
    ///   Mapped to [`TunnelError::MainloopAuthExpired`].
    /// * Any other negative value — generic mainloop failure,
    ///   probably a transient network/libopenconnect issue the
    ///   caller can retry. Mapped to [`TunnelError::MainloopOther`]
    ///   with the raw rc preserved for diagnostics.
    ///
    /// The app-level reconnect loop in `bins/pgn` checks
    /// [`TunnelError::is_terminal`] on the returned error and
    /// breaks out of the retry loop for terminal cases, avoiding
    /// the 60s-flap pathology.
    pub fn run(
        &mut self,
        reconnect_timeout: i32,
        reconnect_interval: i32,
    ) -> Result<(), TunnelError> {
        let rc =
            unsafe { sys::openconnect_mainloop(self.inner, reconnect_timeout, reconnect_interval) };
        if rc >= 0 {
            return Ok(());
        }
        // libc errno constants are positive; mainloop returns
        // the NEGATED form. Compare directly.
        if rc == -libc::EINTR {
            // We asked for this via OC_CMD_CANCEL.
            return Ok(());
        }
        if rc == -libc::EPIPE {
            return Err(TunnelError::MainloopTerminated);
        }
        if rc == -libc::EPERM {
            return Err(TunnelError::MainloopAuthExpired);
        }
        Err(TunnelError::MainloopOther(rc))
    }
}

impl Drop for OpenConnectSession {
    fn drop(&mut self) {
        // Don't close `cmd_write_fd` here: per openconnect.h,
        // openconnect_vpninfo_free closes both ends of the pipe created
        // by openconnect_setup_cmd_pipe. Closing the write fd ourselves
        // would race vpninfo_free into a double-close.
        self.cmd_write_fd = None;
        if !self.inner.is_null() {
            unsafe { sys::openconnect_vpninfo_free(self.inner) };
            self.inner = ptr::null_mut();
        }
    }
}

// OpenConnectSession is !Send + !Sync by default via the raw pointer field.

/// Rust-owned snapshot of libopenconnect's `oc_ip_info`. Every string
/// field is copied out of libopenconnect's internal storage so the
/// snapshot is safe to hold across subsequent API calls (which would
/// otherwise invalidate the pointers the raw struct returns).
#[derive(Debug, Clone, Default)]
pub struct IpInfoSnapshot {
    /// IPv4 address assigned by the server, e.g. `"10.1.2.3"`.
    pub addr: Option<String>,
    /// IPv4 netmask in dotted-quad form, e.g. `"255.255.255.255"`.
    pub netmask: Option<String>,
    /// IPv6 address in `"addr/prefixlen"` form.
    pub addr6: Option<String>,
    /// IPv6 netmask — libopenconnect stores the address+mask together.
    pub netmask6: Option<String>,
    /// Gateway address (derived locally by libopenconnect from
    /// `getnameinfo`, not server-controlled).
    pub gateway_addr: Option<String>,
    /// Search domain pushed by the server, if any.
    pub domain: Option<String>,
    /// MTU reported by the server. `None` if libopenconnect had to
    /// calculate it locally (which it logs as "No MTU received").
    pub mtu: Option<u16>,
    /// Up to three nameservers pushed by the server (libopenconnect
    /// stores them in `oc_ip_info.dns[3]`). Empty if the server
    /// didn't push any.
    pub dns: Vec<String>,
}

fn cstr_to_opt_string(ptr: *const libc::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `ptr` is a valid C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

fn ok_or_ffi(rc: libc::c_int, op: &str) -> Result<(), TunnelError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(TunnelError::OpenConnect(format!("{op} failed: rc={rc}")))
    }
}
