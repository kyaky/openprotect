//! Safe Rust wrapper around `libopenconnect`.
//!
//! Only the subset of the API needed for GlobalProtect tunnels is exposed:
//! session creation, protocol/cookie/OS setup, CSTP connect + TUN setup,
//! blocking main loop, and asynchronous cancellation via a pipe fd.

use std::ffi::{CStr, CString};
use std::ptr;

use gp_openconnect_sys as sys;

use crate::TunnelError;

const GP_PROTOCOL: &CStr = c"gp";

/// Platform alias for the cmd-pipe write end.
/// Unix: pipe fd (c_int). Windows: socket (SOCKET = u64).
#[cfg(not(windows))]
type CmdWriteFd = libc::c_int;
#[cfg(windows)]
type CmdWriteFd = sys::SOCKET;

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
    cmd_write_fd: Option<CmdWriteFd>,
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
    write_fd: CmdWriteFd,
}

impl CancelHandle {
    /// Signal the session's main loop to exit.
    ///
    /// On Unix: `write(fd, OC_CMD_CANCEL, 1)` to the pipe fd.
    /// On Windows: `send(socket, OC_CMD_CANCEL, 1, 0)` to the socket pair.
    pub fn cancel(&self) -> Result<(), TunnelError> {
        #[allow(clippy::unnecessary_cast)]
        let buf = [sys::OC_CMD_CANCEL as u8];
        loop {
            #[cfg(not(windows))]
            let rc = unsafe { libc::write(self.write_fd, buf.as_ptr() as *const libc::c_void, 1) };
            #[cfg(windows)]
            let rc = unsafe {
                extern "system" {
                    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
                }
                send(self.write_fd as usize, buf.as_ptr(), 1, 0) as isize
            };

            if rc == 1 {
                return Ok(());
            }
            if rc == 0 {
                return Err(TunnelError::OpenConnect(
                    "cancel write/send returned 0 bytes".into(),
                ));
            }
            // Use WSAGetLastError on Windows, errno on Unix.
            #[cfg(not(windows))]
            let err = std::io::Error::last_os_error();
            #[cfg(windows)]
            let err = std::io::Error::from_raw_os_error(unsafe {
                extern "system" {
                    fn WSAGetLastError() -> i32;
                }
                WSAGetLastError()
            });
            match err.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected => {
                    // Peer already closed → tunnel exited → cancellation succeeded.
                    return Ok(());
                }
                _ => {
                    return Err(TunnelError::OpenConnect(format!("cancel failed: {err}")));
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
        // On Unix: returns -1 on error (c_int).
        // On Windows: returns INVALID_SOCKET (!0u64) on error.
        #[cfg(not(windows))]
        let cmd_pipe_ok = cmd_write_fd >= 0;
        #[cfg(windows)]
        let cmd_pipe_ok = cmd_write_fd != !0 as sys::SOCKET;
        if !cmd_pipe_ok {
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

    /// Set client certificate + private key for mutual TLS at the
    /// libopenconnect level. Both paths must be PEM-encoded.
    /// For PKCS#12, the caller should extract PEM files first.
    pub fn set_client_cert(&mut self, cert: &str, key: &str) -> Result<(), TunnelError> {
        let c_cert = CString::new(cert)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid cert path: {e}")))?;
        let c_key = CString::new(key)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid key path: {e}")))?;
        let rc = unsafe {
            sys::openconnect_set_client_cert(self.inner, c_cert.as_ptr(), c_key.as_ptr())
        };
        ok_or_ffi(rc, "openconnect_set_client_cert")
    }

    /// Set the reported client OS (`"win"`, `"mac-intel"`, `"linux"`, …).
    pub fn set_os_spoof(&mut self, os: &str) -> Result<(), TunnelError> {
        let c = CString::new(os)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid os string: {e}")))?;
        let rc = unsafe { sys::openconnect_set_reported_os(self.inner, c.as_ptr()) };
        ok_or_ffi(rc, "openconnect_set_reported_os")
    }

    /// Register a CSD (Cisco Secure Desktop) wrapper executable.
    ///
    /// For the GlobalProtect protocol, libopenconnect uses the same
    /// mechanism to dispatch **HIP report generation** to an external
    /// helper. When the gateway says it needs a HIP report (via
    /// `hipreportcheck.esp` returning `hip-report-needed=yes`),
    /// libopenconnect `fork()` + `execv()`s the wrapper binary with a
    /// specific argv contract and reads the wrapper's stdout as the
    /// HIP XML, then POSTs that XML to `/ssl-vpn/hipreport.esp` on
    /// its **own** TLS session — the same session that just ran
    /// `getconfig.esp` during `make_cstp_connection`.
    ///
    /// This is load-bearing for HIP correctness on gateways that
    /// rotate client IPs per getconfig request (Prisma Access does
    /// this). If we submit HIP from a separate Rust `reqwest` session
    /// using a `client_ip` we fetched earlier, the gateway will
    /// assign libopenconnect a DIFFERENT `client_ip` during its CSTP
    /// setup, and our HIP record lands under the wrong session key.
    /// Result: the 60-second HIP grace window expires without a
    /// valid HIP report credited to libopenconnect's CSTP session
    /// and the gateway kicks the client. Confirmed live against UNSW
    /// Prisma Access on 2026-04-14:
    ///
    /// ```text
    /// 00:31:07.642  HIP: gateway reports client_ip=172.26.6.44 (pre-CSTP)
    /// 00:31:07.668  HIP: report submitted successfully
    /// 00:31:07.718  libopenconnect: assigned client_ip=172.26.6.45 (post-CSTP)
    /// 00:32:07.714  Gateway disconnected immediately after GET-tunnel request.
    /// ```
    ///
    /// The wrapper contract (upstream openconnect gpst.c:1012-1027):
    ///
    /// ```text
    /// argv[0] = <wrapper_path>
    /// --cookie <urlencoded cookie>
    /// [--client-ip <v4>]
    /// [--client-ipv6 <v6>]
    /// --md5 <csd token>
    /// --client-os <Windows|Linux|Mac>
    /// ```
    ///
    /// The wrapper MUST print a valid HIP XML document to stdout and
    /// exit 0. libopenconnect reads stdin until EOF, writes the bytes
    /// as the `report` form field on its hipreport.esp POST, and
    /// credits the HIP report against its own CSTP session key.
    ///
    /// # Arguments
    ///
    /// * `uid` — user to `execv` the wrapper as. `0` = run as root
    ///   (same process as pgn); any other uid triggers
    ///   `set_csd_user` to drop privileges before exec. Pangolin
    ///   runs as root via sudo, so passing either works; we prefer
    ///   dropping to the real user (`SUDO_UID`) when available so
    ///   the wrapper doesn't have tun/route capabilities it doesn't
    ///   need.
    /// * `silent` — passed through to libopenconnect. yuezk hard-
    ///   codes `true`; we do the same.
    /// * `wrapper_path` — absolute filesystem path to the executable.
    ///   pgn re-execs itself via `std::env::current_exe()` so this
    ///   is typically `/usr/local/bin/pgn` (or wherever the binary
    ///   lives).
    ///
    /// **Must be called BEFORE `make_cstp_connection`** — otherwise
    /// libopenconnect will hit `hipreportcheck.esp` without a wrapper
    /// configured and fall through to its "WARNING: Server asked us
    /// to submit HIP report" path, which doesn't submit anything.
    pub fn setup_csd(
        &mut self,
        uid: u32,
        silent: bool,
        wrapper_path: &str,
    ) -> Result<(), TunnelError> {
        #[cfg(not(windows))]
        {
            let c = CString::new(wrapper_path)
                .map_err(|e| TunnelError::OpenConnect(format!("invalid csd wrapper path: {e}")))?;
            let rc = unsafe {
                sys::openconnect_setup_csd(
                    self.inner,
                    uid as libc::uid_t,
                    silent as libc::c_int,
                    c.as_ptr(),
                )
            };
            ok_or_ffi(rc, "openconnect_setup_csd")
        }
        #[cfg(windows)]
        {
            // openconnect does not support CSD/HIP script execution on
            // Windows (upstream returns -EPERM). HIP reports must be
            // submitted via gp-hip's builtin XML generator instead.
            let _ = (uid, silent, wrapper_path);
            tracing::warn!(
                "setup_csd: HIP script execution not supported on Windows; \
                 use builtin HIP report generation instead"
            );
            Ok(())
        }
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
    /// Returns the raw `openconnect_setup_dtls` return code:
    /// `0` means ESP/DTLS state machine initialised successfully
    /// (caller should let the probe run), non-zero means FFI-level
    /// setup failed (caller should `disable_esp()` so the mainloop
    /// runs pure-HTTPS cleanly).
    ///
    /// NOTE: rc=0 only means libopenconnect accepted the setup
    /// call — it does NOT mean the actual ESP probe has yet
    /// succeeded or that the runtime tunnel will stay on ESP.
    /// Those state transitions happen inside the mainloop and
    /// are surfaced only through progress callback messages
    /// (`ESP tunnel connected; exiting HTTPS mainloop`, etc.),
    /// so do not treat rc=0 as a "gateway is ESP-friendly"
    /// signal on its own.
    pub fn setup_esp(&mut self, attempt_period_secs: i32) -> i32 {
        // Safety: `openconnect_setup_dtls` is safe to call on a
        // vpninfo that has had `openconnect_set_protocol` called
        // but has not yet entered the mainloop. It only mutates
        // vpninfo internal state.
        unsafe { sys::openconnect_setup_dtls(self.inner, attempt_period_secs) }
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
