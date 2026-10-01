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
/// [`OpenConnectSession`] has been dropped. The current `opc` flow joins
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

/// Accept-all `validate_peer_cert` callback for `--insecure`
/// (issue #53). Returning 0 makes libopenconnect proceed past a
/// certificate verification failure; any non-zero would abort the
/// handshake. The reason string is logged at `warn` so the operator
/// can see WHAT was wrong with the cert even while accepting it —
/// the tunnel is up, but the log tells the truth.
///
/// # Safety
/// `reason` is a NUL-terminated C string from libopenconnect's
/// gnutls verify path (never NULL per upstream callers). `privdata`
/// is unused (we pass NULL to vpninfo_new).
unsafe extern "C" fn accept_invalid_cert(
    _privdata: *mut std::os::raw::c_void,
    reason: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let reason_str = if reason.is_null() {
        std::borrow::Cow::Borrowed("unknown reason")
    } else {
        std::ffi::CStr::from_ptr(reason).to_string_lossy()
    };
    tracing::warn!(
        target: "openconnect",
        "TLS certificate verification failed but accepted (--insecure): {reason_str}"
    );
    0
}

// CancelHandle has no Drop impl on purpose. See the type docstring:
// libopenconnect owns the cmd-pipe fds and frees them in
// openconnect_vpninfo_free.

impl OpenConnectSession {
    /// Create a new openconnect session.
    ///
    /// libopenconnect tolerates null callbacks for write-config/auth
    /// when we provide a pre-obtained authcookie and skip internal
    /// authentication. The progress callback MUST be non-NULL (see
    /// below). The `validate_peer_cert` callback is the ONLY upstream
    /// v9.21 mechanism for accepting a certificate that fails
    /// verification (issue #53): with `None`, gnutls's verify_peer
    /// makes ANY failure — self-signed, private CA, or a name-issued
    /// cert that does not cover the gateway IP — fatal
    /// (`GNUTLS_E_CERTIFICATE_ERROR` → `cstp_handshake` -EIO →
    /// `make_cstp_connection` rc=-5). There is no public setter for
    /// the callback after construction (openconnect.h exposes it only
    /// as a `vpninfo_new` parameter), which is why the flag must be
    /// known here.
    ///
    /// `insecure == true` installs an accept-all validate callback
    /// that logs the verification reason at `warn` and returns 0
    /// (accept) — mirroring what the auth lane's
    /// `danger_accept_invalid_certs(true)` already does for reqwest.
    /// `insecure == false` keeps the previous behavior exactly: NULL
    /// callback, full verification.
    ///
    /// Trap documented in issue #53 so nobody re-fixes this wrong:
    /// `openconnect_set_system_trust(0)` alone is NOT a fix — it does
    /// not skip verify_peer's hostname check and, with no trust
    /// anchors, the chain check fails too, which the NULL callback
    /// still turns into a hard abort. The constructor-time validate
    /// callback is the only correct primitive.
    pub fn new(useragent: &str, insecure: bool) -> Result<Self, TunnelError> {
        let ua = CString::new(useragent)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid useragent: {e}")))?;

        // libopenconnect unconditionally calls the progress callback, so
        // we MUST supply a non-NULL function pointer — NULL here segfaults
        // on the first vpn_progress() in make_cstp_connection. The
        // variadic trampoline lives in gp-openconnect-sys/csrc and has
        // the exact `openconnect_progress_vfn` signature already.
        let progress: sys::openconnect_progress_vfn = Some(sys::openprotect_progress_trampoline);
        // validate_peer_cert: accept-all under --insecure (issue #53).
        // The vfn is plain (non-variadic) so a Rust extern "C" fn works
        // directly — no C trampoline needed, unlike progress. Type the
        // local as the bare fn-pointer and let Option::Some coerce it
        // (a bare fn item does not unify with the Option<fn-pointer>
        // parameter on its own under real-FFI builds — E0308, seen in
        // the first #55 CI round; and `as` cannot cast a fn item to an
        // Option — E0605, seen in the second round. The typed-local
        // pattern is the same one `progress` above uses).
        let validate_fn: sys::openconnect_validate_peer_cert_vfn = if insecure {
            Some(accept_invalid_cert)
        } else {
            None
        };
        let inner = unsafe {
            sys::openconnect_vpninfo_new(
                ua.as_ptr(),
                validate_fn,
                None,
                None,
                progress,
                ptr::null_mut(),
            )
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

    /// Set hostname + port (+ urlpath) from a full `https://host[:port]`
    /// URL literal.
    ///
    /// Issue #43: this is the ONLY public libopenconnect v9.21
    /// entrypoint that applies a non-default CSTP port —
    /// `openconnect_set_hostname` STRDUPs its argument verbatim and
    /// never touches `vpninfo->port` (library.c:995-1006), and there
    /// is no public `openconnect_set_port` (the header exports only
    /// the getter, `openconnect_get_port`, library.c:1223). The
    /// official CLI feeds its raw `--server` argument — which may
    /// carry `host:port` — to exactly this call (main.c:2376-2382 ->
    /// library.c:1262 -> internal_parse_url, http.c:537-602).
    ///
    /// What the call verifies, from the v9.21 source (NOT what an
    /// earlier comment here claimed — it does NOT reject malformed
    /// authorities): `openconnect_parse_url` requires an `https`
    /// scheme (library.c:1279-1284, `-EINVAL` otherwise) and
    /// `internal_parse_url` `-EINVAL`s only a port tail that
    /// `strtol` consumes wholly yet which lands outside 1..=0xffff
    /// (http.c:581-587). A tail like `host:abc` is RETAINED verbatim
    /// in `vpninfo->hostname` (http.c:576-590) and dies later in
    /// `getaddrinfo`. Hence IPv6 hosts must arrive pre-bracketed and
    /// only fully-split halves are ever synthesized here — the
    /// fail-closed gate is [`crate::parse_tunnel_target`], not the
    /// library.
    pub fn parse_url(&mut self, url: &str) -> Result<(), TunnelError> {
        let c = CString::new(url)
            .map_err(|e| TunnelError::OpenConnect(format!("invalid connect url: {e}")))?;
        let rc = unsafe { sys::openconnect_parse_url(self.inner, c.as_ptr()) };
        ok_or_ffi(rc, "openconnect_parse_url")
    }

    /// Read back `vpninfo->port` — diagnostic / test hook for the
    /// issue #43 split-and-set contract (the public API exports the
    /// getter but deliberately no setter).
    pub fn get_port(&self) -> i32 {
        unsafe { sys::openconnect_get_port(self.inner) }
    }

    /// Read back the raw `vpninfo->hostname` — diagnostic / test
    /// hook alongside [`Self::get_port`] (the #43 split-and-set
    /// contract). Deliberately `openconnect_get_dnsname`, not
    /// `openconnect_get_hostname`: per library.c the latter
    /// prefers `unique_hostname` (the resolved IP literal) once a
    /// connection has proceeded.
    pub fn get_dnsname(&self) -> Option<String> {
        // SAFETY: returns a pointer into vpninfo-owned storage valid
        // until the next libopenconnect call; we copy immediately.
        cstr_to_opt_string(unsafe { sys::openconnect_get_dnsname(self.inner) })
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
    /// 00:31:07.642  HIP: gateway reports client_ip=198.51.100.44 (pre-CSTP)
    /// 00:31:07.668  HIP: report submitted successfully
    /// 00:31:07.718  libopenconnect: assigned client_ip=198.51.100.45 (post-CSTP)
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
    ///   (same process as opc); any other uid triggers
    ///   `set_csd_user` to drop privileges before exec. OpenProtect
    ///   runs as root via sudo, so passing either works; we prefer
    ///   dropping to the real user (`SUDO_UID`) when available so
    ///   the wrapper doesn't have tun/route capabilities it doesn't
    ///   need.
    /// * `silent` — passed through to libopenconnect. yuezk hard-
    ///   codes `true`; we do the same.
    /// * `wrapper_path` — absolute filesystem path to the executable.
    ///   opc re-execs itself via `std::env::current_exe()` so this
    ///   is typically `/usr/local/bin/opc` (or wherever the binary
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
            // Windows (upstream returns -EPERM). HIP reports are
            // submitted via the gp-hip builtin XML generator instead
            // — `bins/opc/src/main.rs::submit_hip_from_rust` runs
            // after `setup_tun_device` returns and POSTs the report
            // through the same gateway TLS endpoint. Log at debug so
            // the (entirely expected) lack of csd-wrapper support
            // doesn't read like a warning a user has to act on.
            let _ = (uid, silent, wrapper_path);
            tracing::debug!(
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
    /// The app-level reconnect loop in `bins/opc` checks
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

/// The issue #43 `SessionHandle` surface: forwards to the inherent
/// wrappers above so the generic tunnel-setup seam (and its
/// recording double in `bins/opc`) drives exactly the same FFI calls
/// production does.
impl crate::SessionHandle for OpenConnectSession {
    fn set_protocol_gp(&mut self) -> Result<(), TunnelError> {
        Self::set_protocol_gp(self)
    }
    fn set_hostname(&mut self, hostname: &str) -> Result<(), TunnelError> {
        Self::set_hostname(self, hostname)
    }
    fn parse_url(&mut self, url: &str) -> Result<(), TunnelError> {
        Self::parse_url(self, url)
    }
    fn set_os_spoof(&mut self, os: &str) -> Result<(), TunnelError> {
        Self::set_os_spoof(self, os)
    }
    fn set_cookie(&mut self, cookie: &str) -> Result<(), TunnelError> {
        Self::set_cookie(self, cookie)
    }
    fn set_client_cert(&mut self, cert: &str, key: &str) -> Result<(), TunnelError> {
        Self::set_client_cert(self, cert, key)
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

/// Proof of the issue #43 contract against the REAL libopenconnect
/// FFI, gated on `cfg(has_openconnect)` — i.e. on bindgen having
/// produced bindings, NOT on `OPENCONNECT_DIR` being set on every
/// host: on Windows build.rs links via `OPENCONNECT_DIR` (the
/// release-Windows job sets it but only runs `cargo build --release`,
/// never these tests), on Unix it probes pkg-config (the Ubuntu CI
/// `check` job installs `libopenconnect-dev` for exactly this). Stub
/// builds (bindings not generated — Windows without `OPENCONNECT_DIR`,
/// Unix without a pkg-config-discoverable libopenconnect) do not
/// compile `openconnect.rs` at all, which is structurally why local
/// Windows unit runs never exercised the FFI path #43 broke on. They
/// create a throwaway `vpninfo` (no network, no connect call), read
/// the state back through the public getters, and free it on drop.
#[cfg(test)]
mod target_ffi_tests {
    use super::*;
    use crate::SessionHandle as _;

    /// RED-in-spirit for alpha.23: today the wrapper never applies
    /// a port at all; after the fix a port-bearing target must land
    /// on 11443 via `openconnect_parse_url`, brackets included.
    #[test]
    fn configure_target_uses_parse_url_when_port_present() {
        let mut s = OpenConnectSession::new("opc-test", false).expect("vpninfo_new");
        let t = crate::parse_tunnel_target("[fd00::1]:11443").expect("split");
        s.configure_target(&t).expect("configure_target");
        assert_eq!(s.get_port(), 11443, "port must reach vpninfo->port");
        assert_eq!(s.get_dnsname().as_deref(), Some("[fd00::1]"));
    }

    /// UNSW daily-connect no-regression pin: the port-less lane
    /// keeps riding `openconnect_set_hostname` verbatim and
    /// `vpninfo->port` stays at the library default 443
    /// (library.c:106).
    #[test]
    fn configure_target_no_port_keeps_set_hostname_and_default_443() {
        let mut s = OpenConnectSession::new("opc-test", false).expect("vpninfo_new");
        let t = crate::parse_tunnel_target("ra.vpn.unsw.edu.au").expect("split");
        s.configure_target(&t).expect("configure_target");
        assert_eq!(s.get_port(), 443);
        assert_eq!(s.get_dnsname().as_deref(), Some("ra.vpn.unsw.edu.au"));
    }

    /// Issue #53: the insecure construction (accept-all
    /// validate_peer_cert callback installed) must build and tear
    /// down cleanly through the real FFI. The callback only fires on
    /// an actual verification failure (needs a live TLS endpoint to
    /// exercise end-to-end), so what is pinned here is the
    /// construction path itself: vpninfo_new accepts the callback,
    /// the cmd pipe sets up, and Drop frees without exploding.
    #[test]
    fn insecure_session_constructs_with_accept_callback() {
        let mut s =
            OpenConnectSession::new("opc-test", true).expect("vpninfo_new with accept callback");
        let t = crate::parse_tunnel_target("203.0.113.7:11443").expect("split");
        s.configure_target(&t).expect("configure_target");
        assert_eq!(s.get_port(), 11443);
        drop(s); // vpninfo_free with the callback still installed
    }
}
