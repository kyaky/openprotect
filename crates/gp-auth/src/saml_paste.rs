//! Headless SAML authentication via an external browser + paste callback.
//!
//! This provider has zero GUI dependencies. It's the canonical
//! desktop AND server auth path for openprotect — anywhere a user has
//! access to a browser (their own, not an embedded one) and can
//! copy one URL back to the terminal. Used to be one of two SAML
//! providers in-tree; the embedded webview alternative was removed
//! during the headless-first architecture cleanup, so this is now
//! the primary SAML flow.
//!
//! Flow:
//!
//! 1. opc starts a tiny HTTP server on `127.0.0.1:<port>`. Port defaults
//!    to 0 — the OS picks a free ephemeral port each run so two opc
//!    invocations (or a crashed previous one stuck in TIME_WAIT) can't
//!    collide. The actual bound port is read back via `local_addr()` and
//!    printed in the instructions. Users who want a fixed port for
//!    bookmarks / SSH tunnels can pass `--saml-port <N>`.
//!    If a Tailscale interface is detected on the host, a second listener
//!    binds to the Tailscale IP at the same port so any device on the
//!    user's tailnet can reach the page directly — no SSH tunnel needed.
//!    Both listeners serve the exact same content via two threads.
//! 2. The server serves a launch page at `/` that either (a) redirects
//!    the browser to the IdP SAML URL (`REDIRECT` method) or (b) renders
//!    the auto-submitting HTML form that comes from the portal (`POST`
//!    method, base64-decoded).
//! 3. opc prints the reachable URL(s) to the terminal along with
//!    instructions. If no Tailscale, the terminal hint includes an
//!    `ssh -L <port>:localhost:<port> user@<host>` line, where `<host>` is
//!    the detected public IP (best-effort via api.ipify.org) or a
//!    `<user>@<this-host>` placeholder.
//! 4. The user completes the IdP flow (Azure AD, Okta, Shib, …). GP's
//!    final step redirects the browser to a custom
//!    `globalprotectcallback:…` scheme that browsers can't handle. The
//!    user copies that URL out of the address bar / the error page.
//! 5. There are two ways to hand the URL back to opc:
//!    - **Paste it into the terminal.** opc is reading stdin line-by-line
//!      while the server runs.
//!    - **POST it to `/callback`**, either manually
//!      (`curl -X POST http://localhost:<port>/callback -d 'url=…'`) or
//!      via the bookmarklet printed on the launch page.
//! 6. Whichever path fires first wins; the server + stdin reader both
//!    shut down and opc continues.
//!
//! No display, no embedded browser, no GTK main loop — just HTTP + stdin.

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(unix)]
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use gp_proto::prelogin::{PreloginResponse, SamlPrelogin};
use gp_proto::Credential;

use crate::context::AuthContext;
use crate::error::AuthError;
use crate::saml_common::{parse_globalprotect_callback, SamlCapture};
use crate::AuthProvider;

/// Default port for the local callback server.
///
/// `0` means "let the OS pick a free ephemeral port". A fixed default
/// would conflict with any previous opc invocation whose socket is
/// still stuck in TIME_WAIT (the common case after a crash or Ctrl-C
/// during the paste step) and would refuse to bind. Each fresh
/// invocation now gets a clean port the kernel guarantees is free.
///
/// Users who need a predictable port (SSH port-forwarding bookmarks,
/// firewall rules, a parked browser tab) can pin one explicitly via
/// `--saml-port <N>` on the CLI or `saml_port = N` in a profile.
pub const DEFAULT_PORT: u16 = 0;

/// Headless SAML provider — no GUI required.
pub struct SamlPasteAuthProvider {
    /// Local port to bind the callback server on. 0 = pick any free port.
    pub port: u16,
}

impl SamlPasteAuthProvider {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

impl Default for SamlPasteAuthProvider {
    fn default() -> Self {
        Self::new(DEFAULT_PORT)
    }
}

#[async_trait]
impl AuthProvider for SamlPasteAuthProvider {
    fn name(&self) -> &str {
        "saml-paste"
    }

    fn can_handle(&self, prelogin: &PreloginResponse) -> bool {
        matches!(prelogin, PreloginResponse::Saml(_))
    }

    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        _ctx: &AuthContext,
    ) -> Result<Credential, AuthError> {
        let saml = match prelogin {
            PreloginResponse::Saml(s) => s.clone(),
            _ => return Err(AuthError::Failed("not a SAML prelogin response".into())),
        };

        let port = self.port;
        let capture = tokio::task::spawn_blocking(move || run_paste_flow(&saml, port))
            .await
            .map_err(|e| AuthError::Failed(format!("paste provider join error: {e}")))??;

        tracing::info!("saml capture (paste): user={}", capture.username);
        Ok(capture.into_credential())
    }
}

/// Run the blocking paste flow on the calling thread. Returns as soon as
/// either the stdin reader or the HTTP callback fires.
#[cfg(unix)]
fn run_paste_flow(saml: &SamlPrelogin, port: u16) -> Result<SamlCapture, AuthError> {
    // Turn off TTY echo on stdin for the entire duration of the paste
    // flow. The callback URL contains a short-TTL SAML JWT with the
    // user's identity; echoing it to the terminal means `script(1)`,
    // tmux pane capture, terminal scrollback, and over-the-shoulder
    // readers all see the token. Without echo the user still types
    // fine and the `Enter` keypress still commits the line through our
    // raw stdin reader — they just don't see characters while pasting.
    // We also drop canonical mode here because macOS tty line
    // discipline caps pasted lines at roughly 1024 bytes, which is too
    // short for many SAML JWT callbacks. We restore the prior termios
    // state on every exit path via RAII so a panic in the server thread
    // or an `Err(?)` on `build_launch_body` cannot leave the user's
    // terminal in a modified state.
    //
    // If stdin is not a TTY (piped input, redirected file, cron job,
    // test harness) the guard is a no-op and we stay silent.
    let _echo_guard = TtyEchoGuard::new(libc::STDIN_FILENO);

    // Decode the SAML launch content up front so the server thread can
    // own a plain byte vector without caring about the method.
    let launch_body = build_launch_body(saml)?;

    let loopback_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let loopback_listener = TcpListener::bind(loopback_addr)
        .map_err(|e| AuthError::Failed(format!("bind {loopback_addr}: {e}")))?;
    let actual_addr = loopback_listener
        .local_addr()
        .map_err(|e| AuthError::Failed(format!("local_addr: {e}")))?;
    loopback_listener
        .set_nonblocking(false)
        .map_err(|e| AuthError::Failed(format!("set_blocking: {e}")))?;

    // If Tailscale is up, bind a second listener on the Tailscale IP at
    // the same port. That lets the user open the URL directly from any
    // device on their tailnet — no SSH tunnel needed. Binding to the
    // specific Tailscale IP (not 0.0.0.0) keeps the listener off every
    // other interface (LAN, public).
    let tailscale_ip = detect_tailscale_ipv4();
    let tailscale_listener = tailscale_ip.and_then(|ip| {
        let ts_addr: SocketAddr = (ip, actual_addr.port()).into();
        match TcpListener::bind(ts_addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(false);
                Some((ts_addr, l))
            }
            Err(e) => {
                tracing::debug!("tailscale listener bind {ts_addr} failed: {e}");
                None
            }
        }
    });

    // Public-IP hint only when there's no Tailscale (scenario B).
    // Costs a single short HTTP call out to api.ipify.org; 2s timeout.
    let public_ip = if tailscale_ip.is_none() {
        detect_public_ipv4()
    } else {
        None
    };

    print_instructions(&actual_addr, tailscale_ip, public_ip, saml);

    let (tx, rx) = mpsc::channel::<SamlCapture>();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Self-pipe used to wake the stdin reader out of its `poll(2)` when
    // the HTTP path captures first. Closing the write end fires `POLLHUP`
    // on the read end; the reader exits cleanly without holding the
    // stdin lock — critical, otherwise it would block the gateway
    // login MFA prompt that follows in `opc connect`.
    let (stdin_wake_read, stdin_wake_write) = make_pipe()?;

    // --- HTTP server thread: loopback ---
    let loopback_tx = tx.clone();
    let loopback_shutdown = std::sync::Arc::clone(&shutdown);
    let loopback_body = launch_body.clone();
    let loopback_thread = thread::Builder::new()
        .name("opc-saml-http-lo".into())
        .spawn(move || {
            http_server_loop(
                loopback_listener,
                loopback_body,
                loopback_tx,
                loopback_shutdown,
            )
        })
        .map_err(|e| AuthError::Failed(format!("spawn http server: {e}")))?;

    // --- HTTP server thread: Tailscale (optional) ---
    let tailscale_thread = if let Some((ts_addr, ts_listener)) = tailscale_listener {
        let ts_tx = tx.clone();
        let ts_shutdown = std::sync::Arc::clone(&shutdown);
        let ts_body = launch_body.clone();
        let t = thread::Builder::new()
            .name("opc-saml-http-ts".into())
            .spawn(move || http_server_loop(ts_listener, ts_body, ts_tx, ts_shutdown))
            .map_err(|e| AuthError::Failed(format!("spawn tailscale http server: {e}")))?;
        Some((ts_addr, t))
    } else {
        None
    };

    // --- stdin reader thread ---
    // The reader takes ownership of the read end of the wake pipe and
    // polls both stdin and that fd. The main thread keeps the write end
    // and drops it on shutdown, signalling the reader via POLLHUP.
    let stdin_tx = tx.clone();
    let stdin_thread = thread::Builder::new()
        .name("opc-saml-stdin".into())
        .spawn(move || stdin_reader_loop(stdin_tx, stdin_wake_read))
        .map_err(|e| AuthError::Failed(format!("spawn stdin reader: {e}")))?;

    // Drop our own clone of `tx` so the channel closes once all workers exit.
    drop(tx);

    // Wait for a capture from whichever source gets there first.
    let result = rx.recv().map_err(|_| {
        AuthError::Failed(
            "both callback and stdin readers closed without producing a capture".into(),
        )
    });

    // Signal all workers to stop.
    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

    // Wake the stdin reader by closing the wake pipe's write end. POLLHUP
    // on the reader's poll(2) call fires immediately and the reader exits.
    drop(stdin_wake_write);

    // Poke each HTTP listener with a throwaway connection so its blocking
    // `accept()` returns and the thread sees the shutdown flag. Errors
    // here are ignored — the thread will exit on the next real connection
    // or when the process does.
    let _ = TcpStream::connect_timeout(&actual_addr, Duration::from_millis(200));
    if let Some((ts_addr, _)) = &tailscale_thread {
        let _ = TcpStream::connect_timeout(ts_addr, Duration::from_millis(200));
    }

    // Join every thread so none lingers — the stdin reader in particular
    // MUST be gone before opc returns to collect MFA input. Joining also
    // ensures the TcpListener inside each thread is dropped, which is
    // what actually closes the kernel socket and releases the port.
    let _ = loopback_thread.join();
    if let Some((_, t)) = tailscale_thread {
        let _ = t.join();
    }
    let _ = stdin_thread.join();

    // Belt-and-suspenders: confirm the port really is gone. The kernel
    // can still hold it in TIME_WAIT for ~120s after close, but a fresh
    // bind on the SAME ephemeral port number is now impossible anyway
    // (port 0 next run picks a different free port). This probe just
    // documents the release in the log so operators chasing a
    // "callback server didn't close" report have a clear data point.
    let released = TcpListener::bind(actual_addr).is_ok();
    tracing::debug!(
        "saml callback server: released {} (rebind ok = {})",
        actual_addr,
        released
    );

    result
}

/// Windows version: HTTP callback **and** terminal paste both work.
///
/// The user opens the SAML URL in a browser, completes authentication,
/// then either:
/// - Pastes the `globalprotectcallback:` URL into the opc terminal and
///   presses Enter — same UX as Linux / macOS, OR
/// - POSTs the URI to `http://127.0.0.1:<port>/callback` (used by the
///   GUI and the documented `curl` one-liner), OR
/// - Uses the bookmarklet on the launch page.
///
/// The Windows console `ReadFile` is interruptible only via
/// `CancelSynchronousIo`, so the stdin reader thread duplicates its
/// own `GetCurrentThread` pseudo-handle into a real handle and hands
/// that to the parent. When the HTTP path wins, the parent:
///
///   1. flips the shutdown flag,
///   2. calls `CancelSynchronousIo` on the saved handle (the reader's
///      blocked `ReadFile` returns `ERROR_OPERATION_ABORTED`),
///   3. **joins** the reader thread so its `StdinLock` is fully
///      dropped before this function returns,
///   4. only then `CloseHandle`s the duplicated handle.
///
/// That ordering matters because re-auth on a long-lived session can
/// call `authenticate(..)` again on a fresh `SamlPasteAuthProvider`
/// — if the previous reader were still holding the stdin lock when
/// the new one tried to acquire it, both would deadlock. Joining
/// guarantees the lock is released before we return control to the
/// caller.
#[cfg(windows)]
fn run_paste_flow(saml: &SamlPrelogin, port: u16) -> Result<SamlCapture, AuthError> {
    let launch_body = build_launch_body(saml)?;

    let bind_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| AuthError::Failed(format!("bind {bind_addr}: {e}")))?;
    let actual_addr = listener
        .local_addr()
        .map_err(|e| AuthError::Failed(format!("local_addr: {e}")))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| AuthError::Failed(format!("set_blocking: {e}")))?;

    eprintln!();
    eprintln!("┌─ OpenProtect — headless SAML authentication ─────────────────────────────────┐");
    eprintln!("│                                                                            │");
    eprintln!("│  1. Open this URL in any browser:                                          │");
    eprintln!("│                                                                            │");
    eprintln!("│    http://{actual_addr}/");
    eprintln!("│                                                                            │");
    eprintln!("│  2. Complete the login (Azure AD, Okta, etc.)                              │");
    eprintln!("│                                                                            │");
    eprintln!("│  3. The browser will show 'globalprotectcallback:...' — copy that URL.     │");
    eprintln!("│                                                                            │");
    eprintln!("│  4. Hand it back to opc — pick either method:                              │");
    eprintln!("│                                                                            │");
    eprintln!("│     a) Paste the URL right here and press Enter, OR                        │");
    eprintln!("│     b) From another shell, POST it:                                        │");
    eprintln!("│        curl.exe -X POST http://{actual_addr}/callback --data-raw '<URL>'");
    eprintln!("│                                                                            │");
    eprintln!("│  Tip: use SINGLE quotes around the URL — PowerShell expands & in double.   │");
    eprintln!("└────────────────────────────────────────────────────────────────────────────┘");
    eprintln!();

    let (tx, rx) = mpsc::channel::<SamlCapture>();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // HTTP server thread.
    let server_tx = tx.clone();
    let server_shutdown = std::sync::Arc::clone(&shutdown);
    let server_body = launch_body;
    let server_thread = thread::Builder::new()
        .name("opc-saml-http".into())
        .spawn(move || http_server_loop(listener, server_body, server_tx, server_shutdown))
        .map_err(|e| AuthError::Failed(format!("spawn http server: {e}")))?;

    // Stdin reader — only when stdin is actually a console. When opc
    // is launched by the GUI (or piped/redirected), stdin reads would
    // either hang forever or fail immediately, and the user has no
    // way to type a paste anyway. Skipping the thread in that case
    // avoids leaking a doomed reader.
    //
    // The reader thread sends its duplicated Win32 thread HANDLE
    // back to the parent and never touches it after that. The parent
    // owns the handle, calls `CancelSynchronousIo` on it when the
    // HTTP path wins, joins the reader (so its `StdinLock` is fully
    // dropped before we return), and only THEN closes the handle.
    // The previous design had the child close the handle on its own
    // exit and the parent later cancel a possibly-already-closed
    // handle — racy.
    let stdin_tx = tx;
    let mut stdin_join: Option<thread::JoinHandle<()>> = None;
    let mut stdin_thread_handle: Option<usize> = None;
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let (handle_tx, handle_rx) = mpsc::channel::<usize>();
        let handle = thread::Builder::new()
            .name("opc-saml-stdin-win".into())
            .spawn(move || {
                use windows_sys::Win32::Foundation::{
                    DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
                };
                use windows_sys::Win32::System::Threading::{
                    GetCurrentProcess, GetCurrentThread,
                };
                // `GetCurrentThread` returns a pseudo-handle valid
                // only to its own thread; duplicate it into a real
                // one the parent can pass to `CancelSynchronousIo`.
                let mut real_handle: HANDLE = std::ptr::null_mut();
                let dup_ok = unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        GetCurrentThread(),
                        GetCurrentProcess(),
                        &mut real_handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if dup_ok != 0 {
                    // Parent now owns this handle and is the only one
                    // responsible for `CloseHandle`. We deliberately
                    // do NOT close it on the child side.
                    let _ = handle_tx.send(real_handle as usize);
                }
                windows_stdin_reader_loop(stdin_tx);
            })
            .map_err(|e| AuthError::Failed(format!("spawn stdin reader: {e}")))?;
        stdin_join = Some(handle);
        // 200 ms grace for the new thread to ship its handle back.
        // If we miss it (very slow thread start) we just lose the
        // ability to cancel — the reader still works, it just leaks
        // on shutdown, which is strictly better than no reader.
        stdin_thread_handle = handle_rx.recv_timeout(Duration::from_millis(200)).ok();
    } else {
        tracing::debug!("saml-paste(win): stdin is not a terminal, skipping reader");
        // Drop our copy of the sender so the channel can close
        // properly when only the HTTP thread is left. Without this,
        // `stdin_tx` sits on the parent stack and `rx.recv()` below
        // would block forever if the HTTP thread exited without
        // delivering a capture (panic in the handler, accept error,
        // …) — all clones of the Sender must drop before `recv`
        // returns Err.
        drop(stdin_tx);
    }

    let result = rx.recv().map_err(|_| {
        AuthError::Failed("callback server closed without producing a capture".into())
    });

    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&actual_addr, Duration::from_millis(200));
    let _ = server_thread.join();

    // Cancel the stdin reader (if it's still blocked in ReadFile),
    // JOIN it so we observe the actual unwind of its `StdinLock`,
    // and only then `CloseHandle` the duplicated thread handle. Doing
    // these in that order eliminates the previous race window where
    // a freshly-spawned re-auth reader could try to lock stdin
    // before the old one had finished tearing down.
    if let Some(handle_usize) = stdin_thread_handle {
        unsafe {
            windows_sys::Win32::System::IO::CancelSynchronousIo(handle_usize as _);
        }
        if let Some(j) = stdin_join.take() {
            let _ = j.join();
        }
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle_usize as _);
        }
    } else if let Some(j) = stdin_join.take() {
        // No real thread handle was ever shipped (`DuplicateHandle`
        // failed inside the reader, or our 200 ms `recv_timeout`
        // missed it). Without a handle we cannot cancel a blocked
        // `ReadFile`, so calling `j.join()` here would deadlock the
        // entire reconnect path waiting for the user to type and
        // press Enter — disastrous on Ctrl-C / auto-reconnect.
        //
        // Detach the thread instead by dropping its JoinHandle: it
        // continues running, will eventually return from `ReadFile`
        // (next keystroke, EOF, or process exit), and dies cleanly
        // either way. A leaked thread is recoverable; a deadlocked
        // tunnel is not.
        drop(j);
    }

    // Confirm the port is actually released. Same rationale as the
    // unix path — port 0 makes the next bind succeed on a fresh
    // ephemeral port regardless of TIME_WAIT, but the rebind probe is
    // a clean log signal for "callback server is really gone".
    let released = TcpListener::bind(actual_addr).is_ok();
    tracing::debug!(
        "saml callback server: released {} (rebind ok = {})",
        actual_addr,
        released
    );

    result
}

/// Windows stdin reader. Blocks on `read_line` and parses each line as
/// a potential `globalprotectcallback:` paste; the first match wins
/// and is shipped over the channel.
///
/// Cancellation: the parent thread holds a duplicated thread HANDLE
/// for us and calls `CancelSynchronousIo` when the HTTP path wins
/// first. That returns `ERROR_OPERATION_ABORTED` from our pending
/// `ReadFile`, our `read_line` surfaces an `Err`, and we exit
/// cleanly — releasing stdin's internal lock so the next caller
/// (re-auth SAML, MFA OTP prompt, …) can read without deadlocking.
///
/// Why `BufReader` not raw `libc::read`: Windows has no `poll(2)` on
/// console handles. We need cooked-mode line buffering anyway so the
/// user's `Enter` keypress commits the paste.
#[cfg(windows)]
fn windows_stdin_reader_loop(tx: mpsc::Sender<SamlCapture>) {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        match handle.read_line(&mut line) {
            // EOF — peer (or pipe redirect) closed stdin. Nothing more
            // we can do; let the HTTP path race continue without us.
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(cap) = parse_terminal_callback_line(trimmed) {
                    // Print a brief confirmation BEFORE sending so the
                    // user sees acknowledgement even if the channel
                    // recv path races ahead. Mask the JWT — same
                    // rationale as the Unix path.
                    eprintln!(
                        "openprotect: callback paste captured as `****` — continuing..."
                    );
                    let _ = tx.send(cap);
                    return;
                }
                if trimmed.contains("globalprotectcallback:") {
                    eprintln!(
                        "openprotect: saw a callback-looking paste ({} bytes) but couldn't parse it; \
                         double-check you copied the full URL after `globalprotectcallback:`",
                        trimmed.len()
                    );
                } else {
                    eprintln!(
                        "openprotect: that doesn't start with `globalprotectcallback:`, \
                         try pasting again (or use the curl POST)"
                    );
                }
            }
            // Read error (stdin redirected from a closed pipe, etc.) —
            // bail; the HTTP path can still complete the flow.
            Err(_) => return,
        }
    }
}

// ---------------------------------------------------------------
// Unix-only: terminal echo guard, signal handlers, stdin reader,
// self-pipe. None of these are needed on Windows where we only
// use the HTTP callback path.
// ---------------------------------------------------------------

#[cfg(unix)]
#[cfg(not(any(unix, windows)))]
fn run_paste_flow(_saml: &SamlPrelogin, _port: u16) -> Result<SamlCapture, AuthError> {
    Err(AuthError::Failed(
        "SAML paste auth is not supported on this platform".into(),
    ))
}

/// Process-global pointer used by the signal handler to find the
/// saved `termios` to restore. `null` when no guard is live. Set
/// once by `TtyEchoGuard::new` and cleared by `Drop`. The handler
/// only reads it; both sides use `SeqCst` to keep the window where
/// "signal arrived but the pointer is stale" as small as possible.
///
/// We leak a `Box<TermiosSaved>` deliberately — when the guard
/// goes through normal `Drop`, we take the box back and free it.
/// If the handler fires we let the process exit with the box still
/// on the heap; the kernel will reclaim it.
#[cfg(unix)]
static SAVED_TERMIOS: AtomicPtr<TermiosSaved> = AtomicPtr::new(std::ptr::null_mut());

/// What the signal handler and `Drop` path both need to restore:
/// the fd to write back to, plus the original `termios`.
#[cfg(unix)]
struct TermiosSaved {
    fd: libc::c_int,
    original: libc::termios,
}

/// C signal handler used for SIGINT / SIGTERM while a
/// `TtyEchoGuard` is live. The default SIG_DFL for both signals is
/// "terminate the process", which skips Rust destructors and
/// leaves the terminal stuck in no-echo mode — a user who Ctrl-C's
/// out of the paste prompt would return to a shell where their
/// keystrokes are invisible until they run `stty sane`.
///
/// Instead this handler runs before termination, restores the
/// saved termios with `tcsetattr` (which is commonly
/// async-signal-safe on Linux even though POSIX doesn't mandate
/// it), and then calls `_exit(128 + signum)` so the process exits
/// immediately with the conventional shell exit code for the
/// signal. We deliberately do NOT call Rust destructors,
/// `atexit` handlers, or anything else that might deadlock — this
/// runs inside signal context, so async-signal-safety is the only
/// thing we can assume.
///
/// SAFETY: the handler touches only the atomic pointer and
/// async-signal-safe libc calls (`tcsetattr`, `_exit`). If the
/// pointer is racing with `Drop`'s store of `null`, worst case we
/// read the null and simply `_exit` without restoring — which is
/// no worse than the pre-commit state.
#[cfg(unix)]
extern "C" fn tty_restore_signal_handler(signum: libc::c_int) {
    let ptr = SAVED_TERMIOS.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let saved = &*ptr;
            libc::tcsetattr(saved.fd, libc::TCSAFLUSH, &saved.original);
        }
    }
    // 128 + signum is the conventional shell exit code for a
    // signal-terminated process. bash, zsh, and the POSIX spec all
    // agree on this.
    let exit_code = 128 + signum;
    unsafe { libc::_exit(exit_code) };
}

/// RAII guard that disables TTY echo on a stdin-like fd for its
/// lifetime, then restores the original `termios` on drop.
///
/// Rationale: the paste provider reads a `globalprotectcallback:` URL
/// that carries a short-TTL SAML JWT with the user's identity. With
/// TTY echo on, every byte the user types gets written back to the
/// PTY's output side — which means `script(1)`, tmux `capture-pane`,
/// terminal scrollback, and a shoulder surfer all end up with the
/// token in cleartext. Turning echo off keeps the bytes entirely
/// inside the kernel's line discipline until our `libc::read` below
/// consumes them, at which point they go into the authcookie and
/// nowhere else.
///
/// On non-TTY stdin (pipe, redirected file, test harness) `isatty`
/// returns 0 and the guard becomes a no-op — we never touch termios
/// for fds that don't own one, so piped input still works.
///
/// Normal drop is best-effort: if `tcsetattr` fails during restore
/// (extremely unlikely — the fd was valid at construction time) we
/// log at `debug` and move on. Panicking from a destructor would
/// poison unrelated error-handling paths.
///
/// SIGINT / SIGTERM during the guarded region: handled by the
/// process-global signal handler installed below. It reads the
/// saved `termios` from `SAVED_TERMIOS` and restores it before
/// `_exit`. Without that handler, `Drop` would be skipped on
/// signal termination and the user's terminal would stay in
/// no-echo mode until they ran `stty sane`.
#[cfg(unix)]
struct TtyEchoGuard {
    /// `true` when `new` successfully published a `TermiosSaved` to
    /// `SAVED_TERMIOS` and installed signal handlers. `false` when
    /// either (a) stdin is not a TTY, (b) `tcgetattr` failed, or
    /// (c) `tcsetattr` failed to actually flip ECHO off. `Drop`
    /// uses this to short-circuit.
    active: bool,
    /// The previous SIGINT action, restored on drop.
    prev_sigint: Option<libc::sigaction>,
    /// The previous SIGTERM action, restored on drop.
    prev_sigterm: Option<libc::sigaction>,
}

#[cfg(unix)]
impl TtyEchoGuard {
    fn new(fd: libc::c_int) -> Self {
        // Fast path: non-TTY stdin leaves the guard inactive.
        // No signal handler, no termios mutation.
        if unsafe { libc::isatty(fd) } == 0 {
            return Self {
                active: false,
                prev_sigint: None,
                prev_sigterm: None,
            };
        }

        // Snapshot current termios.
        let original = unsafe {
            let mut t = MaybeUninit::<libc::termios>::zeroed();
            if libc::tcgetattr(fd, t.as_mut_ptr()) != 0 {
                return Self {
                    active: false,
                    prev_sigint: None,
                    prev_sigterm: None,
                };
            }
            t.assume_init()
        };

        // Ordering discipline for the init path. A signal may
        // arrive between any two libc calls below; the order is
        // chosen so every intermediate state exits cleanly:
        //
        //   0. (prior state) Terminal is whatever the caller had.
        //      SAVED_TERMIOS is null. Default SIG_DFL handlers in
        //      place.
        //   1. Install sigaction for SIGINT / SIGTERM. From here
        //      our handler is reachable but SAVED_TERMIOS is
        //      still null, so a racing signal reads null,
        //      skips `tcsetattr`, and `_exit`s. Terminal is still
        //      whatever the caller had → user's shell is fine.
        //   2. Publish `Box<TermiosSaved>` to SAVED_TERMIOS. A
        //      racing signal now reads the box, calls
        //      `tcsetattr(original)` as a no-op (terminal is
        //      still original state because we have not yet
        //      turned ECHO off), and `_exit`s. Terminal still
        //      fine.
        //   3. Finally `tcsetattr(ECHO off)`. From here on
        //      every signal path restores the saved `original`
        //      before exiting.
        //
        // The earlier ordering (2 before 1) left a real window
        // where the handler was not yet installed and a SIGINT
        // arriving immediately after the ECHO-off `tcsetattr`
        // would take the process down with echo still off.
        // Caught on a second review pass; this is the fix.
        let prev_sigint = install_signal_handler(libc::SIGINT);
        let prev_sigterm = install_signal_handler(libc::SIGTERM);

        let saved_box = Box::new(TermiosSaved { fd, original });
        SAVED_TERMIOS.store(Box::into_raw(saved_box), Ordering::SeqCst);

        let mut modified = original;
        modified.c_lflag &= !(libc::ECHO | libc::ICANON);
        // Some macOS terminal setups deliver the Return key as `\r`
        // with ICRNL cleared. Force the standard CR->NL mapping so the
        // stdin reader always sees a completed line on Enter.
        modified.c_iflag &= !libc::IGNCR;
        modified.c_iflag |= libc::ICRNL;
        // Non-canonical mode removes the macOS MAX_CANON line-length
        // ceiling, but we still want reads to block until at least one
        // byte arrives.
        modified.c_cc[libc::VMIN] = 1;
        modified.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &modified) } != 0 {
            // tcsetattr failed after we already installed the
            // handler + published the box. Roll everything back
            // in reverse order so the guard is truly inactive:
            // pull the pointer out of the atomic, free the box,
            // restore the previous sigactions, return inactive.
            let ptr = SAVED_TERMIOS.swap(std::ptr::null_mut(), Ordering::SeqCst);
            if !ptr.is_null() {
                drop(unsafe { Box::from_raw(ptr) });
            }
            restore_signal_handler(libc::SIGINT, prev_sigint);
            restore_signal_handler(libc::SIGTERM, prev_sigterm);
            return Self {
                active: false,
                prev_sigint: None,
                prev_sigterm: None,
            };
        }

        Self {
            active: true,
            prev_sigint,
            prev_sigterm,
        }
    }
}

#[cfg(unix)]
impl Drop for TtyEchoGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        // Ordering discipline for the teardown path. Every
        // intermediate state must either (a) leave the terminal
        // in its original state before any signal could fire, or
        // (b) leave the signal handler pointing at a valid
        // TermiosSaved that restores to the same original.
        //
        //   1. `load` the pointer (don't swap yet). A racing
        //      signal here sees the same box, calls
        //      `tcsetattr(original)`, and `_exit`s — that's the
        //      correct outcome.
        //   2. `tcsetattr(original)` ourselves. The terminal is
        //      now restored. A racing signal here also sees the
        //      box (still non-null), calls `tcsetattr(original)`
        //      as a no-op, and `_exit`s.
        //   3. `swap` the atomic to null. From here the handler
        //      would read null and `_exit` without touching
        //      termios, which is fine because step 2 already
        //      restored it. Any earlier swap would have left a
        //      window where our handler saw null but termios was
        //      still in ECHO-off state.
        //   4. Free the Box we owned all along.
        //   5. Restore the previous sigactions. After this our
        //      handler is unreachable, so even a null-pointer
        //      race is impossible.
        //
        // The earlier ordering (3 before 2) left a real window
        // where a signal arriving between the swap and the
        // `tcsetattr` would read null, `_exit` without
        // restoring, and leave the terminal in no-echo mode.
        // Caught on a second review pass; this is the fix.
        let ptr = SAVED_TERMIOS.load(Ordering::SeqCst);
        if !ptr.is_null() {
            // SAFETY: we are the sole writer of SAVED_TERMIOS
            // (the handler only reads it), and we are still
            // holding the logical `Box` referenced by this
            // pointer until step 4 below. Dereferencing via `&*`
            // is safe so long as no other thread frees it, which
            // no other thread has the authority to do.
            let saved = unsafe { &*ptr };
            let rc = unsafe { libc::tcsetattr(saved.fd, libc::TCSAFLUSH, &saved.original) };
            if rc != 0 {
                tracing::debug!(
                    "TtyEchoGuard::drop: tcsetattr restore failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Only NOW do we swap the pointer to null and free the
        // Box. A racing signal between step 2 and step 3 would
        // have already run a harmless no-op `tcsetattr`.
        let ptr = SAVED_TERMIOS.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !ptr.is_null() {
            // SAFETY: `ptr` came from `Box::into_raw` in
            // `TtyEchoGuard::new` and nobody else has touched
            // it; reclaiming ownership is safe.
            drop(unsafe { Box::from_raw(ptr) });
        }

        restore_signal_handler(libc::SIGINT, self.prev_sigint.take());
        restore_signal_handler(libc::SIGTERM, self.prev_sigterm.take());
    }
}

/// Install `tty_restore_signal_handler` for `signum` and return the
/// previous `sigaction` so the caller can restore it later.
/// Returns `None` if `sigaction` itself failed (extremely unlikely
/// on a sane Linux host).
#[cfg(unix)]
fn install_signal_handler(signum: libc::c_int) -> Option<libc::sigaction> {
    unsafe {
        let mut new_action: libc::sigaction = std::mem::zeroed();
        new_action.sa_sigaction = tty_restore_signal_handler as *const () as libc::sighandler_t;
        // Empty signal mask + no special flags. We don't need
        // SA_RESTART because the handler always exits.
        libc::sigemptyset(&mut new_action.sa_mask);
        new_action.sa_flags = 0;

        let mut old_action = MaybeUninit::<libc::sigaction>::zeroed();
        if libc::sigaction(signum, &new_action, old_action.as_mut_ptr()) == 0 {
            Some(old_action.assume_init())
        } else {
            None
        }
    }
}

/// Reinstall a previously-saved `sigaction` for `signum`. No-op
/// when the caller didn't manage to install anything in the first
/// place.
#[cfg(unix)]
fn restore_signal_handler(signum: libc::c_int, prev: Option<libc::sigaction>) {
    if let Some(prev) = prev {
        unsafe {
            libc::sigaction(signum, &prev, std::ptr::null_mut());
        }
    }
}

/// Create a Unix pipe and wrap both ends in `OwnedFd` so they close on drop.
#[cfg(unix)]
fn make_pipe() -> Result<(OwnedFd, OwnedFd), AuthError> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(AuthError::Failed(format!(
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    use std::os::fd::FromRawFd;
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}

/// Print the instructions the user sees in their terminal.
///
/// Branches on reachability hints:
/// - `tailscale_ip = Some`: print the Tailscale URL first (user can open
///   it directly from any device on their tailnet, no SSH needed) and
///   use the Tailscale IP as the `ssh -L` target hint.
/// - `tailscale_ip = None, public_ip = Some`: only the 127.0.0.1 URL is
///   accessible locally; use the public IP as the `ssh -L` target hint.
/// - Both `None`: show a `<user>@<this-host>` placeholder for the user
///   to fill in.
#[cfg(unix)]
fn print_instructions(
    addr: &SocketAddr,
    tailscale_ip: Option<std::net::Ipv4Addr>,
    public_ip: Option<std::net::Ipv4Addr>,
    saml: &SamlPrelogin,
) {
    let port = addr.port();
    eprintln!();
    eprintln!("┌─ OpenProtect — headless SAML authentication ─────────────────────────────────┐");
    eprintln!("│                                                                            │");
    eprintln!("│  Open this URL in any browser:                                             │");
    eprintln!("│                                                                            │");
    if let Some(ts) = tailscale_ip {
        eprintln!("│    http://{ts}:{port}/   ← any device on your tailnet");
        eprintln!("│    http://127.0.0.1:{port}/   ← on this host only");
    } else {
        eprintln!("│    http://127.0.0.1:{port}/   ← on this host only");
    }
    eprintln!("│                                                                            │");
    eprintln!("│  Over SSH? Port-forward from your laptop:                                  │");
    let ssh_target = match (tailscale_ip, public_ip) {
        (Some(ts), _) => format!("user@{ts}"),
        (None, Some(pub_ip)) => format!("user@{pub_ip}"),
        (None, None) => "<user>@<this-host>".into(),
    };
    eprintln!("│    ssh -L {port}:localhost:{port} {ssh_target}");
    eprintln!("│  Then open http://127.0.0.1:{port}/ on your laptop.");
    eprintln!("│                                                                            │");
    eprintln!("│  After you finish logging in, the browser will land on a page that         │");
    eprintln!("│  fails with \"the URL can't be shown\" — that's expected. The address        │");
    eprintln!("│  bar will start with `globalprotectcallback:…`. Copy it.                    │");
    eprintln!("│                                                                            │");
    eprintln!("│  Paste that URL here and press Enter. Input will NOT be echoed — the      │");
    eprintln!("│  URL is a short-lived credential and we keep it off your scrollback,      │");
    eprintln!("│  tmux capture, and `script(1)` logs.                                      │");
    eprintln!("│                                                                            │");
    eprintln!("└────────────────────────────────────────────────────────────────────────────┘");
    tracing::debug!(
        "paste provider: saml_auth_method={} saml_request_len={} tailscale={} public={}",
        saml.saml_auth_method,
        saml.saml_request.len(),
        tailscale_ip.is_some(),
        public_ip.is_some(),
    );
}

/// Body served at `GET /` — either a tiny redirect page (REDIRECT method)
/// or the raw auto-submit HTML from the portal (POST method).
fn build_launch_body(saml: &SamlPrelogin) -> Result<Vec<u8>, AuthError> {
    match saml.saml_auth_method.as_str() {
        "REDIRECT" => {
            // We can't redirect directly to the IdP URL from the HTTP
            // response because we need the browser to actually navigate
            // there (not just 302 which some configurations break). A
            // tiny HTML page with `<meta refresh>` + an explicit link is
            // the most robust option.
            let url = &saml.saml_request;
            let html = format!(
                "<!doctype html><html><head><meta charset=\"utf-8\">\
                 <meta http-equiv=\"refresh\" content=\"0;url={url}\">\
                 <title>OpenProtect SAML</title></head><body>\
                 <p>Redirecting to identity provider…</p>\
                 <p>If nothing happens, <a href=\"{url}\">click here</a>.</p>\
                 </body></html>"
            );
            Ok(html.into_bytes())
        }
        "POST" => {
            let decoded = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            Ok(decoded)
        }
        other => Err(AuthError::Failed(format!(
            "unknown saml-auth-method: {other}"
        ))),
    }
}

/// The HTTP server loop. Handles one request at a time (the paste flow
/// is inherently serial). Exits when shutdown flag flips or a capture
/// has been sent on `tx`.
fn http_server_loop(
    listener: TcpListener,
    launch_body: Vec<u8>,
    tx: mpsc::Sender<SamlCapture>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    for incoming in listener.incoming() {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let Ok(mut stream) = incoming else { continue };
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
            tracing::trace!("set_read_timeout: {e}");
        }

        match handle_one_request(&mut stream, &launch_body) {
            Ok(Some(uri)) => {
                if let Some(cap) = parse_globalprotect_callback(&uri) {
                    let _ = respond_ok(
                        &mut stream,
                        b"openprotect: authentication captured, you can close this tab\n",
                    );
                    let _ = tx.send(cap);
                    break;
                } else {
                    let _ = respond_plain(
                        &mut stream,
                        400,
                        "Bad Request",
                        b"openprotect: `url` did not start with globalprotectcallback:\n",
                    );
                }
            }
            Ok(None) => {
                // Normal serve path (/ or something else), stream already written.
            }
            Err(e) => {
                tracing::debug!("http request error: {e}");
            }
        }
    }
}

/// Parse a single HTTP/1.x request and reply. Returns
/// `Ok(Some(callback_url))` if the client hit `/callback` with a valid
/// url param, otherwise serves `/` or a 404.
fn handle_one_request(
    stream: &mut TcpStream,
    launch_body: &[u8],
) -> std::io::Result<Option<String>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();

    // Consume headers + any body we can read quickly.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some(v) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    // Read body if the request declared one. `take` plus a hard ceiling
    // to defend against runaway clients.
    let mut body = Vec::new();
    if content_length > 0 && content_length < 1_000_000 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        body = buf;
    }

    // Parse "METHOD PATH HTTP/1.x"
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    tracing::debug!("http {method} {path} (cl={content_length})");

    match (method, path) {
        ("GET", "/") | ("GET", "") => {
            respond(stream, 200, "OK", "text/html; charset=utf-8", launch_body)?;
            Ok(None)
        }
        ("GET", p) if p.starts_with("/callback") => {
            // /callback?url=<encoded>
            let url = extract_query_param(p, "url");
            match url {
                Some(u) => Ok(Some(u)),
                None => {
                    respond_plain(
                        stream,
                        400,
                        "Bad Request",
                        b"openprotect: missing `url` query parameter\n",
                    )?;
                    Ok(None)
                }
            }
        }
        ("POST", p) if p.starts_with("/callback") => {
            // Accept either form-encoded body (`url=…`) or a raw URL.
            let body_str = String::from_utf8_lossy(&body);
            let url = extract_form_param(&body_str, "url").or_else(|| {
                let s = body_str.trim();
                if s.starts_with("globalprotectcallback:") {
                    Some(s.to_string())
                } else {
                    None
                }
            });
            match url {
                Some(u) => Ok(Some(u)),
                None => {
                    respond_plain(
                        stream,
                        400,
                        "Bad Request",
                        b"openprotect: POST /callback needs `url=...` in body\n",
                    )?;
                    Ok(None)
                }
            }
        }
        _ => {
            respond_plain(stream, 404, "Not Found", b"openprotect: not found\n")?;
            Ok(None)
        }
    }
}

fn extract_query_param(path: &str, key: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn extract_form_param(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(url_decode(v));
            }
        }
    }
    None
}

/// Minimal form-urlencoded decoder for the HTTP request side.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_ok(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    respond(stream, 200, "OK", "text/plain; charset=utf-8", body)
}

fn respond_plain(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> std::io::Result<()> {
    respond(stream, status, reason, "text/plain; charset=utf-8", body)
}

/// Parse a callback URL that was pasted into a terminal.
///
/// Some terminals wrap paste payloads in bracketed-paste control
/// sequences (`ESC [ 200 ~ ... ESC [ 201 ~`) or leave the URL embedded
/// inside surrounding prompt text. Extract the first
/// `globalprotectcallback:` substring and stop at the first raw control
/// character / whitespace after it.
fn parse_terminal_callback_line(line: &str) -> Option<SamlCapture> {
    let line = line.trim();
    if let Some(cap) = parse_globalprotect_callback(line) {
        return Some(cap);
    }

    let idx = line.find("globalprotectcallback:")?;
    let tail = &line[idx..];
    let end = tail
        .find(|c: char| c.is_ascii_control() || c.is_ascii_whitespace())
        .unwrap_or(tail.len());
    parse_globalprotect_callback(&tail[..end])
}

/// Cancellable stdin reader.
///
/// Uses `poll(2)` on stdin AND a wake-pipe fd, so the HTTP path can
/// interrupt us cleanly. We deliberately read raw bytes via `libc::read`
/// (no `BufReader` over `Stdin`) for two reasons:
///
/// 1. We never lock `std::io::Stdin` — a leaked `StdinLock` would block
///    the gateway-login MFA prompt that runs *after* this provider.
/// 2. We only consume bytes up to and including a `\n` we care about,
///    leaving subsequent input on the kernel-side stdin buffer for
///    whoever reads next.
#[cfg(unix)]
fn stdin_reader_loop(tx: mpsc::Sender<SamlCapture>, wake_fd: OwnedFd) {
    /// Result of feeding one batch of bytes into the line accumulator.
    enum Feed {
        /// Keep going.
        Continue,
        /// A capture matched — the parent should stop.
        Captured,
    }

    const LINE_CAP_BYTES: usize = 64 * 1024;

    let stdin_fd = libc::STDIN_FILENO;
    let wake_raw = wake_fd.as_raw_fd();
    let mut current_line: Vec<u8> = Vec::with_capacity(2048);
    // True while we're past the line-length cap and skipping bytes until
    // the next newline. Prevents the previous bug where the cap cleared
    // the prefix and then kept appending the tail of the same line,
    // confusing the parser and the user.
    let mut discarding_overlong = false;

    // Helper: consume `n` bytes from `buf` and update `current_line`.
    // Returns Captured if a callback was matched.
    let feed = |buf: &[u8], current_line: &mut Vec<u8>, discarding_overlong: &mut bool| -> Feed {
        for &b in buf {
            if b == b'\n' || b == b'\r' {
                if *discarding_overlong {
                    // End of the overlong line — reset state and move on
                    // without parsing this junk.
                    *discarding_overlong = false;
                    current_line.clear();
                    eprintln!(
                        "openprotect: input line exceeded {} bytes — discarded. \
                         Paste a `globalprotectcallback:` URI and press Enter:",
                        LINE_CAP_BYTES
                    );
                    continue;
                }
                let line = String::from_utf8_lossy(current_line).into_owned();
                current_line.clear();
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match parse_terminal_callback_line(trimmed) {
                    Some(cap) => {
                        eprintln!("openprotect: callback paste captured as `****` — continuing...");
                        let _ = tx.send(cap);
                        return Feed::Captured;
                    }
                    None => {
                        if trimmed.contains("globalprotectcallback:") {
                            eprintln!(
                                "openprotect: saw a callback-looking paste ({} bytes) \
                                 but could not parse it, try again (or Ctrl-C to abort):",
                                trimmed.len()
                            );
                        } else {
                            eprintln!(
                                "openprotect: that doesn't start with `globalprotectcallback:`, \
                                 try again (or Ctrl-C to abort):"
                            );
                        }
                    }
                }
            } else if !*discarding_overlong {
                current_line.push(b);
                if current_line.len() > LINE_CAP_BYTES {
                    *discarding_overlong = true;
                    current_line.clear();
                }
            }
            // else: in discard mode, drop the byte silently
        }
        Feed::Continue
    };

    // Read once from stdin — returns Some(Captured/Continue) to keep
    // looping, or None on EOF / fatal error.
    let read_once = |current_line: &mut Vec<u8>, discarding_overlong: &mut bool| -> Option<Feed> {
        let mut buf = [0u8; 1024];
        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Some(Feed::Continue);
            }
            tracing::debug!("stdin read error: {err}");
            return None;
        }
        if n == 0 {
            return None; // EOF
        }
        Some(feed(&buf[..n as usize], current_line, discarding_overlong))
    };

    loop {
        let mut fds = [
            libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_raw,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            tracing::debug!("stdin poll error: {err}");
            return;
        }

        // Wake fd: any event means the HTTP path won the race — exit
        // immediately, no need to drain stdin.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            return;
        }

        // POLLIN on stdin: read available data. We may also see POLLHUP
        // alongside POLLIN when the writer (a pipe / file feeding stdin)
        // has closed but kernel-buffered data remains. Drain in that case
        // before exiting — otherwise piped input loses its final lines.
        let stdin_revents = fds[0].revents;
        if stdin_revents & libc::POLLIN != 0 {
            match read_once(&mut current_line, &mut discarding_overlong) {
                Some(Feed::Captured) => return,
                Some(Feed::Continue) => {}
                None => return, // EOF / fatal
            }
            continue;
        }

        // POLLHUP / POLLERR with no POLLIN: drain any remaining
        // kernel-buffered bytes, then exit. Use a non-blocking poll on
        // the wake fd between reads so that a sustained EINTR storm on
        // stdin can't trap us here after the HTTP path has already
        // captured a callback.
        if stdin_revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            loop {
                // Cheap wake-fd check: zero-timeout poll. If the wake
                // fd has fired, the HTTP path won — abandon the drain.
                let mut wake_check = libc::pollfd {
                    fd: wake_raw,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let wake_rc = unsafe { libc::poll(std::ptr::from_mut(&mut wake_check), 1, 0) };
                if wake_rc > 0
                    && wake_check.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                {
                    return;
                }

                match read_once(&mut current_line, &mut discarding_overlong) {
                    Some(Feed::Captured) => return,
                    Some(Feed::Continue) => continue,
                    None => return,
                }
            }
        }
    }
}

/// Detect the primary Tailscale IPv4 address, if one exists.
///
/// This shells out to `tailscale ip -4` instead of walking `getifaddrs`
/// manually. The helper is only used to print a best-effort convenience
/// URL in the headless SAML instructions, so falling back to `None` when
/// the CLI is absent or Tailscale is not running is acceptable.
#[cfg(unix)]
fn detect_tailscale_ipv4() -> Option<std::net::Ipv4Addr> {
    use std::net::Ipv4Addr;
    use std::process::Command;

    let output = Command::new("tailscale").args(["ip", "-4"]).output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .and_then(|line| line.parse::<Ipv4Addr>().ok())
}

/// Best-effort public IPv4 detection via `api.ipify.org`, 2-second timeout.
///
/// Returns `None` on any error (offline, blocked, parse failure). Used only
/// as a hint in the `ssh -L …` instruction line when Tailscale isn't present.
/// Behind NAT this returns the router's WAN IP, not a directly reachable
/// address — the hint still helps for cloud VMs with a real public IP and
/// is harmless otherwise.
#[cfg(unix)]
fn detect_public_ipv4() -> Option<std::net::Ipv4Addr> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let body = client
        .get("https://api.ipify.org")
        .send()
        .ok()?
        .text()
        .ok()?;
    body.trim().parse().ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Serialises the tests that touch `TtyEchoGuard` and the
    /// process-global `SAVED_TERMIOS` atomic.
    ///
    /// `SAVED_TERMIOS` is a single atomic pointer shared by the
    /// whole process. Several tests assert "the atomic is null
    /// right now" (the `inactive_guard_drop_does_not_touch_…`
    /// case) while one test installs a non-null value for the
    /// duration of a guard scope (the full pty cycle). cargo test
    /// runs tests in the same crate on separate threads by
    /// default, so those two expectations collide if the tests
    /// interleave.
    ///
    /// A plain `std::sync::Mutex<()>` is enough — we only care
    /// about serialising the test bodies, not about guarding any
    /// shared data inside the lock. Poison is tolerated via
    /// `into_inner()` so a panicked test doesn't wedge subsequent
    /// runs.
    ///
    /// The lock also happens to serialise the single call to
    /// libc's non-reentrant `ptsname(3)` in the pty cycle test;
    /// no other test in this file touches `ptsname`, so holding
    /// the lock while we call it is sufficient protection
    /// against a hypothetical future caller overwriting the
    /// static buffer concurrently.
    fn guard_test_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A pipe read fd is not a TTY, so `TtyEchoGuard::new` must leave
    /// the guard inactive: no termios mutation, no signal handler
    /// install, and `SAVED_TERMIOS` untouched. This is the code path
    /// taken under `cargo test`, CI, cron jobs, `opc < saml.txt`,
    /// and anything else where stdin is not a real terminal.
    #[test]
    fn echo_guard_on_pipe_is_noop() {
        let _lock = guard_test_lock();
        let (read, _write) = make_pipe().expect("pipe()");
        let fd = read.as_raw_fd();
        let before = SAVED_TERMIOS.load(Ordering::SeqCst);
        let guard = TtyEchoGuard::new(fd);
        assert!(
            !guard.active,
            "TtyEchoGuard::new on a pipe fd must stay inactive"
        );
        assert!(
            guard.prev_sigint.is_none() && guard.prev_sigterm.is_none(),
            "inactive guard must not have touched sigaction"
        );
        assert_eq!(
            SAVED_TERMIOS.load(Ordering::SeqCst),
            before,
            "inactive guard must not publish to SAVED_TERMIOS"
        );
        drop(guard);
    }

    /// An already-closed / invalid fd must not panic and must not
    /// touch termios. `isatty(-1)` returns 0 with errno EBADF, so
    /// we exit early and the guard stays inactive.
    #[test]
    fn echo_guard_on_invalid_fd_is_noop() {
        let _lock = guard_test_lock();
        let guard = TtyEchoGuard::new(-1);
        assert!(!guard.active);
        drop(guard);
    }

    /// Dropping an inactive guard must leave `SAVED_TERMIOS` as
    /// `null`. Regression guard against a bug where `Drop` would
    /// swap the atomic unconditionally and lose whatever state a
    /// concurrently-live guard had published.
    #[test]
    fn inactive_guard_drop_does_not_touch_saved_termios() {
        let _lock = guard_test_lock();
        assert!(SAVED_TERMIOS.load(Ordering::SeqCst).is_null());
        let guard = TtyEchoGuard::new(-1);
        drop(guard);
        assert!(SAVED_TERMIOS.load(Ordering::SeqCst).is_null());
    }

    /// Full end-to-end cycle on a real PTY slave fd: confirm that
    /// the normal-drop path actually flips `ECHO` off via
    /// `tcsetattr` and restores it on drop. Previously only the
    /// non-TTY paths (pipe / invalid fd) were covered; those
    /// branches return early and exercise none of the termios
    /// machinery.
    ///
    /// The signal-handler path (SIGINT/SIGTERM arriving while the
    /// guard is live) is deliberately NOT exercised here: the
    /// handler ends with `libc::_exit(128 + signum)`, which would
    /// terminate the entire test runner. Attempting to fork and
    /// raise the signal in a child is also unsafe under cargo
    /// test's multi-threaded harness — the child would inherit a
    /// snapshot of the global allocator's lock state from other
    /// threads and could deadlock on the first heap allocation.
    /// The handler's correctness is instead covered by the
    /// init/teardown ordering invariants documented inline in
    /// `TtyEchoGuard::new` / `Drop`, plus the three "inactive"
    /// unit tests above that ensure Drop cannot clobber a
    /// concurrently-live guard's state.
    ///
    /// This test runs only where `posix_openpt` is available
    /// (Linux, macOS, *BSD). On sandboxed CI runners that disable
    /// `/dev/ptmx` the `posix_openpt` call returns -1 and the
    /// test exits early with a warning rather than failing,
    /// because there is no way to get a real TTY without it.
    #[test]
    fn echo_guard_tty_cycle_saves_and_restores_termios() {
        use std::ffi::CStr;
        use std::os::fd::{FromRawFd, OwnedFd};

        let _lock = guard_test_lock();

        let master_raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master_raw < 0 {
            // Skip silently on sandboxed runners that disable
            // `/dev/ptmx` (some container CIs, some hardened
            // builders). `println!` here is captured by cargo
            // test's default output filter — the skip is only
            // visible with `-- --nocapture`. That's a known
            // coverage gap: we trade test portability for the
            // absence of a "skipped" status in the stdlib test
            // harness. Flag on the PR description when openprotect
            // ever runs on a CI runner where this path fires in
            // normal operation.
            println!(
                "SKIPPING echo_guard_tty_cycle_saves_and_restores_termios: \
                 posix_openpt failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let master: OwnedFd = unsafe { OwnedFd::from_raw_fd(master_raw) };

        assert_eq!(
            unsafe { libc::grantpt(master.as_raw_fd()) },
            0,
            "grantpt failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::unlockpt(master.as_raw_fd()) },
            0,
            "unlockpt failed: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: ptsname returns a pointer to a static buffer
        // inside libc. It is not thread-safe. Two protections
        // cover the call here: (a) `guard_test_lock()` held at
        // the top of this function serialises every test in
        // this file that installs a `TtyEchoGuard`, and
        // (b) no other test in the file calls ptsname at all,
        // so the only way for a racing overwrite to happen is
        // from outside the file — which would itself have to
        // acquire the same lock to be well-behaved. We still
        // copy the returned buffer into an owned CString
        // immediately so the pointer is never dereferenced after
        // the lock is released.
        let slave_name: std::ffi::CString = unsafe {
            let p = libc::ptsname(master.as_raw_fd());
            assert!(!p.is_null(), "ptsname returned NULL");
            CStr::from_ptr(p).to_owned()
        };

        let slave_raw = unsafe { libc::open(slave_name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        assert!(
            slave_raw >= 0,
            "open({:?}) failed: {}",
            slave_name,
            std::io::Error::last_os_error()
        );
        let slave: OwnedFd = unsafe { OwnedFd::from_raw_fd(slave_raw) };

        // Baseline: a freshly-opened pty slave has ECHO set by
        // default. Snapshot it so we can compare after drop.
        let baseline = read_termios(slave.as_raw_fd());
        assert!(
            baseline.c_lflag & libc::ECHO != 0,
            "baseline pty slave should have ECHO set; c_lflag = 0x{:x}",
            baseline.c_lflag
        );

        {
            let guard = TtyEchoGuard::new(slave.as_raw_fd());
            assert!(guard.active, "guard on a real TTY fd must be active");
            let mid = read_termios(slave.as_raw_fd());
            // Tight invariant: the guard should flip EXACTLY one
            // bits in `c_lflag` — `ECHO` and `ICANON` off — and
            // leave every other bit alone. Compare the full field
            // against the baseline with those bits explicitly
            // cleared.
            // This catches a future refactor that accidentally
            // flips any unrelated control bit.
            assert_eq!(
                mid.c_lflag,
                baseline.c_lflag & !(libc::ECHO | libc::ICANON),
                "guard should clear ONLY the ECHO and ICANON bits; \
                 baseline c_lflag = 0x{:x}, mid c_lflag = 0x{:x}",
                baseline.c_lflag,
                mid.c_lflag
            );
            assert_eq!(mid.c_cc[libc::VMIN], 1);
            assert_eq!(mid.c_cc[libc::VTIME], 0);
            assert_eq!(mid.c_iflag & libc::IGNCR, 0);
            assert_ne!(mid.c_iflag & libc::ICRNL, 0);
            assert!(
                !SAVED_TERMIOS.load(Ordering::SeqCst).is_null(),
                "active guard should have published to SAVED_TERMIOS"
            );
        }

        let after = read_termios(slave.as_raw_fd());
        assert_eq!(
            after.c_lflag, baseline.c_lflag,
            "c_lflag should match baseline after drop"
        );
        assert!(
            SAVED_TERMIOS.load(Ordering::SeqCst).is_null(),
            "SAVED_TERMIOS should be null after drop"
        );
    }

    /// Read termios for an fd, panicking on failure. Helper for
    /// the pty cycle test.
    fn read_termios(fd: libc::c_int) -> libc::termios {
        use std::mem::MaybeUninit;
        let mut t = MaybeUninit::<libc::termios>::zeroed();
        let rc = unsafe { libc::tcgetattr(fd, t.as_mut_ptr()) };
        assert_eq!(
            rc,
            0,
            "tcgetattr({fd}) failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { t.assume_init() }
    }

    #[test]
    fn parse_terminal_callback_line_accepts_bracketed_paste_wrappers() {
        let line =
            "\u{1b}[200~globalprotectcallback:cas-as=1&un=alice%40example.com&token=aaa.bbb.ccc\u{1b}[201~";
        let cap = parse_terminal_callback_line(line).expect("callback should parse");
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "aaa.bbb.ccc");
    }

    #[test]
    fn parse_terminal_callback_line_accepts_prompt_noise() {
        let line =
            "copy this -> globalprotectcallback:cas-as=1&un=alice%40example.com&token=aaa.bbb.ccc";
        let cap = parse_terminal_callback_line(line).expect("callback should parse");
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "aaa.bbb.ccc");
    }
}
