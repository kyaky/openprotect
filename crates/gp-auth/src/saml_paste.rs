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
use std::time::{Duration, Instant};

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

/// Seconds between "still waiting" INFO heartbeats while the paste
/// flow blocks on the operator.
const WAIT_HEARTBEAT_SECS: u64 = 30;

/// Grace the worker-shutdown path gives a cancelled stdin reader to
/// actually exit before we WARN and abandon it (see
/// [`shutdown_stdin_reader_with`]).
#[cfg(windows)]
const STDIN_JOIN_GRACE: Duration = Duration::from_secs(2);

/// How long the parent waits for the stdin reader thread to ack its
/// entry into the read loop (by shipping back its duplicated thread
/// handle) before proceeding without cancellation ability.
#[cfg(windows)]
const READER_ACK_GRACE: Duration = Duration::from_secs(2);

/// Name of the Windows stdin reader thread (used in WARNs when it has
/// to be abandoned).
#[cfg(windows)]
const STDIN_READER_THREAD_NAME: &str = "opc-saml-stdin-win";

/// Compute how long the next `recv_timeout` slice should run, or
/// `None` when the overall cap has elapsed.
///
/// Pure so the heartbeat/cap cadence is testable without a live
/// channel. A slice is normally the heartbeat period, shrunk to the
/// remaining budget so the final wait lands exactly on the cap.
fn next_wait_slice(elapsed: Duration, cap: Duration, heartbeat: Duration) -> Option<Duration> {
    // A zero-length remainder means the cap has elapsed — `None`, so
    // the caller fails with the named cap error instead of busy
    // spinning on `recv_timeout(Duration::ZERO)`. (The boundary was
    // caught by `wait_slice_cadence`: `Some(0ns)` was the first cut.)
    cap.checked_sub(elapsed)
        .filter(|left| !left.is_zero())
        .map(|left| left.min(heartbeat))
}

/// Block until one [`SamlCapture`] arrives on `rx`, the channel dies,
/// or `cap` elapses.
///
/// * Arms with an INFO naming the **local listener URL** only — never
///   the credential-carrying `globalprotectcallback:` URL.
/// * Logs a "still waiting" INFO every [`WAIT_HEARTBEAT_SECS`] so an
///   operator (or a log scraper) can tell a patient human apart from
///   a wedge.
/// * Fails with a named error when the wait exceeds the gateway's
///   `<saml-request-timeout>` — the step that hangs here waits on a
///   **human**, not the network, and must surface as such instead of
///   being killed silently mid-stdin.
fn wait_for_capture(
    rx: &mpsc::Receiver<SamlCapture>,
    listener_url: &str,
    cap: Duration,
) -> Result<SamlCapture, AuthError> {
    let heartbeat = Duration::from_secs(WAIT_HEARTBEAT_SECS);
    // Arm logging: INFO, but ONLY with the local listener URL. The
    // credential-carrying `globalprotectcallback:` URL must never be
    // promoted to INFO — the per-request path log in
    // `handle_one_request` (which sees `GET /callback?url=<token>` for
    // the query form) stays at `debug` for the same reason.
    tracing::info!(
        "saml-paste: waiting up to {}s for the operator to complete the browser login \
         and hand back a globalprotectcallback: URL to {listener_url} \
         (paste it in the terminal or POST it to /callback)",
        cap.as_secs(),
    );
    let start = Instant::now();
    loop {
        let Some(slice) = next_wait_slice(start.elapsed(), cap, heartbeat) else {
            // The human step stalled: name the phase and the gateway
            // ceiling we honoured, so `opc connect` exits loudly
            // instead of being killed silently mid-stdin. Teardown of
            // the stdin/console listener happens on the caller's
            // shutdown path either way.
            return Err(AuthError::Failed(format!(
                "saml-paste: timed out after {}s waiting for the SAML callback paste/POST \
                 (phase: operator browser login + URL handback; the gateway's \
                 <saml-request-timeout> is {}s and no callback arrived — complete the \
                 browser flow and retry)",
                cap.as_secs(),
                cap.as_secs(),
            )));
        };
        match rx.recv_timeout(slice) {
            Ok(capture) => {
                tracing::info!(
                    "saml-paste: callback captured after {}s of waiting",
                    start.elapsed().as_secs()
                );
                return Ok(capture);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(AuthError::Failed(
                    "all SAML paste flow workers closed without producing a capture".into(),
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // One heartbeat per elapsed slice. Near the cap the
                // slice shrinks; skip the heartbeat when we are only
                // finishing out the last sliver so the log ends on
                // the cap error, not on noise.
                if start.elapsed() < cap {
                    tracing::info!(
                        "saml-paste: still waiting for the callback — {}s elapsed, {}s cap",
                        start.elapsed().as_secs(),
                        cap.as_secs(),
                    );
                }
            }
        }
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

    // Wait for a capture from whichever source gets there first,
    // armed-logged + heartbeat + capped at the gateway's
    // <saml-request-timeout> (see [`wait_for_capture`]).
    let result = wait_for_capture(
        &rx,
        &format!("http://{actual_addr}/"),
        Duration::from_secs(saml.saml_request_timeout_secs),
    );

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
///   2. calls `CancelSynchronousIo` on the saved handle and
///      **inspects the result** (the reader's blocked `ReadFile`
///      returns `ERROR_OPERATION_ABORTED` when one was pending),
///   3. **waits for the reader thread with a deadline**
///      ([`STDIN_JOIN_GRACE`]) so its `StdinLock` is fully dropped
///      before this function returns in the common case — and WARNs
///      by name + abandons (detaches) when the thread will not die,
///      rather than joining INFINITE and wedging teardown,
///   4. only then `CloseHandle`s the duplicated handle.
///
/// The reader also only ships its handle **after entering its read
/// loop** (see [`EntryAck`]), so step 2 is racing a thread that is
/// provably in (or microseconds from) `ReadFile`, not one that has
/// merely been spawned.
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
    // The reader thread ships its duplicated Win32 thread HANDLE back
    // to the parent only when it has ENTERED its read loop (entry
    // ack), and never touches the handle after that. Shipping the
    // handle *before* the loop — the previous design — let the parent
    // win the spawn race: the HTTP path could complete and call
    // `CancelSynchronousIo` while the reader was still between
    // `spawn` and its first blocking `ReadFile`. The cancel then finds
    // no pending operation, and an unchecked cancel + `join()` with no
    // deadline wedges teardown. The ack shrinks the race to the
    // microsecond gap before `ReadFile` is issued;
    // [`shutdown_stdin_reader_with`] closes that gap by inspecting the
    // cancel result and deadlining the join instead of assuming exit.
    //
    // The parent owns the handle and is the only one responsible for
    // `CloseHandle`, after teardown has observed the thread exit (or
    // abandoned it).
    let stdin_tx = tx;
    let mut stdin_join: Option<thread::JoinHandle<()>> = None;
    let mut stdin_thread_handle: Option<usize> = None;
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let (handle_tx, handle_rx) = mpsc::channel::<usize>();
        let stdin_shutdown = std::sync::Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name(STDIN_READER_THREAD_NAME.into())
            .spawn(move || {
                let stdin = std::io::stdin();
                let reader = stdin.lock();
                match duplicate_current_thread_handle() {
                    Some(h) => run_stdin_reader(
                        reader,
                        stdin_tx,
                        EntryAck::Armed {
                            thread_handle: h,
                            ack: handle_tx,
                        },
                        stdin_shutdown,
                    ),
                    None => {
                        // No real handle exists → the parent cannot
                        // cancel us; drop the ack sender so its wait
                        // resolves as Disconnected (→ detach path).
                        drop(handle_tx);
                        run_stdin_reader(reader, stdin_tx, EntryAck::Lost, stdin_shutdown);
                    }
                }
            })
            .map_err(|e| AuthError::Failed(format!("spawn stdin reader: {e}")))?;
        stdin_join = Some(handle);
        // Wait for the reader to ack entry into its loop. If we miss
        // it (very slow thread start, or DuplicateHandle failed inside
        // the child) we just lose the ability to cancel — the reader
        // still works, it just gets abandoned-by-name on shutdown,
        // which is strictly better than no reader and better still
        // than a wedged teardown.
        stdin_thread_handle = match handle_rx.recv_timeout(READER_ACK_GRACE) {
            Ok(h) => Some(h),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    "saml-paste(win): {STDIN_READER_THREAD_NAME} did not ack loop entry \
                     within {READER_ACK_GRACE:?}; it cannot be cancelled and will be \
                     abandoned at shutdown"
                );
                None
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!(
                    "saml-paste(win): {STDIN_READER_THREAD_NAME} could not duplicate its \
                     thread handle; it cannot be cancelled and will be abandoned at shutdown"
                );
                None
            }
        };
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

    // Bounded, heartbeat-logged, capped wait (previously an unbounded
    // `rx.recv()` at :442 with zero tracing — the hang-report's "no
    // idea what it is waiting on" symptom). The cap honours the
    // gateway's <saml-request-timeout>.
    let result = wait_for_capture(
        &rx,
        &format!("http://{actual_addr}/"),
        Duration::from_secs(saml.saml_request_timeout_secs),
    );

    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&actual_addr, Duration::from_millis(200));
    let _ = server_thread.join();

    // Cancel the stdin reader (if it's still blocked in ReadFile),
    // then join it WITH A DEADLINE so we observe the actual unwind of
    // its `StdinLock` without ever wedging teardown on a thread whose
    // cancellation found nothing pending — and only then `CloseHandle`
    // the duplicated thread handle. Doing these in that order
    // eliminates the previous race window where a freshly-spawned
    // re-auth reader could try to lock stdin before the old one had
    // finished tearing down. The helper WARNs (by thread name) on
    // every abandonment path: an abandoned reader is loud, never
    // silent.
    let report = shutdown_stdin_reader_with(
        stdin_join.take(),
        stdin_thread_handle,
        STDIN_JOIN_GRACE,
        |handle| unsafe { windows_sys::Win32::System::IO::CancelSynchronousIo(handle as _) != 0 },
        STDIN_READER_THREAD_NAME,
    );
    if report.had_handle {
        // The reader never touches its own duplicated handle; we own
        // the single reference, so closing it after teardown (whether
        // the thread exited or was abandoned) is safe.
        if let Some(handle_usize) = stdin_thread_handle {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(handle_usize as _);
            }
        }
    }
    tracing::debug!("saml-paste(win): stdin reader teardown report: {report:?}");

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

/// Duplicate the calling thread's pseudo-handle into a real HANDLE the
/// parent can pass to `CancelSynchronousIo`/`WaitForSingleObject`.
/// Returns the handle as a `usize` (pointer-shaped) or `None`.
///
/// Must be called FROM the thread whose handle is wanted
/// (`GetCurrentThread` returns a self-only pseudo-handle).
#[cfg(windows)]
fn duplicate_current_thread_handle() -> Option<usize> {
    use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};
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
    (dup_ok != 0).then_some(real_handle as usize)
}

/// What [`shutdown_stdin_reader_with`] observed, for logging + tests.
#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct StdinShutdownReport {
    /// The parent ever received a duplicated thread handle to work with.
    had_handle: bool,
    /// `CancelSynchronousIo` returned TRUE (it found and aborted a
    /// pending synchronous read).
    cancel_issued: bool,
    /// The reader thread exited within the join grace.
    thread_exited: bool,
}

/// Tear down the Windows stdin reader after the HTTP path won (or the
/// wait capped out).
///
/// Three fixes over the original inline teardown, each pinned by a
/// `win_shutdown_tests` case:
///
/// * **Inspect the cancel result.** `CancelSynchronousIo` returns
///   FALSE when the thread has no pending synchronous I/O (e.g. it
///   lost the spawn race and has not entered `ReadFile` yet, or the
///   operation is a console wait the I/O manager does not own). The
///   old code ignored this and assumed the thread would exit.
/// * **Deadlined join.** Instead of `JoinHandle::join()` (INFINITE),
///   wait for the thread object with a grace window; on expiry WARN
///   and abandon. A reader parked in a non-alertable read must never
///   wedge process teardown — a leaked thread is recoverable, a
///   deadlocked tunnel is not (same doctrine as the old
///   no-handle-detach comment).
/// * **Abandon-with-name.** Every path that leaves the thread alive
///   logs a WARN naming [`STDIN_READER_THREAD_NAME`] so the operator
///   and the log scraper can see it.
///
/// `cancel` is injectable so the decision logic is testable without a
/// real console `ReadFile` pending (production passes a thin
/// `CancelSynchronousIo` wrapper).
#[cfg(windows)]
fn shutdown_stdin_reader_with<C: FnMut(usize) -> bool>(
    join: Option<thread::JoinHandle<()>>,
    thread_handle: Option<usize>,
    grace: Duration,
    mut cancel: C,
    thread_name: &str,
) -> StdinShutdownReport {
    let Some(handle_usize) = thread_handle else {
        // No real thread handle was ever shipped (`DuplicateHandle`
        // failed inside the reader, or the entry ack timed out).
        // Without a handle we cannot cancel a blocked `ReadFile`, so
        // calling `j.join()` here would deadlock the entire reconnect
        // path waiting for the user to type and press Enter —
        // disastrous on Ctrl-C / auto-reconnect. Detach instead
        // (dropping the JoinHandle detaches): the thread continues
        // running and will eventually return from `ReadFile` (next
        // keystroke, EOF, or process exit).
        tracing::warn!(
            "saml-paste(win): abandoning thread {thread_name} — no cancellable thread \
             handle was ever received; it stays parked until the next keystroke, EOF, \
             or process teardown"
        );
        drop(join);
        return StdinShutdownReport {
            had_handle: false,
            cancel_issued: false,
            thread_exited: false,
        };
    };

    // Re-issue the cancel across the whole grace window instead of a
    // single shot. The reader ships its thread handle the moment it
    // ENTERS its loop, but there is still an irreducible gap before its
    // blocking console `ReadFile` becomes a pending synchronous op the
    // I/O manager owns: cancel that gap and `CancelSynchronousIo`
    // reports FALSE (nothing pending yet). A single-shot cancel then
    // abandons a reader that, once it does arm `ReadFile`, can no
    // longer be interrupted — it keeps holding the process-global
    // `StdinLock`, so the next unbounded `stdin().read_line` (the MFA
    // OTP prompt) blocks forever on the reentrant lock while the
    // orphaned reader eats the keystrokes: the very silent-connect-hang
    // symptom this teardown exists to prevent. Polling
    // cancel+`WaitForSingleObject` in the loop closes both that arming
    // gap and the re-parked case (a reader that returned from one read
    // and re-armed another). A reader stuck in a genuinely
    // non-cancellable wait (a conhost-owned QuickEdit freeze the I/O
    // manager does not own) keeps reporting FALSE and is abandoned
    // after the deadline — unchanged from before, still bounded.
    let deadline = Instant::now() + grace;
    let poll = grace
        .min(Duration::from_millis(50))
        .max(Duration::from_millis(5));
    let mut cancel_issued = false;
    let mut warned_no_pending = false;
    let mut thread_exited = false;
    loop {
        if !cancel_issued {
            cancel_issued = cancel(handle_usize);
            if !cancel_issued && !warned_no_pending {
                warned_no_pending = true;
                tracing::warn!(
                    "saml-paste(win): CancelSynchronousIo({thread_name}) reported no pending \
                     synchronous read (gle: {}); not assuming the thread will exit — re-issuing \
                     across the {grace:?} grace to catch the ReadFile arming gap",
                    std::io::Error::last_os_error()
                );
            }
        }
        if wait_for_thread_exit(handle_usize, poll) {
            thread_exited = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    if !thread_exited {
        tracing::warn!(
            "saml-paste(win): {thread_name} still parked after {grace:?} grace — \
             abandoning it (detached). A thread parked in a non-alertable read must \
             not wedge process teardown. If it still holds the console stdin lock, \
             the next interactive prompt may block until it drains a keystroke."
        );
    }
    match join {
        // Only reap (consume the JoinHandle via join) when the thread
        // is observably gone; otherwise drop it to detach.
        Some(j) if thread_exited => {
            let _ = j.join();
        }
        Some(j) => drop(j),
        None => {}
    }
    StdinShutdownReport {
        had_handle: true,
        cancel_issued,
        thread_exited,
    }
}

/// `WAIT_OBJECT_0`-only thread exit poll with a hard deadline.
/// Anything else — `WAIT_TIMEOUT`, `WAIT_FAILED`, or an absurd grace
/// — is reported conservatively as "not observably finished".
#[cfg(windows)]
fn wait_for_thread_exit(thread_handle: usize, grace: Duration) -> bool {
    // WinUser.h: WAIT_OBJECT_0 == 0.
    const WAIT_OBJECT_0: u32 = 0;
    // INFINITE (0xFFFFFFFF) is deliberately unreachable via clamp —
    // a deadline-less wait is precisely the wedge this fixes.
    let millis = grace.as_millis().clamp(1, u32::MAX as u128 - 1) as u32;
    let status = unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(thread_handle as _, millis)
    };
    status == WAIT_OBJECT_0
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
/// How the stdin reader thread reports its entry into the read loop.
///
/// The handle is acked from INSIDE the reader, after the stdin lock
/// is held and just before the first blocking `read_line` — the
/// parent only ever learns "thread handle exists" once the thread has
/// demonstrably entered its loop, collapsing the spawn-vs-cancel race
/// the old pre-loop send left open. The irreducible microsecond gap
/// between the ack and `ReadFile` becoming pending is handled by
/// [`shutdown_stdin_reader_with`] inspecting the cancel result and
/// deadlining the join.
#[cfg(windows)]
enum EntryAck {
    /// Ship `thread_handle` to the parent on `ack` when the loop is
    /// entered.
    Armed {
        thread_handle: usize,
        ack: mpsc::Sender<usize>,
    },
    /// `DuplicateHandle` failed; nothing to ack.
    Lost,
}

/// Body of the Windows stdin reader, generic over the byte source so
/// the entry-ack protocol and the parse loop are testable without a
/// real console (production passes `StdinLock`, tests a channel-backed
/// `Read`).
#[cfg(windows)]
fn run_stdin_reader<S: std::io::BufRead>(
    mut source: S,
    tx: mpsc::Sender<SamlCapture>,
    ack: EntryAck,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let thread_handle = match ack {
        EntryAck::Armed { thread_handle, ack } => {
            // The reader acknowledges entry here — NOT before the
            // spawn closure acquired the stdin lock, and not after
            // the first read returned.
            let _ = ack.send(thread_handle);
            Some(thread_handle)
        }
        EntryAck::Lost => None,
    };
    let _ = &thread_handle; // the parent owns the handle from here on
    let mut line = String::new();
    loop {
        // Observe the shared shutdown flag BEFORE (re-)arming the
        // blocking console read. When the HTTP path wins, the parent
        // flips this and asks us to die; if our cancellation could not
        // interrupt the pending `ReadFile` (a conhost-owned wait the
        // I/O manager does not own, or the microsecond ack-to-arm gap),
        // we get abandoned here holding the process-global `StdinLock`.
        // Returning as soon as any buffered line drains lets us drop
        // that lock instead of silently swallowing the next keystroke
        // — which would wedge the follow-on MFA OTP prompt (it reads
        // the same `stdin()`, whose reentrant lock we still hold).
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        line.clear();
        match source.read_line(&mut line) {
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
                    eprintln!("openprotect: callback paste captured as `****` — continuing...");
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

/// Escape the five HTML-significant characters so a URL can be safely
/// embedded inside a double-quoted HTML attribute. Used for the REDIRECT
/// launch page; the browser decodes the entities back before following
/// the redirect, so the effective URL is unchanged.
fn html_attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Body served at `GET /` — either a tiny redirect page (REDIRECT method)
/// or the raw auto-submit HTML from the portal (POST method).
fn build_launch_body(saml: &SamlPrelogin) -> Result<Vec<u8>, AuthError> {
    match saml.saml_auth_method.as_str() {
        "REDIRECT" => {
            // GlobalProtect base64-encodes the target URL in
            // `saml-request` for REDIRECT, exactly as it does the HTML
            // form for POST. Decode it first: if the raw base64 string
            // is left in the `<meta refresh>` it has no scheme, so the
            // browser resolves it *relative* to `http://127.0.0.1:<port>/`
            // and navigates back into our own callback server at
            // `/<base64>`, which 404s with "openprotect: not found".
            let decoded = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            let url = String::from_utf8(decoded).map_err(|e| {
                AuthError::Failed(format!("saml-request redirect URL is not valid utf-8: {e}"))
            })?;
            // The IdP URL is already percent-encoded, but it carries `&`
            // query separators and we embed it inside double-quoted HTML
            // attributes — escape the significant characters so a stray
            // `"`/`<` can't break out of the attribute. Browsers decode
            // the entities before following the redirect, so the URL the
            // browser actually navigates to is byte-for-byte the original.
            let url = html_attr_escape(&url);
            // We can't redirect directly to the IdP URL from the HTTP
            // response because we need the browser to actually navigate
            // there (not just 302 which some configurations break). A
            // tiny HTML page with `<meta refresh>` + an explicit link is
            // the most robust option.
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

    // Keep this at `debug` and do NOT promote to INFO: for the query-
    // form callback (`GET /callback?url=<encoded>`) the path carries
    // the credential-bearing globalprotectcallback URL (SAML JWT).
    // INFO-level logging of this flow is handled by `wait_for_capture`
    // which logs only the listener base URL, never request paths.
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

#[cfg(test)]
mod launch_body_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    /// REDIRECT method: GlobalProtect base64-encodes the target URL in
    /// `saml-request` (same as it does the HTML form for POST). The
    /// launch page must redirect to the *decoded* absolute URL — if the
    /// raw base64 leaks through, the browser resolves it relative to
    /// `http://127.0.0.1:<port>/` and walks back into our own callback
    /// server at `/<base64>`, which 404s with "openprotect: not found".
    #[test]
    fn redirect_method_decodes_base64_into_absolute_url() {
        let url = "https://login.microsoftonline.com/tenant-id/saml2?SAMLRequest=abc%2Bdef&RelayState=xyz";
        let saml = SamlPrelogin {
            region: "Default".into(),
            saml_auth_method: "REDIRECT".into(),
            saml_request: B64.encode(url),
            saml_request_timeout_secs: gp_proto::prelogin::DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
        };

        let body = String::from_utf8(build_launch_body(&saml).expect("REDIRECT body builds"))
            .expect("body is utf-8");

        // The decoded IdP URL must be the redirect target so the browser
        // leaves 127.0.0.1 entirely.
        assert!(
            body.contains("https://login.microsoftonline.com/tenant-id/saml2"),
            "redirect body missing decoded IdP URL: {body}"
        );
        // Regression guard: the raw base64 string must NOT appear — that
        // was the bug that produced `/<base64>` and the 404.
        assert!(
            !body.contains(&saml.saml_request),
            "redirect body still contains raw base64 (would 404): {body}"
        );
    }

    /// POST method is unchanged: the decoded bytes are the auto-submit
    /// form served verbatim at `/`.
    #[test]
    fn post_method_returns_decoded_form() {
        let form = "<html><body><form action=\"https://idp.example.com\">…</form></body></html>";
        let saml = SamlPrelogin {
            region: "Default".into(),
            saml_auth_method: "POST".into(),
            saml_request: B64.encode(form),
            saml_request_timeout_secs: gp_proto::prelogin::DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
        };
        let body = build_launch_body(&saml).expect("POST body builds");
        assert_eq!(body, form.as_bytes());
    }
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

#[cfg(test)]
mod wait_tests {
    use super::*;

    fn capture() -> SamlCapture {
        SamlCapture {
            username: "u@example.com".into(),
            prelogin_cookie: "aaa.bbb.ccc".into(),
            portal_user_auth_cookie: None,
        }
    }

    /// The overall cap must fire with a named error so `opc connect`
    /// escapes the human wait instead of blocking forever (the
    /// saml_paste.rs:442 `rx.recv()` wedge). Driven from a helper
    /// thread with a watchdog so a still-unbounded implementation
    /// FAILS this test instead of hanging the whole suite.
    #[test]
    fn overall_cap_expires_with_named_phase_error() {
        let (tx, rx) = mpsc::channel::<SamlCapture>();
        let (done_tx, done_rx) = mpsc::channel::<Result<SamlCapture, AuthError>>();
        thread::spawn(move || {
            let _ = done_tx.send(wait_for_capture(
                &rx,
                "http://127.0.0.1:9/",
                Duration::from_millis(300),
            ));
        });
        let outcome = done_rx.recv_timeout(Duration::from_secs(5));
        drop(tx); // release the helper thread if it is still parked
        match outcome {
            Err(_) => panic!(
                "wait_for_capture did not return 5s after a 300ms cap — \
                 the human wait is still unbounded (rx.recv() behaviour)"
            ),
            Ok(Ok(c)) => panic!("unexpected capture with nobody sending: {c:?}"),
            Ok(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("saml-request-timeout"),
                    "expiry must name the gateway <saml-request-timeout> it honoured: {msg}"
                );
                assert!(
                    msg.contains("paste"),
                    "expiry must name the phase (waiting on the operator's \
                     paste/POST, not on the network): {msg}"
                );
            }
        }
    }

    /// Regression guard (passes before and after): a real capture
    /// arrives promptly and is returned verbatim.
    #[test]
    fn capture_wins_the_race_before_any_cap() {
        let (tx, rx) = mpsc::channel::<SamlCapture>();
        let (done_tx, done_rx) = mpsc::channel::<Result<SamlCapture, AuthError>>();
        thread::spawn(move || {
            done_tx.send(wait_for_capture(
                &rx,
                "http://127.0.0.1:9/",
                Duration::from_secs(60),
            ))
        });
        thread::sleep(Duration::from_millis(50));
        tx.send(capture()).expect("send capture");
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(c)) => {
                assert_eq!(c.username, "u@example.com");
                assert_eq!(c.prelogin_cookie, "aaa.bbb.ccc");
            }
            Ok(Err(e)) => panic!("capture lost: {e}"),
            Err(_) => panic!("wait_for_capture did not return after the capture was sent"),
        }
    }

    /// Regression guard: all senders gone → a clear "closed without
    /// producing a capture" error, not a hang and not a cap timeout.
    #[test]
    fn disconnected_channel_maps_to_clear_error() {
        let (tx, rx) = mpsc::channel::<SamlCapture>();
        drop(tx);
        let (done_tx, done_rx) = mpsc::channel::<Result<SamlCapture, AuthError>>();
        thread::spawn(move || {
            done_tx.send(wait_for_capture(
                &rx,
                "http://127.0.0.1:9/",
                Duration::from_secs(60),
            ))
        });
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Err(e)) => assert!(
                e.to_string().contains("without producing a capture"),
                "unexpected error text: {e}"
            ),
            Ok(Ok(c)) => panic!("unexpected capture from dead channel: {c:?}"),
            Err(_) => panic!("wait_for_capture hung on a disconnected channel"),
        }
    }

    /// Heartbeat/cap cadence is a pure function so the timing logic
    /// is testable without asserting on tracing output (this crate
    /// has no subscriber test harness — logging itself is reviewed,
    /// cadence is asserted here).
    #[test]
    fn wait_slice_cadence() {
        let hb = Duration::from_secs(WAIT_HEARTBEAT_SECS);
        let cap = Duration::from_secs(600);
        assert_eq!(next_wait_slice(Duration::ZERO, cap, hb), Some(hb));
        assert_eq!(
            next_wait_slice(Duration::from_secs(590), cap, hb),
            Some(Duration::from_secs(10)),
            "final slice must shrink to the remaining budget, not overshoot the cap"
        );
        assert_eq!(next_wait_slice(Duration::from_secs(600), cap, hb), None);
        assert_eq!(next_wait_slice(Duration::from_secs(601), cap, hb), None);
        assert_eq!(
            next_wait_slice(Duration::from_millis(700), Duration::from_secs(1), hb),
            Some(Duration::from_millis(300))
        );
    }
}

#[cfg(all(test, windows))]
mod win_shutdown_tests {
    use super::*;

    /// A thread that duplicates its own handle, acks it to the parent,
    /// and then parks in a blocking primitive that
    /// `CancelSynchronousIo` cannot abort (the shape of a console
    /// `ReadFile` wedge, from the parent's point of view). Returns
    /// `(ack_rx, join_handle, gate_tx)`; dropping/sending on `gate_tx`
    /// releases the park.
    fn parked_reader_thread() -> (
        mpsc::Receiver<usize>,
        thread::JoinHandle<()>,
        mpsc::Sender<()>,
    ) {
        let (ack_tx, ack_rx) = mpsc::channel::<usize>();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let join = thread::Builder::new()
            .name("test-parked-reader".into())
            .spawn(move || {
                let h = duplicate_current_thread_handle().expect("DuplicateHandle");
                let _ = ack_tx.send(h);
                let _ = gate_rx.recv(); // park until the test releases us
            })
            .expect("spawn parked reader");
        (ack_rx, join, gate_tx)
    }

    /// Run `shutdown_stdin_reader_with` under a watchdog so a
    /// still-undeadlined implementation FAILS the assertion instead
    /// of hanging the test binary.
    fn shutdown_under_watchdog<C: FnMut(usize) -> bool + Send + 'static>(
        join: Option<thread::JoinHandle<()>>,
        thread_handle: Option<usize>,
        grace: Duration,
        cancel: C,
        name: &'static str,
    ) -> StdinShutdownReport {
        let (done_tx, done_rx) = mpsc::channel::<StdinShutdownReport>();
        thread::spawn(move || {
            let _ = done_tx.send(shutdown_stdin_reader_with(
                join,
                thread_handle,
                grace,
                cancel,
                name,
            ));
        });
        match done_rx.recv_timeout(grace * 4 + Duration::from_secs(2)) {
            Ok(r) => r,
            Err(_) => panic!(
                "shutdown_stdin_reader_with never returned — the join has \
                 no deadline, exactly the wedge the plan says to fix"
            ),
        }
    }

    fn real_cancel(handle: usize) -> bool {
        unsafe { windows_sys::Win32::System::IO::CancelSynchronousIo(handle as _) != 0 }
    }

    /// (4b)+(4c): the HTTP path completed while the reader was parked
    /// with no pending synchronous I/O at all — the real
    /// `CancelSynchronousIo` returns FALSE. The old code ignored that
    /// and joined forever; the fix must inspect the result, then
    /// deadlined-wait and abandon-with-WARN. Red until the deadline
    /// lands: the watchdog fires.
    #[test]
    fn parked_reader_is_abandoned_within_deadline() {
        let (ack_rx, join, gate_tx) = parked_reader_thread();
        let handle = ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reader never acked its entry");

        let report = shutdown_under_watchdog(
            Some(join),
            Some(handle),
            STDIN_JOIN_GRACE,
            real_cancel,
            STDIN_READER_THREAD_NAME,
        );
        assert!(report.had_handle);
        assert!(
            !report.cancel_issued,
            "a thread parked in a non-I/O wait must report CancelSynchronousIo=false \
             (inspecting the result is part of the fix)"
        );
        assert!(
            !report.thread_exited,
            "we must NOT assume a thread whose cancellation found nothing will exit"
        );

        // Leave no zombie: release the park so the abandoned thread ends.
        let _ = gate_tx.send(());
    }

    /// (4b) decision logic: when cancellation DOES report success,
    /// the report must say so (old stub hard-coded "ignored").
    #[test]
    fn cancel_success_is_observed_in_the_report() {
        let (ack_rx, join, gate_tx) = parked_reader_thread();
        let handle = ack_rx.recv_timeout(Duration::from_secs(2)).expect("ack");
        // Release the park first so the thread exits within grace.
        let _ = gate_tx.send(());
        let report = shutdown_under_watchdog(
            Some(join),
            Some(handle),
            STDIN_JOIN_GRACE,
            |_h| true, // fake: "a pending read was cancelled"
            STDIN_READER_THREAD_NAME,
        );
        assert!(
            report.cancel_issued,
            "the CancelSynchronousIo result must be propagated, not swallowed"
        );
        assert!(
            report.thread_exited,
            "a cancelled reader that exits promptly must be joined, not abandoned"
        );
    }

    /// A `BufRead` source that blocks its first `read()` on a channel
    /// (no I/O-manager operation → real `CancelSynchronousIo` cannot
    /// abort it), while recording that a read was issued. Mirrors the
    /// stdin reader's console `ReadFile` from the parent's viewpoint.
    struct GateReader {
        rx: mpsc::Receiver<Vec<u8>>,
        read_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl std::io::Read for GateReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering;
            self.read_started.store(true, Ordering::SeqCst);
            match self.rx.recv() {
                Ok(v) => {
                    let n = v.len().min(buf.len());
                    buf[..n].copy_from_slice(&v[..n]);
                    Ok(n)
                }
                Err(_) => Ok(0), // all senders gone → EOF
            }
        }
    }

    /// (4a): the parent must not learn the reader's thread handle
    /// until the reader has ACKED ENTRY into its loop, and once
    /// acked the reader must actually reach its blocking read. Also
    /// exercises the full happy path of the parse loop (a pasted
    /// callback line delivered through the gate is captured and
    /// shipped, bounded).
    #[test]
    fn reader_acks_entry_and_then_reaches_the_read() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>();
        let reader = GateReader {
            rx: data_rx,
            read_started: started.clone(),
        };
        let (ack_tx, ack_rx) = mpsc::channel::<usize>();
        let (cap_tx, cap_rx) = mpsc::channel::<SamlCapture>();
        const SENTINEL: usize = 0xdead_beef; // never cancelled in this test
        let join = thread::Builder::new()
            .name(STDIN_READER_THREAD_NAME.into())
            .spawn(move || {
                run_stdin_reader(
                    std::io::BufReader::new(reader),
                    cap_tx,
                    EntryAck::Armed {
                        thread_handle: SENTINEL,
                        ack: ack_tx,
                    },
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
            })
            .expect("spawn reader");

        let acked = ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reader never acked entry");
        assert_eq!(acked, SENTINEL);
        // Post-ack, the thread must reach its blocking source read —
        // the property the old pre-loop handle send never guaranteed.
        for _ in 0..100 {
            if started.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(started.load(Ordering::SeqCst), "acked but never read");

        // Now the "HTTP won" moment: ship the pasted line; the reader
        // must parse, send, and exit promptly.
        data_tx
            .send(
                b"globalprotectcallback:cas-as=1&un=alice%40example.com&token=aaa.bbb.ccc\n"
                    .to_vec(),
            )
            .expect("send line");
        let cap = cap_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("capture never arrived");
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "aaa.bbb.ccc");
        join.join().unwrap();
    }

    /// (4a) degenerate branch: `DuplicateHandle` failed → `EntryAck::
    /// Lost` → no ack (parent's recv resolves Disconnected → its
    /// warn+detach path), but the reader still functions normally.
    #[test]
    fn lost_ack_still_reads_and_captures() {
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>();
        let reader = GateReader {
            rx: data_rx,
            read_started: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let (cap_tx, cap_rx) = mpsc::channel::<SamlCapture>();
        let join = thread::spawn(move || {
            run_stdin_reader(
                std::io::BufReader::new(reader),
                cap_tx,
                EntryAck::Lost,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
        });
        data_tx
            .send(b"globalprotectcallback:un=bob&token=x.y.z\n".to_vec())
            .unwrap();
        let cap = cap_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("capture");
        assert_eq!(cap.username, "bob");
        join.join().unwrap();
    }

    /// When the parent never received a thread handle (dup failed /
    /// ack missed), the old detach stays detached — but now loudly
    /// (WARN by name), never silently, and never joining (a join with
    /// no cancellation ability is the deadlock the comment at the old
    /// :466-479 warns about).
    #[test]
    fn missing_handle_detaches_rather_than_deadlocking() {
        let join = thread::Builder::new()
            .name("test-unkillable".into())
            .spawn(|| {
                let (never_tx, never_rx) = mpsc::channel::<()>();
                std::mem::forget(never_tx); // never_rx blocks forever
                let _ = never_rx.recv();
            })
            .expect("spawn");
        let report = shutdown_under_watchdog(
            Some(join),
            None,
            STDIN_JOIN_GRACE,
            |_| unreachable!("no handle → cancel must not be called"),
            STDIN_READER_THREAD_NAME,
        );
        assert!(!report.had_handle);
        assert!(!report.cancel_issued);
        assert!(!report.thread_exited, "detached ≠ exited");
    }

    /// High-severity race remediation: when the parent flips `shutdown`
    /// and our cancellation cannot interrupt the pending console read
    /// (conhost-owned wait / the ack-to-`ReadFile` gap), the reader must
    /// NOT keep re-arming `ReadFile` and eating the next keystroke. As
    /// soon as any buffered line drains, it must observe `shutdown`,
    /// return, and drop the `StdinLock` — otherwise the follow-on MFA
    /// OTP prompt blocks forever on the reentrant lock the orphan holds.
    ///
    /// Red before the fix: `run_stdin_reader` ignored `shutdown` and
    /// looped into another blocking read, so the join never returned
    /// and this test timed out under the watchdog.
    #[test]
    fn abandoned_reader_drains_buffered_line_then_releases_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>();
        let reader = GateReader {
            rx: data_rx,
            read_started: started.clone(),
        };
        let (cap_tx, _cap_rx) = mpsc::channel::<SamlCapture>();
        let shut_clone = std::sync::Arc::clone(&shutdown);
        let join = thread::Builder::new()
            .name(STDIN_READER_THREAD_NAME.into())
            .spawn(move || {
                run_stdin_reader(
                    std::io::BufReader::new(reader),
                    cap_tx,
                    EntryAck::Lost,
                    shut_clone,
                )
            })
            .expect("spawn reader");

        // Let the reader park in its first blocking read.
        for _ in 0..100 {
            if started.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(started.load(Ordering::SeqCst), "reader never reached read");

        // The HTTP path won while cancel could not abort the read:
        // parent abandons us and flips shutdown.
        shutdown.store(true, Ordering::SeqCst);

        // The operator then types at the OTP prompt — but the orphaned
        // reader is the one whose read returns first. It must NOT
        // re-armed to swallow the next keystroke; it must return and
        // release the lock.
        data_tx
            .send(b"not-a-callback-line\n".to_vec())
            .expect("send line");

        let (done_tx, done_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let _ = join.join();
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(Duration::from_secs(2)).expect(
            "abandoned reader never returned — it re-armed ReadFile and ate the \
                 keystroke, holding the StdinLock the OTP prompt needs (silent-hang \
                 regression)",
        );
    }

    /// High-severity race remediation (the other half): a single-shot
    /// `CancelSynchronousIo` that reports FALSE — because the reader is
    /// still in the ack-to-`ReadFile` arming gap — must NOT be the last
    /// attempt. The parent re-issues the cancel across the grace window
    /// so a `ReadFile` that becomes pending after the first try is still
    /// aborted, and the reader exits rather than being abandoned while
    /// it holds the `StdinLock`.
    ///
    /// Red before the fix: the loop existed only as a single cancel +
    /// one blocking wait, so a reader that armed only after the first
    /// (failed) cancel was never aborted and `thread_exited` stayed
    /// false.
    #[test]
    fn shutdown_reissues_cancel_until_the_read_arms() {
        let (ack_tx, ack_rx) = mpsc::channel::<usize>();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        // Models the ack-to-ReadFile gap: the thread does not "arm" its
        // pending read until well after it ships the handle.
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let armed_t = std::sync::Arc::clone(&armed);
        let join = thread::Builder::new()
            .name("test-late-arm-reader".into())
            .spawn(move || {
                let h = duplicate_current_thread_handle().expect("DuplicateHandle");
                let _ = ack_tx.send(h);
                thread::sleep(Duration::from_millis(120)); // still in the gap
                armed_t.store(true, std::sync::atomic::Ordering::SeqCst); // ReadFile now pending
                let _ = gate_rx.recv(); // released only by a *successful* cancel
            })
            .expect("spawn");
        let handle = ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reader never acked entry");

        let cancel_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_c = std::sync::Arc::clone(&cancel_calls);
        let armed_c = std::sync::Arc::clone(&armed);
        let gate_c = gate_tx;
        let report = shutdown_under_watchdog(
            Some(join),
            Some(handle),
            STDIN_JOIN_GRACE,
            move |_h| {
                calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if armed_c.load(std::sync::atomic::Ordering::SeqCst) {
                    // A real CancelSynchronousIo would abort the pending
                    // ReadFile → the reader returns. Emulate by opening
                    // the gate.
                    let _ = gate_c.send(());
                    true
                } else {
                    false // still in the arming gap
                }
            },
            STDIN_READER_THREAD_NAME,
        );

        let calls = cancel_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            report.cancel_issued,
            "a cancel that eventually finds the armed read must report success (calls={calls})"
        );
        assert!(
            report.thread_exited,
            "the re-issued cancel must abort the late-arming read, not abandon the reader (calls={calls})"
        );
        assert!(
            calls >= 2,
            "a single-shot cancel across the arming gap abandons the reader; must re-issue \
             until the read arms (observed {calls} cancel call(s))"
        );
    }
}
