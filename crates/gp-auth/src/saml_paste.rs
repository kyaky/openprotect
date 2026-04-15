//! Headless SAML authentication via an external browser + paste callback.
//!
//! This provider **has no GUI dependencies**. It's the flow you want on
//! servers, SSH sessions, CI runners, containers — anywhere a webkit2gtk
//! window can't exist.
//!
//! Flow:
//!
//! 1. pgn starts a tiny HTTP server on `127.0.0.1:<port>` (default 29999).
//! 2. The server serves a launch page at `/` that either (a) redirects
//!    the browser to the IdP SAML URL (`REDIRECT` method) or (b) renders
//!    the auto-submitting HTML form that comes from the portal (`POST`
//!    method, base64-decoded).
//! 3. pgn prints the local URL to the terminal along with instructions:
//!    open it in any browser, on any machine. If the user is SSH'd in
//!    they can `ssh -L 29999:localhost:29999 …` and open
//!    `http://localhost:29999/` on their own workstation.
//! 4. The user completes the IdP flow (Azure AD, Okta, Shib, …). GP's
//!    final step redirects the browser to a custom
//!    `globalprotectcallback:…` scheme that browsers can't handle. The
//!    user copies that URL out of the address bar / the error page.
//! 5. There are two ways to hand the URL back to pgn:
//!    - **Paste it into the terminal.** pgn is reading stdin line-by-line
//!      while the server runs.
//!    - **POST it to `/callback`**, either manually
//!      (`curl -X POST http://localhost:29999/callback -d 'url=…'`) or
//!      via the bookmarklet printed on the launch page.
//! 6. Whichever path fires first wins; the server + stdin reader both
//!    shut down and pgn continues.
//!
//! No display, no webkit2gtk, no GTK main loop — just HTTP + stdin.

use std::io::{BufRead, BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
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
pub const DEFAULT_PORT: u16 = 29999;

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
fn run_paste_flow(saml: &SamlPrelogin, port: u16) -> Result<SamlCapture, AuthError> {
    // Turn off TTY echo on stdin for the entire duration of the paste
    // flow. The callback URL contains a short-TTL SAML JWT with the
    // user's identity; echoing it to the terminal means `script(1)`,
    // tmux pane capture, terminal scrollback, and over-the-shoulder
    // readers all see the token. Without echo the user still types
    // fine and the `Enter` keypress still commits the line — they just
    // don't see characters while pasting. We restore the prior termios
    // state on every exit path via RAII so a panic in the server
    // thread or an `Err(?)` on `build_launch_body` cannot leave the
    // user's terminal in a no-echo state.
    //
    // If stdin is not a TTY (piped input, redirected file, cron job,
    // test harness) the guard is a no-op and we stay silent.
    let _echo_guard = TtyEchoGuard::new(libc::STDIN_FILENO);

    // Decode the SAML launch content up front so the server thread can
    // own a plain byte vector without caring about the method.
    let launch_body = build_launch_body(saml)?;

    let bind_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| AuthError::Failed(format!("bind {bind_addr}: {e}")))?;
    let actual_addr = listener
        .local_addr()
        .map_err(|e| AuthError::Failed(format!("local_addr: {e}")))?;

    // Non-blocking accept with a small timeout so the server thread can
    // check a shutdown flag between connections.
    listener
        .set_nonblocking(false)
        .map_err(|e| AuthError::Failed(format!("set_blocking: {e}")))?;

    print_instructions(&actual_addr, saml);

    let (tx, rx) = mpsc::channel::<SamlCapture>();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Self-pipe used to wake the stdin reader out of its `poll(2)` when
    // the HTTP path captures first. Closing the write end fires `POLLHUP`
    // on the read end; the reader exits cleanly without holding the
    // stdin lock — critical, otherwise it would block the gateway
    // login MFA prompt that follows in `pgn connect`.
    let (stdin_wake_read, stdin_wake_write) = make_pipe()?;

    // --- HTTP server thread ---
    let server_tx = tx.clone();
    let server_shutdown = std::sync::Arc::clone(&shutdown);
    let server_body = launch_body.clone();
    let server_thread = thread::Builder::new()
        .name("pgn-saml-http".into())
        .spawn(move || http_server_loop(listener, server_body, server_tx, server_shutdown))
        .map_err(|e| AuthError::Failed(format!("spawn http server: {e}")))?;

    // --- stdin reader thread ---
    // The reader takes ownership of the read end of the wake pipe and
    // polls both stdin and that fd. The main thread keeps the write end
    // and drops it on shutdown, signalling the reader via POLLHUP.
    let stdin_tx = tx.clone();
    let stdin_thread = thread::Builder::new()
        .name("pgn-saml-stdin".into())
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

    // Signal both workers to stop.
    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

    // Wake the stdin reader by closing the wake pipe's write end. POLLHUP
    // on the reader's poll(2) call fires immediately and the reader exits.
    drop(stdin_wake_write);

    // Poke the HTTP server: open a throwaway connection so its blocking
    // `accept()` returns and it sees the shutdown flag. If this fails we
    // don't care — the thread will exit on the next real connection or
    // when the process does.
    let _ = TcpStream::connect_timeout(&actual_addr, Duration::from_millis(200));

    // Both threads are now wakeable. Join both so neither lingers — the
    // stdin reader in particular MUST be gone before pgn returns to
    // collect MFA input.
    let _ = server_thread.join();
    let _ = stdin_thread.join();

    result
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
/// Drop is best-effort: if `tcsetattr` fails during restore (extremely
/// unlikely — the fd was valid at construction time) we log at
/// `debug` and move on. Panicking from a destructor would poison
/// unrelated error-handling paths.
struct TtyEchoGuard {
    fd: libc::c_int,
    /// `None` when either (a) stdin isn't a TTY, or (b) `tcgetattr`
    /// failed, so `Drop` has nothing to restore.
    saved: Option<libc::termios>,
}

impl TtyEchoGuard {
    fn new(fd: libc::c_int) -> Self {
        let saved = unsafe {
            if libc::isatty(fd) == 0 {
                None
            } else {
                let mut termios = MaybeUninit::<libc::termios>::zeroed();
                if libc::tcgetattr(fd, termios.as_mut_ptr()) != 0 {
                    None
                } else {
                    let original = termios.assume_init();
                    let mut modified = original;
                    modified.c_lflag &= !libc::ECHO;
                    // Keep ICANON on — we still want the kernel to
                    // deliver line-at-a-time input on Enter so our
                    // reader loop sees `\n` the normal way.
                    if libc::tcsetattr(fd, libc::TCSAFLUSH, &modified) != 0 {
                        None
                    } else {
                        Some(original)
                    }
                }
            }
        };
        Self { fd, saved }
    }
}

impl Drop for TtyEchoGuard {
    fn drop(&mut self) {
        if let Some(original) = self.saved.take() {
            let rc = unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &original) };
            if rc != 0 {
                tracing::debug!(
                    "TtyEchoGuard::drop: tcsetattr restore failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Create a Unix pipe and wrap both ends in `OwnedFd` so they close on drop.
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
fn print_instructions(addr: &SocketAddr, saml: &SamlPrelogin) {
    eprintln!();
    eprintln!("┌─ Pangolin — headless SAML authentication ─────────────────────────────────┐");
    eprintln!("│                                                                            │");
    eprintln!("│  Open this URL in any browser (any machine):                               │");
    eprintln!("│                                                                            │");
    eprintln!(
        "│    http://{}/                                              ",
        addr
    );
    eprintln!("│                                                                            │");
    eprintln!("│  Over SSH? Port-forward first:                                             │");
    eprintln!(
        "│    ssh -L {port}:localhost:{port} …                                          ",
        port = addr.port()
    );
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
        "paste provider: saml_auth_method={} saml_request_len={}",
        saml.saml_auth_method,
        saml.saml_request.len()
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
                 <title>Pangolin SAML</title></head><body>\
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
                        b"pangolin: authentication captured, you can close this tab\n",
                    );
                    let _ = tx.send(cap);
                    break;
                } else {
                    let _ = respond_plain(
                        &mut stream,
                        400,
                        "Bad Request",
                        b"pangolin: `url` did not start with globalprotectcallback:\n",
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
                        b"pangolin: missing `url` query parameter\n",
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
                        b"pangolin: POST /callback needs `url=...` in body\n",
                    )?;
                    Ok(None)
                }
            }
        }
        _ => {
            respond_plain(stream, 404, "Not Found", b"pangolin: not found\n")?;
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
            if b == b'\n' {
                if *discarding_overlong {
                    // End of the overlong line — reset state and move on
                    // without parsing this junk.
                    *discarding_overlong = false;
                    current_line.clear();
                    eprintln!(
                        "pangolin: input line exceeded {} bytes — discarded. \
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
                match parse_globalprotect_callback(trimmed) {
                    Some(cap) => {
                        let _ = tx.send(cap);
                        return Feed::Captured;
                    }
                    None => {
                        eprintln!(
                            "pangolin: that doesn't start with `globalprotectcallback:`, \
                             try again (or Ctrl-C to abort):"
                        );
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
                let mut wake_check = [libc::pollfd {
                    fd: wake_raw,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                let wake_rc = unsafe { libc::poll(wake_check.as_mut_ptr(), 1, 0) };
                if wake_rc > 0
                    && wake_check[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe read fd is not a TTY, so `TtyEchoGuard::new` must leave
    /// `saved` empty and `Drop` must be a no-op. This is the code path
    /// taken under `cargo test`, CI, cron jobs, `pgn < saml.txt`, and
    /// anything else where stdin is not a real terminal.
    #[test]
    fn echo_guard_on_pipe_is_noop() {
        let (read, _write) = make_pipe().expect("pipe()");
        let fd = read.as_raw_fd();
        let guard = TtyEchoGuard::new(fd);
        assert!(
            guard.saved.is_none(),
            "TtyEchoGuard::new on a pipe fd must leave saved=None"
        );
        drop(guard);
    }

    /// An already-closed / invalid fd must not panic and must not
    /// touch termios. `isatty(-1)` returns 0 with errno EBADF, so we
    /// exit early and `saved` stays None.
    #[test]
    fn echo_guard_on_invalid_fd_is_noop() {
        let guard = TtyEchoGuard::new(-1);
        assert!(guard.saved.is_none());
        drop(guard);
    }
}
