//! Shell out to `opc.exe` for connect/disconnect/status.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// PID of the currently running `opc connect` child process.
/// Used by `cancel_connect()` to kill it.
static CONNECT_PID: AtomicU32 = AtomicU32::new(0);

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct StatusInfo {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub portal: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub local_ipv4: Option<String>,
    #[serde(default)]
    pub uptime_seconds: u64,
    #[serde(default)]
    pub tun_ifname: Option<String>,
    /// True when the session's LAST route teardown ended DEGRADED
    /// (route state was unconfirmed at disconnect). Displayed in the
    /// connected panel so a GUI user can see it; the CLI's exit code
    /// already carries it.
    #[serde(default)]
    pub teardown_degraded: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VpnState {
    Connected(StatusInfo),
    Connecting,
    Disconnected,
}

/// Find opc.exe next to opc-gui.exe, or fall back to PATH.
pub fn opc_exe() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("opc-gui.exe"));
    path.set_file_name(if cfg!(windows) { "opc.exe" } else { "opc" });
    if path.exists() {
        path
    } else {
        PathBuf::from(if cfg!(windows) { "opc.exe" } else { "opc" })
    }
}

/// Create a `Command` that does NOT flash a console window on Windows.
/// Also sets the working directory to the exe's parent so that
/// DLLs (wintun.dll, libopenconnect-5.dll) next to opc.exe are found
/// even when the GUI is launched with a different CWD (e.g. admin UAC
/// starts in C:\Windows\System32).
fn hidden_cmd(exe: &std::path::Path) -> Command {
    let mut cmd = Command::new(exe);
    if let Some(dir) = exe.parent() {
        cmd.current_dir(dir);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}

/// Poll `opc status --json` and return the current VPN state.
pub fn poll_status() -> VpnState {
    let output = hidden_cmd(&opc_exe())
        .args(["status", "--json", "--instance", "default"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return VpnState::Disconnected,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(info) = serde_json::from_str::<StatusInfo>(stdout.trim()) {
        if info.state == "connected" {
            return VpnState::Connected(info);
        }
        if info.state == "connecting" || info.state == "reconnecting" {
            return VpnState::Connecting;
        }
    }
    VpnState::Disconnected
}

/// Launch `opc connect` and stream output to log buffer.
///
/// Runs `opc.exe` directly (no UAC elevation) so the GUI can capture
/// stdout/stderr. For production use where the tunnel needs admin
/// rights, the user should run opc-gui itself as administrator.
///
/// `saml_url` is set when the SAML HTTP server URL is detected in output.
pub fn connect(
    portal: &str,
    user: &str,
    split_tunnel: &str,
    verbose: bool,
    log: Arc<Mutex<Vec<String>>>,
    saml_url: Arc<Mutex<Option<String>>>,
    connect_done: Arc<std::sync::atomic::AtomicBool>,
) {
    let opc = opc_exe();
    let portal = portal.to_string();
    let user = user.to_string();
    let split_tunnel = split_tunnel.to_string();

    std::thread::spawn(move || {
        let mut args = vec!["connect".to_string()];
        if !portal.is_empty() {
            args.push(portal);
        }
        if !user.is_empty() {
            args.push("--user".to_string());
            args.push(user);
        }
        // --only accepts comma-separated CIDRs as a single argument
        let routes: String = split_tunnel
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        if !routes.is_empty() {
            args.push("--only".to_string());
            args.push(routes);
        }
        args.push("--log".to_string());
        args.push(if verbose { "debug" } else { "info" }.to_string());

        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match hidden_cmd(&opc)
            .args(&str_args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                let pid = child.id();
                CONNECT_PID.store(pid, Ordering::SeqCst);
                if let Ok(mut l) = log.lock() {
                    l.push(format!("[gui] opc started, PID={pid}"));
                }
                let mut browser_opened = false;
                // Stream stderr (where tracing output goes) into the log.
                if let Some(stderr) = child.stderr.take() {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(Result::ok) {
                        // Detect the SAML HTTP server URL and auto-open
                        // the browser so the user doesn't have to copy it.
                        if !browser_opened {
                            if let Some(url) = extract_saml_url(&line) {
                                let _ = open::that(&url);
                                browser_opened = true;
                                // Store the server URL so the GUI can POST the callback.
                                if let Ok(mut s) = saml_url.lock() {
                                    *s = Some(url.clone());
                                }
                                if let Ok(mut l) = log.lock() {
                                    l.push(format!(
                                        "[gui] opened browser for SAML: {url}"
                                    ));
                                }
                            }
                        }
                        if let Ok(mut l) = log.lock() {
                            l.push(line);
                        }
                    }
                }
                // Wait for child to finish and clear PID.
                let _ = child.wait();
                CONNECT_PID.store(0, Ordering::SeqCst);
            }
            Err(e) => {
                if let Ok(mut l) = log.lock() {
                    l.push(format!("[error] failed to launch opc: {e}"));
                }
            }
        }
        // Signal the UI that the connect thread is done so it can
        // reset the connect_in_flight guard.
        connect_done.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

/// The exact unambiguous marker opc emits (once, at callback-server
/// bind) in front of the SAML URL. Produced by `saml_callback_marker`
/// in crates/gp-auth/src/saml_paste.rs; duplicated here because
/// bins/opc-gui is workspace-excluded and cannot import it — change
/// one side, the saml_url_trust_tests on this side and the
/// marker-contract test on that side fail together.
const SAML_CALLBACK_MARKER: &str = "SAML-CALLBACK-URL ";

/// Extract the SAML callback URL from an opc stderr line.
///
/// Issue #36 checklist M4 trust model: the CLI prints the URL inside a
/// human-readable box (`│    http://127.0.0.1:54912/`), but the issue
/// #36 diagnostics put **gateway-controlled text** (PAN headers, error
/// bodies) on the same stderr stream. A substring scan for
/// `http://127.0.0.1:` would let a hostile gateway impersonate the
/// callback and auto-open a browser (or poison the GUI's stored
/// `saml_url` that receives the callback POST). Matching is therefore
/// marker-only: the line must START with [`SAML_CALLBACK_MARKER`]
/// followed by a plain `http://127.0.0.1:<port>/` URL. Server-sourced
/// text cannot produce such a line: the gp-auth diagnostics flatten
/// control chars out of EVERY server-influenced interpolation —
/// response bodies/headers via `scrub_server_text` (see
/// `scrub_server_text_flattens_server_newlines`) and the `POST {url}`
/// lanes via `flatten_control_chars` — and the portal-advertised
/// gateway address itself is charset-gated at parse
/// (`gp_proto::gateway::Gateway::parse_list`), so attacker text can
/// never start a stderr line at all. The old box parser is gone: no
/// fallback, marker required.
fn extract_saml_url(line: &str) -> Option<String> {
    let rest = line.strip_prefix(SAML_CALLBACK_MARKER)?;
    let url = rest.split_whitespace().next()?;
    let addr = url.strip_prefix("http://127.0.0.1:")?.strip_suffix('/')?;
    if addr.is_empty() {
        return None;
    }
    // Port must parse (rejects `http://127.0.0.1:notaport/` and any
    // path/extra junk glued onto the token; 0 is never a bound port).
    let port = addr.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(url.to_string())
}

#[cfg(test)]
mod saml_url_trust_tests {
    use super::extract_saml_url;

    /// The one line opc emits at bind time (produced by
    /// `saml_callback_marker` in crates/gp-auth/src/saml_paste.rs —
    /// keep the literals in sync; the GUI crate is workspace-excluded
    /// so it cannot import the constant).
    const MARKER_LINE: &str = "SAML-CALLBACK-URL http://127.0.0.1:54912/";

    /// Checklist M4 (RED): a SERVER-controlled diagnostic line — the
    /// issue #36 fix added gateway-body text to stderr — must never
    /// impersonate the callback and auto-open a browser.
    #[test]
    fn server_controlled_text_never_opens_browser() {
        assert!(
            extract_saml_url("error: gateway rejected http://127.0.0.1:9999/").is_none(),
            "M4: unmarked loopback URL in server-reachable text must not \
             trigger the browser-open path"
        );
        // The realistic shape: the new non-2xx diagnostics embed a
        // body head; a hostile gateway could put any URL in it.
        assert!(
            extract_saml_url(
                " WARN gp_auth::client: gateway login rejected: POST https://gw:11443/ssl-vpn/login.esp -> HTTP 512; body=visit http://127.0.0.1:9/ now"
            )
            .is_none(),
            "M4: hostile 512 body must not steer the GUI"
        );
    }

    /// The old box-drawing banner line is no longer trusted by itself:
    /// marker required.
    #[test]
    fn unmarked_box_line_is_not_trusted() {
        assert!(extract_saml_url("│    http://127.0.0.1:54912/").is_none());
    }

    #[test]
    fn marker_line_is_extracted() {
        assert_eq!(
            extract_saml_url(MARKER_LINE).as_deref(),
            Some("http://127.0.0.1:54912/")
        );
    }

    /// Issue #36 adversarial resweep (M4 consumer-contract pin): the
    /// GUI's trust boundary is the marker itself — a marker-led,
    /// loopback, parseable-port line is trusted UNCONDITIONALLY, by
    /// design (M4 chose "marker required", not "marker + provenance";
    /// the consumer cannot distinguish provenance from one flat line).
    /// The security of that design therefore rests ENTIRELY on the
    /// producer never letting server-controlled text emit such a
    /// line. It used to be able to (the `POST {url}` diagnostics
    /// interpolated the raw portal-advertised gateway address, LF and
    /// all — the retired `known_gap_*` pins in gp-auth/gp-proto
    /// proved it); post-fix that is impossible, pinned by
    /// client.rs::`stderr_lines_can_never_start_with_the_trusted_
    /// marker_from_server_text` (`flatten_control_chars` on every URL
    /// interpolation) and gp-proto gateway.rs::`parse_list` (address
    /// charset gate). This test pins the CONSUMER half of that
    /// contract pair: exactly what the marker grants.
    #[test]
    fn marker_led_line_is_trusted_by_the_consumer_by_design() {
        assert_eq!(
            extract_saml_url("SAML-CALLBACK-URL http://127.0.0.1:9999/"),
            Some("http://127.0.0.1:9999/".to_string()),
            "the marker IS the trust token: the consumer accepts it \
             unconditionally (producer lanes must never emit one from \
             server text)"
        );
    }

    #[test]
    fn marker_must_be_loopback_http_with_a_real_port() {
        assert!(extract_saml_url("SAML-CALLBACK-URL http://evil.example:80/").is_none());
        assert!(extract_saml_url("SAML-CALLBACK-URL https://127.0.0.1:54912/").is_none());
        assert!(extract_saml_url("SAML-CALLBACK-URL not-a-url").is_none());
        assert!(extract_saml_url("SAML-CALLBACK-URL http://127.0.0.1:notaport/").is_none());
        assert!(
            extract_saml_url("prefix SAML-CALLBACK-URL http://127.0.0.1:54912/").is_none(),
            "the line must START with the marker — embedded spoofs fail"
        );
    }
}

/// POST the `globalprotectcallback:` URL to opc's local SAML HTTP server.
///
/// Uses raw TCP to avoid depending on curl or any HTTP client crate.
pub fn post_saml_callback(server_url: &str, callback_url: &str, log: Arc<Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // Parse host:port from http://127.0.0.1:PORT/
    let addr = server_url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();

    // Security: only POST to localhost — never send SAML tokens to remote hosts.
    if !addr.starts_with("127.0.0.1:") && !addr.starts_with("[::1]:") {
        if let Ok(mut l) = log.lock() {
            l.push(format!("[error] refusing to POST SAML callback to non-local address: {addr}"));
        }
        return;
    }
    // Send the raw callback URL as the body — opc's HTTP server
    // accepts both `url=<encoded>` form data and a raw
    // `globalprotectcallback:...` string. The raw form avoids
    // URL-encoding issues with `&` in the callback URL.
    let body = callback_url.to_string();

    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<String> {
            let mut stream = TcpStream::connect(&addr)?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

            let request = format!(
                "POST /callback HTTP/1.1\r\n\
                 Host: {addr}\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            );
            stream.write_all(request.as_bytes())?;
            stream.flush()?;

            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            Ok(response)
        })();

        match result {
            Ok(resp) => {
                // Extract just the body (after the blank line).
                let body_text = resp
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b)
                    .unwrap_or(&resp);
                if let Ok(mut l) = log.lock() {
                    l.push(format!("[gui] SAML callback → {}", body_text.trim()));
                }
            }
            Err(e) => {
                if let Ok(mut l) = log.lock() {
                    l.push(format!("[error] SAML callback POST failed: {e}"));
                }
            }
        }
    });
}

/// Kill the running `opc connect` child process (used by Cancel).
pub fn cancel_connect(log: &Arc<Mutex<Vec<String>>>) {
    let pid = CONNECT_PID.load(Ordering::SeqCst);
    if let Ok(mut l) = log.lock() {
        l.push(format!("[gui] cancel: killing PID {pid}"));
    }
    if pid != 0 {
        // Use a plain Command (not hidden_cmd which sets CWD to opc dir).
        #[cfg(windows)]
        {
            let mut cmd = Command::new("taskkill");
            // CREATE_NO_WINDOW to avoid console flash.
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let _ = cmd
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
        }
        #[cfg(not(windows))]
        {
            let _ = Command::new("kill")
                .arg(pid.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
        }
        CONNECT_PID.store(0, Ordering::SeqCst);
    }
}

/// Send disconnect signal.
pub fn disconnect() {
    let _ = hidden_cmd(&opc_exe())
        .args(["disconnect", "--instance", "default"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// Run `opc diagnose <portal>` and stream output to log.
pub fn diagnose(portal: &str, log: Arc<Mutex<Vec<String>>>) {
    let opc = opc_exe();
    let portal = portal.to_string();

    std::thread::spawn(move || {
        if let Ok(mut l) = log.lock() {
            l.push(format!("[diagnose] running opc diagnose {portal}..."));
        }

        let output = hidden_cmd(&opc)
            .args(["diagnose", &portal])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                if let Ok(mut l) = log.lock() {
                    for line in text.lines() {
                        l.push(line.to_string());
                    }
                    for line in err.lines() {
                        l.push(format!("[stderr] {line}"));
                    }
                    l.push("[diagnose] done.".to_string());
                }
            }
            Err(e) => {
                if let Ok(mut l) = log.lock() {
                    l.push(format!("[error] diagnose failed: {e}"));
                }
            }
        }
    });
}
