//! Shell out to `opc.exe` for connect/disconnect/status.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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
fn hidden_cmd(exe: &std::path::Path) -> Command {
    let mut cmd = Command::new(exe);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW (0x08000000) — prevents the child from
        // allocating a visible console, which would flash a black
        // window every time the GUI spawns opc.exe.
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
    log: Arc<Mutex<Vec<String>>>,
    saml_url: Arc<Mutex<Option<String>>>,
    connect_done: Arc<std::sync::atomic::AtomicBool>,
) {
    let opc = opc_exe();
    let portal = portal.to_string();
    let user = user.to_string();

    std::thread::spawn(move || {
        let mut args = vec!["connect".to_string()];
        if !portal.is_empty() {
            args.push(portal);
        }
        if !user.is_empty() {
            args.push("--user".to_string());
            args.push(user);
        }
        args.push("--log".to_string());
        args.push("info".to_string());

        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match hidden_cmd(&opc)
            .args(&str_args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => {
                let mut browser_opened = false;
                // Stream stderr (where tracing output goes) into the log.
                if let Some(stderr) = child.stderr {
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

/// Extract the SAML callback URL from an opc stderr line.
///
/// opc prints the URL inside a box-drawing frame like:
///   `│    http://127.0.0.1:29999/`
/// We scan the line for anything that looks like `http://127.0.0.1:PORT/`.
fn extract_saml_url(line: &str) -> Option<String> {
    if let Some(start) = line.find("http://127.0.0.1:") {
        let rest = &line[start..];
        // Take up to the first whitespace or non-ASCII char (box drawing).
        let end = rest
            .find(|c: char| c.is_whitespace() || !c.is_ascii())
            .unwrap_or(rest.len());
        let url = &rest[..end];
        if url.len() > "http://127.0.0.1:".len() {
            return Some(url.to_string());
        }
    }
    None
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
