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

/// Poll `opc status --json` and return the current VPN state.
pub fn poll_status() -> VpnState {
    let output = Command::new(opc_exe())
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

/// Launch `opc connect` with admin elevation and stream output to log buffer.
pub fn connect(portal: &str, user: &str, log: Arc<Mutex<Vec<String>>>) {
    let opc = opc_exe();
    let portal = portal.to_string();
    let user = user.to_string();

    std::thread::spawn(move || {
        let _log = log; // suppress unused warning on Windows
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

        #[cfg(windows)]
        {
            // On Windows, use ShellExecuteW for UAC elevation.
            // We can't capture stdout from elevated processes easily,
            // so just launch it and let status polling pick up the state.
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            fn to_wide(s: &OsStr) -> Vec<u16> {
                s.encode_wide().chain(std::iter::once(0)).collect()
            }

            let exe = to_wide(opc.as_os_str());
            let args_str = args.join(" ");
            let args_w = to_wide(OsStr::new(&args_str));
            let verb = to_wide(OsStr::new("runas"));

            unsafe {
                windows_sys::Win32::UI::Shell::ShellExecuteW(
                    std::ptr::null_mut(),
                    verb.as_ptr(),
                    exe.as_ptr(),
                    args_w.as_ptr(),
                    std::ptr::null(),
                    windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
                );
            }
        }

        #[cfg(not(windows))]
        {
            let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match Command::new("sudo")
                .arg("-E")
                .arg(&opc)
                .args(&str_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    stream_output(&mut child, &_log);
                    let _ = child.wait();
                }
                Err(e) => {
                    if let Ok(mut l) = _log.lock() {
                        l.push(format!("[error] failed to launch opc: {e}"));
                    }
                }
            }
        }
    });
}

/// Read child stdout/stderr lines into the log buffer.
#[cfg(not(windows))]
fn stream_output(child: &mut std::process::Child, log: &Arc<Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader};
    if let Some(stdout) = child.stdout.take() {
        let log = log.clone();
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(mut l) = log.lock() {
                l.push(line);
            }
        }
    }
}

/// Send disconnect signal.
pub fn disconnect() {
    let _ = Command::new(opc_exe())
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

        let output = Command::new(&opc)
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
