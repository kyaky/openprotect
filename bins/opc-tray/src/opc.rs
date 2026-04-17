//! Shell out to `opc.exe` for connect/disconnect/status.

use std::path::PathBuf;
use std::process::{Command, Stdio};

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

/// Find opc.exe next to opc-tray.exe, or fall back to PATH.
pub fn opc_exe() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("opc-tray.exe"));
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

/// Launch `opc connect` with admin elevation.
pub fn connect(profile: &str) {
    let opc = opc_exe();

    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        fn to_wide(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        // Use OsStr directly to avoid lossy conversion.
        let exe = to_wide(opc.as_os_str());
        // Quote profile name to handle spaces safely.
        // Sanitize profile name: strip any characters that could
        // break the ShellExecuteW argument string.
        let safe_profile: String = profile
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        let args_str = if safe_profile.is_empty() {
            "connect --log info".to_string()
        } else {
            format!("connect {} --log info", safe_profile)
        };
        let args = to_wide(OsStr::new(&args_str));
        let verb = to_wide(OsStr::new("runas"));

        let result = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                exe.as_ptr(),
                args.as_ptr(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns HINSTANCE > 32 on success.
        if (result as isize) <= 32 {
            eprintln!(
                "opc-tray: failed to launch opc.exe (ShellExecuteW returned {})",
                result as isize
            );
        }
    }

    #[cfg(not(windows))]
    {
        let mut args = vec!["connect"];
        if !profile.is_empty() {
            args.push(profile);
        }
        args.extend(["--log", "info"]);
        let _ = Command::new("sudo").arg("-E").arg(&opc).args(&args).spawn();
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
