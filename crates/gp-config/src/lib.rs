//! Pangolin configuration file (`config.toml`) and credential store (keyring).
//!
//! # Shape
//!
//! ```toml
//! [default]
//! os = "win"
//! portal = "work"        # picked when `pgn connect` has no positional arg
//!
//! [portal.work]
//! url = "vpn.corp.example.com"
//! username = "alice"
//! os = "win"
//! auth_mode = "paste"
//! only = "10.0.0.0/8,intranet.example.com"
//! hip = "auto"
//!
//! [portal.home-lab]
//! url = "vpn.home.example.net"
//! auth_mode = "webview"
//! ```
//!
//! # Resolution order
//!
//! The top-level `[default]` section holds machine-wide defaults.
//! Each `[portal.<name>]` section overrides those for connections
//! to that portal. CLI flags passed to `pgn connect` override
//! everything, including profile settings.
//!
//! The file lives at `~/.config/pangolin/config.toml` by default,
//! with the path resolved via the `directories` crate so it
//! follows XDG on Linux, the Application Support dir on macOS, and
//! `%APPDATA%` on Windows.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),

    #[error("config parse error: {0}")]
    Parse(String),

    #[error("config serialize error: {0}")]
    Serialize(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Top-level pangolin configuration (`~/.config/pangolin/config.toml`).
///
/// `BTreeMap` is used for the portal section instead of `HashMap`
/// so `pgn portal list` and `save()` output are stable (sorted by
/// profile name) — keeps diffs clean and tests deterministic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PangolinConfig {
    /// Global defaults.
    #[serde(default)]
    pub default: DefaultConfig,

    /// Named portal profiles, keyed by profile name (not URL).
    #[serde(default)]
    pub portal: BTreeMap<String, PortalProfile>,
}

/// Global default settings. Applied when a specific portal
/// profile doesn't override the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    /// OS to spoof (`"win"`, `"mac"`, `"linux"`).
    #[serde(default = "default_os")]
    pub os: String,

    /// Automatically reconnect on disconnect (future work —
    /// honored by Phase 2 auto-reconnect, ignored today).
    #[serde(default = "default_true")]
    pub reconnect: bool,

    /// Name of the portal profile to use when `pgn connect` is
    /// invoked without a positional argument. Set via
    /// `pgn portal use <name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<String>,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            os: default_os(),
            reconnect: true,
            portal: None,
        }
    }
}

/// A named portal connection profile.
///
/// Every field except `url` is optional. `None` means "inherit the
/// global default" for `os`, and "don't pass the flag at all" for
/// the rest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortalProfile {
    /// Portal hostname or URL. The only required field.
    pub url: String,

    /// Default username (rarely needed for SAML flows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Preferred gateway address. Reserved for future use — pgn
    /// currently picks the preferred gateway via region match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,

    /// OS to spoof. If unset, inherits `default.os`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// SAML auth mode: `"webview"` or `"paste"`. If unset, uses
    /// `pgn connect`'s built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,

    /// Port for paste-mode SAML's local HTTP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_port: Option<u16>,

    /// vpnc-compatible script for routes/DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpnc_script: Option<String>,

    /// Split-tunnel target list (comma-separated CIDRs / IPs /
    /// hostnames). Matches the `--only` CLI flag format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only: Option<String>,

    /// HIP mode: `"auto"`, `"force"`, or `"off"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hip: Option<String>,

    /// Accept invalid TLS certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,

    /// Keep the tunnel alive across brief network blips by
    /// passing a larger `reconnect_timeout` to libopenconnect.
    /// See `pgn connect --reconnect` for the full semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<bool>,
}

fn default_os() -> String {
    "win".into()
}
fn default_true() -> bool {
    true
}

impl PangolinConfig {
    /// Load configuration from the default path, returning defaults
    /// if the file does not exist.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(&Self::default_path())
    }

    /// Load from an explicit path. Returns defaults if the file
    /// does not exist — callers that want to distinguish missing
    /// vs empty should check `path.exists()` first.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Serialize back to TOML and write to the default path,
    /// creating the parent directory if needed. The write is done
    /// atomically via a temp file + rename so a crash mid-write
    /// can't corrupt the existing config.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::default_path())
    }

    /// Save to an explicit path. Atomic via temp file + rename.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        let body =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write to `<path>.tmp` then rename into place. `rename(2)`
        // is atomic on POSIX, so readers either see the old file
        // or the new one — never a partial write.
        let tmp_path = path.with_extension("toml.tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Platform-appropriate config file path.
    pub fn default_path() -> PathBuf {
        directories::ProjectDirs::from("", "", "pangolin")
            .map(|d| d.config_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    }

    /// Look up a portal profile by name, falling back to a URL
    /// match against any profile's `url` field.
    pub fn find_portal(&self, name_or_url: &str) -> Option<&PortalProfile> {
        if let Some(profile) = self.portal.get(name_or_url) {
            return Some(profile);
        }
        self.portal.values().find(|p| p.url == name_or_url)
    }

    /// Insert or replace a profile by name.
    pub fn set_portal(&mut self, name: impl Into<String>, profile: PortalProfile) {
        self.portal.insert(name.into(), profile);
    }

    /// Remove a profile by name. Returns `true` if something was
    /// actually removed. Also clears `default.portal` if it
    /// pointed at the deleted profile.
    pub fn remove_portal(&mut self, name: &str) -> bool {
        let removed = self.portal.remove(name).is_some();
        if removed && self.default.portal.as_deref() == Some(name) {
            self.default.portal = None;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> PangolinConfig {
        let mut c = PangolinConfig::default();
        c.default.portal = Some("work".into());
        c.set_portal(
            "work",
            PortalProfile {
                url: "vpn.corp.example.com".into(),
                username: Some("alice".into()),
                os: Some("win".into()),
                auth_mode: Some("paste".into()),
                only: Some("10.0.0.0/8".into()),
                hip: Some("auto".into()),
                reconnect: Some(true),
                ..PortalProfile::default()
            },
        );
        c.set_portal(
            "home",
            PortalProfile {
                url: "vpn.home.example.net".into(),
                auth_mode: Some("webview".into()),
                ..PortalProfile::default()
            },
        );
        c
    }

    #[test]
    fn toml_round_trip_preserves_profiles() {
        let config = sample_config();
        let body = toml::to_string_pretty(&config).unwrap();
        let back: PangolinConfig = toml::from_str(&body).unwrap();
        assert_eq!(back.default.portal.as_deref(), Some("work"));
        assert_eq!(back.portal.len(), 2);
        let work = back.portal.get("work").unwrap();
        assert_eq!(work.url, "vpn.corp.example.com");
        assert_eq!(work.auth_mode.as_deref(), Some("paste"));
        assert_eq!(work.only.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(work.hip.as_deref(), Some("auto"));
        assert_eq!(work.reconnect, Some(true));
    }

    #[test]
    fn missing_file_yields_default_config() {
        let path = std::env::temp_dir().join(format!(
            "pangolin-cfg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        // Path does not exist — load_from should return default.
        let cfg = PangolinConfig::load_from(&path).unwrap();
        assert!(cfg.portal.is_empty());
        assert_eq!(cfg.default.os, "win");
        assert!(cfg.default.reconnect);
        assert!(cfg.default.portal.is_none());
    }

    #[test]
    fn save_then_load_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "pangolin-cfg-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let config = sample_config();
        config.save_to(&path).unwrap();
        let reloaded = PangolinConfig::load_from(&path).unwrap();
        assert_eq!(reloaded.portal.len(), 2);
        assert_eq!(
            reloaded.find_portal("work").unwrap().url,
            "vpn.corp.example.com"
        );
        assert_eq!(
            reloaded.find_portal("home").unwrap().auth_mode.as_deref(),
            Some("webview")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn find_portal_matches_by_name_then_url() {
        let c = sample_config();
        assert_eq!(c.find_portal("work").unwrap().url, "vpn.corp.example.com");
        assert_eq!(
            c.find_portal("vpn.home.example.net")
                .unwrap()
                .auth_mode
                .as_deref(),
            Some("webview")
        );
        assert!(c.find_portal("does-not-exist").is_none());
    }

    #[test]
    fn remove_portal_clears_default_when_matching() {
        let mut c = sample_config();
        assert!(c.remove_portal("work"));
        assert!(c.default.portal.is_none(), "default.portal should clear");
        // Removing an already-gone name returns false.
        assert!(!c.remove_portal("work"));
    }

    #[test]
    fn remove_portal_leaves_default_alone_when_not_matching() {
        let mut c = sample_config();
        assert!(c.remove_portal("home"));
        assert_eq!(c.default.portal.as_deref(), Some("work"));
    }

    #[test]
    fn empty_profile_fields_omitted_on_serialize() {
        // A profile with only `url` set should produce minimal
        // TOML — every other field has a `skip_serializing_if`.
        let mut c = PangolinConfig::default();
        c.set_portal(
            "bare",
            PortalProfile {
                url: "vpn.minimal.example".into(),
                ..PortalProfile::default()
            },
        );
        let body = toml::to_string_pretty(&c).unwrap();
        assert!(body.contains("[portal.bare]"));
        assert!(body.contains(r#"url = "vpn.minimal.example""#));
        // None fields are skipped.
        assert!(!body.contains("username"));
        assert!(!body.contains("auth_mode"));
        assert!(!body.contains("only"));
    }
}
