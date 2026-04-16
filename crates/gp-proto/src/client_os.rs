//! Client OS spoofing configuration.

use serde::{Deserialize, Serialize};

/// The operating system identity presented to the GP server.
///
/// Defaults to [`Linux`](ClientOs::Linux), matching yuezk and upstream
/// openconnect's GlobalProtect client defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientOs {
    Win,
    Mac,
    #[default]
    Linux,
}

impl ClientOs {
    /// Value sent in the `clientos` form parameter.
    pub fn clientos(&self) -> &'static str {
        match self {
            Self::Win => "Windows",
            Self::Mac => "Mac",
            Self::Linux => "Linux",
        }
    }

    /// Value used with `openconnect_set_reported_os()`.
    pub fn openconnect_os(&self) -> &'static str {
        match self {
            Self::Win => "win",
            Self::Mac => "mac-intel",
            Self::Linux => "linux",
        }
    }

    /// User-Agent header sent with every HTTP request.
    ///
    /// Real GlobalProtect clients send an OS tag after the version:
    ///
    /// * Windows: `PAN GlobalProtect/5.1.0-28`
    /// * macOS:   `PAN GlobalProtect/5.1.0-28`
    /// * Linux:   `PAN GlobalProtect/5.1.0-28 (Linux)`
    ///
    /// We mirror the pattern so the gateway sees a plausible
    /// user-agent consistent with the `clientos` and HIP identity
    /// we already send. The version here deliberately matches
    /// `gp_hip::DEFAULT_CLIENT_VERSION` ("5.1.0-28") so the
    /// UA-visible version and the HIP `<client-version>` don't
    /// diverge.
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Win => "PAN GlobalProtect/5.1.0-28",
            Self::Mac => "PAN GlobalProtect/5.1.0-28",
            Self::Linux => "PAN GlobalProtect/5.1.0-28 (Linux)",
        }
    }

    /// OS version string sent as the `os-version` form parameter.
    pub fn os_version(&self) -> &'static str {
        match self {
            Self::Win => "Microsoft Windows 10 Pro, 64-bit",
            Self::Mac => "Apple Mac OS X 13.0",
            Self::Linux => "Linux 6.1",
        }
    }
}

impl std::fmt::Display for ClientOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Win => write!(f, "win"),
            Self::Mac => write!(f, "mac"),
            Self::Linux => write!(f, "linux"),
        }
    }
}

impl std::str::FromStr for ClientOs {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "win" | "windows" => Ok(Self::Win),
            "mac" | "macos" | "darwin" => Ok(Self::Mac),
            "linux" => Ok(Self::Linux),
            _ => Err(format!("unknown OS: {s} (expected: win, mac, linux)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_linux() {
        assert_eq!(ClientOs::default(), ClientOs::Linux);
    }

    #[test]
    fn openconnect_os_matches_variants() {
        assert_eq!(ClientOs::Win.openconnect_os(), "win");
        assert_eq!(ClientOs::Mac.openconnect_os(), "mac-intel");
        assert_eq!(ClientOs::Linux.openconnect_os(), "linux");
    }

    #[test]
    fn user_agent_contains_version_and_os_tag() {
        // All variants must include the version number.
        for os in [ClientOs::Win, ClientOs::Mac, ClientOs::Linux] {
            assert!(
                os.user_agent().contains("5.1.0-28"),
                "{os:?} UA missing version"
            );
        }
        // Linux is the only variant that appends an OS tag.
        assert!(ClientOs::Linux.user_agent().contains("(Linux)"));
        assert!(!ClientOs::Win.user_agent().contains("("));
    }

    #[test]
    fn os_version_no_stray_whitespace() {
        // Regression: Windows os_version previously had an extra
        // space before the comma ("Pro , 64-bit").
        let win = ClientOs::Win.os_version();
        assert!(
            !win.contains(" ,"),
            "stray space before comma in Win os_version: {win:?}"
        );
    }
}
