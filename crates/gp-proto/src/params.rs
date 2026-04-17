//! GP request parameters shared across API calls.

use crate::ClientOs;

/// Strip scheme and trailing slash from a server address.
///
/// Ensures we never build URLs like `https://https://host/...`.
pub fn normalize_server(server: &str) -> &str {
    let s = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server);
    s.trim_end_matches('/')
}

/// Parameters sent with every GlobalProtect API request.
#[derive(Debug, Clone)]
pub struct GpParams {
    /// Whether the target is a gateway (true) or portal (false).
    pub is_gateway: bool,
    /// OS identity to present.
    pub client_os: ClientOs,
    /// OS version string.
    pub os_version: String,
    /// GP client version (typically `"4100"`).
    pub client_version: String,
    /// Local hostname.
    pub computer: String,
    /// HTTP User-Agent header.
    pub user_agent: String,
    /// Accept invalid TLS certificates.
    pub ignore_tls_errors: bool,
    /// Path to a PEM-encoded client certificate for mutual TLS.
    pub client_cert: Option<String>,
    /// Path to the PEM-encoded private key for `client_cert`.
    pub client_key: Option<String>,
    /// Path to a PKCS#12 bundle (alternative to cert + key).
    pub client_pkcs12: Option<String>,
    /// MFA input-str state (set during MFA flow).
    pub input_str: Option<String>,
    /// MFA OTP code.
    pub otp: Option<String>,
}

impl GpParams {
    /// Create parameters with sensible defaults.
    pub fn new(client_os: ClientOs) -> Self {
        Self {
            is_gateway: false,
            client_os,
            os_version: client_os.os_version().into(),
            client_version: "4100".into(),
            computer: get_hostname(),
            user_agent: client_os.user_agent().into(),
            ignore_tls_errors: false,
            client_cert: None,
            client_key: None,
            client_pkcs12: None,
            input_str: None,
            otp: None,
        }
    }

    /// URL path prefix: `/ssl-vpn` for gateways, `/global-protect` for portals.
    pub fn path_prefix(&self) -> &'static str {
        if self.is_gateway {
            "/ssl-vpn"
        } else {
            "/global-protect"
        }
    }

    /// Build the prelogin endpoint URL.
    pub fn prelogin_url(&self, server: &str) -> String {
        let host = normalize_server(server);
        format!("https://{}{}/prelogin.esp", host, self.path_prefix())
    }

    /// Build the login / config endpoint URL.
    pub fn login_url(&self, server: &str) -> String {
        let host = normalize_server(server);
        if self.is_gateway {
            format!("https://{host}/ssl-vpn/login.esp")
        } else {
            format!("https://{host}/global-protect/getconfig.esp")
        }
    }

    /// Build the getconfig endpoint URL (gateway tunnel config).
    pub fn getconfig_url(&self, server: &str) -> String {
        let host = normalize_server(server);
        format!("https://{host}/ssl-vpn/getconfig.esp")
    }

    /// Prelogin-specific form parameters (narrower set than login).
    pub fn to_prelogin_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("tmp", "tmp".into()),
            ("clientVer", self.client_version.clone()),
            ("clientos", self.client_os.clientos().into()),
            ("os-version", self.os_version.clone()),
            ("host-id", self.computer.clone()),
            ("ipv6-support", "yes".into()),
            ("default-browser", "1".into()),
            ("cas-support", "yes".into()),
        ]
    }

    /// Login / config form parameters (full set).
    pub fn to_params(&self) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("prot", "https:".into()),
            ("jnlpReady", "jnlpReady".into()),
            ("ok", "Login".into()),
            ("direct", "yes".into()),
            ("ipv6-support", "yes".into()),
            ("clientVer", self.client_version.clone()),
            ("clientos", self.client_os.clientos().into()),
            ("os-version", self.os_version.clone()),
            ("host-id", self.computer.clone()),
            ("computer", self.computer.clone()),
            ("default-browser", "1".into()),
            ("cas-support", "yes".into()),
        ];

        if let Some(ref input_str) = self.input_str {
            params.push(("inputStr", input_str.clone()));
        }
        if let Some(ref otp) = self.otp {
            params.push(("passwd", otp.clone()));
        }

        params
    }
}

fn get_hostname() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "openprotect".into())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "openprotect".into())
    }
}
