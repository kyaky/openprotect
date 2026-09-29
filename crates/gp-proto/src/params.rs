//! GP request parameters shared across API calls.

use crate::credential::Credential;
use crate::ClientOs;

/// Form keys the PAN gateway treats as named secret material.
/// `GpParams::gateway_login_form` never emits any of them with an
/// empty value — mirroring the CALLER-level omission around upstream
/// `append_opt` (`gpst_login` skips the call for NULL-valued options;
/// `append_opt` itself writes `key=` unconditionally — issue #36
/// checklist M5 wording correction). Note the
/// source-grounded reject class is narrower than "any empty key":
/// openconnect #859 documents a `passwd` that is **empty or absent
/// when it reaches the auth engine** being refused with
/// `X-Private-Pan-Sslvpn: auth-failed` plus
/// `X-Private-Pan-Sslvpn-Extension: auth-failed-password-empty`, while
/// the yuezk reference client ships present-but-empty `token=` /
/// `prelogin-cookie=` keys on real gateways every day. Only the two
/// portal pass-through cookies have real-world support for an
/// empty-string value being toxic.
pub const LOGIN_SECRET_KEYS: [&str; 5] = [
    "passwd",
    "token",
    "prelogin-cookie",
    "portal-userauthcookie",
    "portal-prelogonuserauthcookie",
];

/// Form keys that are not login credentials but must still be scrubbed
/// from server-supplied diagnostic text: `inputStr` carries the
/// gateway's own MFA challenge token — replayable second-factor
/// material that must never surface in logs or user-visible errors
/// (issue #36 review). Kept separate from [`LOGIN_SECRET_KEYS`] so the
/// omit-empty taxonomy the gateway-login tests pin stays source-true.
pub const SCRUB_ONLY_KEYS: [&str; 1] = ["inputStr"];

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

/// Outcome of separating the port component of a `host:port` label
/// (issue #43). See [`split_host_port`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec<'a> {
    /// No `:port` component was present (or the tail is not a port —
    /// e.g. a bare unbracketed IPv6 address, whose colons belong to
    /// the address).
    Absent,
    /// A numeric port in `1..=u16::MAX`.
    Valid(u16),
    /// The tail after the last colon is all-ASCII-digits but is not a
    /// usable service port — `0` or out of the `1..=65535` range
    /// (e.g. `"gw.example.com:99999"`), matching libopenconnect's
    /// `internal_parse_url` validation. Consumers that must not
    /// silently downgrade to 443 fail loudly on this.
    OutOfRange(&'a str),
}

impl PortSpec<'_> {
    /// The port value when it is present and in range.
    pub fn port(self) -> Option<u16> {
        match self {
            PortSpec::Valid(p) => Some(p),
            PortSpec::Absent | PortSpec::OutOfRange(_) => None,
        }
    }
}

/// The ONE bracket-aware `host:port` splitter for the whole
/// application (issue #43).
///
/// Splits a trailing `:port` off a hostname / IP literal label:
///
/// * the tail after the LAST colon must be non-empty and all
///   ASCII digits to count as a port;
/// * an unbracketed multi-colon head is treated as a bare IPv6
///   address (the colons belong to the address, not a port
///   delimiter) — mirrors libopenconnect's expectation that IPv6
///   URL literals travel as `[addr]:port` (`ssl.c` only strips
///   brackets when the whole hostname is bracketed);
/// * a bracketed head keeps its brackets — consumers that feed the
///   host to a URL authority or to `openconnect_parse_url` need the
///   bracketed form; `getaddrinfo`-style consumers must not be
///   handed a bracketed literal at all (they classify it before
///   calling, see `bins/opc::resolve_gateway_for_exclude_with`).
///
/// `server_field` is defined as the host half of this function so
/// the `server=` form field (issue #42) and every #43 consumer share
/// one implementation. The port half is `None` for
/// [`PortSpec::Absent`] and [`PortSpec::OutOfRange`] — use the
/// returned [`PortSpec`] directly when an out-of-range port must be
/// distinguished from no port at all.
pub fn split_host_port(server: &str) -> (&str, PortSpec<'_>) {
    if let Some((head, tail)) = server.rsplit_once(':') {
        let port_like = !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit());
        let unbracketed_ipv6 =
            head.contains(':') && !(head.starts_with('[') && head.ends_with(']'));
        if port_like && !unbracketed_ipv6 {
            let spec = match tail.parse::<u16>() {
                Ok(p) if p != 0 => PortSpec::Valid(p),
                Ok(_) => PortSpec::OutOfRange(tail),
                Err(_) => PortSpec::OutOfRange(tail),
            };
            return (head, spec);
        }
    }
    (server, PortSpec::Absent)
}

/// The advertised service port of a `host[:port]` label, `None` when
/// absent or out of range (issue #43 seam S1).
pub fn service_port(server: &str) -> Option<u16> {
    split_host_port(server).1.port()
}

/// The `server=` login form value: hostname only, port stripped.
///
/// libopenconnect `gpst_login` sends `append_opt(request_body,
/// "server", hostname)` and yuezk's `resolve_server` returns the
/// hostname (the service port is held separately). Portal-advertised
/// gateway addresses may carry the port (issue #36 runs the gateway on
/// :11443); sending `server=<host>:11443` risks the portal/gateway-name
/// mismatch reject class on strict configs. IPv6-aware: `"[::1]:443"`
/// yields `"[::1]"`, while a bare `"2001:db8::1"` is never mistaken
/// for host:port.
///
/// Defined as the host half of [`split_host_port`] (issue #43): the
/// #42 behaviour is byte-identical — the head is returned exactly
/// when the old inline guard judged the tail port-like.
pub fn server_field(server: &str) -> &str {
    split_host_port(server).0
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
    /// Optional `(hostname, socket_addr)` pin that bypasses the
    /// system DNS resolver for `hostname` on this client. Used by
    /// the Windows HIP fallback: once we install the VPN's NRPT
    /// rules, the gateway hostname starts resolving to an internal
    /// IP (whose TLS cert doesn't match), so HIP must keep using
    /// the public IP we resolved BEFORE NRPT was applied.
    pub resolve_override: Option<(String, std::net::SocketAddr)>,
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
            resolve_override: None,
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

    /// Assemble the gateway `/ssl-vpn/login.esp` form (issue #36).
    ///
    /// This is the single authoritative builder for that endpoint.
    /// Deltas from the legacy `to_params() + extend(cred.to_params()) +
    /// push(server)` assembly, toward the libopenconnect `gpst_login`
    /// reference:
    ///
    /// * **secret keys only when non-empty** — `passwd`, `token`,
    ///   `prelogin-cookie` and the two portal cookies appear only with
    ///   non-empty values, mirroring upstream's caller-level omission
    ///   around `append_opt` (which itself writes `key=`
    ///   unconditionally). The old
    ///   credential serialization hard-emitted all of them empty, which
    ///   on a portal that issued no pass-through cookies left the POST
    ///   with zero credential material — the #36 asymmetry vs the
    ///   reporter's working minimal curl. (Whether PAN rejects *every*
    ///   present-but-empty key or only empty portal-cookie values is
    ///   not settled by the sources — yuezk ships empty `token=` /
    ///   `prelogin-cookie=` on real gateways — but omitting them
    ///   conforms to the reference either way.)
    /// * **exactly one `passwd`** — on an MFA retry the OTP (pushed by
    ///   `to_params`) wins and the credential's password is suppressed,
    ///   killing the old `passwd=<otp>&…&passwd=` duplicate whose
    ///   outcome depended on the gateway's first/last-wins parse.
    /// * **no duplicate keys at all** — first occurrence wins.
    /// * **hostname-only `server`** — see [`server_field`].
    ///
    /// Base identity fields (`host-id`, `default-browser`, `cas-support`,
    /// …) are unchanged from `to_params`: the real-world evidence shows
    /// those extras are tolerated (they ride the working portal getconfig
    /// POST), and trimming them is a separate, evidence-gated change.
    pub fn gateway_login_form(
        &self,
        cred: &Credential,
        server: &str,
    ) -> Vec<(&'static str, String)> {
        // Base fields, minus any empty value (an empty `passwd=` from a
        // junk `otp` string must never reach the wire either).
        let mut params: Vec<(&'static str, String)> = self
            .to_params()
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .collect();
        let otp_present = params.iter().any(|(k, v)| *k == "passwd" && !v.is_empty());
        params.extend(cred.gateway_login_params(otp_present));
        // `server=` is hostname-only: openconnect's `gpst_login` sends
        // `append_opt(request_body, "server", hostname)` (the port is
        // held separately) and yuezk's `resolve_server` returns the
        // hostname. A port-bearing value risks the portal/gateway-name
        // mismatch reject class; the request URL keeps its port, only
        // this field is stripped (issue #36 review).
        params.push(("server", server_field(server).to_string()));

        // Enforce key uniqueness, keeping the FIRST occurrence so the
        // OTP `passwd` outranks any credential-side push.
        let mut seen: Vec<&'static str> = Vec::with_capacity(params.len());
        params.retain(|(k, _)| {
            if seen.contains(k) {
                false
            } else {
                seen.push(k);
                true
            }
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;

    fn params_base() -> GpParams {
        let mut p = GpParams::new(crate::ClientOs::Win);
        p.computer = "TESTBOX".into();
        p
    }

    fn pw_cred(user: &str, pw: &str) -> Credential {
        Credential::Password {
            username: user.into(),
            password: pw.into(),
        }
    }

    fn cookie_cred(user: &str, c: &str, p: &str, replay: Option<&str>) -> Credential {
        Credential::AuthCookie {
            username: user.into(),
            user_auth_cookie: c.into(),
            prelogon_user_auth_cookie: p.into(),
            password: replay.map(str::to_string),
        }
    }

    fn vals(form: &[(&'static str, String)], key: &str) -> Vec<String> {
        form.iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn assert_unique_keys(form: &[(&'static str, String)]) {
        let mut keys: Vec<&str> = form.iter().map(|(k, _)| *k).collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(
            keys.len(),
            n,
            "duplicate form key(s) in gateway login: {form:?}"
        );
    }

    fn assert_no_empty_secrets(form: &[(&'static str, String)]) {
        let empties: Vec<&str> = form
            .iter()
            .filter(|(k, v)| LOGIN_SECRET_KEYS.contains(k) && v.is_empty())
            .map(|(k, _)| *k)
            .collect();
        assert!(
            empties.is_empty(),
            "issue #36: present-but-empty secret key(s) {empties:?} — the \
             fixed gateway form must never emit these (the omit-empty rule \
             mirrors upstream's caller-level omission around append_opt, \
             which itself writes key= unconditionally; the #859 reject \
             class is an empty/absent passwd reaching the auth engine); \
             form: {form:?}"
        );
    }

    #[test]
    fn gateway_login_form_password_carries_single_nonempty_passwd() {
        let form =
            params_base().gateway_login_form(&pw_cred("test-user", "REDACTED-pw"), "gw:11443");
        assert_eq!(vals(&form, "passwd"), vec!["REDACTED-pw".to_string()]);
        assert_eq!(vals(&form, "user"), vec!["test-user".to_string()]);
        // The old credential path hard-emitted these empty; they must be
        // ABSENT entirely (upstream omits such keys at the gpst_login
        // CALLERS; append_opt itself writes key= unconditionally).
        for k in [
            "token",
            "prelogin-cookie",
            "portal-userauthcookie",
            "portal-prelogonuserauthcookie",
        ] {
            assert!(vals(&form, k).is_empty(), "{k} must not appear when unused");
        }
        // Identity/agent fields preserved from to_params (unchanged wire
        // shape for everything the reference clients send today).
        for k in [
            "prot",
            "jnlpReady",
            "ok",
            "direct",
            "clientVer",
            "clientos",
            "os-version",
            "computer",
            "server",
        ] {
            assert!(!vals(&form, k).is_empty(), "{k} missing from gateway login");
        }
        // Issue #36 review: the `server=` form field is hostname-only
        // (openconnect `append_opt(request_body, "server", hostname)` /
        // yuezk `resolve_server`); a port-bearing value risks the
        // portal/gateway-name mismatch reject class. The URL keeps the
        // port — only this field is stripped.
        assert_eq!(vals(&form, "server"), vec!["gw".to_string()]);
        assert_unique_keys(&form);
        assert_no_empty_secrets(&form);
    }

    #[test]
    fn gateway_login_form_auth_cookie_replays_portal_password() {
        // Issue #36 root cause: the portal-derived credential must carry
        // the replayed password so the gateway sees a real secret even
        // when it does not honor portal pass-through cookies.
        let cred = cookie_cred("test-user", "MOCK-c1", "MOCK-c2", Some("REDACTED-pw"));
        let form = params_base().gateway_login_form(&cred, "gw.example.com");
        assert_eq!(vals(&form, "passwd"), vec!["REDACTED-pw".to_string()]);
        assert_eq!(
            vals(&form, "portal-userauthcookie"),
            vec!["MOCK-c1".to_string()]
        );
        assert_eq!(
            vals(&form, "portal-prelogonuserauthcookie"),
            vec!["MOCK-c2".to_string()]
        );
        assert_unique_keys(&form);
        assert_no_empty_secrets(&form);
    }

    #[test]
    fn gateway_login_form_cookieless_auth_credential_posts_no_secrets_at_all() {
        // Portal issued nothing and there is no password to replay:
        // the form must contain NO secret key (not even empty ones).
        let cred = cookie_cred("test-user", "", "", None);
        let form = params_base().gateway_login_form(&cred, "gw.example.com");
        for k in LOGIN_SECRET_KEYS {
            assert!(
                vals(&form, k).is_empty(),
                "{k} must be omitted, not sent empty"
            );
        }
        assert!(!vals(&form, "user").is_empty());
        assert_unique_keys(&form);
        assert_no_empty_secrets(&form);
    }

    #[test]
    fn gateway_login_form_mfa_retry_has_exactly_one_passwd_the_otp() {
        // Old bug: to_params pushed passwd=<otp> and the credential then
        // appended a second (empty) passwd=. One key, the OTP, wins —
        // even if the credential also carries a replayable password.
        let mut p = params_base();
        p.otp = Some("123456".into());
        p.input_str = Some("challenge-token".into());
        let cred = cookie_cred("test-user", "MOCK-c1", "MOCK-c2", Some("REDACTED-pw"));
        let form = p.gateway_login_form(&cred, "gw.example.com");
        assert_eq!(vals(&form, "passwd"), vec!["123456".to_string()]);
        assert_eq!(vals(&form, "inputStr"), vec!["challenge-token".to_string()]);
        assert_unique_keys(&form);
        assert_no_empty_secrets(&form);
    }

    #[test]
    fn gateway_login_form_prelogin_credential_omits_passwd_entirely() {
        // SAML/Prelogin lane: no password exists, so the `passwd` key
        // must not appear at all (reference alt-secret form).
        let cred = Credential::Prelogin {
            username: "test-user".into(),
            prelogin_cookie: Some("MOCK-prelogin".into()),
            token: None,
        };
        let form = params_base().gateway_login_form(&cred, "gw.example.com");
        assert!(vals(&form, "passwd").is_empty());
        assert!(vals(&form, "token").is_empty());
        assert_eq!(
            vals(&form, "prelogin-cookie"),
            vec!["MOCK-prelogin".to_string()]
        );
        assert_unique_keys(&form);
        assert_no_empty_secrets(&form);
    }

    #[test]
    fn gateway_login_form_server_field_is_hostname_only() {
        // Issue #36 review, protocol-truth: portal-advertised gateway
        // addresses can carry the service port (":11443" in #36's
        // environment). libopenconnect `gpst_login` and yuezk's
        // `resolve_server` both send the bare hostname in `server=`;
        // gateways that compare it to their FQDN see a mismatch on a
        // port-bearing value. The request URL is built separately and
        // keeps its port — only this form field is stripped.
        let cred = pw_cred("test-user", "REDACTED-pw");
        let server_val = |server: &str| {
            let form = params_base().gateway_login_form(&cred, server);
            vals(&form, "server")
        };
        assert_eq!(server_val("vpn.example.com:11443"), vec!["vpn.example.com"]);
        assert_eq!(server_val("vpn.example.com"), vec!["vpn.example.com"]);
        assert_eq!(server_val("10.0.0.5:443"), vec!["10.0.0.5"]);
        // IPv6 literals: bracketed keeps its brackets, unbracketed
        // multi-colon values are never mistaken for host:port.
        assert_eq!(server_val("[2001:db8::1]:11443"), vec!["[2001:db8::1]"]);
        assert_eq!(server_val("2001:db8::1"), vec!["2001:db8::1"]);
    }

    // ---------- issue #43: the shared splitter + URL-lane pins ----------

    /// The host half must stay byte-identical to the #42 corpus
    /// (server_field now delegates to split_host_port).
    #[test]
    fn server_field_bracketed_ipv6_regression() {
        assert_eq!(server_field("[::1]:443"), "[::1]");
        assert_eq!(server_field("2001:db8::1"), "2001:db8::1");
        assert_eq!(server_field("vpn.example.com:11443"), "vpn.example.com");
        assert_eq!(server_field("ra.vpn.unsw.edu.au"), "ra.vpn.unsw.edu.au");
        // Same through the splitter itself (single implementation).
        assert_eq!(split_host_port("[::1]:443").0, "[::1]");
        assert_eq!(split_host_port("2001:db8::1").0, "2001:db8::1");
    }

    /// The port half: advertised ports round-trip, absence is
    /// `Absent` (downstream defaults 443), and an unusable numeric
    /// tail is `OutOfRange` — distinguishable from absence so the
    /// tunnel lane can fail closed instead of silently downgrading.
    #[test]
    fn split_host_port_port_half() {
        assert_eq!(
            split_host_port("203.0.113.7:11443").1,
            PortSpec::Valid(11443)
        );
        assert_eq!(split_host_port("ra.vpn.unsw.edu.au").1, PortSpec::Absent);
        assert_eq!(split_host_port("2001:db8::1").1, PortSpec::Absent);
        assert_eq!(split_host_port("[fd00::1]:11443").1, PortSpec::Valid(11443));
        assert_eq!(
            split_host_port("gw.example.com:99999").1,
            PortSpec::OutOfRange("99999")
        );
        // Out-of-range is NOT a port: service_port maps it to None
        // (consumers must go through split_host_port to tell the
        // difference — see gp-tunnel parse_tunnel_target failing
        // closed).
        assert_eq!(service_port("gw.example.com:99999"), None);
        assert_eq!(service_port("gw.example.com:11443"), Some(11443));
        assert_eq!(service_port("gw.example.com"), None);
        assert_eq!(service_port("gw.example.com:0"), None);
    }

    #[test]
    fn gateway_login_url_keeps_advertised_port_and_no_port_defaults_https_443() {
        // URL lane characterization (issue #42 contract, re-pinned
        // for the #43 refactor): the request authority keeps the
        // port; a port-less host (maintainer's daily connect shape)
        // targets the implicit https 443.
        let mut p = params_base();
        p.is_gateway = true;
        assert_eq!(
            p.login_url("ra.vpn.unsw.edu.au"),
            "https://ra.vpn.unsw.edu.au/ssl-vpn/login.esp"
        );
        assert_eq!(
            p.login_url("203.0.113.7:11443"),
            "https://203.0.113.7:11443/ssl-vpn/login.esp"
        );
    }

    #[test]
    fn to_params_still_emits_full_key_set_for_portal_path() {
        // The portal getconfig contract (credential.rs doc: portals want
        // every key present) is unchanged by the issue #36 fix.
        let cred = pw_cred("u", "REDACTED-pw");
        let params = cred.to_params();
        for k in [
            "user",
            "passwd",
            "prelogin-cookie",
            "portal-userauthcookie",
            "portal-prelogonuserauthcookie",
            "token",
        ] {
            assert!(
                params.iter().any(|(key, _)| *key == k),
                "{k} must stay present for portals"
            );
        }
    }
}
