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
    /// No usable `:port` component: absent, an empty tail (`"host:"`
    /// — the WHATWG/url grammar the reqwest lane reads as no-port, the
    /// colon stripped), or the colons belong to a BARE IPv6 address —
    /// unbracketed ones included, which the url lane cannot parse at
    /// all (`Url::parse("https://2001:db8::1/")` errors: WHATWG wants
    /// brackets). The bare-v6 acceptance is an INTENTIONAL
    /// stricter-for-everyone-else / looser-here policy divergence,
    /// pinned with its reasoning in
    /// `split_host_port_differential_against_the_url_crate`; bracket
    /// usage additionally requires `bracketed_ipv6_inner` to validate
    /// the contents (issue #43 review round 2, MUST-R1/A).
    Absent,
    /// A numeric port in `1..=u16::MAX`.
    Valid(u16),
    /// The tail after the last colon is all-ASCII-digits but is not a
    /// usable service port — `0` or out of the `1..=65535` range
    /// (e.g. `"gw.example.com:99999"`). Upstream agrees on failing:
    /// this is the shape v9.21 `internal_parse_url` rejects with
    /// `-EINVAL` — any tail `strtol` consumes wholly (digits, a sign,
    /// or empty) but which yields `port <= 0 || port > 0xffff`
    /// (http.c:577-587). Against the REQWEST lane this is the second
    /// INTENTIONAL divergence: `Url::parse("https://gw:0/")` is Ok
    /// with `port() == Some(0)` (pinned in the differential test);
    /// no lane of this application may dial port 0 or silently fall
    /// back to 443 for it. Consumers that must not silently
    /// downgrade fail loudly on this spec.
    OutOfRange(&'a str),
    /// Issue #43 review (findings 2/3/4, M1/M2): the label is not a
    /// valid authority at all — a colon-bearing string that is
    /// neither `host:port`, nor `host:` with an empty port tail, nor
    /// a bare IPv6 literal (`"203.0.113.7:11443:"` double-colon,
    /// `"gw.example.com:abc"` non-numeric tail, `"[fd00::1]:abc"`
    /// garbage after a bracketed head, `"host:abc:443"` digit tail
    /// behind a non-IPv6 interior-colon label, `"fe80::1%eth0"`
    /// zone-id), and/or an empty host (`":443"`, `""`). Upstream v9.21
    /// behaviour per shape (re-read against oc921, http.c:577-590 —
    /// NOT the blanket claim an earlier draft here made):
    /// `internal_parse_url` `-EINVAL`s every label whose tail
    /// `strtol` consumes WHOLLY yet which is unusable — including
    /// `[fd00::1]:-1` (strtol: port -1) and the trailing-colon
    /// `203.0.113.7:11443:` (strtol on the empty tail: port 0);
    /// `[::1]:abc:]` / `fe80::1%eth0`-style zone tails die LATER
    /// (getaddrinfo); and `:443` is not rejected at all — it stores
    /// an EMPTY `vpninfo->hostname` with port 443. For the
    /// non-wholly-numeric tails (`host:abc`) it simply RETAINS the
    /// colon-bearing label in `vpninfo->hostname` (http.c:581-583).
    /// The reqwest lane's `Url::parse` rejects this class outright —
    /// with one caveat: WHATWG strips ASCII TAB/LF/CR from the input
    /// first, so the agreement is scoped to whitespace-free labels
    /// (both facts pinned in
    /// `split_host_port_differential_against_the_url_crate`; the tab
    /// case is an intentional stricter-than-url divergence, not
    /// agreement). Every consumer must treat `Malformed` like
    /// `OutOfRange`: fail closed loudly, never hand the
    /// colon-bearing host half to a getaddrinfo-style dialer. The
    /// returned host half for this spec is the verbatim label;
    /// branch on the spec.
    Malformed,
}

impl PortSpec<'_> {
    /// The port value when it is present and in range.
    pub fn port(self) -> Option<u16> {
        match self {
            PortSpec::Valid(p) => Some(p),
            PortSpec::Absent | PortSpec::OutOfRange(_) | PortSpec::Malformed => None,
        }
    }
}

/// The ONE bracketed-IPv6-URL-authority validator (issue #43 review
/// round 2, MUST-R1/A): a label is a bracketed IPv6 authority iff it
/// is exactly `[inner]` with a SINGLE outer pair (the first `]` is
/// the last character — no inner/extra brackets, which is what let
/// `[::1]:abc:]` sneak through the arms that only tested
/// `ends_with(']')`) AND `inner` is non-empty and parses via
/// `std::net::Ipv6Addr`. Every arm of [`split_host_port`] that hands
/// out `Absent` or `Valid` for a bracket-bearing label routes the
/// host half through here; anything failing it is `Malformed`.
///
/// Zone ids (`fe80::1%eth0`) are rejected: `std::net::Ipv6Addr`
/// refuses ALL `%zone` forms while Windows' getaddrinfo accepts
/// scoped literals — an intentional stricter-than-the-OS divergence
/// (a zone-bearing literal is a link-local artefact a portal must
/// never advertise, and it is unnameable on every non-Windows lane
/// the application runs).
fn bracketed_ipv6_inner(label: &str) -> Option<&str> {
    let inner = label.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() || inner.contains('[') || inner.contains(']') {
        return None;
    }
    inner.parse::<std::net::Ipv6Addr>().ok()?;
    Some(inner)
}

/// Bracket guard for the accepting arms of [`split_host_port`]: a
/// host half may contain bracket characters ONLY as one valid
/// bracketed IPv6 URL authority (the validator above). Any other
/// bracket usage — DNS names or IPv4 literals wearing a shell,
/// mismatched or doubled brackets — is a malformed authority, never
/// a plain no-port host (downstream `bare_dial_host` /
/// `getaddrinfo` would otherwise receive the stripped-but-bogus
/// node, the #43 rc=-5 class in new clothing).
fn brackets_are_valid_ipv6_authority(host_half: &str) -> bool {
    !(host_half.contains('[') || host_half.contains(']'))
        || bracketed_ipv6_inner(host_half).is_some()
}

/// The ONE bracket-aware `host:port` splitter for the whole
/// application (issue #43).
///
/// Splits a trailing `:port` off a hostname / IP literal label:
///
/// * the tail after the LAST colon must be non-empty and all
///   ASCII digits to count as a port;
/// * an empty tail (`"host:"`) reads as **no port** and the colon is
///   stripped — the same reading the WHATWG/url grammar behind
///   reqwest applies (`Url::parse("https://vpn.example.com:/x")` →
///   host `vpn.example.com`, port None → default 443). Without this
///   the auth lane and every bare-host consumer diverged on the
///   trailing-colon shape and re-fired the #43 getaddrinfo failure
///   (review findings 2/3/12);
/// * an unbracketed multi-colon head is treated as a bare IPv6
///   address (the colons belong to the address, not a port
///   delimiter) — mirrors libopenconnect's expectation that IPv6
///   URL literals travel as `[addr]:port` (`ssl.c` only strips
///   brackets when the whole hostname is bracketed) — but only
///   after the WHOLE label parses as an `Ipv6Addr` (issue #43
///   review M2): a digit tail behind a NON-IPv6 interior-colon
///   label (`"host:abc:443"`) is Malformed, not a silent verbatim
///   host. A trailing colon on such a head is likewise stripped
///   only when the remainder (or the whole label, for `"fd00::"`)
///   is a valid IPv6 literal;
/// * a bracketed head keeps its brackets — consumers that feed the
///   host to a URL authority or to `openconnect_parse_url` need the
///   bracketed form; `getaddrinfo`-style consumers must not be
///   handed a bracketed literal at all (they classify it before
///   calling, see `bins/opc::resolve_gateway_for_exclude_with`).
///   A bracketed head with a NON-EMPTY tail after `]:` is never a
///   bare IPv6 literal: the numeric tail splits as the port, any
///   other tail is Malformed (issue #43 review M1 — the
///   wholly-bracketed reading applies only when the LAST colon sits
///   inside the brackets, as in `"[::1]"`);
/// * a label that matches none of the above (colon-bearing junk like
///   `"203.0.113.7:11443:"` or `"gw.example.com:abc"`, an empty host
///   like `":443"`, or the empty string) classifies as
///   [`PortSpec::Malformed`] with the verbatim whole as host half,
///   so consumers fail closed loudly instead of dialing the colon
///   (review findings 2/3/4). The url crate rejects this class at
///   `Url::parse` (differential-pinned in
///   `split_host_port_differential_against_the_url_crate`); v9.21
///   `internal_parse_url` is mixed — it `-EINVAL`s tails strtol
///   parses wholly to an unusable port (signed or empty included)
///   but otherwise stores the label UNVALIDATED in the hostname
///   (http.c:577-590; per-shape detail in [`PortSpec::Malformed`]),
///   which is exactly the #43 failure class this classification
///   exists to pre-empt.
///
/// `server_field` is defined as the host half of this function so
/// the `server=` form field (issue #42) and every #43 consumer share
/// one implementation. The port half is `None` for
/// [`PortSpec::Absent`], [`PortSpec::OutOfRange`] and
/// [`PortSpec::Malformed`] — use the returned [`PortSpec`] directly
/// when an unusable port must be distinguished from no port at all.
pub fn split_host_port(server: &str) -> (&str, PortSpec<'_>) {
    if let Some((head, tail)) = server.rsplit_once(':') {
        let bracketed = head.starts_with('[') && head.ends_with(']');
        let interior_colon_unbracketed = head.contains(':') && !bracketed;
        let port_like = !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit());

        if port_like {
            if interior_colon_unbracketed {
                // Bare IPv6 whose final group is numeric
                // ("fd00::1:8443"): the colons belong to the
                // address — verbatim, no port — but ONLY after the
                // WHOLE label parses as an IPv6 literal (issue #43
                // review M2). "host:abc:443" has a digit tail behind
                // a non-IPv6 interior-colon label and is a malformed
                // authority; the nine-group "1:2:3:4:5:6:7:8:9" the
                // old comment called structurally-valid is NOT an
                // address either and classifies the same way.
                return if server.parse::<std::net::Ipv6Addr>().is_ok() {
                    (server, PortSpec::Absent)
                } else {
                    (server, PortSpec::Malformed)
                };
            }
            if head.is_empty() {
                // ":443" — empty host must not fail open into
                // TunnelTarget { hostname: "", port: Some(443) }
                // (review finding 4).
                return (server, PortSpec::Malformed);
            }
            if !brackets_are_valid_ipv6_authority(head) {
                // Issue #43 review round 2 (MUST-R1/A, arm (a)): a
                // numeric tail must not earn Valid for an
                // unvalidated bracket shell — "[host:abc]:443" and
                // "[127.0.0.1]:8443" are malformed authorities
                // (today: Valid(443/8443) with the bogus shell
                // straight into parse_url/set_hostname).
                return (server, PortSpec::Malformed);
            }
            let spec = match tail.parse::<u16>() {
                Ok(p) if p != 0 => PortSpec::Valid(p),
                Ok(_) => PortSpec::OutOfRange(tail),
                Err(_) => PortSpec::OutOfRange(tail),
            };
            return (head, spec);
        }

        if tail.is_empty() {
            // Empty port tail ("host:", "[v6]:", "v6…:"): the url
            // grammar reads an empty tail as no-port — strip the
            // colon — EXCEPT a bare IPv6 whose trailing colon is
            // part of the address ("fd00::", "::").
            if head.is_empty() {
                return (server, PortSpec::Malformed); // ":" alone
            }
            if interior_colon_unbracketed {
                return if head.parse::<std::net::Ipv6Addr>().is_ok() {
                    (head, PortSpec::Absent) // "2001:db8::1:" strips
                } else if server.parse::<std::net::Ipv6Addr>().is_ok() {
                    (server, PortSpec::Absent) // "fd00::" stays whole
                } else {
                    (server, PortSpec::Malformed) // "203.0.113.7:11443:"
                };
            }
            if !brackets_are_valid_ipv6_authority(head) {
                // MUST-R1/A arm (b): "[host:abc]:" and "[]:" carry
                // brackets that are not one valid IPv6 URL literal —
                // fail closed (today: head returned verbatim-Absent,
                // shell and all).
                return (server, PortSpec::Malformed);
            }
            return (head, PortSpec::Absent); // "vpn.example.com:" / "[fd00::1]:"
        }

        // Non-numeric tail after a colon. Every bracket-bearing label
        // reaches exactly one verdict here via the shared validator
        // (issue #43 review M1 from round 1 fused with round 2's
        // MUST-R1/A arm (c)): the wholly-bracketed no-port shape is
        // granted only when the last colon sits INSIDE one
        // well-formed `[ipv6]` pair whose inner parses as an
        // IPv6Addr ("[::1]", tail "1]" — the #42 corpus shape stays
        // verbatim Absent); everything else bracketed —
        // "[fd00::1]:abc", "[fd00::1]:-1", "[host:abc]",
        // "[::1]:abc:]" — is Malformed, never Absent (no silent 443
        // for garbage). This is stricter than upstream on purpose:
        // v9.21 internal_parse_url -EINVALs only tails strtol parses
        // wholly to an unusable number (http.c:577-587 — which is
        // how "[fd00::1]:-1" and the trailing-colon "203.0.113.7:11443:"
        // do die upstream, port -1 and port 0) and otherwise stores
        // the label UNVALIDATED in vpninfo->hostname; the reqwest
        // lane rejects the class at Url::parse, so we fail closed to
        // keep every consumer coherent.
        if server.starts_with('[') {
            return match bracketed_ipv6_inner(server) {
                Some(_) => (server, PortSpec::Absent),
                None => (server, PortSpec::Malformed),
            };
        }
        if !interior_colon_unbracketed {
            return (server, PortSpec::Malformed); // "host:abc"
        }
        if server.parse::<std::net::Ipv6Addr>().is_ok() {
            return (server, PortSpec::Absent); // "fe80::a" — valid v6
        }
        return (server, PortSpec::Malformed); // "fe80::1%eth0"
    }
    if server.is_empty() {
        return (server, PortSpec::Malformed); // empty label (finding 4)
    }
    if !brackets_are_valid_ipv6_authority(server) {
        // MUST-R1/A arm (d): the no-colon fallback belongs only to
        // labels without brackets, or to one valid bracketed IPv6
        // URL authority — "[127.0.0.1]" and "[host]" are Malformed,
        // not verbatim no-port hosts.
        return (server, PortSpec::Malformed);
    }
    (server, PortSpec::Absent)
}

/// The advertised service port of a `host[:port]` label, `None` when
/// absent, out of range, or malformed (issue #43 seam S1). Consumers
/// that must distinguish "no port advertised" from "unusable port
/// advertised" go through [`split_host_port`] and match on the spec.
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
/// Defined as the host half of [`split_host_port`] (issue #43): on
/// the #42 corpus (port / no-port / bracketed-v6 / bare-v6) the
/// behaviour is byte-identical to the old inline guard. The issue
/// #43 REVIEW findings additionally strip a trailing empty-port
/// colon (`"host:"` → `"host"`, matching the reqwest/url lane) —
/// the `server=` value must never keep a dangling colon either.
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

    /// Issue #43 review (trailing-colon class): a label whose final
    /// colon carries an EMPTY port tail must split to the bare host
    /// with `Absent`, matching what the reqwest/`url` auth lane already
    /// does (`Url::parse("https://vpn.example.com:/x")` yields host
    /// `vpn.example.com`, port None → default 443). Today the splitter
    /// falls through to `(server, Absent)` and hands every bare-host
    /// consumer (set_hostname → getaddrinfo, the exclude resolver
    /// node, the HIP resolve key, the `server=` field) the
    /// colon-bearing whole — the exact rc=-5 failure class #43 closed
    /// for the well-formed shapes.
    #[test]
    fn split_host_port_trailing_colon_matches_the_url_lane() {
        assert_eq!(
            split_host_port("vpn.example.com:"),
            ("vpn.example.com", PortSpec::Absent)
        );
        assert_eq!(
            split_host_port("203.0.113.7:"),
            ("203.0.113.7", PortSpec::Absent)
        );
        assert_eq!(
            split_host_port("[fd00::1]:"),
            ("[fd00::1]", PortSpec::Absent)
        );
        // Valid bare IPv6 + a stray trailing colon: strip the colon,
        // the address half is a well-formed literal.
        assert_eq!(
            split_host_port("2001:db8::1:"),
            ("2001:db8::1", PortSpec::Absent)
        );
        // The #42 form-field lane consumes the same rule (finding 3:
        // server= must not keep the colon either).
        assert_eq!(server_field("vpn.example.com:"), "vpn.example.com");
    }

    /// Anti-over-trim guard: a bare IPv6 literal ending in `::` is a
    /// complete address, not a `host:` with an empty port. The last
    /// colon belongs to the address.
    #[test]
    fn split_host_port_keeps_bare_ipv6_trailing_double_colon() {
        assert_eq!(split_host_port("fd00::"), ("fd00::", PortSpec::Absent));
        assert_eq!(split_host_port("::"), ("::", PortSpec::Absent));
        assert_eq!(split_host_port("fe80::1"), ("fe80::1", PortSpec::Absent));
    }

    /// Fail-closed arm: a colon-bearing label that is neither a
    /// well-formed `host:port`, nor a bare IPv6 literal, nor a
    /// `host:` with an empty port tail, must NOT be classified as a
    /// plain no-port host. Upstream v9.21 is NOT uniform here (exact
    /// per-shape behaviour in [`PortSpec::Malformed`]'s doc): tails
    /// strtol parses wholly to an unusable port — including the
    /// signed `-1` and the empty tail behind a trailing colon — are
    /// `-EINVAL`ed, while genuinely non-numeric tails
    /// (`host:abc`, `fe80::1%eth0`) pass through UNVALIDATED into
    /// `vpninfo->hostname` (http.c:577-590). So the fail-closed
    /// classification is our own policy, matching the reqwest lane's
    /// `Url::parse` rejection (whitespace-free labels; see the
    /// differential test), so consumers never dial a colon-bearing
    /// node. (Asserted via `Absent`
    /// exclusion so the pin holds whatever the named variant looks
    /// like; the named corpus is pinned in
    /// split_host_port_malformed_authority_variant below after the
    /// splitter lands the variant.)
    #[test]
    fn split_host_port_malformed_colon_labels_are_not_plain_no_port() {
        // (head, spec) with a colon-bearing, non-IPv6 label:
        assert!(
            !matches!(split_host_port("203.0.113.7:11443:").1, PortSpec::Absent),
            "double-trailing-colon authority must fail closed"
        );
        assert!(
            !matches!(split_host_port("gw.example.com:abc").1, PortSpec::Absent),
            "non-numeric colon tail must fail closed"
        );
        assert!(
            !matches!(split_host_port("fe80::1%eth0").1, PortSpec::Absent),
            "zone-id labels are rejected by both the reqwest lane and Ipv6Addr — \
             they must not flow through as a plain host"
        );
        assert!(
            !matches!(split_host_port(":443").1, PortSpec::Valid(443)),
            "empty host with a port tail must not fail open (finding 4)"
        );
        assert!(
            split_host_port("").1 != PortSpec::Absent,
            "empty label must not masquerade as a no-port host"
        );
    }

    /// The named fail-closed corpus (issue #43 review findings 2/3/4):
    /// upstream `internal_parse_url` `-EINVAL`s the tails it parses
    /// wholly to an unusable port (sign and empty tail included,
    /// http.c:577-587) and passes the rest through UNVALIDATED (see
    /// [`PortSpec::Malformed`]); this Malformed class is pinned
    /// against the reqwest lane's `Url::parse` rejections (the
    /// url-crate differential test below): malformed
    /// authorities classify as `PortSpec::Malformed` with the verbatim
    /// whole as host half (consumers branch on the spec), while the
    /// structurally-IPv6 shapes keep today's verbatim `Absent` rule.
    #[test]
    fn split_host_port_malformed_authority_variant() {
        for bad in [
            "203.0.113.7:11443:",
            "gw.example.com:abc",
            "fe80::1%eth0",
            ":443",
            ":",
            "",
        ] {
            let (host, spec) = split_host_port(bad);
            assert_eq!(host, bad, "Malformed keeps the verbatim label");
            assert_eq!(spec, PortSpec::Malformed, "{bad:?} must classify Malformed");
            assert_eq!(service_port(bad), None);
        }
        // Port-like interior-colon labels are IPv6-validated as a
        // WHOLE (issue #43 review M2): nine groups is NOT an address,
        // so the previously "structurally pinned" shape classifies
        // Malformed (the old pin asserted Absent WITHOUT validating);
        // genuine bare v6 with a numeric final group keeps the
        // verbatim Absent rule:
        assert_eq!(
            split_host_port("1:2:3:4:5:6:7:8:9"),
            ("1:2:3:4:5:6:7:8:9", PortSpec::Malformed)
        );
        assert_eq!(
            split_host_port("fd00::1:8443"),
            ("fd00::1:8443", PortSpec::Absent)
        );
        // valid bare v6 with a hex final group (non-digit tail) stays:
        assert_eq!(split_host_port("fe80::a"), ("fe80::a", PortSpec::Absent));
        // bracketed IPv6 with NO port: the last colon sits inside the
        // brackets (tail "1]") — verbatim no-port, never Malformed
        // (regression caught by the probe lane's dialer pin):
        assert_eq!(split_host_port("[::1]"), ("[::1]", PortSpec::Absent));
        assert_eq!(
            split_host_port("[fd00::1]"),
            ("[fd00::1]", PortSpec::Absent)
        );
    }

    /// Issue #43 review M1 (release-blocking): a BRACKETED head with
    /// a non-empty tail after the `]:` is never a bare IPv6 literal —
    /// the last colon sits OUTSIDE the brackets. With a numeric tail
    /// it is a port (Valid/OutOfRange); with any other tail it must
    /// be Malformed. Today `[fd00::1]:abc` and `[fd00::1]:-1`
    /// classify Absent — the silent-default-443 class the review
    /// no-go'ed. The wholly-bracketed label (`[::1]`, last colon
    /// INSIDE the brackets) keeps its verbatim Absent rule.
    #[test]
    fn split_host_port_bracketed_head_with_tail_is_never_absent() {
        for bad in [
            "[fd00::1]:abc",
            "[fd00::1]:-1",
            "[fd00::1]:x443",
            "[::1]:http",
            "[2001:db8::1]:443x",
        ] {
            let (host, spec) = split_host_port(bad);
            assert_eq!(
                spec,
                PortSpec::Malformed,
                "{bad:?}: garbage after a bracketed host must fail closed, \
                 never ride the no-port 443 default"
            );
            assert_eq!(host, bad, "Malformed keeps the verbatim label");
            assert_eq!(service_port(bad), None);
        }
        // The numeric side of the same shape (M1 must not over-reject
        // advertised ports on bracketed hosts):
        assert_eq!(
            split_host_port("[fd00::1]:11443"),
            ("[fd00::1]", PortSpec::Valid(11443))
        );
        assert_eq!(
            split_host_port("[fd00::1]:99999"),
            ("[fd00::1]", PortSpec::OutOfRange("99999"))
        );
        assert_eq!(
            split_host_port("[fd00::1]:0"),
            ("[fd00::1]", PortSpec::OutOfRange("0"))
        );
        // Wholly-bracketed labels (last colon inside the brackets)
        // remain verbatim Absent — re-pinned so the M1 fix cannot
        // regress the #42 corpus shape.
        assert_eq!(
            split_host_port("[fd00::1]"),
            ("[fd00::1]", PortSpec::Absent)
        );
        assert_eq!(split_host_port("[::1]"), ("[::1]", PortSpec::Absent));
    }

    /// Issue #43 review M2 (release-blocking): the port-like
    /// interior-colon arm must not wave through ANY colon-bearing
    /// label whose final group is digits — it has to be a genuine
    /// IPv6 literal first. `host:abc:443` (digit tail after a
    /// NON-IPv6 interior-colon label) is Malformed, while valid bare
    /// IPv6 with a numeric final group keeps the verbatim Absent
    /// rule. `Ipv6Addr::from_str` is the validator, so the embedded
    /// IPv4 form stays accepted too.
    #[test]
    fn split_host_port_interior_colon_digit_tail_is_ipv6_validated() {
        assert_eq!(
            split_host_port("host:abc:443"),
            ("host:abc:443", PortSpec::Malformed)
        );
        assert_eq!(service_port("host:abc:443"), None);
        assert_eq!(
            split_host_port("gw.example.com:11443:8443").1,
            PortSpec::Malformed,
            "host:port:port is not an authority either"
        );
        // Validity is what earns the verbatim Absent pass:
        assert_eq!(split_host_port("fd00::1:8443").1, PortSpec::Absent);
        assert_eq!(split_host_port("2001:db8::1:8443").1, PortSpec::Absent);
        assert_eq!(
            split_host_port("1:2:3:4:5:6:1.2.3.4").1,
            PortSpec::Absent,
            "eight groups with an embedded IPv4 tail IS a valid literal"
        );
    }

    /// Issue #43 review round 2 (MUST-R1/A): the bracket SHELL is not
    /// the authority — CONTENTS are validated. A label is a bracketed
    /// IPv6 URL authority iff it is exactly `[inner]` with a single
    /// outer pair (no inner/extra brackets, which is what let
    /// `[::1]:abc:]` sneak through the ends-with-`]` string test) and
    /// `inner` parses via `std::net::Ipv6Addr`. Every previously
    /// bracket-trusting arm (numeric tail → Valid, empty tail →
    /// Absent, wholly-bracketed → Absent, no-colon fallback → Absent)
    /// must route through that one validator; anything failing it is
    /// Malformed — never Absent, never Valid, never verbatim-into-a-
    /// dialer (downstream `bare_dial_host` strips the shell, so an
    /// unvalidated `[127.0.0.1]`/`[host:abc]` became a dialable bogus
    /// host and a `parse_tunnel_target` Ok).
    ///
    /// Zone ids (`[fe80::1%eth0]`) are rejected: `std::net::Ipv6Addr`
    /// refuses ALL `%zone` forms while Windows' getaddrinfo accepts
    /// them — an intentional stricter-than-the-OS divergence (the
    /// bare `fe80::1%eth0` zone pin predates this and stays).
    #[test]
    fn split_host_port_bracketed_contents_validated() {
        // The review's full rejection corpus — every one classified
        // Malformed with the verbatim label (RED against the
        // shell-only classifier: four arms waved these through as
        // Absent or Valid(8443/443)).
        for bad in [
            "[host:abc]",
            "[host:abc]:",
            "[]:",
            "[::1]:abc:]",
            "[host:abc]:443",
            "[127.0.0.1]:8443",
            "[127.0.0.1]",
            "[host]",
        ] {
            let (host, spec) = split_host_port(bad);
            assert_eq!(
                spec,
                PortSpec::Malformed,
                "{bad:?}: bracket shell alone must never earn Absent/Valid — \
                 contents must parse as an IPv6 literal"
            );
            assert_eq!(host, bad, "Malformed keeps the verbatim label");
            assert_eq!(service_port(bad), None, "{bad:?} must advertise no port");
        }
        // Acceptance pins — genuine bracketed IPv6 authorities keep
        // every existing behavior (and the bare forms keep theirs):
        assert_eq!(split_host_port("[::1]"), ("[::1]", PortSpec::Absent));
        assert_eq!(
            split_host_port("[fe80::1]"),
            ("[fe80::1]", PortSpec::Absent)
        );
        assert_eq!(split_host_port("fe80::1"), ("fe80::1", PortSpec::Absent));
        assert_eq!(
            split_host_port("[fd00::1]:11443"),
            ("[fd00::1]", PortSpec::Valid(11443))
        );
        assert_eq!(
            split_host_port("[fd00::1]:0"),
            ("[fd00::1]", PortSpec::OutOfRange("0"))
        );
        // Single-pair enforcement: a second bracket anywhere inside is
        // fatal even when the OUTER pair looks plausible.
        assert_eq!(
            split_host_port("[[::1]]").1,
            PortSpec::Malformed,
            "nested brackets are never a URL authority"
        );
        // Zone-id divergence (documented above).
        assert_eq!(
            split_host_port("[fe80::1%eth0]").1,
            PortSpec::Malformed,
            "std rejects every %zone form; we fail closed rather than \
             trusting a Windows-only getaddrinfo tolerance"
        );
    }

    /// Issue #43 review S2: differential against the WHATWG grammar
    /// the reqwest auth lane actually parses with (the `url` crate
    /// here is the same one reqwest 0.12 uses for `Url::parse`). For
    /// every label the splitter ACCEPTS as a no-port or port-bearing
    /// host, the (host, effective-port) pair must equal
    /// `Url::parse("https://<label>/")`'s host_str +
    /// port_or_known_default. The INTENTIONAL policy divergences are
    /// EXACTLY three, each pinned in its own arm with the behaviour
    /// the url lane actually shows: (2) bare-IPv6 acceptance (url
    /// wants brackets), (3) the port-zero rejection policy (url
    /// parses `:0` as a real port), and (5) the url lane's ASCII
    /// TAB/LF/CR input stripping, which our splitter does not
    /// share. Everything the two grammars both reject — the
    /// Malformed corpus of arm (4), bracket shells with non-IPv6
    /// contents included, and the non-ASCII digit tails pinned
    /// alongside arm (5) as an AGREEMENT addendum — is agreement,
    /// not divergence, and must not be labelled otherwise. A future
    /// "consistency" edit cannot silently flip any of these rows,
    /// and no doc may claim blanket "url rejects" agreement beyond
    /// whitespace-free labels.
    #[test]
    fn split_host_port_differential_against_the_url_crate() {
        // (1) Agreement: labels both grammars accept.
        let agreed = [
            "ra.vpn.unsw.edu.au",
            "vpn.example.com",
            "203.0.113.7",
            "10.0.0.5",
            "vpn.example.com:11443",
            "203.0.113.7:11443",
            "[::1]:443",
            "[fd00::1]:11443",
            "[2001:db8::1]:8443",
            "vpn.example.com:",
            "[fd00::1]:",
            "[::1]",
            "[fd00::1]",
        ];
        for label in agreed {
            let (host, spec) = split_host_port(label);
            assert!(
                matches!(spec, PortSpec::Absent | PortSpec::Valid(_)),
                "{label:?} must be an accepted shape, got {spec:?}"
            );
            let parsed = url::Url::parse(&format!("https://{label}/"))
                .unwrap_or_else(|e| panic!("url crate must accept accepted label {label:?}: {e}"));
            assert_eq!(
                parsed.host_str(),
                Some(host),
                "host half differs for {label:?}"
            );
            // Effective port: Absent is the implicit https 443 (the
            // reading this splitter documents for the empty tail).
            assert_eq!(
                parsed.port_or_known_default(),
                Some(spec.port().unwrap_or(443)),
                "port half differs for {label:?}"
            );
        }

        // (2) PINNED DIVERGENCE — bare IPv6 acceptance. WHATWG wants
        // brackets around a colon-bearing host (Url::parse fails on
        // every label below); the splitter keeps the verbatim-Absent
        // rule because portal-advertised entries historically carry
        // unbracketed v6 and getaddrinfo-style consumers classify
        // before dialing. If either side of this arm ever flips, the
        // split rule changed — re-read the issue #43 contract first.
        for label in [
            "2001:db8::1",
            "fd00::1",
            "fe80::1",
            "fd00::",
            "::",
            "fe80::a",
            "fd00::1:8443",
        ] {
            assert_eq!(
                split_host_port(label).1,
                PortSpec::Absent,
                "bare-v6 acceptance is policy-pinned: {label:?}"
            );
            assert!(
                url::Url::parse(&format!("https://{label}/")).is_err(),
                "url crate unexpectedly ACCEPTS the unbracketed {label:?}: \
                 the pinned divergence needs re-reading"
            );
        }

        // (3) PINNED DIVERGENCE — port-0 rejection. The WHATWG
        // grammar keeps `:0` as a real port; our OutOfRange spec
        // exists precisely so no lane can dial (or silently default
        // from) port 0 — issue #43's no-silent-443 rule.
        assert_eq!(
            split_host_port("gw.example.com:0").1,
            PortSpec::OutOfRange("0")
        );
        let zero = url::Url::parse("https://gw.example.com:0/").expect("WHATWG keeps :0 as a port");
        assert_eq!(
            zero.port(),
            Some(0),
            "url lane now agrees with the splitter — the pinned \
             port-0 divergence changed shape; re-read before relaxing the gate"
        );
        // `:99999` agrees in KIND (both unusable): the url crate
        // errors rather than silently nulling the port to 443.
        assert_eq!(
            split_host_port("gw.example.com:99999").1,
            PortSpec::OutOfRange("99999")
        );
        assert!(url::Url::parse("https://gw.example.com:99999/").is_err());

        // (4) The fail-closed class agrees with the url lane's own
        // rejections — this pins the docs' claim that every consumer
        // sees Malformed shapes fail (the reqwest auth lane rejects
        // them at Url::parse — for these whitespace-free labels; the
        // tab/CR normalization caveat is arm (5)). Includes round
        // 1's three shapes and the full round-2 bracket-shell corpus
        // (MUST-R1/A): BOTH lanes must reject every row.
        for label in [
            "[fd00::1]:abc",
            "[fd00::1]:-1",
            "host:abc:443",
            "gw.example.com:abc",
            "203.0.113.7:11443:",
            "fe80::1%eth0",
            ":443",
            "",
            "[host:abc]",
            "[host:abc]:",
            "[]:",
            "[::1]:abc:]",
            "[host:abc]:443",
            "[127.0.0.1]:8443",
            "[127.0.0.1]",
            "[host]",
        ] {
            assert_eq!(
                split_host_port(label).1,
                PortSpec::Malformed,
                "{label:?} must fail closed in the splitter"
            );
            assert!(
                url::Url::parse(&format!("https://{label}/")).is_err(),
                "the Malformed class must match a url::Url parse failure: {label:?}"
            );
        }

        // (5) PINNED DIVERGENCE — input pre-processing, not grammar.
        // The url crate implements WHATWG's "remove tabs and
        // newlines" preprocessing, stripping ALL ASCII TAB (0x09),
        // LF (0x0A) and CR (0x0D) bytes from the input BEFORE
        // parsing, so `host\t:443`, `host\r:443` and `host\r\n:443`
        // each parse as if the whitespace were never there (host
        // "host", port 443). Our splitter does NOT normalize — the
        // control bytes survive verbatim in the host half, strict
        // rather than laundered, and die fail-closed in every
        // getaddrinfo consumer instead of being silently cleaned.
        // Pinned PER ROW (verified behaviour, both lanes), as the
        // whitespace divergence — one of exactly three, alongside
        // the bare-IPv6 acceptance and port-zero arms above. This
        // is why the arm-(4) "url rejects" agreement is scoped to
        // whitespace-free labels.
        for (ws, ws_name) in [("\t", "TAB"), ("\r", "CR"), ("\r\n", "CRLF")] {
            let labeled = format!("host{ws}:443");
            let parsed = url::Url::parse(&format!("https://{labeled}/")).unwrap_or_else(|e| {
                panic!("WHATWG strips {ws_name}, so {labeled:?} must parse: {e}")
            });
            assert_eq!(
                parsed.host_str(),
                Some("host"),
                "url lane stripped the {ws_name} before parsing"
            );
            assert_eq!(
                parsed.port_or_known_default(),
                Some(443),
                "{ws_name} row: the explicit 443 survives the strip"
            );
            let (ours_host, ours_spec) = split_host_port(&labeled);
            assert_eq!(
                ours_host,
                format!("host{ws}"),
                "we keep the {ws_name} verbatim in the host half — no WHATWG-style laundering"
            );
            assert_eq!(
                ours_spec,
                PortSpec::Valid(443),
                "{ws_name} row: digits still parse as the port"
            );
        }

        // AGREEMENT ADDENDUM (explicitly NOT one of the three
        // divergences): non-ASCII digit tails. Our port gate is
        // all-ASCII-digits, and the url lane's port state likewise
        // rejects non-ASCII digits — BOTH lanes fail closed, so
        // `:٤٤٣` agrees with arm (4)'s rejected class. Pinned
        // so neither side's behaviour is assumed; if the url lane
        // ever starts accepting them, this row flips and the
        // agreement claim (not any divergence list) needs re-reading.
        let arabic = "\u{664}\u{664}\u{663}"; // ٤٤٣
        assert_eq!(
            split_host_port(&format!("gw.example.com:{arabic}")).1,
            PortSpec::Malformed,
            "non-ASCII digits are not a port tail for us"
        );
        assert!(
            url::Url::parse(&format!("https://gw.example.com:{arabic}/")).is_err(),
            "the url lane's own non-ASCII digit behaviour changed shape \
             (this row is AGREEMENT — both lanes must reject)"
        );
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
