//! Canonical host:port handling for the libopenconnect tunnel lane
//! (issue #43).
//!
//! Portal-advertised gateway entry names may carry the service port
//! (`"203.0.113.7:11443"`). `openconnect_set_hostname` STRDUPs its
//! argument verbatim into `vpninfo->hostname` and never parses a port
//! (library.c), and libopenconnect v9.21 exposes **no public
//! `openconnect_set_port`** — only the getter `openconnect_get_port` —
//! so a `host:port` string reaching the hostname slot makes the
//! library's own `getaddrinfo` fail (`os error 11001` / `rc=-5` in
//! issue #43). The only public entrypoint that sets hostname and port
//! together is `openconnect_parse_url`, which is exactly what the
//! official CLI uses for its raw `--server` argument (main.c). This
//! module encodes that split-and-set contract; it is compiled in
//! every build (real bindings and the OPENCONNECT_DIR-unset stub) so
//! the decision logic is unit-testable offline without FFI.

use crate::TunnelError;
use gp_proto::params::{split_host_port, PortSpec};

/// A gateway address split into the pieces the libopenconnect API
/// expects: a bare host (brackets KEPT for IPv6 URL literals, per
/// `ssl.c` which only special-cases a wholly-bracketed hostname) and
/// an optional service port (`None` = library default 443).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelTarget {
    /// Bare hostname / IP literal, port component removed.
    pub hostname: String,
    /// Advertised TLS port, or `None` to keep libopenconnect's
    /// default (443).
    pub port: Option<u16>,
}

/// Split a portal-advertised gateway address (bare `host`,
/// `host:port`, `[v6]`, or `[v6]:port`) into a [`TunnelTarget`].
///
/// Delegates the split to the single bracket-aware splitter
/// [`gp_proto::params::split_host_port`] — the same one behind the
/// #42 `server=` field — so there is exactly one host:port rule in
/// the application. A digit-only port tail outside `1..=65535` (or
/// `0`) is a hard error rather than a silent drop to 443: aiming a
/// security tunnel at the wrong port must fail loudly. Malformed
/// authorities (empty host, colon-bearing non-IPv6 labels — issue
/// #43 review findings 2/3/4) likewise error here instead of handing
/// a colon-bearing node to `getaddrinfo`, mirroring upstream
/// `internal_parse_url`'s `-EINVAL` (an empty-port tail `host:` is
/// NOT malformed: it splits to the bare host, no port, like the
/// reqwest/url lane).
pub fn parse_tunnel_target(address: &str) -> Result<TunnelTarget, TunnelError> {
    let (hostname, spec) = split_host_port(address);
    // Fail-closed on an advertised-but-unusable port or a malformed
    // authority: never silently downgrade to 443 and never let a
    // colon-bearing host reach the session — the tunnel must not come
    // up aimed at a port the portal did not advertise, nor at a node
    // getaddrinfo cannot name (upstream `internal_parse_url` rejects
    // ports outside 1..=0xffff and non-parseable authorities alike).
    let port = match spec {
        PortSpec::Absent => None,
        PortSpec::Valid(p) => Some(p),
        PortSpec::OutOfRange(tail) => {
            return Err(TunnelError::OpenConnect(format!(
                "gateway address {address:?} advertises unusable port {tail:?}"
            )));
        }
        PortSpec::Malformed => {
            return Err(TunnelError::OpenConnect(format!(
                "gateway address {address:?} is not a valid host or host:port label"
            )));
        }
    };
    Ok(TunnelTarget {
        hostname: hostname.to_string(),
        port,
    })
}

/// The session-config surface [`crate`] consumers drive, as a trait
/// so the tunnel setup sequence is testable with a recording double
/// instead of real FFI (mirrors gp-route's injectable `CommandRunner`
/// precedent). The real implementation forwards to
/// [`crate::OpenConnectSession`]'s inherent methods; the offline stub
/// implements it too so both builds expose the same surface.
pub trait SessionHandle {
    /// `openconnect_set_protocol("gp")`.
    fn set_protocol_gp(&mut self) -> Result<(), TunnelError>;
    /// `openconnect_set_hostname` — verbatim, no parsing, no port.
    fn set_hostname(&mut self, hostname: &str) -> Result<(), TunnelError>;
    /// `openconnect_parse_url` — sets hostname + port + urlpath
    /// atomically from a full `https://host[:port]` URL.
    fn parse_url(&mut self, url: &str) -> Result<(), TunnelError>;
    /// `openconnect_set_reported_os`.
    fn set_os_spoof(&mut self, os: &str) -> Result<(), TunnelError>;
    /// `openconnect_set_cookie`.
    fn set_cookie(&mut self, cookie: &str) -> Result<(), TunnelError>;
    /// `openconnect_set_client_cert`.
    fn set_client_cert(&mut self, cert: &str, key: &str) -> Result<(), TunnelError>;

    /// Canonical split-and-set for a gateway target (issue #43):
    ///
    /// * `port == None` → `set_hostname` verbatim. This is the
    ///   maintainer's port-less daily-connect lane
    ///   (`ra.vpn.unsw.edu.au`): byte-identical FFI sequence to the
    ///   pre-#43 code, and `vpninfo->port` stays at the library
    ///   default 443.
    /// * `port == Some(p)` → `parse_url("https://{hostname}:{p}")`,
    ///   the only public v9.21 entrypoint that applies a non-default
    ///   CSTP port (no `openconnect_set_port` exists).
    fn configure_target(&mut self, target: &TunnelTarget) -> Result<(), TunnelError> {
        match target.port {
            // Port-less (UNSW daily-connect) lane: verbatim
            // set_hostname, byte-identical to the pre-#43 FFI
            // sequence; vpninfo->port keeps its 443 default.
            None => self.set_hostname(&target.hostname),
            // Port-bearing lane: synthesize the URL literal — the
            // bracketed `[v6]` form is already guaranteed by the
            // splitter — and let the library split-and-set both
            // fields atomically, exactly like the official CLI.
            Some(port) => self.parse_url(&format!("https://{}:{}", target.hostname, port)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- issue #43 group (b): the split at the wrapper seam ----------

    /// RED on seeded (today-behaving) code: an `IP:port` entry must
    /// split into bare host + advertised port. This is the core #43
    /// repro at the seam: today the whole `"203.0.113.7:11443"`
    /// reaches the getaddrinfo node and rc=-5 comes back.
    #[test]
    fn tunnel_target_splits_ipv4_port_entry() {
        let t = parse_tunnel_target("203.0.113.7:11443").unwrap();
        assert_eq!(t.hostname, "203.0.113.7");
        assert_eq!(t.port, Some(11443));
    }

    /// UNSW-shape pin (no-regression): a port-less host passes
    /// through verbatim with no port override, so the library keeps
    /// its 443 default exactly as today.
    #[test]
    fn tunnel_target_no_port_uses_default_443() {
        let t = parse_tunnel_target("ra.vpn.unsw.edu.au").unwrap();
        assert_eq!(t.hostname, "ra.vpn.unsw.edu.au");
        assert_eq!(t.port, None);
    }

    /// Bracketed IPv6 keeps its brackets (the URL-literal form
    /// libopenconnect's `ssl.c` strips + AI_NUMERICHOSTs) and
    /// splits its advertised port.
    #[test]
    fn tunnel_target_bracketed_ipv6_keeps_brackets_and_port() {
        let t = parse_tunnel_target("[fd00::1]:11443").unwrap();
        assert_eq!(t.hostname, "[fd00::1]");
        assert_eq!(t.port, Some(11443));
    }

    /// A bare (unbracketed) IPv6 address must NEVER be chopped at
    /// its last colon — the colons belong to the address.
    #[test]
    fn tunnel_target_unbracketed_ipv6_not_split_at_last_colon() {
        let t = parse_tunnel_target("fd00::1").unwrap();
        assert_eq!(t.hostname, "fd00::1");
        assert_eq!(t.port, None);
        let t = parse_tunnel_target("2001:db8::1").unwrap();
        assert_eq!(t.hostname, "2001:db8::1");
        assert_eq!(t.port, None);
    }

    /// A digit-only but unusable port fails loudly (fail-closed):
    /// no silent downgrade to 443 for a security tunnel.
    #[test]
    fn tunnel_target_out_of_range_port_is_error() {
        assert!(parse_tunnel_target("gw.example.com:99999").is_err());
        assert!(parse_tunnel_target("gw.example.com:0").is_err());
    }

    /// IPv6 localhost literal end-to-end at the string level: the
    /// synthesized openconnect-style connect URL keeps the bracketed
    /// host and round-trips the advertised port (no `url` crate dep
    /// here — asserted structurally, no socket involved).
    #[test]
    fn tunnel_target_ipv6_localhost_mock() {
        let t = parse_tunnel_target("[::1]:11443").unwrap();
        assert_eq!(t.hostname, "[::1]");
        assert_eq!(t.port, Some(11443));
        let url = format!("https://{}:{}", t.hostname, t.port.unwrap_or(443));
        assert_eq!(url, "https://[::1]:11443");
        let rest = url.strip_prefix("https://").expect("synthesized scheme");
        let (host, port) = rest.rsplit_once(':').expect("port component");
        assert_eq!(host, "[::1]");
        assert_eq!(port.parse::<u16>().unwrap(), 11443);
    }

    // ---------- issue #43 review: fail-closed at the target seam ----------

    /// Finding 4: an EMPTY host half must fail closed, not produce a
    /// `TunnelTarget { hostname: "", port: Some(443) }` that
    /// configures `openconnect_parse_url("https://:443")` — the
    /// module's stated fail-closed contract covers unusable ports AND
    /// a missing host (upstream `internal_parse_url` fails the whole
    /// call before anything reaches `vpninfo->hostname`).
    #[test]
    fn parse_tunnel_target_empty_host_fails_closed() {
        assert!(
            parse_tunnel_target(":443").is_err(),
            "empty hostname with an advertised port must not fail open"
        );
        assert!(parse_tunnel_target("").is_err(), "empty label must error");
        assert!(parse_tunnel_target(":").is_err(), "bare colon must error");
    }

    /// Findings 2/3: a `host:` label with an empty port tail is a
    /// no-port label (matching the reqwest/url lane); the colon must
    /// not survive into the hostname half.
    #[test]
    fn parse_tunnel_target_trailing_colon_strips_the_empty_port() {
        let t = parse_tunnel_target("vpn.example.com:").unwrap();
        assert_eq!((t.hostname.as_str(), t.port), ("vpn.example.com", None));
        let t = parse_tunnel_target("[fd00::1]:").unwrap();
        assert_eq!((t.hostname.as_str(), t.port), ("[fd00::1]", None));
        let t = parse_tunnel_target("2001:db8::1:").unwrap();
        assert_eq!((t.hostname.as_str(), t.port), ("2001:db8::1", None));
    }

    /// Findings 2/3 (fail-closed half): labels that are neither
    /// well-formed `host:port`, nor bare IPv6, nor `host:` must be a
    /// hard error — never a colon-bearing hostname reaching
    /// set_hostname/getaddrinfo (the #43 rc=-5 class).
    #[test]
    fn parse_tunnel_target_malformed_authority_fails_closed() {
        assert!(parse_tunnel_target("203.0.113.7:11443:").is_err());
        assert!(parse_tunnel_target("gw.example.com:abc").is_err());
        assert!(parse_tunnel_target("fe80::1%eth0").is_err());
        // The fail-closed arm must NOT over-reject valid shapes:
        assert!(parse_tunnel_target("fd00::").is_ok());
        assert!(parse_tunnel_target("::").is_ok());
        // Structurally-bare-IPv6 with a numeric final group keeps
        // today's verbatim rule (the documented bare-v6 protection).
        assert!(parse_tunnel_target("1:2:3:4:5:6:7:8:9").is_ok());
        // Bracketed IPv6 with NO advertised port: the last colon is
        // inside the brackets — verbatim hostname, brackets KEPT
        // (openconnect's own convention), no port.
        let t = parse_tunnel_target("[fd00::1]").unwrap();
        assert_eq!((t.hostname.as_str(), t.port), ("[fd00::1]", None));
    }

    /// Recorder-level pin of the shipped set_hostname invariant
    /// (main.rs's run_tunnel_hands_no_port_bearing_host_to_set_hostname
    /// only fed the well-formed "host:port") extended to the
    /// trailing-colon shape end-to-end: parse → configure → the
    /// recorded set_hostname call must carry a colon-free host.
    #[test]
    fn configure_target_trailing_colon_never_reaches_set_hostname() {
        let mut r = Recorder::default();
        let t = parse_tunnel_target("vpn.example.com:").expect("split");
        r.configure_target(&t).unwrap();
        assert_eq!(r.hostnames, vec!["vpn.example.com"]);
        assert!(r.urls.is_empty());
    }

    // ---------- SessionHandle seam: the canonical branch ----------

    /// Recording double: no FFI, no sockets — pins exactly which
    /// wrapper primitive the split-and-set branch chooses.
    #[derive(Debug, Default)]
    struct Recorder {
        hostnames: Vec<String>,
        urls: Vec<String>,
    }

    impl SessionHandle for Recorder {
        fn set_protocol_gp(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn set_hostname(&mut self, hostname: &str) -> Result<(), TunnelError> {
            self.hostnames.push(hostname.to_string());
            Ok(())
        }
        fn parse_url(&mut self, url: &str) -> Result<(), TunnelError> {
            self.urls.push(url.to_string());
            Ok(())
        }
        fn set_os_spoof(&mut self, _os: &str) -> Result<(), TunnelError> {
            Ok(())
        }
        fn set_cookie(&mut self, _cookie: &str) -> Result<(), TunnelError> {
            Ok(())
        }
        fn set_client_cert(&mut self, _cert: &str, _key: &str) -> Result<(), TunnelError> {
            Ok(())
        }
    }

    /// RED on the seeded default: today everything rides
    /// set_hostname, so an `IP:port` target would hand the whole
    /// colon-bearing string to the resolver. Post-fix, a port-bearing
    /// target must reach `openconnect_parse_url` with the
    /// `https://{host}:{port}` literal and must NOT call
    /// `set_hostname` at all.
    #[test]
    fn configure_target_with_port_uses_parse_url_and_no_set_hostname() {
        let mut r = Recorder::default();
        let t = TunnelTarget {
            hostname: "203.0.113.7".into(),
            port: Some(11443),
        };
        r.configure_target(&t).unwrap();
        assert!(
            r.hostnames.is_empty(),
            "set_hostname must not see a port-bearing target: {:?}",
            r.hostnames
        );
        assert_eq!(r.urls, vec!["https://203.0.113.7:11443"]);
    }

    /// Bracketed IPv6 form of the parse_url literal.
    #[test]
    fn configure_target_bracketed_ipv6_parse_url_literal() {
        let mut r = Recorder::default();
        let t = TunnelTarget {
            hostname: "[fd00::1]".into(),
            port: Some(11443),
        };
        r.configure_target(&t).unwrap();
        assert_eq!(r.urls, vec!["https://[fd00::1]:11443"]);
        assert!(r.hostnames.is_empty());
    }

    /// UNSW no-regression pin: port-less targets keep riding the
    /// verbatim `set_hostname` lane with ZERO parse_url calls —
    /// byte-identical FFI sequence to the pre-#43 code, and
    /// `vpninfo->port` stays at the library's 443 default.
    #[test]
    fn configure_target_no_port_delegates_to_set_hostname_only() {
        let mut r = Recorder::default();
        let t = TunnelTarget {
            hostname: "ra.vpn.unsw.edu.au".into(),
            port: None,
        };
        r.configure_target(&t).unwrap();
        assert_eq!(r.hostnames, vec!["ra.vpn.unsw.edu.au"]);
        assert!(r.urls.is_empty(), "no parse_url on the port-less lane");
    }

    /// PortSpec reachability from this crate's splitter use: guards
    /// that an out-of-range advertised port cannot sneak through
    /// `parse_tunnel_target` as a silent 443.
    #[test]
    fn parse_tunnel_target_surfaces_out_of_range_as_error_not_default() {
        // The split itself distinguishes the two shapes…
        let (h, spec) = split_host_port("gw.example.com:99999");
        assert_eq!(h, "gw.example.com");
        assert_eq!(spec, PortSpec::OutOfRange("99999"));
        // …and parse_tunnel_target turns it into a hard error.
        assert!(parse_tunnel_target("gw.example.com:99999").is_err());
    }
}
