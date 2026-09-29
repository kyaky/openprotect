//! Gateway types and login response parsing.

use crate::credential::AuthCookie;
use crate::error::ProtoError;
use crate::xml::XmlNode;

/// A VPN gateway parsed from the portal configuration.
#[derive(Debug, Clone)]
pub struct Gateway {
    /// Gateway hostname or IP address.
    pub address: String,
    /// Human-readable description.
    pub description: String,
    /// Base priority (lower is preferred).
    pub priority: u32,
    /// Region-specific priority overrides.
    pub priority_rules: Vec<PriorityRule>,
}

/// Character gate for portal-advertised gateway addresses (see
/// [`Gateway::parse_list`], issue #36 resweep checklist M4): ASCII
/// hostnames/FQDNs/IP literals with an optional `:port` — ASCII
/// alphanumerics plus `.` `-` `_` `:` `[` `]` only, and non-empty.
/// Anything else (control bytes, whitespace, URL structural chars) is
/// rejected at the boundary where server text becomes client state,
/// before it can become a URL component, a `server=` form field, or a
/// log interpolation that could impersonate a trusted line.
fn is_valid_gateway_address(address: &str) -> bool {
    !address.is_empty()
        && address.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

/// Per-region priority override for a gateway.
#[derive(Debug, Clone)]
pub struct PriorityRule {
    pub region: String,
    pub priority: u32,
}

impl Gateway {
    /// Host half of the advertised `address`, with any trailing
    /// `:port` removed (issue #43).
    ///
    /// `address` itself stays verbatim: it is the entry NAME the
    /// portal advertised, needed for display, `--gateway` matching
    /// and the request-URL authority (which must keep the port —
    /// issue #42). This accessor exists for consumers that need a
    /// bare host: `getaddrinfo`-style resolution, the gp-route
    /// gateway-exclude pin, and libopenconnect's hostname slot.
    /// A bracketed IPv6 literal keeps its brackets (`"[fd00::1]"`),
    /// matching the URL-literal convention libopenconnect expects;
    /// an unbracketed IPv6 address is returned whole, never chopped
    /// at an interior colon. Delegates to the single shared
    /// bracket-aware splitter [`crate::params::split_host_port`].
    pub fn host(&self) -> &str {
        crate::params::split_host_port(&self.address).0
    }

    /// Advertised service port parsed out of `address`, `None` when
    /// the portal entry carries no `:port` (issue #43).
    pub fn port(&self) -> Option<u16> {
        crate::params::service_port(&self.address)
    }

    /// Effective priority for a given region, falling back to `"Any"` or the
    /// base priority.
    pub fn priority_for_region(&self, region: &str) -> u32 {
        self.priority_rules
            .iter()
            .find(|r| r.region.eq_ignore_ascii_case(region))
            .or_else(|| self.priority_rules.iter().find(|r| r.region == "Any"))
            .map(|r| r.priority)
            .unwrap_or(self.priority)
    }

    /// Parse a list of gateways from a `<gateways>` XML node.
    ///
    /// Trust gate (issue #36 resweep, checklist M4): a gateway address
    /// is only ever used to compose the login URL and the `server=`
    /// form field, so characters outside the hostname[:port] set are
    /// hostile by construction — CR/LF and other control bytes (which
    /// `XmlNode` keeps verbatim in attribute values, xml.rs:90, and
    /// which the `url` crate silently strips from the request target
    /// while the RAW string still reaches the diagnostics), whitespace,
    /// and the URL structural chars a forged attribute would ride
    /// (`/ ? # @ % \`). Such entries are DROPPED here, at the boundary
    /// where server text becomes client state, instead of flowing to
    /// every log line, form field, and the GUI's stderr reader. With
    /// all entries dropped, `PortalConfig::parse`'s fallback (the
    /// operator-supplied portal host) takes over as usual.
    pub(crate) fn parse_list(gateways_node: &XmlNode) -> Vec<Gateway> {
        // Prefer external gateways (typical for VPN clients connecting remotely).
        let list_node = gateways_node
            .at("external/list")
            .or_else(|| gateways_node.at("internal/list"));

        let Some(list_node) = list_node else {
            return Vec::new();
        };

        list_node
            .children_named("entry")
            .filter(|entry| entry.attr("name").is_some_and(is_valid_gateway_address))
            .filter_map(|entry| {
                let address = entry.attr("name")?.to_string();
                let description = entry
                    .child_text("description")
                    .unwrap_or(&address)
                    .to_string();

                let priority_rules: Vec<PriorityRule> = entry
                    .child("priority-rule")
                    .map(|pr| {
                        pr.children_named("entry")
                            .filter_map(|rule| {
                                let region = rule.attr("name")?.to_string();
                                let priority: u32 = rule.child_text("priority")?.parse().ok()?;
                                Some(PriorityRule { region, priority })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Use the explicit <priority> child if present, otherwise
                // fall back to the "Any" priority rule, then u32::MAX.
                let priority = entry
                    .child_text("priority")
                    .and_then(|s| s.parse::<u32>().ok())
                    .or_else(|| {
                        priority_rules
                            .iter()
                            .find(|r| r.region == "Any")
                            .map(|r| r.priority)
                    })
                    .unwrap_or(u32::MAX);

                Some(Gateway {
                    address,
                    description,
                    priority,
                    priority_rules,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Gateway login response
// ---------------------------------------------------------------------------

/// Result of a gateway login attempt.
#[derive(Debug, Clone)]
pub enum GatewayLoginResult {
    /// Login succeeded — contains the auth token for the tunnel.
    Success(AuthCookie),
    /// Server requests an MFA challenge.
    MfaChallenge { message: String, input_str: String },
}

impl GatewayLoginResult {
    /// Parse the gateway `/ssl-vpn/login.esp` response body.
    ///
    /// The response is either a JNLP XML document (success) or an HTML page
    /// with JavaScript variables indicating an MFA challenge.
    pub fn parse(body: &str, computer: &str) -> Result<Self, ProtoError> {
        if body.contains("\"Challenge\"") || body.contains("respStatus = \"Challenge\"") {
            return Self::parse_mfa(body);
        }
        Self::parse_jnlp(body, computer)
    }

    fn parse_jnlp(xml: &str, computer: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;
        let app_desc = root
            .child("application-desc")
            .ok_or(ProtoError::MissingField {
                field: "application-desc",
                context: "gateway login response",
            })?;

        let args: Vec<&str> = app_desc
            .children_named("argument")
            .map(|a| a.text.as_str())
            .collect();

        let authcookie = args
            .get(1)
            .filter(|s| !s.is_empty())
            .ok_or(ProtoError::MissingField {
                field: "authcookie (argument[1])",
                context: "gateway login JNLP",
            })?
            .to_string();

        let get = |i: usize| -> Option<String> {
            args.get(i).map(|s| s.to_string()).filter(|s| !s.is_empty())
        };

        Ok(Self::Success(AuthCookie {
            username: get(4).unwrap_or_default(),
            authcookie,
            portal: get(3).unwrap_or_default(),
            domain: get(7),
            preferred_ip: get(15),
            computer: Some(computer.to_string()),
        }))
    }

    fn parse_mfa(html: &str) -> Result<Self, ProtoError> {
        let message =
            extract_js_var(html, "respMsg").unwrap_or_else(|| "MFA challenge".to_string());
        let input_str = extract_js_var(html, "inputStr")
            .or_else(|| extract_js_assignment(html, "thisForm.inputStr.value"))
            .unwrap_or_default();

        Ok(Self::MfaChallenge { message, input_str })
    }
}

/// Extract `var name = "value";` from HTML/JS.
fn extract_js_var(html: &str, var_name: &str) -> Option<String> {
    let pattern = format!("var {} = \"", var_name);
    let start = html.find(&pattern)? + pattern.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

/// Extract `lhs = "value";` from HTML/JS.
fn extract_js_assignment(html: &str, lhs: &str) -> Option<String> {
    let pattern = format!("{} = \"", lhs);
    let start = html.find(&pattern)? + pattern.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gateway_list() {
        let xml = r#"
        <gateways>
            <external>
                <list>
                    <entry name="gw1.example.com">
                        <description>US East</description>
                        <priority-rule>
                            <entry name="US"><priority>5</priority></entry>
                            <entry name="Any"><priority>100</priority></entry>
                        </priority-rule>
                    </entry>
                    <entry name="gw2.example.com">
                        <description>EU West</description>
                        <priority-rule>
                            <entry name="EU"><priority>3</priority></entry>
                            <entry name="Any"><priority>50</priority></entry>
                        </priority-rule>
                    </entry>
                </list>
            </external>
        </gateways>"#;

        let node = XmlNode::parse(xml).unwrap();
        let gateways = Gateway::parse_list(&node);
        assert_eq!(gateways.len(), 2);

        assert_eq!(gateways[0].address, "gw1.example.com");
        assert_eq!(gateways[0].priority_for_region("US"), 5);
        assert_eq!(gateways[0].priority_for_region("APAC"), 100); // falls back to Any

        assert_eq!(gateways[1].address, "gw2.example.com");
        assert_eq!(gateways[1].priority_for_region("EU"), 3);
    }

    // ---------- issue #43: port-bearing entry names ----------

    /// Characterization (GREEN by design): the entry name is stored
    /// VERBATIM by parse. The split must NOT move into the parser —
    /// the request-URL authority and `--gateway` matching depend on
    /// the verbatim `host:port` (issue #42).
    #[test]
    fn parse_list_keeps_ip_port_entry_name_verbatim() {
        let xml = r#"
        <gateways>
            <external>
                <list>
                    <entry name="203.0.113.7:11443"/>
                </list>
            </external>
        </gateways>"#;
        let node = XmlNode::parse(xml).unwrap();
        let gateways = Gateway::parse_list(&node);
        assert_eq!(gateways.len(), 1);
        assert_eq!(gateways[0].address, "203.0.113.7:11443");
        // description falls back to the verbatim address (unchanged).
        assert_eq!(gateways[0].description, "203.0.113.7:11443");
    }

    /// Characterization: the #36 trust gate must keep admitting
    /// bracketed IPv6 + port entries while the #43 fix lands —
    /// over-tightening it would silently drop the reporter's POP.
    #[test]
    fn is_valid_gateway_address_accepts_bracketed_ipv6_with_port_entry() {
        let xml = r#"
        <gateways>
            <external>
                <list>
                    <entry name="[fd00::1]:11443"/>
                </list>
            </external>
        </gateways>"#;
        let node = XmlNode::parse(xml).unwrap();
        assert_eq!(Gateway::parse_list(&node).len(), 1);
    }

    fn gw(address: &str) -> Gateway {
        Gateway {
            address: address.into(),
            description: "x".into(),
            priority: 0,
            priority_rules: Vec::new(),
        }
    }

    /// RED today: `host()` strips the advertised port (issue #43).
    #[test]
    fn gateway_host_accessor_strips_advertised_port() {
        assert_eq!(gw("203.0.113.7:11443").host(), "203.0.113.7");
    }

    /// RED today: `port()` returns the advertised port; the no-port
    /// (UNSW daily-connect) shape gives `host()` verbatim + `None`;
    /// bracketed IPv6 keeps its brackets; unbracketed IPv6 is never
    /// mis-split at an interior colon.
    #[test]
    fn gateway_port_accessor_returns_advertised_port() {
        assert_eq!(gw("203.0.113.7:11443").port(), Some(11443));
        assert_eq!(gw("ra.vpn.unsw.edu.au").port(), None);
        assert_eq!(gw("ra.vpn.unsw.edu.au").host(), "ra.vpn.unsw.edu.au");
        assert_eq!(gw("[fd00::1]:11443").host(), "[fd00::1]");
        assert_eq!(gw("[fd00::1]:11443").port(), Some(11443));
        assert_eq!(gw("2001:db8::1").host(), "2001:db8::1");
        assert_eq!(gw("2001:db8::1").port(), None);
        // hostnames (not just IP literals) carry ports too.
        assert_eq!(gw("gw.corp.example:8443").host(), "gw.corp.example");
        assert_eq!(gw("gw.corp.example:8443").port(), Some(8443));
    }

    #[test]
    fn parse_jnlp_response() {
        let xml = r#"
        <jnlp>
            <application-desc>
                <argument>arg0</argument>
                <argument>COOKIE_VALUE</argument>
                <argument>arg2</argument>
                <argument>portal.example.com</argument>
                <argument>alice</argument>
                <argument>arg5</argument>
                <argument>arg6</argument>
                <argument>CORP</argument>
            </application-desc>
        </jnlp>"#;

        let result = GatewayLoginResult::parse(xml, "myhost").unwrap();
        if let GatewayLoginResult::Success(cookie) = result {
            assert_eq!(cookie.authcookie, "COOKIE_VALUE");
            assert_eq!(cookie.portal, "portal.example.com");
            assert_eq!(cookie.username, "alice");
            assert_eq!(cookie.domain.as_deref(), Some("CORP"));
        } else {
            panic!("expected Success");
        }
    }

    #[test]
    fn parse_mfa_challenge() {
        let html = r#"
        <html><body><script>
        var respStatus = "Challenge";
        var respMsg = "Enter your OTP code";
        thisForm.inputStr.value = "abc123";
        </script></body></html>"#;

        let result = GatewayLoginResult::parse(html, "myhost").unwrap();
        if let GatewayLoginResult::MfaChallenge { message, input_str } = result {
            assert_eq!(message, "Enter your OTP code");
            assert_eq!(input_str, "abc123");
        } else {
            panic!("expected MfaChallenge");
        }
    }
}
