//! Portal configuration response parsing.

use crate::credential::Credential;
use crate::error::ProtoError;
use crate::gateway::Gateway;
use crate::xml::XmlNode;

/// Configuration returned by the portal after authentication.
///
/// Parsed from the `/global-protect/getconfig.esp` response.
#[derive(Debug, Clone)]
pub struct PortalConfig {
    /// Portal hostname.
    pub portal: String,
    /// Authenticated username.
    pub username: String,
    /// Portal user-auth cookie.
    pub user_auth_cookie: String,
    /// Portal prelogon user-auth cookie.
    pub prelogon_user_auth_cookie: String,
    /// Available VPN gateways.
    pub gateways: Vec<Gateway>,
    /// Configuration digest (opaque hash).
    pub config_digest: Option<String>,
}

/// Normalize a portal pass-through cookie value to the client's ABSENT
/// marker (empty string).
///
/// A PAN portal `getconfig.esp` may return the literal sentinel
/// `<portal-userauthcookie>empty</portal-userauthcookie>`. Upstream
/// openconnect v9.21 (`auth-globalprotect.c:522-531`, the revision
/// pinned by `.github/workflows/release.yml:188`) frees that value to
/// NULL when the text is `""` or the case-sensitive literal `"empty"`;
/// the cookie keys are then OMITTED from the gateway form by the
/// callers around `append_opt` (which itself writes `key=`
/// unconditionally). We mirror the normalization here so
/// [`PortalConfig::to_gateway_credential`]'s cookieless predicate sees
/// the sentinel as absent and the password-replay lane (issue #36 M1)
/// activates, instead of posting `portal-userauthcookie=empty` while
/// suppressing the password. `XmlNode` already trims text at parse
/// time; the extra `trim` keeps this correct for any caller that
/// supplies raw values.
fn normalize_portal_cookie(value: Option<&str>) -> String {
    match value.map(str::trim) {
        Some(v) if !v.is_empty() && v != "empty" => v.to_string(),
        _ => String::new(),
    }
}

impl PortalConfig {
    /// Parse from the XML body of `/global-protect/getconfig.esp`.
    pub fn parse(xml: &str, portal: &str, username: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;

        // Use recursive search — real responses may nest these under
        // intermediate elements (e.g. <policy>).
        let user_auth_cookie = normalize_portal_cookie(root.find_text("portal-userauthcookie"));
        let prelogon_user_auth_cookie =
            normalize_portal_cookie(root.find_text("portal-prelogonuserauthcookie"));
        let config_digest = root.find_text("config-digest").map(|s| s.to_string());

        let mut gateways = root
            .find("gateways")
            .map(Gateway::parse_list)
            .unwrap_or_default();

        // Fallback: use the portal itself as a gateway.
        if gateways.is_empty() {
            gateways.push(Gateway {
                address: portal.to_string(),
                description: format!("{portal} (fallback)"),
                priority: 0,
                priority_rules: Vec::new(),
            });
        }

        Ok(Self {
            portal: portal.to_string(),
            username: username.to_string(),
            user_auth_cookie,
            prelogon_user_auth_cookie,
            gateways,
            config_digest,
        })
    }

    /// Build the [`Credential`] for gateway login from the portal
    /// result plus the credential that authenticated the portal.
    ///
    /// The literal sentinel value `empty` (and `""`) is treated as
    /// ABSENT — normalized in [`PortalConfig::parse`], upstream
    /// openconnect parity — so a portal that "issued" only sentinels
    /// lands on the cookieless lane below, not the cookie lane.
    ///
    /// * **Portal issued pass-through cookies** → plain
    ///   [`Credential::AuthCookie`], with **no** password replay. That
    ///   is the request the working UNSW-class password+cookie flow
    ///   sends today; replaying the portal password at a gateway whose
    ///   auth profile differs from the portal's (portal=password,
    ///   gateway=cert/SAML is exactly what pass-through cookies exist
    ///   for) would turn a working login into an auth-failed on every
    ///   connect *and* every reconnect, burning the AD lockout budget.
    /// * **Cookieless portal, password flow** → replay the portal
    ///   password (libopenconnect `blind_retry` / yuezk conformance) so
    ///   the gateway receives real secret material instead of issue
    ///   #36's credential-less form (an `passwd` empty/absent at the
    ///   engine is openconnect #859's auth-failed-password-empty
    ///   class).
    /// * **Cookieless portal, SAML/Prelogin flow** → forward the
    ///   captured `prelogin-cookie`/`token` verbatim
    ///   ([`Credential::Prelogin`], openconnect #859's alt-secret form).
    ///   Coercing it into an `AuthCookie` dropped those secrets and
    ///   reproduced #36 on that lane too.
    ///
    /// In every case `Credential::gateway_login_params` omits secret
    /// keys whose value would be empty, so no present-but-empty key
    /// reaches login.esp.
    pub fn to_gateway_credential(&self, portal_cred: &Credential) -> Credential {
        let cookieless =
            self.user_auth_cookie.is_empty() && self.prelogon_user_auth_cookie.is_empty();
        if cookieless {
            if let Credential::Prelogin {
                prelogin_cookie,
                token,
                ..
            } = portal_cred
            {
                return Credential::Prelogin {
                    username: self.username.clone(),
                    prelogin_cookie: prelogin_cookie.clone(),
                    token: token.clone(),
                };
            }
        }
        // Only the cookieless password lane replays. The cookie lane
        // drops ONLY EMPTY-VALUE keys and uses a hostname-only
        // `server=` (both in GpParams::gateway_login_form), mirroring
        // upstream's caller-level omission around `append_opt` — not a
        // byte-identical claim (checklist M5 wording); the UNSW cookie
        // path is verified on the reporter's / next connect.
        let password = match portal_cred {
            Credential::Password { password, .. } if !password.is_empty() && cookieless => {
                Some(password.clone())
            }
            _ => None,
        };
        Credential::AuthCookie {
            username: self.username.clone(),
            user_auth_cookie: self.user_auth_cookie.clone(),
            prelogon_user_auth_cookie: self.prelogon_user_auth_cookie.clone(),
            password,
        }
    }

    /// Select the best gateway, preferring the given region.
    pub fn preferred_gateway(&self, region: Option<&str>) -> Option<&Gateway> {
        if self.gateways.is_empty() {
            return None;
        }
        if let Some(region) = region {
            let mut sorted: Vec<_> = self.gateways.iter().collect();
            sorted.sort_by_key(|g| g.priority_for_region(region));
            Some(sorted[0])
        } else {
            self.gateways.iter().min_by_key(|g| g.priority)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_portal_config() {
        let xml = r#"
        <response>
            <portal-userauthcookie>COOKIE1</portal-userauthcookie>
            <portal-prelogonuserauthcookie>COOKIE2</portal-prelogonuserauthcookie>
            <config-digest>abc123</config-digest>
            <gateways>
                <external>
                    <list>
                        <entry name="gw.example.com">
                            <description>Main GW</description>
                            <priority-rule>
                                <entry name="Any"><priority>10</priority></entry>
                            </priority-rule>
                        </entry>
                    </list>
                </external>
            </gateways>
        </response>"#;

        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        assert_eq!(config.user_auth_cookie, "COOKIE1");
        assert_eq!(config.prelogon_user_auth_cookie, "COOKIE2");
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].address, "gw.example.com");
        assert_eq!(config.config_digest.as_deref(), Some("abc123"));
    }

    #[test]
    fn gateway_credential_replays_portal_password_and_flags_cookieless() {
        let xml = r#"<response></response>"#; // no portal cookies issued
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        // Password flow: the portal password is carried for gateway replay,
        // and the derived credential still yields a login form with a real
        // secret and no present-but-empty keys (issue #36).
        let cred = Credential::Password {
            username: "alice".into(),
            password: "REDACTED-pw".into(),
        };
        let gw_cred = config.to_gateway_credential(&cred);
        match &gw_cred {
            Credential::AuthCookie {
                username,
                user_auth_cookie,
                prelogon_user_auth_cookie,
                password,
            } => {
                assert_eq!(username, "alice");
                assert_eq!(user_auth_cookie, "");
                assert_eq!(prelogon_user_auth_cookie, "");
                assert_eq!(password.as_deref(), Some("REDACTED-pw"));
            }
            other => panic!("expected AuthCookie, got {other:?}"),
        }
        let form = gw_cred.gateway_login_params(false);
        assert_eq!(
            form.iter()
                .filter(|(k, v)| *k == "passwd" && !v.is_empty())
                .count(),
            1,
            "cookie-less portal must still present exactly one real passwd"
        );
        assert!(
            !form.iter().any(|(_, v)| v.is_empty()),
            "no present-but-empty key may reach the gateway: {form:?}"
        );

        // SAML/Prelogin flow on a portal that DID issue pass-through
        // cookies: cookie-only AuthCookie — nothing to replay, so the
        // `passwd` key is omitted entirely rather than sent empty.
        let cookie_xml = r#"
        <response>
            <portal-userauthcookie>MOCK-c1</portal-userauthcookie>
            <portal-prelogonuserauthcookie>MOCK-c2</portal-prelogonuserauthcookie>
        </response>"#;
        let with_cookies = PortalConfig::parse(cookie_xml, "portal.example.com", "alice").unwrap();
        let saml = Credential::Prelogin {
            username: "alice".into(),
            prelogin_cookie: Some("MOCK-prelogin".into()),
            token: None,
        };
        let gw_cred = with_cookies.to_gateway_credential(&saml);
        match &gw_cred {
            Credential::AuthCookie { password, .. } => assert_eq!(password, &None),
            other => panic!("expected AuthCookie, got {other:?}"),
        }
        let form = gw_cred.gateway_login_params(false);
        assert!(
            !form.iter().any(|(k, _)| *k == "passwd"),
            "credential-less AuthCookie must omit passwd, never send it empty"
        );
        assert!(form.iter().any(|(k, _)| *k == "user"));
    }

    #[test]
    fn gateway_credential_does_not_replay_password_when_cookies_present() {
        // Issue #36 review (no-regression): a password flow whose portal
        // issued both pass-through cookies must keep sending the working
        // cookie-only request. An unconditional replay would newly
        // expose the portal password to gateways whose auth profile
        // differs from the portal's (portal=password, gateway=cert/SAML
        // is exactly what cookies exist for) — a wrong-lane auth-failed
        // on every connect AND every reconnect burns the AD lockout
        // budget with it.
        let xml = r#"
        <response>
            <portal-userauthcookie>MOCK-c1</portal-userauthcookie>
            <portal-prelogonuserauthcookie>MOCK-c2</portal-prelogonuserauthcookie>
        </response>"#;
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        let cred = Credential::Password {
            username: "alice".into(),
            password: "REDACTED-pw".into(),
        };
        let gw_cred = config.to_gateway_credential(&cred);
        match &gw_cred {
            Credential::AuthCookie {
                user_auth_cookie,
                prelogon_user_auth_cookie,
                password,
                ..
            } => {
                assert_eq!(user_auth_cookie, "MOCK-c1");
                assert_eq!(prelogon_user_auth_cookie, "MOCK-c2");
                assert_eq!(password, &None, "cookie lane stays replay-free");
            }
            other => panic!("expected AuthCookie, got {other:?}"),
        }
        let form = gw_cred.gateway_login_params(false);
        assert!(
            !form.iter().any(|(k, _)| *k == "passwd"),
            "cookie-present login must omit passwd entirely: {form:?}"
        );
        assert!(!form.iter().any(|(_, v)| v.is_empty()));
    }

    #[test]
    fn gateway_credential_forwards_prelogin_secret_when_cookieless() {
        // Issue #36 review: the SAML-paste / Okta lane yields
        // Credential::Prelogin (saml_common::SamlCapture::into_credential)
        // carrying the real gateway secret. On a cookieless portal the
        // old code coerced it to an AuthCookie with neither cookies nor a
        // replayable password — a credential-less form that reproduces
        // #36 on that lane. The prelogin secret must reach the gateway.
        let xml = r#"<response></response>"#;
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        let cred = Credential::Prelogin {
            username: "someone-else".into(),
            prelogin_cookie: Some("MOCK-prelogin".into()),
            token: None,
        };
        let gw_cred = config.to_gateway_credential(&cred);
        match &gw_cred {
            Credential::Prelogin {
                username,
                prelogin_cookie,
                token,
            } => {
                assert_eq!(username, "alice", "portal identity wins");
                assert_eq!(prelogin_cookie.as_deref(), Some("MOCK-prelogin"));
                assert_eq!(token, &None);
            }
            other => panic!("expected forwarded Credential::Prelogin, got {other:?}"),
        }
        let form = gw_cred.gateway_login_params(false);
        assert!(form
            .iter()
            .any(|(k, v)| *k == "prelogin-cookie" && v == "MOCK-prelogin"));
        assert!(!form.iter().any(|(k, _)| *k == "passwd"));
        assert!(!form.iter().any(|(_, v)| v.is_empty()), "{form:?}");

        // Prisma token lane behaves the same: token forwarded, no passwd.
        let token_cred = Credential::Prelogin {
            username: "someone-else".into(),
            prelogin_cookie: None,
            token: Some("MOCK-JWT-aaa.bbb.ccc".into()),
        };
        let gw_cred = config.to_gateway_credential(&token_cred);
        match &gw_cred {
            Credential::Prelogin { token, .. } => {
                assert_eq!(token.as_deref(), Some("MOCK-JWT-aaa.bbb.ccc"));
            }
            other => panic!("expected forwarded Credential::Prelogin, got {other:?}"),
        }
    }

    /// Issue #36 (checklist M1): PAN portals can return the literal
    /// sentinel `<portal-userauthcookie>empty</portal-userauthcookie>`.
    /// Upstream openconnect v9.21 (`auth-globalprotect.c:522-531`,
    /// pinned by .github/workflows/release.yml:188) normalizes that
    /// literal (and "") case-sensitively to NULL before deciding
    /// whether to append the cookie keys at all; we normalize to the
    /// same ABSENT marker at parse time so the cookieless
    /// password-replay lane activates instead of posting a useless
    /// `portal-userauthcookie=empty` while suppressing the password.
    #[test]
    fn sentinel_empty_cookies_count_as_absent_and_replay_activates() {
        let xml = r#"
        <response>
            <portal-userauthcookie>empty</portal-userauthcookie>
            <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
        </response>"#;
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        assert_eq!(
            config.user_auth_cookie, "",
            "literal `empty` sentinel must normalize to ABSENT (upstream parity)"
        );
        assert_eq!(
            config.prelogon_user_auth_cookie, "",
            "literal `empty` sentinel must normalize to ABSENT (upstream parity)"
        );

        // Password portal credential -> cookieless replay lane, and the
        // gateway form carries the replayed passwd with NO cookie keys.
        let cred = Credential::Password {
            username: "alice".into(),
            password: "REDACTED-pw".into(),
        };
        let gw_cred = config.to_gateway_credential(&cred);
        match &gw_cred {
            Credential::AuthCookie { password, .. } => {
                assert_eq!(
                    password.as_deref(),
                    Some("REDACTED-pw"),
                    "sentinel cookies must not suppress the password replay"
                );
            }
            other => panic!("expected AuthCookie on the replay lane, got {other:?}"),
        }
        let form = gw_cred.gateway_login_params(false);
        assert!(
            form.iter()
                .any(|(k, v)| *k == "passwd" && v == "REDACTED-pw"),
            "form must carry the replayed passwd: {form:?}"
        );
        for k in ["portal-userauthcookie", "portal-prelogonuserauthcookie"] {
            assert!(
                !form.iter().any(|(key, _)| *key == k),
                "sentinel cookie key {k} must never reach the wire: {form:?}"
            );
        }
        assert!(
            !form.iter().any(|(_, v)| v.is_empty()),
            "no present-but-empty key may reach the gateway: {form:?}"
        );

        // Surrounding whitespace must not defeat the sentinel (the XML
        // parser trims, but the contract spells trim()==); and the
        // CASE must follow upstream: the comparison is a case-sensitive
        // strcmp, so `Empty` is a real (odd) cookie value and keeps the
        // request on the cookie lane with no replay.
        let ws_xml = r#"
        <response>
            <portal-userauthcookie>  empty  </portal-userauthcookie>
            <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
        </response>"#;
        let ws = PortalConfig::parse(ws_xml, "portal.example.com", "alice").unwrap();
        assert_eq!(
            ws.user_auth_cookie, "",
            "sentinel with surrounding whitespace must normalize to ABSENT"
        );

        let case_xml = r#"
        <response>
            <portal-userauthcookie>Empty</portal-userauthcookie>
        </response>"#;
        let cased = PortalConfig::parse(case_xml, "portal.example.com", "alice").unwrap();
        assert_eq!(
            cased.user_auth_cookie, "Empty",
            "upstream normalizes only the case-sensitive literal `empty`"
        );
        let cred = Credential::Password {
            username: "alice".into(),
            password: "REDACTED-pw".into(),
        };
        match cased.to_gateway_credential(&cred) {
            Credential::AuthCookie {
                user_auth_cookie,
                password,
                ..
            } => {
                assert_eq!(user_auth_cookie, "Empty");
                assert_eq!(
                    password, None,
                    "a present (non-sentinel) cookie keeps the replay-free cookie lane"
                );
            }
            other => panic!("expected AuthCookie, got {other:?}"),
        }
    }

    #[test]
    fn fallback_gateway() {
        let xml = r#"<response></response>"#;
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].address, "portal.example.com");
    }

    /// RED today (issue #43): the portal-fallback Gateway is built
    /// from the connect-flow server string (normalized at the CLI
    /// layer, port KEPT), so a port-bearing portal must also expose
    /// split host()/port() through the shared accessors — the same
    /// [W] entry point the advertised list has.
    #[test]
    fn portal_fallback_gateway_has_split_host_port() {
        let xml = r#"<response></response>"#;
        let config = PortalConfig::parse(xml, "10.0.0.1:11443", "alice").unwrap();
        assert_eq!(config.gateways.len(), 1);
        // address stays verbatim (URL lane, #42), halves split.
        assert_eq!(config.gateways[0].address, "10.0.0.1:11443");
        assert_eq!(config.gateways[0].host(), "10.0.0.1");
        assert_eq!(config.gateways[0].port(), Some(11443));
    }

    /// CONTRACT (M4 trust surface, resweep fix): gateway addresses are
    /// only ever used to compose the login URL and the `server=` form
    /// field, so the parser gates them to the hostname[:port] charset.
    /// A hostile portal's raw-LF `<entry name="…">` (which `XmlNode`
    /// keeps verbatim — no unescape, no normalization, xml.rs:90) must
    /// be DROPPED at parse and must never reach `GpParams::login_url`,
    /// the client.rs diagnostics, or the stderr the GUI reads.
    #[test]
    fn hostile_gateway_address_with_raw_control_chars_is_dropped_at_parse() {
        let xml = "<response><gateways><external><list>
                   <entry name=\"evil.example/&#10;\n\
                   SAML-CALLBACK-URL http://127.0.0.1:9999/\n/\">
                   <description>d</description></entry>
                   </list></external></gateways></response>";
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        // The poisoned entry is gone; only the operator-supplied
        // portal fallback remains (same shape as `fallback_gateway`).
        assert_eq!(
            config.gateways.len(),
            1,
            "hostile entry must be dropped, leaving the fallback: {:?}",
            config
                .gateways
                .iter()
                .map(|g| &g.address)
                .collect::<Vec<_>>()
        );
        assert_eq!(config.gateways[0].address, "portal.example.com");
        let params = crate::params::GpParams::new(crate::ClientOs::Win);
        let url = params.login_url(&config.gateways[0].address);
        assert!(
            !url.split('\n').any(|l| l.starts_with("SAML-CALLBACK-URL")),
            "forged marker line survived into the composed URL: {url:?}"
        );
        // A well-formed port-bearing address (issue #36 ran gateways on
        // :11443) must still pass the gate untouched.
        let ok_xml = "<response><gateways><external><list>\n\
                      <entry name=\"gw.example.com:11443\">\
                      <description>ok</description></entry>\n\
                      <entry name=\"[2001:db8::1]:11443\">\
                      <description>v6</description></entry>\n\
                      </list></external></gateways></response>";
        let ok = PortalConfig::parse(ok_xml, "portal.example.com", "alice").unwrap();
        assert_eq!(
            ok.gateways.len(),
            2,
            "legit host:port and IPv6 entries kept"
        );
        assert_eq!(ok.gateways[0].address, "gw.example.com:11443");
        assert_eq!(ok.gateways[1].address, "[2001:db8::1]:11443");
    }

    // The d55869e evidence pin `known_gap_hostile_gateway_address_
    // forges_a_marker_led_line` (which asserted the raw-LF attribute
    // SURVIVED parse) is RETIRED by the address gate above, as its
    // doc demanded ("a fix must consciously retire them"): with the
    // gate it can only fail against
    // `hostile_gateway_address_with_raw_control_chars_is_dropped_at_
    // parse`, which now carries the contract.
}
