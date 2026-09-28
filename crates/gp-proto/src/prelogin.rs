//! Prelogin response parsing.
//!
//! The prelogin endpoint (`prelogin.esp`) tells the client what authentication
//! method the portal or gateway expects (password vs SAML).

use crate::error::ProtoError;
use crate::xml::XmlNode;

/// Parsed prelogin response from a portal or gateway.
#[derive(Debug, Clone)]
pub enum PreloginResponse {
    /// Standard username + password authentication.
    Standard(StandardPrelogin),
    /// SAML-based authentication (browser redirect or POST).
    Saml(SamlPrelogin),
}

/// Fields for standard (password) authentication.
#[derive(Debug, Clone)]
pub struct StandardPrelogin {
    pub region: String,
    pub auth_message: String,
    pub label_username: String,
    pub label_password: String,
}

/// Default for `<saml-request-timeout>` when the gateway omits the
/// element (or sends an unparseable value). Matches the value the
/// GlobalProtect gateways in this deployment serve by default; the
/// paste provider (`gp-auth::saml_paste`) uses it as the overall
/// ceiling on the human wait so a stalled browser step can no longer
/// wedge `opc connect` forever.
pub const DEFAULT_SAML_REQUEST_TIMEOUT_SECS: u64 = 600;

/// Fields for SAML authentication.
#[derive(Debug, Clone)]
pub struct SamlPrelogin {
    pub region: String,
    /// `"POST"` or `"REDIRECT"`.
    pub saml_auth_method: String,
    /// Base64-encoded SAML request body or redirect URL.
    pub saml_request: String,
    /// Seconds the gateway is willing to keep a SAML request alive,
    /// from `<saml-request-timeout>`. Surfaced so the paste provider
    /// can bound its wait on the operator's browser round-trip; the
    /// gateway itself never accepted a callback after this window
    /// anyway, so waiting longer is guaranteed failure.
    ///
    /// [`DEFAULT_SAML_REQUEST_TIMEOUT_SECS`] when the element is
    /// absent or its text is not a sane positive integer.
    pub saml_request_timeout_secs: u64,
}

impl PreloginResponse {
    /// Parse from the XML body returned by `prelogin.esp`.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;

        // Check status
        let status = root.child_text("status").unwrap_or("Success");
        if !status.eq_ignore_ascii_case("success") {
            return Err(ProtoError::UnexpectedStatus(status.to_string()));
        }

        let region = root.child_text("region").unwrap_or("Unknown").to_string();

        // SAML auth?
        if let Some(method) = root.child_text("saml-auth-method") {
            let request = root
                .child_text("saml-request")
                .ok_or(ProtoError::MissingField {
                    field: "saml-request",
                    context: "SAML prelogin response",
                })?
                .to_string();

            // `<saml-request-timeout>` was previously parsed away and
            // discarded — the gateway advertises e.g. 600 there and the
            // client must honour it as the ceiling on the paste wait
            // (a callback the gateway has already expired can never be
            // accepted, so waiting past it is guaranteed failure).
            // A missing / non-numeric / out-of-sane-range value falls
            // back to the documented default instead of erroring the
            // whole prelogin for an optional field.
            let saml_request_timeout_secs = root
                .child_text("saml-request-timeout")
                .and_then(|t| t.trim().parse::<u64>().ok())
                .filter(|n| (1..=86_400).contains(n))
                .unwrap_or(DEFAULT_SAML_REQUEST_TIMEOUT_SECS);

            return Ok(Self::Saml(SamlPrelogin {
                region,
                saml_auth_method: method.to_string(),
                saml_request: request,
                saml_request_timeout_secs,
            }));
        }

        // Standard (password) auth
        Ok(Self::Standard(StandardPrelogin {
            region,
            auth_message: root
                .child_text("authentication-message")
                .unwrap_or("Enter login credentials")
                .to_string(),
            label_username: root
                .child_text("username-label")
                .unwrap_or("Username")
                .to_string(),
            label_password: root
                .child_text("password-label")
                .unwrap_or("Password")
                .to_string(),
        }))
    }

    /// Server region string.
    pub fn region(&self) -> &str {
        match self {
            Self::Standard(s) => &s.region,
            Self::Saml(s) => &s.region,
        }
    }

    /// Whether the server requires SAML authentication.
    pub fn is_saml(&self) -> bool {
        matches!(self, Self::Saml(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard() {
        let xml = r#"
        <prelogin-response>
            <status>Success</status>
            <region>Americas</region>
            <authentication-message>Sign in</authentication-message>
            <username-label>Email</username-label>
            <password-label>Secret</password-label>
        </prelogin-response>"#;

        let resp = PreloginResponse::parse(xml).unwrap();
        assert!(!resp.is_saml());
        assert_eq!(resp.region(), "Americas");

        if let PreloginResponse::Standard(s) = &resp {
            assert_eq!(s.auth_message, "Sign in");
            assert_eq!(s.label_username, "Email");
            assert_eq!(s.label_password, "Secret");
        } else {
            panic!("expected Standard");
        }
    }

    #[test]
    fn parse_saml() {
        let xml = r#"
        <prelogin-response>
            <status>Success</status>
            <region>EMEA</region>
            <saml-auth-method>REDIRECT</saml-auth-method>
            <saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20=</saml-request>
        </prelogin-response>"#;

        let resp = PreloginResponse::parse(xml).unwrap();
        assert!(resp.is_saml());

        if let PreloginResponse::Saml(s) = &resp {
            assert_eq!(s.saml_auth_method, "REDIRECT");
            assert_eq!(s.saml_request, "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20=");
        } else {
            panic!("expected Saml");
        }
    }

    #[test]
    fn parse_error_status() {
        let xml = r#"<prelogin-response><status>Error</status></prelogin-response>"#;
        assert!(PreloginResponse::parse(xml).is_err());
    }

    /// `<saml-request-timeout>` must reach the caller instead of being
    /// parsed away and discarded. The live gateways here serve `600`;
    /// the paste provider bounds the human wait with this value, so a
    /// gateway that advertises a different ceiling must be honoured
    /// and a stalled browser step must stop wedging `opc connect`.
    #[test]
    fn parse_saml_surfaces_saml_request_timeout() {
        let xml = r#"
        <prelogin-response>
            <status>Success</status>
            <region>EMEA</region>
            <saml-auth-method>REDIRECT</saml-auth-method>
            <saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20=</saml-request>
            <saml-request-timeout>123</saml-request-timeout>
        </prelogin-response>"#;

        match PreloginResponse::parse(xml).unwrap() {
            PreloginResponse::Saml(s) => assert_eq!(
                s.saml_request_timeout_secs, 123,
                "<saml-request-timeout>123</saml-request-timeout> must surface as 123, not the default"
            ),
            other => panic!("expected Saml, got {other:?}"),
        }
    }

    /// Absent, unparseable, zero, and out-of-range timeout values all
    /// fall back to the documented default instead of poisoning the
    /// prelogin (a malformed optional element must never break auth).
    #[test]
    fn parse_saml_request_timeout_falls_back_to_default() {
        let cases: &[(&str, u64, &str)] = &[
            // (element text — empty string means element absent, expected, why)
            ("", DEFAULT_SAML_REQUEST_TIMEOUT_SECS, "element absent"),
            ("600", 600, "gateway-served default"),
            ("1", 1, "sanity floor"),
            (" 45 ", 45, "surrounding whitespace tolerated"),
            (
                "0",
                DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
                "zero would insta-timeout",
            ),
            (
                "abc",
                DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
                "non-numeric must not error the prelogin",
            ),
            (
                "-5",
                DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
                "negative rejected by u64 parse",
            ),
            (
                "99999999999999999999999999",
                DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
                "u64 overflow rejected",
            ),
            ("86400", 86_400, "sane ceiling (24h) accepted"),
            (
                "90000",
                DEFAULT_SAML_REQUEST_TIMEOUT_SECS,
                "beyond sane ceiling falls back",
            ),
        ];
        for (text, expected, why) in cases {
            let element = if text.is_empty() {
                String::new()
            } else {
                format!("<saml-request-timeout>{text}</saml-request-timeout>")
            };
            let xml = format!(
                r#"<prelogin-response>
                       <status>Success</status>
                       <region>R</region>
                       <saml-auth-method>POST</saml-auth-method>
                       <saml-request>aGk=</saml-request>
                       {element}
                   </prelogin-response>"#
            );
            let parsed = PreloginResponse::parse(&xml)
                .unwrap_or_else(|e| panic!("prelogin parse failed for {element:?}: {e}"));
            let PreloginResponse::Saml(s) = parsed else {
                panic!("expected Saml for {element:?}");
            };
            assert_eq!(
                s.saml_request_timeout_secs, *expected,
                "case {why:?}: text {text:?} should give {expected}"
            );
        }
    }
}
