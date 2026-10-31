//! Shared types and helpers used by every SAML auth provider
//! (`saml_paste` today, the macOS `saml_webview` provider alongside
//! it). Historically this module also fed an embedded GTK+WebKit
//! provider (`saml_webview`) that was removed when openprotect
//! standardised on headless auth; the name returned with a
//! different kernel — a wry/WKWebView window that auto-captures
//! the gateway's `globalprotectcallback:` anchor.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use gp_proto::prelogin::SamlPrelogin;
use gp_proto::Credential;

use crate::error::AuthError;

/// What the SAML launch step hands to a browser or an embedded
/// webview: the IdP URL for REDIRECT binds, the auto-submit form HTML
/// for POST binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlLaunch {
    /// `saml-auth-method = "REDIRECT"`: the decoded, percent-encoded
    /// IdP URL.
    Redirect(String),
    /// `saml-auth-method = "POST"`: the decoded auto-submit form HTML
    /// (raw bytes — a portal may declare a legacy charset; converting
    /// through UTF-8 here would mangle hidden field values).
    Post(Vec<u8>),
}

/// Decode a prelogin SAML response into its launch content.
///
/// Both bind shapes base64-encode the payload in `saml-request`:
/// REDIRECT carries the IdP URL, POST the whole auto-submit form.
/// Callers render it however their transport needs — the paste flow
/// wraps the REDIRECT URL in a meta-refresh page and serves the POST
/// form verbatim from its loopback server; an embedded webview
/// navigates to the URL or loads the form HTML directly.
pub fn saml_launch(saml: &SamlPrelogin) -> Result<SamlLaunch, AuthError> {
    match saml.saml_auth_method.as_str() {
        "REDIRECT" => {
            let decoded = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            let url = String::from_utf8(decoded).map_err(|e| {
                AuthError::Failed(format!("saml-request redirect URL is not valid utf-8: {e}"))
            })?;
            Ok(SamlLaunch::Redirect(url))
        }
        "POST" => {
            let decoded = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            Ok(SamlLaunch::Post(decoded))
        }
        other => Err(AuthError::Failed(format!(
            "unknown saml-auth-method: {other}"
        ))),
    }
}

/// Data we extract from a completed SAML flow, regardless of transport.
///
/// `prelogin_cookie` here is the raw captured string — it may be a classic
/// on-prem GP prelogin cookie OR a Prisma Access JWT. The provider decides
/// which one it is via [`looks_like_jwt`] before building the final
/// [`Credential`].
#[derive(Debug, Clone)]
pub struct SamlCapture {
    pub username: String,
    pub prelogin_cookie: String,
    pub portal_user_auth_cookie: Option<String>,
}

impl SamlCapture {
    /// Build a [`Credential::Prelogin`] from this capture, routing the
    /// secret into either the `token` field (JWT — Prisma Access) or
    /// `prelogin_cookie` field (classic GP).
    pub fn into_credential(self) -> Credential {
        let (prelogin_cookie, token) = if looks_like_jwt(&self.prelogin_cookie) {
            (None, Some(self.prelogin_cookie))
        } else {
            (Some(self.prelogin_cookie), None)
        };
        Credential::Prelogin {
            username: self.username,
            prelogin_cookie,
            token,
        }
    }
}

/// Heuristic: three non-empty base64-url segments separated by `.`.
pub fn looks_like_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
        })
}

/// Parse a Prisma Access `globalprotectcallback:` URI into a [`SamlCapture`].
///
/// Format: `globalprotectcallback:cas-as=1&un=<user>&token=<JWT>` — not a
/// standard URL (no `//`), so we split the scheme prefix and parse the
/// remainder as application/x-www-form-urlencoded.
///
/// Both modern (`un` / `token`) and slightly older (`user` /
/// `prelogin-cookie`) field name variants are recognized. The classic
/// on-prem callback form `globalprotectcallback:<base64-blob>` is also
/// recognized by base64-decoding the payload and extracting
/// `<saml-username>` / `<prelogin-cookie>` tags from the embedded HTML.
pub fn parse_globalprotect_callback(uri: &str) -> Option<SamlCapture> {
    let rest = uri.strip_prefix("globalprotectcallback:")?;
    let rest = rest.trim();
    let rest = rest.strip_prefix('?').unwrap_or(rest).trim();

    parse_query_callback(rest).or_else(|| parse_classic_cookie_callback(rest))
}

fn parse_query_callback(rest: &str) -> Option<SamlCapture> {
    let mut username: Option<String> = None;
    let mut secret: Option<String> = None;
    let mut portal_user_auth_cookie: Option<String> = None;

    for pair in rest.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = percent_decode(v);
        match k {
            "un" | "user" => username = Some(v),
            "token" | "prelogin-cookie" => secret = Some(v),
            "portal-userauthcookie" => portal_user_auth_cookie = Some(v),
            _ => {}
        }
    }

    Some(SamlCapture {
        username: username?,
        prelogin_cookie: secret?,
        portal_user_auth_cookie,
    })
}

fn parse_classic_cookie_callback(rest: &str) -> Option<SamlCapture> {
    let decoded = BASE64.decode(rest.as_bytes()).ok()?;
    let decoded = String::from_utf8_lossy(&decoded);

    Some(SamlCapture {
        username: extract_tag_text(&decoded, "saml-username")?,
        prelogin_cookie: extract_tag_text(&decoded, "prelogin-cookie")?,
        portal_user_auth_cookie: extract_tag_text(&decoded, "portal-userauthcookie"),
    })
}

fn extract_tag_text(doc: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = doc.find(&open)? + open.len();
    let end = doc[start..].find(&close)? + start;
    Some(doc[start..end].trim().to_string())
}

/// Minimal application/x-www-form-urlencoded decoder. Handles `%XX` and `+`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prisma_access_callback() {
        let uri = "globalprotectcallback:cas-as=1&un=alice%40example.com&token=aaa.bbb.ccc";
        let cap = parse_globalprotect_callback(uri).unwrap();
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "aaa.bbb.ccc");
    }

    #[test]
    fn parse_classic_base64_callback() {
        // Synthetic. The blob this fixture replaced was lifted from a
        // public upstream bug report and still carried that reporter's
        // real (long-expired) prelogin-cookie next to a hand-blanked
        // username — a partial redaction is not a redaction. Shape and
        // element order are preserved exactly; only the values are
        // placeholders.
        let uri = concat!(
            "globalprotectcallback:",
            "PGh0bWw+PCEtLSA8c2FtbC1hdXRoLXN0YXR1cz4xPC9zYW1sLWF1dGgtc3RhdHVzPjxwcmVsb2dpbi1jb29raWU+",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            "QUFBQT09PC9wcmVsb2dpbi1jb29raWU+PHNhbWwtdXNlcm5hbWU+YWxpY2VAZXhhbXBsZS5jb208L3NhbWwtdXNl",
            "cm5hbWU+PHNhbWwtc2xvPm5vPC9zYW1sLXNsbz48c2FtbC1TZXNzaW9uTm90T25PckFmdGVyPjwvc2FtbC1TZXNz",
            "aW9uTm90T25PckFmdGVyPiAtLT48L2h0bWw+"
        );
        let cap = parse_globalprotect_callback(uri).unwrap();
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(
            cap.prelogin_cookie,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        );
    }

    #[test]
    fn jwt_detection() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(looks_like_jwt("eyJ0eXAi.eyJzdWIi.sig_value"));
        assert!(!looks_like_jwt("just-a-random-cookie"));
        assert!(!looks_like_jwt("aaa.bbb"));
        assert!(!looks_like_jwt(""));
    }
}

#[cfg(test)]
mod saml_launch_tests {
    use super::*;

    fn prelogin(method: &str, request: &str) -> SamlPrelogin {
        SamlPrelogin {
            region: String::new(),
            saml_auth_method: method.into(),
            saml_request: request.into(),
            saml_request_timeout_secs: 60,
        }
    }

    #[test]
    fn redirect_launch_decodes_to_the_idp_url() {
        use base64::Engine as _;
        let encoded = BASE64.encode("https://idp.example.com/sso?RelayState=abc");
        let launch = saml_launch(&prelogin("REDIRECT", &encoded)).unwrap();
        assert_eq!(
            launch,
            SamlLaunch::Redirect("https://idp.example.com/sso?RelayState=abc".into())
        );
    }

    #[test]
    fn post_launch_decodes_to_the_form_html() {
        use base64::Engine as _;
        let form = "<form method=\"POST\" action=\"https://sp.example.com/ACS\"></form>";
        let encoded = BASE64.encode(form.as_bytes());
        let launch = saml_launch(&prelogin("POST", &encoded)).unwrap();
        assert_eq!(launch, SamlLaunch::Post(form.as_bytes().to_vec()));
    }

    #[test]
    fn unknown_method_is_rejected() {
        assert!(saml_launch(&prelogin("WEIRD", "x")).is_err());
    }
}
