//! Shared types and helpers used by every SAML auth provider
//! (`saml_paste` today, any future headless variant tomorrow).
//!
//! Historically this module also fed an embedded GTK+WebKit
//! provider (`saml_webview`). That provider was removed when
//! pangolin standardised on headless auth — see
//! `SamlAuthMode::Paste` and `SamlAuthMode::Okta` — so only the
//! paste/IdP-callback helpers still live here.

use gp_proto::Credential;

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
/// `globalprotectcallback:<base64-blob>` (no `&`-separated query) is
/// **not** currently supported — if you hit one, file an issue with a
/// scrubbed sample of the URI.
pub fn parse_globalprotect_callback(uri: &str) -> Option<SamlCapture> {
    let rest = uri.strip_prefix("globalprotectcallback:")?;
    let rest = rest.strip_prefix('?').unwrap_or(rest);

    let mut username: Option<String> = None;
    let mut secret: Option<String> = None;

    for pair in rest.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = percent_decode(v);
        match k {
            "un" | "user" => username = Some(v),
            "token" | "prelogin-cookie" => secret = Some(v),
            _ => {}
        }
    }

    Some(SamlCapture {
        username: username?,
        prelogin_cookie: secret?,
        portal_user_auth_cookie: None,
    })
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
    fn jwt_detection() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(looks_like_jwt("eyJ0eXAi.eyJzdWIi.sig_value"));
        assert!(!looks_like_jwt("just-a-random-cookie"));
        assert!(!looks_like_jwt("aaa.bbb"));
        assert!(!looks_like_jwt(""));
    }
}
