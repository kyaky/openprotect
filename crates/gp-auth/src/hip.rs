//! HIP (Host Information Profile) HTTP flow helpers.
//!
//! GlobalProtect gateways can require a host-integrity check before
//! letting traffic flow. The protocol is:
//!
//! 1. Client computes a "csd md5" from the authcookie string. The
//!    gateway uses this to decide whether a fresh report is needed.
//! 2. Client POSTs `/ssl-vpn/hipreportcheck.esp` with the md5. The
//!    gateway replies `<hip-report-needed>yes|no</hip-report-needed>`.
//! 3. If yes, the client builds a full HIP XML document and POSTs
//!    it to `/ssl-vpn/hipreport.esp`.
//!
//! The XML *document* itself is built by `gp-hip`. This module only
//! provides the md5 helper and the field-name contract — the HTTP
//! calls live in [`crate::client::GpClient`] because they share the
//! same reqwest client and authcookie-as-form-fields convention as
//! the rest of the GP endpoints.

/// Compute the MD5 `csd` token that
/// [`crate::client::GpClient::hip_report_check`] sends as the `md5`
/// form field.
///
/// The GP convention (verified against yuezk's reference client)
/// is: take the cookie query string the caller already built for
/// libopenconnect, drop the three fields that libopenconnect
/// treats as session-local (`authcookie`, `preferred-ip`,
/// `preferred-ipv6`), re-serialize the remainder in the same
/// `key=value&key=value` form, MD5-hash the result, and
/// lowercase-hex-encode it.
///
/// Note that this is MD5 and weak by any modern metric. Pangolin
/// does not use it for authentication — the value is only
/// forwarded to the gateway as a "did the cookie change" marker.
/// We accept the legacy hash so the protocol still interoperates.
pub fn compute_csd_md5(cookie: &str) -> String {
    let filtered = filter_cookie_fields(cookie);
    let serialized = serialize_cookie_fields(&filtered);
    let digest = md5::compute(serialized.as_bytes());
    format!("{:x}", digest)
}

/// Parse an ampersand-separated `key=value` cookie string into
/// owned tuples, dropping the three entries that must not
/// participate in the MD5.
fn filter_cookie_fields(cookie: &str) -> Vec<(String, String)> {
    const DROP: [&str; 3] = ["authcookie", "preferred-ip", "preferred-ipv6"];
    cookie
        .split('&')
        .filter_map(|entry| entry.split_once('='))
        .filter(|(k, _)| !DROP.contains(k))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn serialize_cookie_fields(fields: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Turn a cookie query string into `Vec<(&str, String)>` tuples
/// suitable for merging into a reqwest form body. Unlike
/// [`filter_cookie_fields`], this retains every field including
/// `authcookie` — the HIP endpoints want the full set.
pub fn cookie_to_form_fields(cookie: &str) -> Vec<(String, String)> {
    cookie
        .split('&')
        .filter_map(|entry| entry.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_drops_authcookie_and_preferred_ip() {
        let cookie = "authcookie=ABC&portal=p.example.com&user=alice&preferred-ip=10.1.2.3";
        let md5 = compute_csd_md5(cookie);
        // Expected hash of the serialized remainder
        // "portal=p.example.com&user=alice".
        let expected = format!("{:x}", md5::compute("portal=p.example.com&user=alice"));
        assert_eq!(md5, expected);
    }

    #[test]
    fn md5_drops_preferred_ipv6() {
        let cookie = "authcookie=X&user=u&preferred-ipv6=%3A%3A1";
        let md5 = compute_csd_md5(cookie);
        let expected = format!("{:x}", md5::compute("user=u"));
        assert_eq!(md5, expected);
    }

    #[test]
    fn md5_empty_cookie_yields_md5_of_empty() {
        let md5 = compute_csd_md5("");
        let expected = format!("{:x}", md5::compute(""));
        assert_eq!(md5, expected);
        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn filter_preserves_order() {
        let cookie = "portal=p&authcookie=X&user=u&domain=D&preferred-ip=1.2.3.4&computer=C";
        let fields = filter_cookie_fields(cookie);
        assert_eq!(
            fields,
            vec![
                ("portal".to_string(), "p".to_string()),
                ("user".to_string(), "u".to_string()),
                ("domain".to_string(), "D".to_string()),
                ("computer".to_string(), "C".to_string()),
            ]
        );
    }

    #[test]
    fn cookie_to_form_fields_retains_all() {
        let cookie = "authcookie=X&user=alice&portal=p.example.com";
        let fields = cookie_to_form_fields(cookie);
        assert_eq!(fields.len(), 3);
        assert!(fields.iter().any(|(k, _)| k == "authcookie"));
        assert!(fields.iter().any(|(k, _)| k == "user"));
        assert!(fields.iter().any(|(k, _)| k == "portal"));
    }

    #[test]
    fn cookie_to_form_fields_ignores_malformed_entries() {
        // "garbage" has no '=' so it's dropped silently — matches
        // yuezk / serde_urlencoded behaviour.
        let cookie = "authcookie=X&garbage&user=u";
        let fields = cookie_to_form_fields(cookie);
        assert_eq!(fields.len(), 2);
    }
}
