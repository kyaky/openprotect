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
/// `preferred-ipv6`), re-serialize the remainder in canonical
/// `application/x-www-form-urlencoded` form (percent-decode on
/// input, percent-encode on output), MD5-hash the result, and
/// lowercase-hex-encode it.
///
/// The round-trip through `serde_urlencoded` matters: the
/// reference client normalises percent-escapes and reserved
/// characters via this route, and the gateway validates the hash
/// against its own `serde_urlencoded`-style encoder. A raw
/// `split('&').split('=')` approach would silently diverge on
/// any cookie value containing `%`, `&`, or `=`, and the
/// resulting MD5 mismatch would be rejected by the HIP check
/// without any visible error on our side.
///
/// Note that this is MD5 and weak by any modern metric. OpenProtect
/// does not use it for authentication — the value is only
/// forwarded to the gateway as a "did the cookie change" marker.
/// We accept the legacy hash so the protocol still interoperates.
pub fn compute_csd_md5(cookie: &str) -> String {
    // Parse with serde_urlencoded so percent-escapes are decoded
    // into their literal bytes in Rust-side Strings. An unparseable
    // cookie falls back to an empty field list — the resulting
    // empty-string MD5 is harmless, and the subsequent hip check
    // request will fail loudly on the real `authcookie`-less
    // cookie anyway.
    let mut fields: Vec<(String, String)> = serde_urlencoded::from_str(cookie).unwrap_or_default();
    const DROP: [&str; 3] = ["authcookie", "preferred-ip", "preferred-ipv6"];
    fields.retain(|(k, _)| !DROP.contains(&k.as_str()));
    // Re-serialize through the same library so percent-encoding
    // matches byte-for-byte what the gateway sees.
    let serialized = serde_urlencoded::to_string(&fields).unwrap_or_default();
    let digest = md5::compute(serialized.as_bytes());
    format!("{:x}", digest)
}

/// Turn a cookie query string into `Vec<(String, String)>`
/// tuples suitable for merging into a reqwest form body. Unlike
/// [`compute_csd_md5`], this retains every field including
/// `authcookie` — the HIP endpoints want the full set.
///
/// Values are percent-decoded during parse, matching yuezk's
/// approach. `reqwest::RequestBuilder::form` will re-encode them
/// before hitting the wire, so the final request body is byte-
/// identical to what the reference client sends.
pub fn cookie_to_form_fields(cookie: &str) -> Vec<(String, String)> {
    serde_urlencoded::from_str(cookie).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_drops_authcookie_and_preferred_ip() {
        let cookie = "authcookie=ABC&portal=p.example.com&user=alice&preferred-ip=10.1.2.3";
        let md5 = compute_csd_md5(cookie);
        // Hash is taken over the serde_urlencoded-serialized
        // remainder. We compute the expected value through the
        // same round trip so the test tracks the real encoding
        // contract rather than a hand-rolled string.
        let expected_fields: Vec<(String, String)> = vec![
            ("portal".into(), "p.example.com".into()),
            ("user".into(), "alice".into()),
        ];
        let expected_serialized = serde_urlencoded::to_string(&expected_fields).unwrap();
        let expected = format!("{:x}", md5::compute(expected_serialized.as_bytes()));
        assert_eq!(md5, expected);
    }

    #[test]
    fn md5_drops_preferred_ipv6() {
        // The preferred-ipv6 value is percent-encoded. After the
        // round trip, the remainder should only be `user=u`, and
        // the MD5 should match the round-trip encoding of that.
        let cookie = "authcookie=X&user=u&preferred-ipv6=%3A%3A1";
        let md5 = compute_csd_md5(cookie);
        let expected_serialized = serde_urlencoded::to_string([("user", "u")]).unwrap();
        let expected = format!("{:x}", md5::compute(expected_serialized.as_bytes()));
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
    fn md5_canonicalizes_percent_escapes() {
        // Two logically identical cookies that differ only in
        // whether a value was percent-encoded on input. After
        // round-tripping through serde_urlencoded, both should
        // produce the same MD5 — this is the failure mode the
        // raw-split implementation would miss.
        let decoded_cookie = "authcookie=Z&user=a b";
        let encoded_cookie = "authcookie=Z&user=a%20b";
        // Note: the `+` form is also valid url-encoded whitespace
        // and commonly appears. Include it too.
        let plus_cookie = "authcookie=Z&user=a+b";
        let m1 = compute_csd_md5(decoded_cookie);
        let m2 = compute_csd_md5(encoded_cookie);
        let m3 = compute_csd_md5(plus_cookie);
        assert_eq!(m1, m2, "decoded vs %-encoded diverged");
        assert_eq!(m1, m3, "decoded vs +-encoded diverged");
    }

    #[test]
    fn md5_handles_reserved_chars_via_encoding() {
        // A cookie value containing a literal `=` or `&` must be
        // percent-encoded on the wire. If someone built such a
        // cookie and fed it to us as already-encoded, we should
        // decode it on parse and re-encode it on serialize, so
        // the MD5 matches what the gateway would compute.
        let cookie = "authcookie=X&user=a%3Db"; // user = "a=b"
        let md5 = compute_csd_md5(cookie);
        let expected = format!(
            "{:x}",
            md5::compute(
                serde_urlencoded::to_string([("user", "a=b")])
                    .unwrap()
                    .as_bytes()
            )
        );
        assert_eq!(md5, expected);
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
    fn cookie_to_form_fields_percent_decodes_values() {
        // `%20` should round-trip into a Rust-side " " so that
        // reqwest's form encoder re-encodes it canonically on
        // the wire.
        let cookie = "user=alice+smith&email=foo%40example.com";
        let fields = cookie_to_form_fields(cookie);
        assert_eq!(fields.len(), 2);
        // serde_urlencoded decodes `+` as ' ' per form-url spec.
        assert_eq!(fields[0].1, "alice smith");
        assert_eq!(fields[1].1, "foo@example.com");
    }
}
