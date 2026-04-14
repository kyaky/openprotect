//! Parser for `/ssl-vpn/hipreportcheck.esp` responses.
//!
//! The gateway replies with a small XML document like:
//!
//! ```xml
//! <response status="success">
//!   <hip-report-needed>yes</hip-report-needed>
//! </response>
//! ```
//!
//! The only field that drives client behaviour is
//! `<hip-report-needed>`. Values `"yes"` and `"no"` are common; we
//! treat anything else as "not needed" to avoid false positives.

use crate::error::ProtoError;
use crate::xml::XmlNode;

/// Distilled hipreportcheck response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HipCheckResponse {
    /// `true` iff the gateway wants us to POST a full HIP report.
    pub needed: bool,
}

impl HipCheckResponse {
    /// Parse a gateway `hipreportcheck.esp` XML response.
    ///
    /// Returns `ProtoError::MissingField` only when the document
    /// has no `<hip-report-needed>` element at all. A malformed
    /// or unrecognized value is treated as "not needed" — the
    /// safer default on an unknown signal is to keep going without
    /// a report rather than block the connection.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;
        let value = root
            .find_text("hip-report-needed")
            .ok_or(ProtoError::MissingField {
                field: "hip-report-needed",
                context: "hipreportcheck.esp response",
            })?;
        Ok(Self {
            needed: value.eq_ignore_ascii_case("yes"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_needed_yes() {
        let xml = r#"<response><hip-report-needed>yes</hip-report-needed></response>"#;
        assert_eq!(HipCheckResponse::parse(xml).unwrap(), HipCheckResponse { needed: true });
    }

    #[test]
    fn parse_needed_no() {
        let xml = r#"<response><hip-report-needed>no</hip-report-needed></response>"#;
        assert_eq!(HipCheckResponse::parse(xml).unwrap(), HipCheckResponse { needed: false });
    }

    #[test]
    fn parse_case_insensitive() {
        let xml = r#"<response><hip-report-needed>YES</hip-report-needed></response>"#;
        assert!(HipCheckResponse::parse(xml).unwrap().needed);
    }

    #[test]
    fn parse_unrecognized_value_treated_as_not_needed() {
        let xml = r#"<response><hip-report-needed>maybe</hip-report-needed></response>"#;
        assert!(!HipCheckResponse::parse(xml).unwrap().needed);
    }

    #[test]
    fn parse_missing_field_is_error() {
        let xml = r#"<response status="success"/>"#;
        let err = HipCheckResponse::parse(xml).unwrap_err();
        match err {
            ProtoError::MissingField { field, .. } => assert_eq!(field, "hip-report-needed"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
