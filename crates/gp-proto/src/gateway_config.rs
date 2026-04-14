//! Parser for the response of a direct `/ssl-vpn/getconfig.esp` POST
//! against a gateway.
//!
//! libopenconnect calls `getconfig.esp` itself during its internal
//! CSTP setup path, but we also call it once from the Rust side
//! **before** `make_cstp_connection` runs so that we can read the
//! server-assigned client IP. The HIP flow needs that IP in the
//! `client-ip` form field of the subsequent `hipreportcheck.esp`
//! and `hipreport.esp` POSTs, and trying to read it out of
//! libopenconnect's internal state would require a second round
//! of channel plumbing between the tunnel thread and the async
//! main thread.
//!
//! This module does NOT replace the full `TunnelConfig` parser —
//! it just extracts the one field we need for HIP. If a future
//! commit needs more fields, extend [`GatewayConfig`] rather than
//! creating a parallel parser.

use crate::error::ProtoError;
use crate::xml::XmlNode;

/// Just the slice of a gateway `getconfig.esp` response we care
/// about for the HIP flow.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// The IPv4 address the gateway assigned to the client. Used
    /// verbatim as the `client-ip` form field in `hipreportcheck.esp`
    /// and `hipreport.esp` submissions.
    pub client_ipv4: String,
}

impl GatewayConfig {
    /// Parse a gateway `getconfig.esp` XML response. Looks for a
    /// top-level `<ip-address>` element; errors out with
    /// `ProtoError::MissingField` if it's missing.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;
        let ip = root
            .find_text("ip-address")
            .ok_or(ProtoError::MissingField {
                field: "ip-address",
                context: "gateway getconfig.esp response",
            })?
            .to_string();
        Ok(Self { client_ipv4: ip })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_client_ip() {
        let xml = r#"
        <response>
            <ip-address>10.1.2.3</ip-address>
            <netmask>255.255.255.255</netmask>
            <mtu>1422</mtu>
        </response>"#;
        let cfg = GatewayConfig::parse(xml).unwrap();
        assert_eq!(cfg.client_ipv4, "10.1.2.3");
    }

    #[test]
    fn parse_rejects_missing_ip() {
        let xml = r#"<response><mtu>1422</mtu></response>"#;
        let err = GatewayConfig::parse(xml).unwrap_err();
        match err {
            ProtoError::MissingField { field, .. } => assert_eq!(field, "ip-address"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_finds_deep_ip() {
        // Some gateway responses wrap the ip-address in a
        // <network-info> or similar container. find_text walks
        // the whole tree.
        let xml = r#"
        <response>
            <network-info>
                <interfaces>
                    <ip-address>172.16.0.42</ip-address>
                </interfaces>
            </network-info>
        </response>"#;
        let cfg = GatewayConfig::parse(xml).unwrap();
        assert_eq!(cfg.client_ipv4, "172.16.0.42");
    }
}
