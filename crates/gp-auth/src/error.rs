//! Authentication error types.

use thiserror::Error;

/// Errors that can occur during authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("protocol error: {0}")]
    Proto(#[from] gp_proto::ProtoError),

    #[error("SAML authentication required but not supported in this build")]
    SamlRequired,

    #[error("authentication failed: {0}")]
    Failed(String),

    /// A portal/gateway HTTP reject that carries **no auth-engine
    /// value**: no `X-Private-Pan-Sslvpn(-Extension)` header value
    /// naming a PAN reject class and no body verdict sentence (issue
    /// #36 review, checklist M2 — classification is by discriminator
    /// VALUE, so a bare 4xx lands here too). This is an infrastructure
    /// condition — maintenance, a proxy error, a 404/408/429 — not a
    /// credential problem, so it keeps the classification the legacy
    /// `.error_for_status()?` gave such responses via
    /// [`AuthError::Http`] (opc maps it to `GATEWAY_UNREACHABLE`, exit
    /// 3), while the message still carries the full diagnostics.
    #[error("{0}")]
    Server(String),

    #[error("MFA not completed after {0} attempts")]
    MfaExhausted(u32),

    #[error("user cancelled")]
    Cancelled,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
