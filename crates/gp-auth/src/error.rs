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

    #[error("MFA not completed after {0} attempts")]
    MfaExhausted(u32),

    #[error("user cancelled")]
    Cancelled,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
