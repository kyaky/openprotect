//! Authentication engine for GlobalProtect.
//!
//! Provides the [`AuthProvider`] plugin trait and concrete implementations
//! (password, SAML, Okta, certificate).

pub mod client;
pub mod context;
pub mod error;
pub mod hip;
pub mod okta;
pub mod password;
pub mod saml_common;
pub mod saml_paste;
#[cfg(feature = "saml-webview")]
pub mod saml_webview;

pub use client::GpClient;
pub use context::AuthContext;
pub use error::AuthError;
pub use okta::{OktaAuthConfig, OktaAuthProvider};
pub use password::PasswordAuthProvider;
pub use saml_paste::SamlPasteAuthProvider;
#[cfg(feature = "saml-webview")]
pub use saml_webview::SamlBrowserAuthProvider;

use async_trait::async_trait;
use gp_proto::{Credential, PreloginResponse};

/// Trait implemented by each authentication method.
///
/// Providers are selected based on the prelogin response and return a
/// [`Credential`] that can be used for portal config retrieval or
/// gateway login.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Human-readable name (e.g. `"password"`, `"saml-browser"`).
    fn name(&self) -> &str;

    /// Whether this provider can handle the given prelogin response.
    fn can_handle(&self, prelogin: &PreloginResponse) -> bool;

    /// Run the authentication flow and return credentials.
    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        ctx: &AuthContext,
    ) -> Result<Credential, AuthError>;
}
