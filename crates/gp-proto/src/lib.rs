//! GlobalProtect protocol types and XML parsing.
//!
//! This crate contains pure data types and (de)serialization logic for the
//! GlobalProtect SSL-VPN API. It performs no I/O.

pub mod client_os;
pub mod credential;
pub mod error;
pub mod gateway;
pub mod gateway_config;
pub mod hip_check;
pub mod params;
pub mod portal;
pub mod prelogin;
pub mod tunnel;
pub mod xml;

pub use client_os::ClientOs;
pub use credential::{AuthCookie, Credential};
pub use error::ProtoError;
pub use gateway::{Gateway, GatewayLoginResult};
pub use gateway_config::GatewayConfig;
pub use hip_check::HipCheckResponse;
pub use params::GpParams;
pub use portal::PortalConfig;
pub use prelogin::PreloginResponse;
pub use tunnel::TunnelConfig;
