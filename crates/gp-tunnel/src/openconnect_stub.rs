//! Stub implementation of the openconnect wrapper for non-Unix platforms.
//!
//! All constructors return an error. The types compile so downstream
//! code can reference them behind runtime gates without platform `cfg`.

use crate::TunnelError;

pub struct CancelHandle {
    _private: (),
}

impl CancelHandle {
    pub fn cancel(&self) -> Result<(), TunnelError> {
        Err(not_available())
    }
}

unsafe impl Send for CancelHandle {}
unsafe impl Sync for CancelHandle {}

pub struct OpenConnectSession {
    _private: (),
}

impl OpenConnectSession {
    pub fn new(_useragent: &str) -> Result<Self, TunnelError> {
        Err(not_available())
    }

    pub fn cancel_handle(&mut self) -> Option<CancelHandle> {
        None
    }

    pub fn set_protocol_gp(&mut self) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn set_hostname(&mut self, _hostname: &str) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn parse_url(&mut self, _url: &str) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn set_cookie(&mut self, _cookie: &str) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn set_client_cert(&mut self, _cert: &str, _key: &str) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn set_os_spoof(&mut self, _os: &str) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn setup_csd(
        &mut self,
        _uid: u32,
        _silent: bool,
        _wrapper_path: &str,
    ) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn make_cstp_connection(&mut self) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn setup_esp(&mut self, _attempt_period_secs: i32) -> i32 {
        -1
    }

    pub fn disable_esp(&mut self) {}

    pub fn setup_tun_device(&mut self, _vpnc_script: Option<&str>) -> Result<(), TunnelError> {
        Err(not_available())
    }

    pub fn get_ifname(&self) -> Option<String> {
        None
    }

    pub fn get_ip_info(&self) -> Result<IpInfoSnapshot, TunnelError> {
        Err(not_available())
    }

    pub fn run(
        &mut self,
        _reconnect_timeout: i32,
        _reconnect_interval: i32,
    ) -> Result<(), TunnelError> {
        Err(not_available())
    }
}

/// Stub build (`OPENCONNECT_DIR` unset): same `SessionHandle`
/// surface as the real wrapper so the generic tunnel-setup seam
/// (and the issue #43 recording-double tests) compile and run in
/// every build; every call reports not-available, as before.
impl crate::SessionHandle for OpenConnectSession {
    fn set_protocol_gp(&mut self) -> Result<(), TunnelError> {
        Self::set_protocol_gp(self)
    }
    fn set_hostname(&mut self, hostname: &str) -> Result<(), TunnelError> {
        Self::set_hostname(self, hostname)
    }
    fn parse_url(&mut self, url: &str) -> Result<(), TunnelError> {
        Self::parse_url(self, url)
    }
    fn set_os_spoof(&mut self, os: &str) -> Result<(), TunnelError> {
        Self::set_os_spoof(self, os)
    }
    fn set_cookie(&mut self, cookie: &str) -> Result<(), TunnelError> {
        Self::set_cookie(self, cookie)
    }
    fn set_client_cert(&mut self, cert: &str, key: &str) -> Result<(), TunnelError> {
        Self::set_client_cert(self, cert, key)
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpInfoSnapshot {
    pub addr: Option<String>,
    pub netmask: Option<String>,
    pub addr6: Option<String>,
    pub netmask6: Option<String>,
    pub gateway_addr: Option<String>,
    pub domain: Option<String>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
}

fn not_available() -> TunnelError {
    TunnelError::OpenConnect("openconnect not available on this platform".into())
}
