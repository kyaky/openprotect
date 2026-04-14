//! HTTP client for GlobalProtect API endpoints.

use gp_proto::*;

use crate::error::AuthError;
use crate::hip::cookie_to_form_fields;

/// HTTP client wrapping the GlobalProtect REST-ish API.
pub struct GpClient {
    http: reqwest::Client,
    /// The GP request parameters attached to every call.
    pub gp_params: GpParams,
}

impl GpClient {
    /// Create a new client from the given parameters.
    pub fn new(gp_params: GpParams) -> Result<Self, AuthError> {
        let http = reqwest::Client::builder()
            .user_agent(&gp_params.user_agent)
            .danger_accept_invalid_certs(gp_params.ignore_tls_errors)
            .build()?;
        Ok(Self { http, gp_params })
    }

    /// Portal or gateway prelogin — determines the required auth method.
    pub async fn prelogin(&self, server: &str) -> Result<PreloginResponse, AuthError> {
        let url = self.gp_params.prelogin_url(server);
        let params = self.gp_params.to_prelogin_params();

        tracing::debug!("prelogin POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("prelogin response ({} bytes)", body.len());
        Ok(PreloginResponse::parse(&body)?)
    }

    /// Retrieve the portal configuration (gateway list + auth cookies).
    ///
    /// This doubles as the "portal login" step — the credential is verified
    /// by the portal before it returns the config.
    pub async fn portal_config(
        &self,
        portal: &str,
        cred: &Credential,
    ) -> Result<PortalConfig, AuthError> {
        let url = self.gp_params.login_url(portal);
        let mut params = self.gp_params.to_params();
        params.extend(cred.to_params());
        let host = gp_proto::params::normalize_server(portal).to_string();
        params.push(("server", host.clone()));
        params.push(("host", host));

        tracing::debug!("portal config POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("portal config response ({} bytes)", body.len());
        Ok(PortalConfig::parse(&body, portal, cred.username())?)
    }

    /// Fetch the gateway's tunnel config by POSTing directly to
    /// `/ssl-vpn/getconfig.esp` with the authcookie already in hand.
    /// libopenconnect calls this internally during
    /// `make_cstp_connection`, but we also call it from the Rust
    /// side earlier in the flow so the HIP submission path knows
    /// the client-ip without having to pump state back out of the
    /// running tunnel thread.
    ///
    /// `cookie_str` is the authcookie query string built by
    /// [`crate::AuthContext`] / `build_openconnect_cookie` — the
    /// same `authcookie=…&portal=…&user=…` form libopenconnect
    /// consumes via `openconnect_set_cookie`.
    pub async fn gateway_getconfig(
        &self,
        gateway: &str,
        cookie_str: &str,
    ) -> Result<GatewayConfig, AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/getconfig.esp");

        // gp_params::to_params yields (&'static str, String); the
        // cookie fields are (String, String). Converting once up
        // front lets both lists share one owned Vec.
        let mut params: Vec<(String, String)> = self
            .gp_params
            .to_params()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        params.extend(cookie_to_form_fields(cookie_str));
        params.push(("client-type".to_string(), "1".to_string()));
        params.push(("protocol-version".to_string(), "p1".to_string()));
        params.push(("internal".to_string(), "no".to_string()));
        params.push(("ipv6-support".to_string(), "yes".to_string()));

        tracing::debug!("gateway getconfig POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        tracing::trace!("gateway getconfig response ({} bytes)", body.len());
        Ok(GatewayConfig::parse(&body)?)
    }

    /// POST `/ssl-vpn/hipreportcheck.esp`. Returns
    /// [`HipCheckResponse::needed`] = `true` iff the gateway wants
    /// us to follow up with a full report submission.
    pub async fn hip_report_check(
        &self,
        gateway: &str,
        cookie_str: &str,
        client_ip: &str,
        md5: &str,
    ) -> Result<HipCheckResponse, AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/hipreportcheck.esp");

        let mut params = cookie_to_form_fields(cookie_str);
        params.push(("client-role".to_string(), "global-protect-full".to_string()));
        params.push(("client-ip".to_string(), client_ip.to_string()));
        params.push(("md5".to_string(), md5.to_string()));

        tracing::debug!("hipreportcheck POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        tracing::trace!("hipreportcheck response ({} bytes)", body.len());
        Ok(HipCheckResponse::parse(&body)?)
    }

    /// POST `/ssl-vpn/hipreport.esp` with the full HIP XML document.
    /// Ignores the gateway's response body — a successful
    /// `error_for_status` is taken as acceptance.
    pub async fn submit_hip_report(
        &self,
        gateway: &str,
        cookie_str: &str,
        client_ip: &str,
        report_xml: &str,
    ) -> Result<(), AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/hipreport.esp");

        let mut params = cookie_to_form_fields(cookie_str);
        params.push(("client-role".to_string(), "global-protect-full".to_string()));
        params.push(("client-ip".to_string(), client_ip.to_string()));
        params.push(("report".to_string(), report_xml.to_string()));

        tracing::debug!("hipreport POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        tracing::trace!("hipreport response ({} bytes): {}", body.len(), body);
        Ok(())
    }

    /// Gateway login — exchange credentials for an authcookie.
    pub async fn gateway_login(
        &self,
        gateway: &str,
        cred: &Credential,
    ) -> Result<GatewayLoginResult, AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/login.esp");
        let mut params = self.gp_params.to_params();
        params.extend(cred.to_params());
        params.push(("server", host.to_string()));

        tracing::debug!("gateway login POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("gateway login response ({} bytes)", body.len());
        Ok(GatewayLoginResult::parse(&body, &self.gp_params.computer)?)
    }
}
