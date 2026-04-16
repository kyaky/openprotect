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
        let mut builder = reqwest::Client::builder()
            .user_agent(&gp_params.user_agent)
            .danger_accept_invalid_certs(gp_params.ignore_tls_errors);

        // Mutual TLS: PKCS#12 takes precedence over PEM cert+key.
        if let Some(p12_path) = &gp_params.client_pkcs12 {
            // reqwest + rustls doesn't support PKCS#12 directly
            // (from_pkcs12_der requires native-tls). Convert to PEM
            // via rustls-pemfile + pkcs8. For now, require PEM format
            // and bail with a clear message for PKCS#12.
            return Err(AuthError::Other(format!(
                "--pkcs12 is not supported with the rustls TLS backend. \
                 Convert your PKCS#12 bundle to PEM format:\n\
                 \n  openssl pkcs12 -in {p12_path} -out cert.pem -nodes\n\
                 \nThen use `--cert cert.pem --key cert.pem` instead."
            )));
        } else if let Some(cert_path) = &gp_params.client_cert {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| AuthError::Other(format!("reading cert {cert_path}: {e}")))?;
            let key_path = gp_params.client_key.as_deref().ok_or_else(|| {
                AuthError::Other("--cert requires --key (PEM private key path)".into())
            })?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| AuthError::Other(format!("reading key {key_path}: {e}")))?;
            let mut combined = cert_pem;
            combined.push(b'\n');
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| AuthError::Other(format!("loading PEM identity: {e}")))?;
            builder = builder.identity(identity);
        }

        let http = builder.build()?;
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
    ///
    /// # Param set
    ///
    /// This endpoint is **picky** about extra form fields. Sending
    /// the full `gp_params::to_params()` set (which is tailored to
    /// `/ssl-vpn/login.esp`) produces a ~69-byte "error" XML with
    /// no root element — observed live against Prisma Access on a
    /// real UNSW deployment. The fix is to send the minimal set
    /// that yuezk v2's `HipReporter::retrieve_client_ip` uses:
    ///
    ///   client-type, protocol-version, internal, ipv6-support,
    ///   clientos, hmac-algo, enc-algo, os-version, app-version
    ///
    /// plus every field from the merged cookie (authcookie, portal,
    /// user, domain, computer, preferred-ip).
    ///
    /// Notably absent: `prot`, `jnlpReady`, `ok`, `direct`, `host-id`,
    /// `default-browser`, `cas-support`, `computer` (it's already in
    /// the cookie) and `clientVer` (replaced by `app-version`, which
    /// is the correct field name for this endpoint).
    pub async fn gateway_getconfig(
        &self,
        gateway: &str,
        cookie_str: &str,
    ) -> Result<GatewayConfig, AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/getconfig.esp");

        let client_os: String = self.gp_params.client_os.clientos().to_string();
        let os_version: String = self.gp_params.os_version.clone();
        let client_version: String = self.gp_params.client_version.clone();

        // Start with the minimal "correct" param set for this endpoint.
        let mut params: Vec<(String, String)> = vec![
            ("client-type".to_string(), "1".to_string()),
            ("protocol-version".to_string(), "p1".to_string()),
            ("internal".to_string(), "no".to_string()),
            ("ipv6-support".to_string(), "yes".to_string()),
            ("clientos".to_string(), client_os),
            // Match yuezk's reference client's algo advertisements.
            // We don't actually negotiate ESP / DTLS ourselves —
            // libopenconnect redoes getconfig internally and handles
            // that — but the gateway expects these fields and some
            // deployments reject POSTs that omit them.
            ("hmac-algo".to_string(), "sha1,md5,sha256".to_string()),
            (
                "enc-algo".to_string(),
                "aes-128-cbc,aes-256-cbc".to_string(),
            ),
            ("os-version".to_string(), os_version),
            // Note: this endpoint wants `app-version`, not `clientVer`.
            // Sending `clientVer` causes the server to return an error
            // XML with no root element (observed live against UNSW
            // Prisma Access).
            ("app-version".to_string(), client_version),
        ];

        // Append cookie fields (authcookie, portal, user, domain,
        // computer, preferred-ip). `computer` is in the cookie; we
        // deliberately do NOT send a separate top-level `computer`
        // field because duplicating it has been reported to confuse
        // some gateway deployments.
        params.extend(cookie_to_form_fields(cookie_str));

        tracing::debug!("gateway getconfig POST {url}");
        let response = self.http.post(&url).form(&params).send().await?;
        let status = response.status();
        let body = response.text().await?;
        tracing::trace!(
            "gateway getconfig response: status={status} bytes={} body_head={:?}",
            body.len(),
            body.chars().take(256).collect::<String>()
        );
        if !status.is_success() {
            return Err(AuthError::Failed(format!(
                "gateway getconfig returned HTTP {status}: {body_head}",
                body_head = body.chars().take(256).collect::<String>()
            )));
        }
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
