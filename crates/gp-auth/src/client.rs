//! HTTP client for GlobalProtect API endpoints.

use std::time::Duration;

use gp_proto::*;

use crate::error::AuthError;
use crate::hip::cookie_to_form_fields;

/// Default per-connection (TCP + TLS handshake) timeout applied to
/// every `GpClient`, overridable via `OPC_HTTP_CONNECT_TIMEOUT_SECS`.
///
/// Rationale: `opc connect` hung indefinitely against gateways that
/// accepted the TCP socket and then went silent (see the hang report
/// this bound ships against — diagnosis-independent by design). 15s
/// is well above any sane LAN/WAN TCP+TLS setup and far below "forever".
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 15;

/// Default **whole-request** timeout applied to every `GpClient`,
/// overridable via `OPC_HTTP_REQUEST_TIMEOUT_SECS`.
///
/// reqwest's `timeout` covers the full request/response cycle,
/// including response-body consumption, so every call made through
/// `self.http` (`hip_report_check` / `submit_hip_report`'s
/// `.send().await?.error_for_status()?.text().await?` chains and the
/// portal/gateway/prelogin equivalents) is bounded by it — that is
/// the check the hang report asked for: no call site may stream a
/// body over a client that was built without this.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Env var name overriding [`DEFAULT_CONNECT_TIMEOUT_SECS`] (integer
/// seconds; `0`, unparsable, or absent → the default).
pub const ENV_CONNECT_TIMEOUT_SECS: &str = "OPC_HTTP_CONNECT_TIMEOUT_SECS";

/// Env var name overriding [`DEFAULT_REQUEST_TIMEOUT_SECS`] (integer
/// seconds; `0`, unparsable, or absent → the default).
pub const ENV_REQUEST_TIMEOUT_SECS: &str = "OPC_HTTP_REQUEST_TIMEOUT_SECS";

/// Resolve one timeout knob from the environment.
///
/// Shared by the builder and its unit tests; kept side-effect free so
/// the fallback behaviour (warn + default on junk) is testable without
/// a network. Values of `0` are treated as junk rather than "disable
/// the timeout" — reqwest rejects zero-duration timeouts, and a user
/// asking for "no timeout" on a client whose whole purpose is bounding
/// hangs gets the loud warn + safe default instead.
fn timeout_secs_from_env(var: &str, default_secs: u64) -> Duration {
    let raw = match std::env::var(var) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Duration::from_secs(default_secs),
        Err(_) => {
            tracing::warn!(
                "{var} is set but not valid unicode (or not a string); using default {default_secs}s"
            );
            return Duration::from_secs(default_secs);
        }
    };
    match raw.trim().parse::<u64>() {
        Ok(n) if n >= 1 => Duration::from_secs(n),
        Ok(_) => {
            tracing::warn!(
                "{var}={raw:?} is zero; timeouts cannot be disabled, using default {default_secs}s"
            );
            Duration::from_secs(default_secs)
        }
        Err(_) => {
            tracing::warn!(
                "{var}={raw:?} is not an integer number of seconds; using default {default_secs}s"
            );
            Duration::from_secs(default_secs)
        }
    }
}

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

        // Diagnosis-independent bounds for the "connect often hangs"
        // class: reqwest previously had NO connect/request timeout, so
        // a gateway that accepted TCP and went silent (or trickled a
        // body) wedged the caller forever. `timeout` covers the whole
        // request/response exchange **including body consumption**, so
        // the `.send().await? … .text().await?` chains in
        // hip_report_check / submit_hip_report / gateway_login are all
        // inside it — none of them stream a body on a separately built
        // client. No retry logic is added anywhere: a timed-out
        // auth POST fails fast and stays failed (auth POSTs must never
        // be auto-retried).
        let connect_timeout =
            timeout_secs_from_env(ENV_CONNECT_TIMEOUT_SECS, DEFAULT_CONNECT_TIMEOUT_SECS);
        let request_timeout =
            timeout_secs_from_env(ENV_REQUEST_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS);
        tracing::debug!(
            "GpClient: connect_timeout={connect_timeout:?} request_timeout={request_timeout:?} \
             (env {ENV_CONNECT_TIMEOUT_SECS}/{ENV_REQUEST_TIMEOUT_SECS})"
        );
        builder = builder
            .connect_timeout(connect_timeout)
            .timeout(request_timeout);

        // DNS pin: if the caller supplied a pre-resolved IP for the
        // gateway, route the hostname directly there. Used by the
        // Windows HIP fallback so the post-NRPT internal DNS can't
        // hijack the gateway hostname out from under us. TLS / SNI
        // still uses the hostname so cert validation is unaffected.
        if let Some((host, addr)) = gp_params.resolve_override.clone() {
            tracing::debug!("GpClient: resolve override {host} -> {addr}");
            builder = builder.resolve(&host, addr);
        }

        // Mutual TLS: PKCS#12 takes precedence over PEM cert+key.
        if let Some(p12_path) = &gp_params.client_pkcs12 {
            // reqwest + rustls doesn't support PKCS#12 directly
            // (from_pkcs12_der requires native-tls). Convert to PEM
            // via rustls-pemfile + pkcs8. For now, require PEM format
            // and bail with a clear message for PKCS#12.
            return Err(AuthError::Other(format!(
                "--pkcs12 is not supported with the rustls TLS backend. \
                 Convert your PKCS#12 bundle to a combined PEM file:\n\
                 \n  openssl pkcs12 -in {p12_path} -out combined.pem -nodes\n\
                 \nThis produces a single file containing both the certificate \
                 and private key. Pass it to both flags:\n\
                 \n  opc connect --cert combined.pem --key combined.pem ..."
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
        self.prelogin_at(&url).await
    }

    /// Wire half of [`Self::prelogin`] with a caller-supplied URL, the
    /// same loopback seam as [`Self::gateway_login_url`]: production
    /// builds the `https://` URL via `prelogin_url`; a plain-HTTP mock
    /// on `127.0.0.1:0` cannot terminate TLS.
    pub(crate) async fn prelogin_at(&self, url: &str) -> Result<PreloginResponse, AuthError> {
        let params = self.gp_params.to_prelogin_params();
        // Resweep M4 uniformity: server-influenced or not, every URL
        // interpolation into a log line is control-char-flattened
        // (see `flatten_control_chars`).
        let url_log = flatten_control_chars(url);

        tracing::debug!("prelogin POST {url_log}");
        // Issue #36 checklist M3d: same non-2xx diagnostics as
        // gateway_login_url / portal_config (status + allow-listed PAN
        // headers + bounded scrubbed body head), classified via
        // reject_error. Pre-3a50d75 this was `.error_for_status()?`,
        // which discarded them; a plain (no-auth-claim) 4xx/5xx now
        // yields AuthError::Server, and main.rs classify_exit_code
        // maps Http and Server to the same GATEWAY_UNREACHABLE exit 3,
        // so the legacy prelogin exit-code contract is preserved.
        let response = self.http.post(url).form(&params).send().await?;
        let status = response.status();
        let body = if !status.is_success() {
            let headers = response.headers().clone();
            let body = read_capped_body(response, DIAG_BODY_MAX_BYTES).await?;
            // prelogin submits no credential keys; the scrub set is
            // empty by construction but flows the same pipeline.
            let secrets = submitted_secret_values(&params);
            let msg = format!(
                "prelogin rejected: POST {url_log} -> HTTP {status}; {}; body[:{BODY_HEAD_CHARS}]={}",
                pan_diagnostic_headers(&headers, &secrets),
                scrub_server_text(&body, &secrets, BODY_HEAD_CHARS),
            );
            tracing::warn!("{msg}");
            return Err(reject_error(status, &headers, &body, msg));
        } else {
            response.text().await?
        };

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
        self.portal_config_url(&url, portal, cred).await
    }

    /// Wire half of [`Self::portal_config`] with the caller-supplied
    /// POST URL (same loopback seam as `gateway_login_url` /
    /// `prelogin_at`: production always builds the `https://` URL via
    /// `login_url`; a plain-HTTP mock on `127.0.0.1:0` cannot
    /// terminate TLS).
    ///
    /// Issue #43 review S4(a): this function body is what production
    /// runs, so the wire-capture test
    /// `portal_config_wire_sends_hostname_only_server_and_host` pins
    /// the CALL SITE of [`portal_config_form_host`] — reverting the
    /// two form pushes to `normalize_server(portal)` (which keeps the
    /// port) flips that test, where the helper's own unit tests could
    /// not.
    pub(crate) async fn portal_config_url(
        &self,
        url: &str,
        portal: &str,
        cred: &Credential,
    ) -> Result<PortalConfig, AuthError> {
        let mut params = self.gp_params.to_params();
        params.extend(cred.to_params());
        let host = portal_config_form_host(portal);
        params.push(("server", host.clone()));
        params.push(("host", host));

        let url_log = flatten_control_chars(url);
        tracing::debug!("portal config POST {url_log}");
        // Issue #36 diagnostics: on non-2xx, keep status + X-Private-Pan-*
        // headers + a BOUNDED, secret-scrubbed body head instead of
        // letting `.error_for_status()?` discard them, and classify
        // transient 5xx (no auth header) as AuthError::Server so opc's
        // exit-code contract (GATEWAY_UNREACHABLE) survives, mirroring
        // gateway_login_url. Transport failures still surface as
        // AuthError::Http via the `?` on send()/text()/chunk().
        let response = self.http.post(url).form(&params).send().await?;
        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            let body = read_capped_body(response, DIAG_BODY_MAX_BYTES).await?;
            let secrets = submitted_secret_values(&params);
            let msg = format!(
                "portal config rejected: POST {url_log} -> HTTP {status}; {}; body[:{BODY_HEAD_CHARS}]={}",
                pan_diagnostic_headers(&headers, &secrets),
                scrub_server_text(&body, &secrets, BODY_HEAD_CHARS),
            );
            tracing::warn!("{msg}");
            return Err(reject_error(status, &headers, &body, msg));
        }

        let body = response.text().await?;
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

        // Resweep M4 uniformity: server-influenced or not, every URL
        // interpolation into a log line is control-char-flattened.
        let url_log = flatten_control_chars(&url);
        tracing::debug!("gateway getconfig POST {url_log}");
        let response = self.http.post(url).form(&params).send().await?;
        let status = response.status();
        let body = response.text().await?;
        tracing::trace!(
            "gateway getconfig response: status={status} bytes={} body_head={:?}",
            body.len(),
            body.chars().take(256).collect::<String>()
        );
        if !status.is_success() {
            return Err(getconfig_reject_error(status, &body));
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
        let url = hip_report_check_url(gateway);
        self.hip_report_check_at(&url, cookie_str, client_ip, md5)
            .await
    }

    /// Wire half of [`Self::hip_report_check`] with a caller-supplied
    /// URL (issue #43 test seam, following the #42 `gateway_login_url`
    /// precedent: production reaches it only through the public
    /// entry point; a plain-HTTP loopback mock can terminate it).
    pub(crate) async fn hip_report_check_at(
        &self,
        url: &str,
        cookie_str: &str,
        client_ip: &str,
        md5: &str,
    ) -> Result<HipCheckResponse, AuthError> {
        let mut params = cookie_to_form_fields(cookie_str);
        params.push(("client-role".to_string(), "global-protect-full".to_string()));
        params.push(("client-ip".to_string(), client_ip.to_string()));
        params.push(("md5".to_string(), md5.to_string()));

        let url_log = flatten_control_chars(url);
        tracing::debug!("hipreportcheck POST {url_log}");
        let body = self
            .http
            .post(url)
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
        let url = hip_report_url(gateway);
        self.hip_report_submit_at(&url, cookie_str, client_ip, report_xml)
            .await
    }

    /// Wire half of [`Self::submit_hip_report`] with a caller-supplied
    /// URL (issue #43 test seam, same pattern as
    /// [`Self::hip_report_check_at`]).
    pub(crate) async fn hip_report_submit_at(
        &self,
        url: &str,
        cookie_str: &str,
        client_ip: &str,
        report_xml: &str,
    ) -> Result<(), AuthError> {
        let mut params = cookie_to_form_fields(cookie_str);
        params.push(("client-role".to_string(), "global-protect-full".to_string()));
        params.push(("client-ip".to_string(), client_ip.to_string()));
        params.push(("report".to_string(), report_xml.to_string()));

        let url_log = flatten_control_chars(url);
        tracing::debug!("hipreport POST {url_log}");
        let body = self
            .http
            .post(url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        // Resweep M3: the HIP submit response is server text too — mask
        // secret-keyed material and flatten control chars before it
        // can reach the rolling log file.
        tracing::trace!(
            "hipreport response ({} bytes): {}",
            body.len(),
            scrub_server_text(&body, &[], 256)
        );
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
        self.gateway_login_url(&url, host, cred).await
    }

    /// Wire half of [`Self::gateway_login`] with the URL and the `server`
    /// form value supplied by the caller.
    ///
    /// Extraction added for issue #36: the public entry point hard-codes
    /// `https://`, which a loopback mock (plain HTTP on `127.0.0.1:0`, no
    /// TLS material in dev-deps) cannot terminate. Production reaches
    /// this only through `gateway_login`.
    ///
    /// Issue #36 fixes live here:
    ///
    /// * The form is built by `GpParams::gateway_login_form` — secret
    ///   keys are emitted only when non-empty (mirroring upstream's
    ///   caller-level omission around `append_opt`, which itself writes
    ///   `key=` unconditionally), so a portal-derived `AuthCookie`
    ///   can no longer POST a credential-less `passwd=&token=&…` form.
    /// * Non-2xx responses are classified and reported with the full
    ///   URL (resolved port visible), the status, the `X-Private-Pan-*`
    ///   discriminator headers and a bounded, secret-scrubbed body head
    ///   — the observability gap that made #36's bare "512 status code
    ///   512" unanswerable. `.error_for_status()?` must NOT come back:
    ///   it discards exactly those headers/body.
    /// * Classification (see [`reject_error`], checklist M2):
    ///   `AuthError::Failed` (opc exit 2, credential problem) **only**
    ///   when an `X-Private-Pan-Sslvpn(-Extension)` header VALUE or the
    ///   body names a PAN auth-engine reject class; everything else
    ///   (bare 4xx and 5xx without an auth claim) →
    ///   `AuthError::Server` (opc exit 3, GATEWAY_UNREACHABLE), keeping
    ///   the transient-outage classification the legacy
    ///   `.error_for_status()?` had via `AuthError::Http` — review
    ///   finding: monitoring must not page on a maintenance window.
    ///   The error-path body is additionally **read-capped**
    ///   ([`read_capped_body`], [`DIAG_BODY_MAX_BYTES`]).
    /// * Transport failures (connect/timeout/body-stream) still
    ///   propagate through `?` as `AuthError::Http`, preserving the
    ///   `timeout_tests` contract (`reqwest_err(&e).is_timeout()`).
    pub(crate) async fn gateway_login_url(
        &self,
        url: &str,
        server: &str,
        cred: &Credential,
    ) -> Result<GatewayLoginResult, AuthError> {
        let params = self.gp_params.gateway_login_form(cred, server);
        let secrets = submitted_secret_values(&params);
        // Issue #36 resweep (M4): `url` here derives from the
        // portal-advertised gateway address — server-influenced text.
        // The POST keeps the raw string; EVERY log/error interpolation
        // uses the control-char-flattened copy so hostile text can
        // never start a new stderr line (e.g. with the GUI's trusted
        // `SAML-CALLBACK-URL ` marker).
        let url_log = flatten_control_chars(url);
        if secrets.is_empty() {
            tracing::warn!(
                "gateway login POST {url_log}: form carries NO non-empty credential \
                 material (passwd/prelogin-cookie/token/portal-*cookies all absent) \
                 — the portal issued no pass-through cookie and no password was \
                 replayed; expect the gateway to reject this (issue #36)"
            );
        }
        tracing::debug!(
            "gateway login POST {url_log} ({} fields: {})",
            params.len(),
            params.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(",")
        );
        let response = self.http.post(url).form(&params).send().await?;
        let status = response.status();
        if !status.is_success() {
            // Error path: take the headers, read ONLY a bounded head of
            // the body (issue #36 review — never materialise a hostile
            // or oversized error payload to show 256 chars of it), scrub
            // every submitted secret in every echo encoding, then
            // classify so transient 5xx keeps the exit-3 (gateway
            // unreachable) contract while auth rejects stay exit 2.
            let headers = response.headers().clone();
            let body = read_capped_body(response, DIAG_BODY_MAX_BYTES).await?;
            let msg = format!(
                "gateway login rejected: POST {url_log} -> HTTP {status}; {}; body[:{BODY_HEAD_CHARS}]={}",
                pan_diagnostic_headers(&headers, &secrets),
                scrub_server_text(&body, &secrets, BODY_HEAD_CHARS),
            );
            // WARN (not just trace): this is the reject-class
            // discriminator that made issue #36 unanswerable.
            tracing::warn!("{msg}");
            return Err(reject_error(status, &headers, &body, msg));
        }

        let body = response.text().await?;
        tracing::trace!("gateway login response ({} bytes)", body.len());
        Ok(GatewayLoginResult::parse(&body, &self.gp_params.computer)?)
    }
}

/// Max chars of a non-2xx response body kept for diagnostics (issue #36):
/// long enough for `<response status="error"><error>…</error></response>`,
/// short enough to bound a hostile/verbose gateway's payload in a log line.
const BODY_HEAD_CHARS: usize = 256;

/// Non-2xx gateway getconfig error message. Extracted so the redaction
/// rule below is unit-testable without a TLS-terminating mock: the body
/// head is server-controlled text on the USER-VISIBLE error path (opc
/// prints it to stderr), so it must not be able to echo a session
/// secret or forge a marker-led line.
fn getconfig_reject_error(status: reqwest::StatusCode, body: &str) -> AuthError {
    AuthError::Failed(format!(
        "gateway getconfig returned HTTP {status}: {}",
        // Same pipeline as the login diagnostics (issue #36 resweep):
        // secret-needles (none submitted here), key-name masking
        // (authcookie/gpsessionticket/portal cookies the gateway just
        // rotated), and CR/LF flattening so this user-visible line can
        // neither leak nor impersonate the GUI's trusted marker.
        scrub_server_text(body, &[], BODY_HEAD_CHARS)
    ))
}

/// Max **raw bytes** of a non-2xx response body read for diagnostics
/// (issue #36 review): the displayed head is `BODY_HEAD_CHARS` chars
/// after scrubbing, so buffering more than a few KiB from a peer that
/// is unauthenticated under `--insecure` buys nothing and lets a huge
/// or slow error payload balloon memory / burn the request timeout.
/// Success-path callers still read the full body via `.text()`.
const DIAG_BODY_MAX_BYTES: usize = 4096;

/// Read at most `max_bytes` of a response body as lossy UTF-8, for the
/// non-2xx diagnostic path. Transport errors still propagate through
/// `?` as `AuthError::Http` (the timeout_tests contract); once the cap
/// is reached the rest of the stream is **not** read (the response is
/// dropped and the connection discarded).
async fn read_capped_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, AuthError> {
    let mut buf: Vec<u8> = Vec::new();
    // Check the cap BEFORE awaiting the next chunk (checklist S1): a
    // peer that delivers exactly `max_bytes` and then parks would turn
    // a post-await check into a request-timeout transport error,
    // throwing away the status+headers diagnostic the whole read
    // exists for. With the pre-await check, hitting the cap exits the
    // loop without ever waiting on the stalled stream.
    while buf.len() < max_bytes {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let room = max_bytes - buf.len();
        if chunk.len() <= room {
            buf.extend_from_slice(&chunk);
        } else {
            buf.extend_from_slice(&chunk[..room]);
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// PAN auth-engine reject-class tokens. The SOURCE-GROUNDED member is
/// `auth-failed`: openconnect #859's taxonomy records it with dashed
/// refinements such as `auth-failed-password-empty`, and the issue #36
/// reporter observed `X-Private-Pan-Sslvpn: auth-failed` on the wire.
/// `invalid-input` and `missing-form` are NOT attested in any upstream
/// source or issue record verified for this branch — they are carried
/// from the remediation checklist's (M2) reject-class enumeration as
/// DEFENSIVE match values only (checklist M5 honesty: the first cut
/// of this comment called them "documented" without a source). These
/// appear in the `X-Private-Pan-Sslvpn(-Extension)` header VALUES —
/// matching on header PRESENCE would misclaim credential failure for
/// any response that merely carries the header (checklist M2).
const PAN_AUTH_FAILURE_TOKENS: [&str; 3] = ["auth-failed", "invalid-input", "missing-form"];

/// The same classes as named in the response BODY. The two verdict
/// sentences are the source-grounded members: PAN's `<error>` text as
/// recorded by the reporter's own curl controls in issue #36 ("Invalid
/// username or password", "Invalid authentication cookie"). The three
/// reject-class tokens are the same defensive-only values as
/// [`PAN_AUTH_FAILURE_TOKENS`] (checklist M5 honesty: only `auth-failed`
/// is attested upstream). A header-stripping middlebox must not be able
/// to hide an explicit auth-engine verdict behind infrastructure
/// classification.
const PAN_AUTH_FAILURE_BODY_PHRASES: [&str; 5] = [
    "auth-failed",
    "invalid-input",
    "missing-form",
    "invalid username or password",
    "invalid authentication cookie",
];

/// Token-level (case-insensitive) match of a discriminator VALUE:
/// equal to a PAN reject-class token, or the token plus a `-suffix`
/// refinement (`auth-failed-password-empty`). Bare substring presence
/// is deliberately NOT a match — `notauth-failed` is not the
/// discriminator.
fn pan_failure_value(value: &str) -> bool {
    value.split([' ', ',', ';']).any(|raw| {
        let token = raw.trim();
        !token.is_empty()
            && PAN_AUTH_FAILURE_TOKENS.iter().any(|class| {
                token.eq_ignore_ascii_case(class)
                    || (token.len() > class.len() + 1
                        && token[..class.len()].eq_ignore_ascii_case(class)
                        && token.as_bytes()[class.len()] == b'-')
            })
    })
}

/// Whether the response's `X-Private-Pan-Sslvpn` or
/// `X-Private-Pan-Sslvpn-Extension` header VALUE names a PAN
/// auth-engine reject class (checklist M2: value, not mere presence).
fn has_pan_auth_signal(headers: &reqwest::header::HeaderMap) -> bool {
    headers.iter().any(|(name, value)| {
        let lower = name.as_str().to_ascii_lowercase();
        (lower == "x-private-pan-sslvpn" || lower == "x-private-pan-sslvpn-extension")
            && pan_failure_value(value.to_str().unwrap_or_default())
    })
}

/// Whether the response BODY carries an auth-engine verdict (the
/// header-stripped fallback of [`has_pan_auth_signal`], same value
/// taxonomy).
fn body_pan_auth_failure_claim(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    PAN_AUTH_FAILURE_BODY_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
}

/// Classify a portal/gateway HTTP reject for the opc exit-code contract
/// (issue #36 review, checklist M2). Credential failure
/// (`AuthError::Failed` → exit 2) is claimed **only** when a PAN
/// discriminator VALUE — an auth-failed/invalid-input/missing-form
/// header value ([`has_pan_auth_signal`]) or the body's auth-engine
/// verdict sentence ([`body_pan_auth_failure_claim`]) — records an
/// auth reject. `status` no longer participates: a bare 4xx is not a
/// credential reject by status class alone (proxy 403s, 404, 408, 429
/// and every 5xx without an auth claim keep the classification the
/// legacy `.error_for_status()?` gave all non-2xx via
/// `AuthError::Http` → [`AuthError::Server`] → GATEWAY_UNREACHABLE,
/// exit 3), so retry/backoff automation does not treat infra trouble
/// as a broken password. The enriched diagnostics ride in the message
/// either way.
fn reject_error(
    _status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    msg: String,
) -> AuthError {
    // Checklist M2: credential failure is claimed ONLY on a PAN
    // discriminator VALUE (header or body verdict), never on status
    // class or header presence. Everything else keeps the legacy
    // infrastructure lane (Server -> exit 3) the pre-fix
    // `.error_for_status()?` gave all non-2xx via AuthError::Http.
    if has_pan_auth_signal(headers) || body_pan_auth_failure_claim(body) {
        AuthError::Failed(msg)
    } else {
        AuthError::Server(msg)
    }
}

/// Values of the keys that must never appear in server-supplied text
/// that we log or show, for scrubbing before display (issue #36
/// redaction rule): the login secret keys **plus** the scrub-only
/// material such as the MFA `inputStr` challenge token — replayable
/// second-factor state handed back by that same gateway, which must not
/// surface in logs or user-visible errors even though it is not a
/// present-but-empty classification key.
fn submitted_secret_values(params: &[(&'static str, String)]) -> Vec<String> {
    params
        .iter()
        .filter(|(k, v)| {
            !v.is_empty()
                && (gp_proto::params::LOGIN_SECRET_KEYS.contains(k)
                    || gp_proto::params::SCRUB_ONLY_KEYS.contains(k))
        })
        .map(|(_, v)| v.clone())
        .collect()
}

/// The EXPLICIT response-header allow-list for diagnostics (checklist
/// M3c): the two discriminator headers the PAN auth engine sets and
/// that the issue #36 reporter was asked to quote. The old
/// `x-private-pan*` / `x-pan*` prefix wildcards would have logged any
/// other gateway header (descriptions, diag values, cookies arriving
/// under a PAN-ish name); no other header is ever logged, allow-list
/// membership is exact-name (case-insensitive), not prefix.
const PAN_DIAG_HEADERS: [&str; 2] = ["x-private-pan-sslvpn", "x-private-pan-sslvpn-extension"];

/// Render the allow-listed [`PAN_DIAG_HEADERS`] response headers that
/// the PAN auth engine uses to discriminate login rejects, scrubbing
/// submitted secrets out of their values; or state plainly that no such
/// header was present (the sources do not tie header-absence to a
/// specific reject class — see the gw_login_tests module docs).
fn pan_diagnostic_headers(headers: &reqwest::header::HeaderMap, secrets: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if PAN_DIAG_HEADERS.contains(&lower.as_str()) {
            parts.push(format!(
                "{lower}={}",
                scrub_server_text(value.to_str().unwrap_or("<non-utf8>"), secrets, 128)
            ));
        }
    }
    if parts.is_empty() {
        // Honest statement: the auth-engine discriminator header is
        // simply absent. Which reject class that corresponds to is not
        // established by the sources (openconnect #859's empty-passwd
        // reject *carries* auth-failed headers); the body head and the
        // status together let the reporter's re-run arbitrate.
        "no X-Private-Pan-Sslvpn header (no auth-engine reject recorded)".to_string()
    } else {
        parts.join("; ")
    }
}

/// Flatten every character that can START a new line for a log
/// consumer (all C0 control bytes, DEL, and the Unicode line/paragraph
/// separators NEL/U+2028/U+2029) into a VISIBLE TOKEN. Applied to every
/// server-INFLUENCED interpolation into a diagnostic string — above
/// all the `POST {url}` lanes, whose URL is built from the
/// portal-advertised gateway `<entry name>` (checklist M4: the GUI
/// trusts a column-0 `SAML-CALLBACK-URL ` line; reqwest/`url` strip a
/// raw LF from the request target, so the POST still reaches the
/// hostile gateway while the RAW string lands in the log line — the
/// exact forgery this closes, pinned by
/// `stderr_lines_can_never_start_with_the_trusted_marker_from_server_text`).
///
/// The visible-token rendering (was: plain space) keeps the forgery
/// closure AND makes the truncation observable: a field report that
/// shows `<CR>`/`<LF>`/`<0x0B>` can see exactly WHAT the hostile peer
/// sent where, instead of a silently rewritten line — the same
/// single-escaper contract gp-route's completion records use (the two
/// crates cannot share one fn; gp-route does not depend on gp-auth,
/// and the markers are byte-identical by these paired pins).
fn flatten_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\u{2028}' {
                "<LS>"
            } else if c == '\u{2029}' {
                "<PS>"
            } else if c.is_control() {
                match c {
                    '\r' => "<CR>",
                    '\n' => "<LF>",
                    '\u{85}' => "<NEL>",
                    '\u{7f}' => "<DEL>",
                    _ => {
                        return format!("<0x{:02X}>", c as u32);
                    }
                }
            } else {
                return c.to_string();
            }
            .to_string()
        })
        .collect()
}

/// Truncate server-supplied text for diagnostics, scrubbing every secret
/// we submitted — in **every encoding a reflecting gateway could echo**
/// (raw, urlencoded wire form, lowercase-hex re-render, `%20`-space
/// form) — so no password/cookie value can leak into a log line or the
/// user-visible error even if the gateway echoes the request back.
/// reqwest's `.form()` percent-encodes the body, so matching only the
/// raw string leaks the wire rendering (issue #36 review). Scrubbing
/// runs BEFORE truncation; needles are applied longest-first so a short
/// secret cannot shred a longer overlapping one.
fn scrub_server_text(text: &str, secrets: &[String], max_chars: usize) -> String {
    let mut needles: Vec<String> = Vec::new();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        needles.push(secret.clone());
        // `+`-space wire form and its lowercase-hex re-render…
        let enc = form_urlencode(secret);
        needles.push(enc.clone());
        needles.push(lowercase_percent_hex(&enc));
        // …and the FULL percent-encoded rendering (space as `%20`,
        // checklist M3a: `p@ ss` -> `p%40%20ss`, both hex cases), which
        // re-encoding middleboxes and JSON/XML serializers emit.
        let pct = percent_encode_all(secret);
        needles.push(pct.clone());
        needles.push(lowercase_percent_hex(&pct));
        if secret.contains(' ') {
            needles.push(secret.replace(' ', "%20"));
        }
    }
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    // Flatten server newlines FIRST (checklist M4): log forgery must be
    // impossible at the source — text that can start a new terminal
    // line can impersonate the GUI's trusted SAML marker line to the
    // stderr reader (or any downstream log consumer). The same
    // visible-token rendering as [`flatten_control_chars`] (PR-B item
    // 3: one escaper contract per crate, paired by pins), so the
    // escape is observable in the field report rather than a silent
    // space-rewrite.
    let mut out: String = text
        .chars()
        .map(|c| match c {
            '\n' => "<LF>".to_string(),
            '\r' => "<CR>".to_string(),
            _ => c.to_string(),
        })
        .collect();
    for needle in &needles {
        out = out.replace(needle.as_str(), "[REDACTED]");
    }
    // Decode-compare belt (M3a robustness ask): any delimiter-bounded
    // token that PERCENT-DECODES to a submitted secret is that secret,
    // whatever mixed casing or partial encoding the echo used — no
    // needle enumeration needs to have anticipated it.
    for token in decode_matched_tokens(&out, secrets) {
        out = out.replace(token.as_str(), "[REDACTED]");
    }
    // Key-name mask (checklist M3b): server-echoed values for secret
    // keys the client NEVER submitted are unknown to value scrubbing —
    // mask them by key so a rotated/issued secret in an error body
    // cannot reach a log line or a pasted issue comment.
    out = mask_secret_key_values(&out);
    let count = out.chars().count();
    if count > max_chars {
        let mut head: String = out.chars().take(max_chars).collect();
        head.push('…');
        head
    } else {
        out
    }
}

/// Percent-encode EVERY byte outside the RFC-3986 unreserved set
/// (uppercases the alphanumerics and `*-._` through), including space
/// as `%20` — the rendering form encoders that use `%20` instead of
/// `+` put on the wire. [`form_urlencode`]’s `+`-for-space sibling.
fn percent_encode_all(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The percent-decode-compare lane of [`scrub_server_text`]
/// (checklist M3a, hardened by the issue #36 final resweep): split
/// `text` on the delimiters that appear around echoed form/XML values
/// — including the punctuation a reflecting gateway glues onto values
/// (`=`, `(`/`)`, `[`/`]`, `/`, `:`; the original 12-char set let
/// `(credential=<echo>)` survive) — and return every token that
/// percent-decodes to text **containing** one of the `secrets` at any
/// decode depth. The decode runs to a fixed point (capped): a
/// re-encoding proxy double-encodes (`%25XX` -> `%XX` -> byte) and one
/// pass would stop at the intermediate rendering; per-escape case
/// mixes match no precomputed needle, so equality on a single pass was
/// both too narrow (whole-token) and too shallow (one pass). Only
/// tokens containing `%` are candidates — raw and single-rendering
/// echoes are exact needles already.
fn decode_matched_tokens(text: &str, secrets: &[String]) -> Vec<String> {
    if secrets.is_empty() {
        return Vec::new();
    }
    const DELIMS: [char; 19] = [
        ' ', '\t', '\r', '\n', '&', ';', '"', '\'', '<', '>', '|', ',', '=', '(', ')', '[', ']',
        '/', ':',
    ];
    /// A hostile echo cannot usefully nest encodings beyond a couple
    /// of layers; the cap bounds work and guarantees termination (each
    /// pass only ever shrinks or stabilizes the bytes).
    const MAX_DECODE_PASSES: usize = 4;
    let mut hits: Vec<String> = Vec::new();
    'tokens: for token in text.split(DELIMS) {
        if token.is_empty() || !token.contains('%') {
            continue;
        }
        let mut cur: Vec<u8> = token.as_bytes().to_vec();
        for _ in 0..MAX_DECODE_PASSES {
            let dec = percent_decode_bytes(&cur);
            if dec == cur {
                break; // fixed point: no escapes left to unfold
            }
            cur = dec;
            if secrets
                .iter()
                .any(|s| !s.is_empty() && cur.windows(s.len()).any(|w| w == s.as_bytes()))
            {
                hits.push(token.to_string());
                continue 'tokens;
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

/// Decode `%XX` escapes (either hex case) and `+`-for-space, keeping
/// other bytes verbatim and a stray `%` literal. Mirrors the wire
/// semantics of `application/x-www-form-urlencoded` so an echo token
/// can be compared byte-exact against the submitted secret. Takes and
/// returns **bytes** so the decode-compare lane can iterate it to a
/// fixed point without UTF-8 round-trip artifacts between passes.
fn percent_decode_bytes(s: &[u8]) -> Vec<u8> {
    let bytes = s;
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                // Byte-slice, not str-slice: the two bytes after `%`
                // need not sit on a UTF-8 boundary (a bare `%` followed
                // by a multibyte char).
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Encode like `application/x-www-form-urlencoded` — the
/// `url::form_urlencoded` algorithm reqwest's `.form()` uses for the
/// POST body: ASCII alphanumerics and `*`, `-`, `.`, `_` pass through,
/// space becomes `+`, every other byte becomes uppercase `%XX` over its
/// UTF-8 bytes. A gateway that echoes the submitted form reflects these
/// wire renderings, not the raw values — the scrub must know both.
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Lowercase the hex digits of every `%XX` escape in an already
/// percent-encoded (pure-ASCII) string: a re-encoding proxy or
/// middlebox may reflect `%2b` where the wire said `%2B`, and the scrub
/// must catch both renderings.
fn lowercase_percent_hex(encoded: &str) -> String {
    debug_assert!(
        encoded.is_ascii(),
        "intended for form_urlencode output (pure ASCII)"
    );
    let bytes = encoded.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push((bytes[i + 1] as char).to_ascii_lowercase());
            out.push((bytes[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Form/response keys whose **server-side value** must be masked by
/// key name, independent of what the client submitted (checklist M3b):
/// a rejecting gateway can echo or rotate portal cookies, mint a fresh
/// prelogin secret or hand back session-ticket material inside the
/// error body itself, and none of those values are knowable to
/// value-scrubbing. The key stays visible (it is the diagnosis), the
/// value becomes `[REDACTED]`. Covers the login secret keys plus the
/// scrub-only `inputStr` and the PAN session-ticket / authcookie
/// material.
const SECRET_ECHO_KEYS: [&str; 8] = [
    "passwd",
    "token",
    "prelogin-cookie",
    "portal-userauthcookie",
    "portal-prelogonuserauthcookie",
    "inputStr",
    "gpsessionticket",
    "authcookie",
];

/// Mask server-side secret values by KEY name, in every shape a PAN
/// response delivers them (issue #36 checklist M3b, hardened by the
/// final resweep):
///
/// * `key=VALUE` — the `application/x-www-form-urlencoded` echo;
/// * `<key>VALUE</key>` — the XML **element** form GlobalProtect's own
///   lanes use for pass-through cookie material (the resweep showed
///   the original `=`-only mask leaked a gateway-ROTATED, never-
///   submitted `<portal-userauthcookie>…` intact into the pasted
///   error); attributes/whitespace allowed inside the open tag;
/// * `Set-Cookie: NAME=VALUE` echoed inside a body — the cookie name
///   is unknowable, so the whole pair is masked (the response-HEADER
///   lane can't leak this: M3c's allow-list logs only the two PAN
///   discriminator headers; this is the hostile-reflects-it-in-the-
///   body shape the checklist preamble "any Set-Cookie value must never
///   be logged" demands).
///
/// The key stays visible (it is the diagnosis), the value becomes
/// `[REDACTED]`, in ANY case form. Matching runs on the
/// ASCII-lowercased copy; slicing uses the ORIGINAL text
/// (`to_ascii_lowercase` preserves byte length and index alignment for
/// ASCII-only folding), so non-ASCII content stays intact.
fn mask_secret_key_values(text: &str) -> String {
    let lower_bytes = text.to_ascii_lowercase().into_bytes();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    'outer: while i < bytes.len() {
        // Body-embedded `Set-Cookie:` pair (whole `NAME=VALUE` masked,
        // attributes after `;` kept — Path/flags are diagnosis, the
        // value is not).
        const SET_COOKIE: &[u8] = b"set-cookie:";
        if lower_bytes[i..].starts_with(SET_COOKIE) {
            out.push_str(&text[i..i + SET_COOKIE.len()]); // keep the label
            i += SET_COOKIE.len();
            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
                out.push_str(&text[i..i + 1]);
                i += 1;
            }
            let start = i;
            while i < bytes.len()
                && !matches!(
                    bytes[i],
                    b' ' | b'\t' | b'\r' | b'\n' | b';' | b',' | b'"' | b'\'' | b'<' | b'>'
                )
            {
                i += 1;
            }
            if i > start {
                out.push_str("[REDACTED]");
            }
            continue 'outer;
        }
        for key in SECRET_ECHO_KEYS {
            let k = key.as_bytes();
            // XML element form: `<key>`, `<key/>`, or `<key attrs>`.
            if bytes.get(i) == Some(&b'<')
                && lower_bytes[i + 1..].starts_with(k)
                && matches!(
                    lower_bytes.get(i + 1 + k.len()),
                    Some(b'>') | Some(b' ') | Some(b'/')
                )
            {
                if let Some(off) = lower_bytes[i + 1 + k.len()..]
                    .iter()
                    .position(|&b| b == b'>')
                {
                    let open_end = i + 1 + k.len() + off; // index of the open tag's '>'
                    out.push_str(&text[i..=open_end]); // keep the open tag
                    let val_start = open_end + 1;
                    let mut j = val_start;
                    while j < bytes.len() && bytes[j] != b'<' {
                        j += 1;
                    }
                    if j > val_start {
                        out.push_str("[REDACTED]");
                        i = j;
                    } else {
                        i = val_start;
                    }
                    continue 'outer;
                }
                // No '>' anywhere after the key: malformed, treat as
                // prose rather than mis-masking across the rest of
                // the body.
            }
            if lower_bytes[i..].starts_with(k) && bytes.get(i + k.len()) == Some(&b'=') {
                out.push_str(&text[i..i + k.len() + 1]); // keep `key=`
                i += k.len() + 1;
                let start = i;
                while i < bytes.len()
                    && !matches!(
                        bytes[i],
                        b' ' | b'\t'
                            | b'\r'
                            | b'\n'
                            | b'&'
                            | b';'
                            | b'"'
                            | b'\''
                            | b'<'
                            | b'>'
                            | b'|'
                            | b','
                            | b'{'
                            | b'}'
                    )
                {
                    i += 1;
                }
                if i > start {
                    out.push_str("[REDACTED]");
                }
                continue 'outer;
            }
        }
        // Copy one whole UTF-8 char (all keys are ASCII, so a match can
        // never begin inside a multibyte sequence).
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1; // continuation bytes
        }
        out.push_str(&text[start..i]);
    }
    out
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use gp_proto::{ClientOs, Credential};
    use std::net::TcpListener;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    /// Serialises every test that mutates the process-wide environment
    /// (`set_var`/`remove_var` are visible to all threads in the test
    /// binary, so two of these racing would read each other's values).
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A localhost TCP stub that `accept()`s connections and then says
    /// **nothing** — no bytes back, handshake never completes. This is
    /// the "hung gateway" shape from the `opc connect` hang report:
    /// the socket opens, the peer is silent, and without a bound the
    /// client waits forever. Binding an ephemeral 127.0.0.1:0 port
    /// only; nothing leaves the loopback interface.
    ///
    /// Returns the bound address. The accept loop runs on a leaked
    /// daemon thread that holds every accepted stream open (dropping
    /// them would RST and turn the stall into a fast error, which is
    /// not the behaviour under test).
    fn silent_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::Builder::new()
            .name("test-silent-stub".into())
            .spawn(move || {
                let mut held = Vec::new();
                // Localhost accepts never fail in this test; if one
                // ever did, the stub exits and the per-test tokio
                // watchdog turns it into a loud failure anyway.
                for stream in listener.incoming().flatten() {
                    held.push(stream);
                }
            })
            .expect("spawn stub");
        addr
    }

    /// Value plumbing for the two timeout knobs: absent → documented
    /// defaults, valid → honoured (trim-tolerant), junk/zero → default
    /// with a warn. Pins the "values configurable, defaults documented"
    /// contract without touching the network.
    #[test]
    fn timeout_env_plumbing() {
        let cases: &[(&str, Option<&str>, u64, &str)] = &[
            // (var to set, value — None = unset, expected secs, why)
            (
                ENV_CONNECT_TIMEOUT_SECS,
                None,
                DEFAULT_CONNECT_TIMEOUT_SECS,
                "connect default",
            ),
            (
                ENV_REQUEST_TIMEOUT_SECS,
                None,
                DEFAULT_REQUEST_TIMEOUT_SECS,
                "request default",
            ),
            (ENV_CONNECT_TIMEOUT_SECS, Some("45"), 45, "connect override"),
            (
                ENV_REQUEST_TIMEOUT_SECS,
                Some(" 120 "),
                120,
                "request override, whitespace trimmed",
            ),
            (
                ENV_REQUEST_TIMEOUT_SECS,
                Some("0"),
                DEFAULT_REQUEST_TIMEOUT_SECS,
                "zero rejected → default",
            ),
            (
                ENV_REQUEST_TIMEOUT_SECS,
                Some("ten"),
                DEFAULT_REQUEST_TIMEOUT_SECS,
                "junk → default",
            ),
            (
                ENV_CONNECT_TIMEOUT_SECS,
                Some("-1"),
                DEFAULT_CONNECT_TIMEOUT_SECS,
                "negative → default",
            ),
        ];
        let _guard = env_lock();
        for (var, value, expected, why) in cases {
            // Start from a clean slate for both knobs every iteration so
            // a previous row cannot leak into this one.
            std::env::remove_var(ENV_CONNECT_TIMEOUT_SECS);
            std::env::remove_var(ENV_REQUEST_TIMEOUT_SECS);
            if let Some(v) = value {
                std::env::set_var(var, v);
            }
            let default = if *var == ENV_CONNECT_TIMEOUT_SECS {
                DEFAULT_CONNECT_TIMEOUT_SECS
            } else {
                DEFAULT_REQUEST_TIMEOUT_SECS
            };
            let got = timeout_secs_from_env(var, default);
            assert_eq!(got, Duration::from_secs(*expected), "case {why:?}");
            std::env::remove_var(var);
        }
    }

    fn win_params() -> GpParams {
        GpParams {
            ignore_tls_errors: true,
            ..GpParams::new(ClientOs::Win)
        }
    }

    /// Extract the inner `reqwest::Error` from an `AuthError` so we can
    /// assert it is specifically a *timeout*, not any error.
    fn reqwest_err(e: &AuthError) -> Option<&reqwest::Error> {
        match e {
            AuthError::Http(r) => Some(r),
            _ => None,
        }
    }

    /// RED for the unbounded builder: `prelogin` against a server that
    /// accepts TCP but never completes TLS must return a bounded
    /// `Err(reqwest timeout)` once the (configurable) whole-request
    /// timeout is wired into the builder. Before the fix the builder
    /// at client.rs:18-62 sets no timeouts at all, so the future sits
    /// in the handshake forever and the tokio watchdog below fires.
    #[tokio::test(flavor = "multi_thread")]
    async fn prelogin_against_silent_server_times_out() {
        let addr;
        let client;
        // GpClient reads the env only while building, so the process-
        // wide env mutation is fenced inside a sync scope and the
        // guard is released before any await (clippy::await_holding_lock).
        {
            let _guard = env_lock();
            std::env::set_var(ENV_REQUEST_TIMEOUT_SECS, "1");
            std::env::remove_var(ENV_CONNECT_TIMEOUT_SECS);
            addr = silent_server();
            client = GpClient::new(win_params()).expect("build client");
            std::env::remove_var(ENV_REQUEST_TIMEOUT_SECS);
        }

        let started = Instant::now();
        // Watchdog generously above the configured 1s: "no error within
        // 10s" is exactly the hang we are trying to bound.
        let raced =
            tokio::time::timeout(Duration::from_secs(10), client.prelogin(&addr.to_string())).await;

        let elapsed = started.elapsed();
        match raced {
            Err(_) => panic!(
                "prelogin against a silent localhost gateway never returned \
                 (waited {elapsed:?}) — GpClient builder applies no request timeout"
            ),
            Ok(Err(e)) => {
                let rw = reqwest_err(&e)
                    .unwrap_or_else(|| panic!("expected AuthError::Http, got {e:?}"));
                assert!(
                    rw.is_timeout(),
                    "expected a reqwest timeout error, got: {rw:?}"
                );
                assert!(
                    elapsed < Duration::from_secs(8),
                    "timeout took {elapsed:?}, far beyond the configured 1s"
                );
            }
            Ok(Ok(ok)) => panic!("prelogin unexpectedly succeeded against a stub: {ok:?}"),
        }
    }

    /// Same bound on `gateway_login` (the second call named in the
    /// hang report). Also proves the bound applies to the whole call,
    /// not just to one helper: every method shares `self.http`.
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_login_against_silent_server_times_out() {
        let addr;
        let client;
        let cred = Credential::Password {
            username: "tester".into(),
            password: "not-a-real-secret".into(),
        };
        {
            let _guard = env_lock();
            std::env::set_var(ENV_REQUEST_TIMEOUT_SECS, "1");
            std::env::remove_var(ENV_CONNECT_TIMEOUT_SECS);
            addr = silent_server();
            client = GpClient::new(win_params()).expect("build client");
            std::env::remove_var(ENV_REQUEST_TIMEOUT_SECS);
        }

        let started = Instant::now();
        let raced = tokio::time::timeout(
            Duration::from_secs(10),
            client.gateway_login(&addr.to_string(), &cred),
        )
        .await;

        let elapsed = started.elapsed();
        match raced {
            Err(_) => panic!(
                "gateway_login against a silent localhost gateway never returned \
                 (waited {elapsed:?}) — GpClient builder applies no request timeout"
            ),
            Ok(Err(e)) => {
                let rw = reqwest_err(&e)
                    .unwrap_or_else(|| panic!("expected AuthError::Http, got {e:?}"));
                assert!(
                    rw.is_timeout(),
                    "expected a reqwest timeout error, got: {rw:?}"
                );
                assert!(
                    elapsed < Duration::from_secs(8),
                    "timeout took {elapsed:?}, far beyond the configured 1s"
                );
            }
            Ok(Ok(ok)) => panic!("gateway_login unexpectedly succeeded against a stub: {ok:?}"),
        }
    }
}

/// Issue #36 RED tests: gateway-login wire shape + 512 response diagnostics,
/// driven through a localhost mock that reproduces the reporter's verified
/// control experiments (issue: gateway login HTTP 512 vs minimal curl 200).
///
/// Classification, re-based on the primary sources after review
/// (openconnect issue #859 and the shipping password-lane form of the
/// yuezk GlobalProtect-openconnect reference client; the earlier
/// "any present-but-empty key is a bare pre-auth 512" rule was the
/// implementer's taxonomy, not PAN's — see finding #36 review):
///
/// * **cookie-512** (bare, body `Invalid authentication cookie`): a
///   portal pass-through cookie key (`portal-userauthcookie`,
///   `portal-prelogonuserauthcookie`) present with an **empty-string
///   value** — the only present-but-empty class with real-world
///   support (yuezk substitutes a non-empty sentinel rather than ever
///   posting one empty). The header set for this class is not
///   established by the sources; the reporter's re-run, whose reject is
///   now fully logged, arbitrates the true shape.
/// * **auth-512** (`X-Private-Pan-Sslvpn: auth-failed`, body
///   `Invalid username or password`): a non-empty `passwd` that failed
///   the password engine — mirrors the reporter's wrong-password curl
///   (c). `passwd` **empty or absent** with no valid cookie/prelogin
///   secret is the openconnect #859 class: an auth-engine reject that
///   *carries* the headers plus
///   `X-Private-Pan-Sslvpn-Extension: auth-failed-password-empty`.
/// * **accept-200**: `user` + matching non-empty `passwd` + `ok=Login`,
///   the valid non-empty portal-cookie pair, or the valid
///   `prelogin-cookie`/`token` secret — mirrors the reporter's working
///   minimal curl (d), but returns the *agent* success shape (JNLP with
///   `authcookie`), not the empty 200 of the clientless contract
///   (skeptic finding 1). Present-but-empty `token=` /
///   `prelogin-cookie=` keys are **tolerated**: yuezk ships exactly
///   that shape on real gateways, and the fixed client's
///   `gateway_login_form` still omits them (mirrors upstream's
///   caller-level omission around `append_opt`, which itself writes
///   `key=` unconditionally — not a documented reject).
///
/// Hard rules honored: nothing leaves `127.0.0.1:0`; no real credentials
/// anywhere (all literals are `REDACTED-`/`MOCK-` class tokens).
/// Build the `/ssl-vpn/hipreportcheck.esp` request URL for a
/// (possibly port-bearing) gateway label (issue #43 extraction,
/// characterization-only: same `normalize_server` + `format!` the
/// method inlined before, so the URL authority keeps `:port` exactly
/// as the #42 URL lane does — the split must NEVER leak here).
pub(crate) fn hip_report_check_url(gateway: &str) -> String {
    hip_url_with_scheme("https", gateway, "hipreportcheck")
}

/// Build the `/ssl-vpn/hipreport.esp` request URL (see
/// [`hip_report_check_url`]).
pub(crate) fn hip_report_url(gateway: &str) -> String {
    hip_url_with_scheme("https", gateway, "hipreport")
}

/// Shared HIP URL builder; the scheme is a parameter purely so the
/// loopback wire tests can terminate plain HTTP (the production
/// callers hard-code `https`, same as the pre-#43 inline `format!`).
fn hip_url_with_scheme(scheme: &str, gateway: &str, endpoint: &str) -> String {
    let host = gp_proto::params::normalize_server(gateway);
    format!("{scheme}://{host}/ssl-vpn/{endpoint}.esp")
}

/// The `server=`/`host=` form values for the portal
/// `/global-protect/getconfig.esp` POST: hostname-only (issue #43
/// review, completeness finding). Upstream
/// `auth-globalprotect.c:742` sends `server=vpninfo->hostname` on
/// BOTH the portal getconfig and the gateway login, and that
/// hostname is port-free by construction (`openconnect_parse_url`) —
/// a port-bearing value risks the portal/gateway-name mismatch
/// reject class documented in params.rs (the #42 rationale applies
/// verbatim to this lane). Delegates to the ONE shared splitter via
/// `server_field`, exactly like the #42 gateway-login field; the
/// #42 URL contract is untouched (the request authority keeps the
/// port — characterized in `portal_config_lane_tests`). The no-port
/// (UNSW daily-connect) label is byte-identical to the old
/// `normalize_server` value.
pub(crate) fn portal_config_form_host(portal: &str) -> String {
    gp_proto::params::server_field(gp_proto::params::normalize_server(portal)).to_string()
}

#[cfg(test)]
mod gw_login_tests {
    use super::*;
    use gp_proto::{ClientOs, Credential};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    const EXPECTED_USER: &str = "test-user";
    const CORRECT_PASSWD: &str = "REDACTED-correct-pw";
    const WRONG_PASSWD: &str = "REDACTED-wrong-pw";
    const OTP: &str = "123456";
    const VALID_COOKIE: &str = "MOCK-portal-userauthcookie";
    const VALID_PRELOGON_COOKIE: &str = "MOCK-portal-prelogonuserauthcookie";
    const MOCK_AUTHCOOKIE: &str = "MOCK-AUTHCOOKIE-777";
    const VALID_PRELOGIN: &str = "MOCK-prelogin-cookie";
    const MOCK_TOKEN: &str = "MOCK-prisma-token";
    /// Unsubmitted server-echoed secret values (checklist M3b): the
    /// scrub must mask these by KEY NAME — value-scrubbing cannot know
    /// what the client never sent.
    const SURPRISE_COOKIE: &str = "MOCK-SURPRISE-unsubmitted-cookie";
    const SURPRISE_PRELOGIN: &str = "MOCK-SURPRISE-unsubmitted-prelogin";
    const SURPRISE_TICKET: &str = "MOCK-SURPRISE-gpsessionticket";
    /// Password with RFC-3986-reserved characters (space, @, !, &, =, +,
    /// ~) — each percent-encodes differently, so a scrub that only
    /// matches the raw string leaks the wire form (issue #36 review).
    const PW_ECHO: &str = "REDACTED p@ss!&w=+~";
    /// The same password as reqwest's `.form()` puts it on the wire
    /// (application/x-www-form-urlencoded: alphanumeric `*` `-` `.` `_`
    /// pass through, space -> `+`, the rest -> uppercase `%XX`).
    /// Hardcoded here as an independent oracle of the encoder.
    const PW_ECHO_WIRE: &str = "REDACTED+p%40ss%21%26w%3D%2B%7E";
    const PW_ECHO_WIRE_LOWER: &str = "REDACTED+p%40ss%21%26w%3D%2B%7e";
    const PW_ECHO_PCT20: &str = "REDACTED%20p@ss!&w=+~";
    const WRONG_OTP: &str = "000000";
    const INPUT_STR: &str = "MOCK+chal/enge=";
    /// MFA challenge body in the PAN agent (HTML) shape that
    /// `GatewayLoginResult::parse` recognizes (checklist S2).
    const CHALLENGE_HTML: &str = "<html><head><script>\n\
        var respStatus = \"Challenge\";\n\
        var respMsg = \"Enter the 6-digit code from your authenticator.\";\n\
        </script></head><body><form name=\"thisForm\">\n\
        <input type=\"hidden\" name=\"inputStr\">\n\
        <script>thisForm.inputStr.value = \"MOCK+challenge/token=\";</script>\n\
        </form></body></html>";
    const CHALLENGE_INPUT_STR: &str = "MOCK+challenge/token=";
    /// INPUT_STR on the urlencoded wire (`+`->`%2B`, `/`->`%2F`,
    /// `=`->`%3D`), hardcoded as the oracle for the inputStr scrub.
    const INPUT_STR_WIRE: &str = "MOCK%2Bchal%2Fenge%3D";

    /// Keys the PAN gateway treats as named secrets. The **fixed**
    /// `gateway_login_form` must never emit any of them present-but-
    /// empty (mirrors upstream's caller-level omission around
    /// `append_opt`, which itself writes `key=` unconditionally); which
    /// empty shapes the real
    /// gateway actually rejects is the re-based mock taxonomy — see
    /// module docs.
    const SECRET_KEYS: [&str; 5] = [
        "passwd",
        "token",
        "prelogin-cookie",
        "portal-userauthcookie",
        "portal-prelogonuserauthcookie",
    ];

    // ------------------------------------------------------------------
    // Credential fixtures via helpers (single edit point if the AuthCookie
    // variant gains a portal-password field in the green phase).
    // ------------------------------------------------------------------
    fn password_cred(user: &str, pw: &str) -> Credential {
        Credential::Password {
            username: user.to_string(),
            password: pw.to_string(),
        }
    }

    fn auth_cookie(user: &str, cookie: &str, prelogon: &str) -> Credential {
        Credential::AuthCookie {
            username: user.to_string(),
            user_auth_cookie: cookie.to_string(),
            prelogon_user_auth_cookie: prelogon.to_string(),
            // No portal password replayed on these fixtures: the tests
            // pin the cookie-lane shape (issue #36). The green-phase
            // to_gateway_credential replay path is covered in
            // gp-proto's portal::tests.
            password: None,
        }
    }

    fn gw_params() -> GpParams {
        GpParams {
            // Mirrors the reporter's `--insecure`; irrelevant over plain
            // http but keeps the builder path identical to production.
            ignore_tls_errors: true,
            ..GpParams::new(ClientOs::Win)
        }
    }

    // ------------------------------------------------------------------
    // Captured request
    // ------------------------------------------------------------------
    #[derive(Clone, Debug)]
    struct Captured {
        path: String,
        content_type: Option<String>,
        /// Decoded urlencoded pairs, in wire order (duplicate keys kept —
        /// the MFA double-passwd bug is only visible as a duplicate).
        pairs: Vec<(String, String)>,
    }

    impl Captured {
        fn vals(&self, key: &str) -> Vec<String> {
            self.pairs
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .collect()
        }

        fn empty_secret_keys(&self) -> Vec<&'static str> {
            SECRET_KEYS
                .iter()
                .copied()
                .filter(|k| self.pairs.iter().any(|(x, v)| x == k && v.is_empty()))
                .collect()
        }

        /// Render for assertion messages: secret values are length- or
        /// EMPTY-marked, never printed verbatim.
        fn summary(&self) -> String {
            self.pairs
                .iter()
                .map(|(k, v)| {
                    if SECRET_KEYS.contains(&k.as_str()) {
                        if v.is_empty() {
                            format!("{k}=<EMPTY>")
                        } else {
                            format!("{k}=<set,len={}>", v.len())
                        }
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    fn urldecode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' if i + 2 < bytes.len() => {
                    match u8::from_str_radix(
                        std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                        16,
                    ) {
                        Ok(b) => {
                            out.push(b);
                            i += 3;
                        }
                        Err(_) => {
                            out.push(b'%');
                            i += 1;
                        }
                    }
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn parse_form(body: &str) -> Vec<(String, String)> {
        body.split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (urldecode(k), urldecode(v))
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Mock PAN gateway
    // ------------------------------------------------------------------
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum MockMode {
        /// PAN-style auth classification (see module docs).
        Normal,
        /// Normal, but every reject also reflects the submitted
        /// **urlencoded wire form** of `passwd`/`inputStr` back into the
        /// error body and an `X-Private-Pan-Diag` header — the
        /// hostile/verbose-gateway shape the redaction rule must survive
        /// (issue #36 review).
        EchoReject,
        /// Gateway under maintenance: 503, no X-Private-Pan-* headers —
        /// transient class, must keep the exit-3 contract (issue #36
        /// review, error-classification finding).
        Transient503,
        /// 503 that does carry `X-Private-Pan-Sslvpn: auth-failed` — an
        /// auth reject on an unusual status must still classify as
        /// credential failure.
        AuthFailed503,
        /// 403 with no PAN headers and no body auth claim: checklist
        /// M2 — a bare 4xx is NOT a credential reject by status class
        /// alone; it keeps the Server/exit-3 infrastructure lane.
        Forbidden403,
        /// 512 that declares a 1 MiB body, sends only 8 KiB, then sits
        /// silent for 5 seconds: the diagnostic read must be CAPPED —
        /// only a client that stops at the cap returns promptly, while
        /// the legacy full `.text()` stream waits out the stall (and
        /// chokes on the truncated stream). Loopback write-buffering
        /// makes a naive "did the server's write fail" check
        /// non-deterministic; this shape is deterministic either way.
        Trickle512,
        /// Checklist S1: chunked 512 that streams **exactly** the
        /// DIAG_BODY_MAX_BYTES cap and then parks WITHOUT the
        /// terminating zero-chunk (no close, no more bytes). A reader
        /// that checks the cap only after `chunk().await` blocks until
        /// the request timeout and dies as `AuthError::Http`, losing
        /// the status+headers diagnostic it already had.
        ParkedBody4096,
        /// Checklist M3b: a 512 whose body ECHOES secret-keyed values
        /// the client never submitted (`portal-userauthcookie=…`,
        /// `prelogin-cookie=…`, a session-ticket value). Value-based
        /// scrubbing cannot know these strings; only the key-name
        /// mask keeps them out of logs and the user-visible error.
        EchoUnsubmitted,
        /// Checklist S2: an MFA gateway — the first agent login (real
        /// passwd, no inputStr) answers 200 with the CHALLENGE HTML;
        /// the retry carrying inputStr + the OTP as the single passwd
        /// gets the JNLP authcookie. Mirrors the main.rs retry loop.
        ChallengeThenOtp,
    }

    struct MockConfig {
        expected_user: &'static str,
        expected_passwd: &'static str,
        cookie: &'static str,
        prelogon_cookie: &'static str,
        prelogin_cookie: &'static str,
        token: &'static str,
        mode: MockMode,
    }

    struct MockResp {
        status: u16,
        /// X-Private-Pan-* class headers to emit (plus the reflected
        /// `X-Private-Pan-Diag` header in EchoReject mode). No PAN
        /// headers at all means the cookie/maintenance classes — the
        /// reporter's blind spot under the old `.error_for_status()?`
        /// code, which could not observe any of these.
        pan_headers: Vec<(String, String)>,
        body: String,
    }

    /// Pull the **raw urlencoded** value of `key` out of the request
    /// body (not percent-decoded): this is the exact string a reflecting
    /// gateway would echo, including `%XX` encodings.
    fn wire_value(raw_body: &str, key: &str) -> String {
        let prefix = format!("{key}=");
        raw_body
            .split('&')
            .find_map(|kv| kv.strip_prefix(&prefix))
            .unwrap_or_default()
            .to_string()
    }

    fn classify(pairs: &[(String, String)], cfg: &MockConfig, raw_body: &str) -> MockResp {
        let jnlp = |user: &str| {
            format!(
                "<jnlp><application-desc><argument>10.0.0.5</argument>\
                 <argument>{MOCK_AUTHCOOKIE}</argument><argument>x</argument>\
                 <argument>portal.example.com</argument><argument>{user}</argument>\
                 </application-desc></jnlp>"
            )
        };
        match cfg.mode {
            MockMode::Transient503 => {
                return MockResp {
                    status: 503,
                    pan_headers: Vec::new(),
                    body: "<html>Service Unavailable</html>".to_string(),
                }
            }
            MockMode::AuthFailed503 => {
                return MockResp {
                    status: 503,
                    pan_headers: vec![(
                        "x-private-pan-sslvpn".to_string(),
                        "auth-failed".to_string(),
                    )],
                    body: "<response status=\"error\"><error>Invalid username or password</error></response>".to_string(),
                }
            }
            MockMode::Forbidden403 => {
                return MockResp {
                    status: 403,
                    pan_headers: Vec::new(),
                    body: "<html>Forbidden</html>".to_string(),
                }
            }
            MockMode::EchoUnsubmitted => {
                // Values the client NEVER submitted: a rotated portal
                // cookie, a fresh prelogin secret, a session ticket and
                // a Set-Cookie-style blob. Only the key-name mask
                // stands between them and the log line (M3b).
                return MockResp {
                    status: 512,
                    pan_headers: vec![(
                        "x-private-pan-sslvpn".to_string(),
                        "auth-failed".to_string(),
                    )],
                    body: format!(
                        "<response status=\"error\"><error>Invalid username or password</error></response> \
                         |echo portal-userauthcookie={SURPRISE_COOKIE} \
                         prelogin-cookie={SURPRISE_PRELOGIN} \
                         gpsessionticket={SURPRISE_TICKET}|"
                    ),
                }
            }
            // Trickle512/ParkedBody4096 never reach classification:
            // handle_login short-circuits with the raw stream first.
            MockMode::Trickle512 | MockMode::ParkedBody4096 => {
                unreachable!("handle_login intercepts raw-stream modes")
            }
            MockMode::Normal | MockMode::EchoReject | MockMode::ChallengeThenOtp => {}
        }

        let value = |k: &str| pairs.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());
        let field_ok = matches!(value("ok"), None | Some("Login"));
        let user = value("user").unwrap_or("");
        // Checklist S2 (reporter-faithful oracle): the JAVA/AGENT
        // contract answers success with a JNLP (authcookie in
        // argument[1]); the reporter's CLIENTLESS minimal curl saw the
        // EXACT empty 200 (Content-Length: 0). Presence of the agent
        // markers is what discriminates the two shapes — the client's
        // own form (gateway_login_form) always carries them.
        let agent_form = pairs
            .iter()
            .any(|(k, _)| k == "clientVer" || k == "jnlpReady");
        let success_body = |user: &str| {
            if agent_form {
                jnlp(user)
            } else {
                String::new()
            }
        };

        // Cookie-512 class: an empty-string VALUE on a portal
        // pass-through cookie key is the one present-but-empty shape
        // with real-world grounding (yuezk substitutes a non-empty
        // sentinel rather than ever posting one empty). Empty
        // `token=`/`prelogin-cookie=` are tolerated — yuezk ships them —
        // and an empty/absent `passwd` reaches the auth engine below.
        if ["portal-userauthcookie", "portal-prelogonuserauthcookie"]
            .iter()
            .any(|k| value(k) == Some(""))
        {
            return MockResp {
                status: 512,
                pan_headers: Vec::new(),
                body: "<response status=\"error\"><error>Invalid authentication cookie</error></response>".to_string(),
            };
        }

        // S2 MFA gate: the first password-correct login without an
        // inputStr answers 200 + challenge HTML; the OTP retry falls
        // through to the normal lanes below.
        if cfg.mode == MockMode::ChallengeThenOtp
            && user == cfg.expected_user
            && field_ok
            && value("passwd") == Some(CORRECT_PASSWD)
            && value("inputStr").unwrap_or_default().is_empty()
        {
            return MockResp {
                status: 200,
                pan_headers: Vec::new(),
                body: CHALLENGE_HTML.to_string(),
            };
        }

        let mut resp = match value("passwd") {
            Some(pw) if !pw.is_empty() => {
                // auth engine lane
                if user == cfg.expected_user && pw == cfg.expected_passwd && field_ok {
                    MockResp {
                        status: 200,
                        pan_headers: Vec::new(),
                        body: success_body(user),
                    }
                } else {
                    MockResp {
                        status: 512,
                        pan_headers: vec![(
                            "x-private-pan-sslvpn".to_string(),
                            "auth-failed".to_string(),
                        )],
                        body: "<response status=\"error\"><error>Invalid username or password</error></response>".to_string(),
                    }
                }
            }
            // `passwd` empty OR absent reaching the auth engine —
            // openconnect #859's auth-failed-password-empty class —
            // unless the cookie pair or the prelogin/token secret
            // authenticates on its own lane.
            _ => {
                let named_secret_lane = user == cfg.expected_user
                    && field_ok
                    && (value("prelogin-cookie") == Some(cfg.prelogin_cookie)
                        || value("token") == Some(cfg.token));
                let cookie_lane = user == cfg.expected_user
                    && field_ok
                    && value("portal-userauthcookie") == Some(cfg.cookie)
                    && value("portal-prelogonuserauthcookie") == Some(cfg.prelogon_cookie);
                if named_secret_lane || cookie_lane {
                    MockResp {
                        status: 200,
                        pan_headers: Vec::new(),
                        body: jnlp(user),
                    }
                } else {
                    MockResp {
                        status: 512,
                        pan_headers: vec![
                            (
                                "x-private-pan-sslvpn".to_string(),
                                "auth-failed".to_string(),
                            ),
                            (
                                "x-private-pan-sslvpn-extension".to_string(),
                                "auth-failed-password-empty".to_string(),
                            ),
                        ],
                        body: "<response status=\"error\"><error>Invalid username or password</error></response>".to_string(),
                    }
                }
            }
        };

        if cfg.mode == MockMode::EchoReject && resp.status != 200 {
            // Reflect the submitted wire values verbatim — including
            // their percent-encodings — into both the body and a PAN-style
            // header: the worst realistic echo of the POST we just sent.
            let pw_echo = wire_value(raw_body, "passwd");
            let tok_echo = wire_value(raw_body, "inputStr");
            resp.body = format!(
                "{}|reflected passwd={pw_echo} inputStr={tok_echo}|",
                resp.body
            );
            resp.pan_headers.push((
                "x-private-pan-diag".to_string(),
                format!("passwd={pw_echo};inputStr={tok_echo}"),
            ));
        }
        resp
    }

    struct MockGateway {
        addr: SocketAddr,
        captures: Arc<Mutex<Vec<Captured>>>,
    }

    impl MockGateway {
        fn start(expected_user: &'static str, expected_passwd: &'static str) -> Self {
            Self::start_mode(expected_user, expected_passwd, MockMode::Normal)
        }

        fn start_mode(
            expected_user: &'static str,
            expected_passwd: &'static str,
            mode: MockMode,
        ) -> Self {
            let cfg = Arc::new(MockConfig {
                expected_user,
                expected_passwd,
                cookie: VALID_COOKIE,
                prelogon_cookie: VALID_PRELOGON_COOKIE,
                prelogin_cookie: VALID_PRELOGIN,
                token: MOCK_TOKEN,
                mode,
            });
            let captures = Arc::new(Mutex::new(Vec::new()));
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("bind localhost mock on ephemeral port");
            let addr = listener.local_addr().expect("local_addr");
            let (cap_t, cfg_t) = (captures.clone(), cfg.clone());
            std::thread::Builder::new()
                .name("test-gw-login-mock".into())
                .spawn(move || {
                    for stream in listener.incoming().flatten() {
                        let (cap, cfg) = (cap_t.clone(), cfg_t.clone());
                        // One request per connection (we answer with
                        // Connection: close); a per-connection thread keeps
                        // a stalled client from serialising the suite.
                        std::thread::spawn(move || {
                            let _ = handle_login(stream, &cfg, &cap);
                        });
                    }
                })
                .expect("spawn mock accept loop");
            Self { addr, captures }
        }

        fn url(&self) -> String {
            format!("http://{}/ssl-vpn/login.esp", self.addr)
        }

        fn server_field(&self) -> String {
            self.addr.to_string()
        }

        fn only_capture(&self) -> Captured {
            let v = self.captures.lock().unwrap();
            assert_eq!(
                v.len(),
                1,
                "expected exactly one login.esp POST at the mock, got {}",
                v.len()
            );
            v[0].clone()
        }
    }

    fn handle_login(
        mut stream: TcpStream,
        cfg: &MockConfig,
        captures: &Mutex<Vec<Captured>>,
    ) -> std::io::Result<()> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        // Response-write bound: with a capped diagnostic read the client
        // stops draining the (huge) body and drops the connection; the
        // mock's remaining write_all must fail — reset or, worst case on
        // a FIN-without-drain, this write timeout — so
        // write_errs becomes a deterministic signal, never a hang.
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut req_line = String::new();
        if reader.read_line(&mut req_line)? == 0 {
            return Ok(());
        }
        let path = req_line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut content_type = None;
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            if line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => content_length = v.trim().parse().unwrap_or(0),
                    "content-type" => content_type = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        let mut buf = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut buf)?;
        }
        let raw_body = String::from_utf8_lossy(&buf).into_owned();
        let pairs = parse_form(&raw_body);
        captures.lock().unwrap().push(Captured {
            path,
            content_type,
            pairs: pairs.clone(),
        });

        if cfg.mode == MockMode::ParkedBody4096 {
            // Checklist S1 fixture: exactly DIAG_BODY_MAX_BYTES in one
            // complete chunked frame, then the stream parks with no
            // terminator for 6s. The capped reader must break BEFORE
            // the next `chunk().await` and return status+headers now;
            // only a client that awaits another chunk stalls out into
            // a transport error with no diagnostics at all.
            let head = "HTTP/1.1 512 Custom Error\r\n\
                        x-private-pan-sslvpn: auth-failed\r\n\
                        content-type: application/xml\r\n\
                        transfer-encoding: chunked\r\n\
                        connection: close\r\n\r\n";
            stream.write_all(head.as_bytes())?;
            stream.write_all(b"1000\r\n")?;
            stream.write_all(&[b'B'; 4096])?;
            stream.write_all(b"\r\n")?;
            stream.flush()?;
            std::thread::sleep(Duration::from_secs(6));
            // No terminating zero-chunk, ever: the stream is truncated.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }

        if cfg.mode == MockMode::Trickle512 {
            // Declared 1 MiB, only 8 KiB ever sent, then a 5s stall: a
            // client that streams the whole body into memory (the
            // pre-fix `.text()` behaviour) waits out the stall and
            // errors on truncation; the capped diagnostic reader takes
            // its head and returns in milliseconds.
            let head = "HTTP/1.1 512 Custom Error\r\n\
                        x-private-pan-sslvpn: auth-failed\r\n\
                        content-type: application/xml\r\n\
                        content-length: 1048576\r\n\
                        connection: close\r\n\r\n";
            stream.write_all(head.as_bytes())?;
            stream.write_all(&[b'B'; 8192])?;
            stream.flush()?;
            std::thread::sleep(Duration::from_secs(5));
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }

        let resp = classify(&pairs, cfg, &raw_body);
        let reason = if resp.status == 200 {
            "OK"
        } else {
            "Custom Error"
        };
        let body_bytes = resp.body.into_bytes();
        let mut out = format!("HTTP/1.1 {} {reason}\r\n", resp.status).into_bytes();
        for (k, v) in &resp.pan_headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "content-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body_bytes.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&body_bytes);
        stream.write_all(&out)?;
        stream.flush()?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    async fn login_via_seam(
        client: &GpClient,
        mock: &MockGateway,
        cred: &Credential,
    ) -> Result<GatewayLoginResult, AuthError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            client.gateway_login_url(&mock.url(), &mock.server_field(), cred),
        )
        .await
        .expect("gateway_login hung against the localhost mock (>10s)")
    }

    // ------------------------------------------------------------------
    // GREEN anchor: the mock's classification reproduces the reporter's
    // own control experiments (issue #36 datapoints (c) and (d)).
    // ------------------------------------------------------------------

    /// Sanity-check the mock itself with the reporter's two curl controls,
    /// bypassing `gateway_login` entirely. Expected to PASS today.
    #[tokio::test]
    async fn mock_gateway_reproduces_reporter_curl_controls() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let http = reqwest::Client::new();

        // (c) wrong password, minimal 3-field form -> 512 +
        // X-Private-Pan-Sslvpn: auth-failed + 'Invalid username or password'
        let r = http
            .post(mock.url())
            .form(&[
                ("user", EXPECTED_USER),
                ("passwd", WRONG_PASSWD),
                ("ok", "Login"),
            ])
            .send()
            .await
            .expect("control POST (c)");
        assert_eq!(r.status().as_u16(), 512, "wrong-pw control must be a 512");
        assert_eq!(
            r.headers()
                .get("x-private-pan-sslvpn")
                .and_then(|v| v.to_str().ok()),
            Some("auth-failed"),
            "wrong-pw control must carry the auth-failed discriminator header"
        );
        assert!(
            r.text()
                .await
                .unwrap()
                .contains("Invalid username or password"),
            "wrong-pw control body must name the password engine's verdict"
        );

        // (d) correct password, **minimal** (clientless) form -> the
        // reporter's EXACT control: 200 OK, Content-Length: 0, no JNLP
        // body (checklist S2 oracle fix: the previous mock answered the
        // minimal form with a JNLP, which is not what the field
        // showed). A form carrying the agent markers (clientVer /
        // jnlpReady) is the Java/agent contract and gets JNLP; pinned
        // as a separate case below.
        let r2 = http
            .post(mock.url())
            .form(&[
                ("user", EXPECTED_USER),
                ("passwd", CORRECT_PASSWD),
                ("ok", "Login"),
            ])
            .send()
            .await
            .expect("control POST (d)");
        assert!(r2.status().is_success(), "correct-pw control must be 200");
        assert_eq!(
            r2.headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("0"),
            "reporter's control (d) was an EXACT empty 200"
        );
        assert!(
            r2.text().await.unwrap().is_empty(),
            "minimal-form success must carry NO JNLP body (clientless contract)"
        );

        // Agent-shape success (client markers present) -> JNLP with the
        // authcookie. This is what opc's gateway_login_form sends, and
        // the only success shape an agent can complete on.
        let r3 = http
            .post(mock.url())
            .form(&[
                ("user", EXPECTED_USER),
                ("passwd", CORRECT_PASSWD),
                ("ok", "Login"),
                ("jnlpReady", "jnlpReady"),
                ("clientVer", "4100"),
            ])
            .send()
            .await
            .expect("agent-form POST (d')");
        assert!(r3.status().is_success(), "agent correct-pw must be 200");
        assert!(
            r3.text().await.unwrap().contains(MOCK_AUTHCOOKIE),
            "agent-login success must carry the JNLP authcookie"
        );
    }

    // ------------------------------------------------------------------
    // RED for the request-shape root cause (empty credential keys) and
    // the response-diagnostics gap.
    // ------------------------------------------------------------------

    /// The password-carrying gateway login (what the reporter's working
    /// curl sent, and what the reference clients replay at the gateway)
    /// must produce an agent success AND must never post a present-but-
    /// empty credential key. RED today: `Credential::to_params`
    /// hard-emits `token=`/`prelogin-cookie=`/`portal-*cookie=` empty
    /// (credential.rs:47-54) — the empty portal-cookie values hit the
    /// mock's cookie-512 reject class (the one present-but-empty shape
    /// with source grounding), and with no cookies issued the POST
    /// carried zero real secret material (issue #36).
    #[tokio::test]
    async fn gateway_login_password_form_is_accepted_by_mock_gateway() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);

        let res = login_via_seam(&client, &mock, &cred).await;
        let cap = mock.only_capture();

        assert_eq!(
            cap.path, "/ssl-vpn/login.esp",
            "gateway login must target the gateway login.esp endpoint, never \
             a portal interface path (openconnect #151/#180 reject class)"
        );
        let empties = cap.empty_secret_keys();
        assert!(
            empties.is_empty(),
            "issue #36: gateway login posted present-but-empty credential keys \
             {empties:?} (upstream omits such keys at the gpst_login CALLERS; \
             append_opt itself writes key= unconditionally); posted: {}",
            cap.summary()
        );
        assert_eq!(
            cap.vals("passwd"),
            vec![CORRECT_PASSWD.to_string()],
            "exactly one non-empty passwd key expected; posted: {}",
            cap.summary()
        );
        assert!(
            cap.content_type
                .as_deref()
                .unwrap_or_default()
                .starts_with("application/x-www-form-urlencoded"),
            "login.esp Content-Type must stay urlencoded; got {:?}",
            cap.content_type
        );

        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE);
                assert_eq!(cookie.username, EXPECTED_USER);
            }
            Ok(GatewayLoginResult::MfaChallenge { message, .. }) => {
                panic!("unexpected MFA challenge: {message}");
            }
            Err(e) => panic!(
                "issue #36 root cause: gateway login must be accepted when it \
                 carries the real password; got Err({e})\nposted: {}",
                cap.summary()
            ),
        }
    }

    /// A present-but-wrong password must reach the auth engine and opc
    /// must surface the discriminating evidence: the full URL (incl.
    /// resolved port), the numeric status, the X-Private-Pan-Sslvpn
    /// header and a body head. RED today: `.error_for_status()?`
    /// (client.rs) converts the 512 into `AuthError::Http` before any
    /// header/body read, yielding only the reporter's verbatim bare
    /// 'HTTP request failed: HTTP status server error (512 status code
    /// 512)' string.
    #[tokio::test]
    async fn gateway_login_512_error_exposes_pan_headers_and_body() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, WRONG_PASSWD);

        let res = login_via_seam(&client, &mock, &cred).await;
        let e = match res {
            Err(e) => e,
            Ok(ok) => panic!("wrong password must not authenticate, got {ok:?}"),
        };
        // Sanity today (and after the fix): the failure carries the 512.
        assert!(
            e.to_string().contains("512"),
            "error must name the status code; got: {e}"
        );
        let es = e.to_string();
        assert!(
            es.contains("auth-failed"),
            "FINDING #1 (issue #36): the 512's X-Private-Pan-Sslvpn header \
             must be observable to the user; error was: {es}"
        );
        assert!(
            es.contains("Invalid username or password"),
            "FINDING #1 (issue #36): the 512 body head must be observable; \
             error was: {es}"
        );
        assert!(
            es.contains(&mock.addr.port().to_string()),
            "FINDING #1 (issue #36): the error must name the full request URL \
             incl. resolved port so reporter-side port blindness (443 vs \
             11443) is answerable from logs; error was: {es}"
        );
    }

    /// The reporter-path credential — `Credential::AuthCookie` with the
    /// portal having issued NOTHING (both cookies empty, as happens when
    /// the getconfig XML lacks the elements; portal.rs:34-41) — must
    /// (a) not post a single present-but-empty secret key, and (b) fail
    /// with an error that names its reject class, not a bare status.
    /// RED today on both counts.
    #[tokio::test]
    async fn gateway_login_cookieless_auth_credential_never_posts_empty_secrets() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = auth_cookie(EXPECTED_USER, "", "");

        let res = login_via_seam(&client, &mock, &cred).await;
        let cap = mock.only_capture();

        let empties = cap.empty_secret_keys();
        assert!(
            empties.is_empty(),
            "issue #36: the credential-less gateway login posted {} empty \
             credential key(s) {empties:?} — a credential-less form must send \
             NONE of them (upstream's gpst_login CALLERS skip empty options; \
             append_opt itself writes `key=` unconditionally); posted: {}",
            empties.len(),
            cap.summary()
        );
        assert!(
            res.is_err(),
            "a gateway login carrying zero non-empty credential material must \
             not report success; the mock would have accepted nothing anyway"
        );
        let es = res.unwrap_err().to_string();
        assert!(
            es.contains("auth-failed") || es.contains("Invalid authentication cookie"),
            "FINDING #1 (issue #36): the error must classify the 512 (auth-\
             failed vs pre-auth reject) via header/body evidence; bare \
             status is what made #36 unanswerable. Error was: {es}"
        );
        assert!(
            es.contains(&mock.addr.port().to_string()),
            "FINDING #1 (issue #36): the error must include the full URL \
             (port visible); error was: {es}"
        );
    }

    /// When the portal DID issue both pass-through cookies, an
    /// `AuthCookie` gateway login must succeed on the cookie lane even
    /// with no portal password available — i.e. the client must not
    /// poison the request with an empty `passwd=` key. RED today:
    /// `Credential::to_params` emits `passwd=""` (credential.rs:49),
    /// tripping the mock's present-but-empty reject rule.
    #[tokio::test]
    async fn gateway_login_valid_portal_cookies_are_accepted_without_empty_passwd() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = auth_cookie(EXPECTED_USER, VALID_COOKIE, VALID_PRELOGON_COOKIE);

        let res = login_via_seam(&client, &mock, &cred).await;
        let cap = mock.only_capture();

        let empties = cap.empty_secret_keys();
        assert!(
            empties.is_empty(),
            "issue #36: cookie-auth login must not send any empty secret key \
             (mirrors upstream's caller-level omission around append_opt, \
             which itself writes `key=` unconditionally; an empty passwd \
             *reaching the engine* is the openconnect #859 auth-failed \
             class); \
             found {empties:?}; posted: {}",
            cap.summary()
        );
        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE);
            }
            other => panic!(
                "valid portal-issued cookies must authenticate on the cookie \
                 lane; got {other:?}\nposted: {}",
                cap.summary()
            ),
        }
    }

    /// The MFA-retry shape (main.rs sets `otp` on a gateway client whose
    /// credential is still `AuthCookie`): the assembled form must carry
    /// EXACTLY ONE `passwd` key equal to the OTP. RED today: `to_params`
    /// pushes `passwd=123456` (params.rs:137-139) and then
    /// `cred.to_params()` appends a second `passwd=` empty
    /// (credential.rs:49) — first/last-wins parse decides whether the
    /// OTP survives.
    #[tokio::test]
    async fn gateway_login_mfa_retry_posts_single_passwd() {
        // The gateway's second factor validates the OTP as the passwd.
        let mock = MockGateway::start(EXPECTED_USER, OTP);
        let mut params = gw_params();
        params.otp = Some(OTP.to_string());
        let client = GpClient::new(params).expect("build GpClient");
        let cred = auth_cookie(EXPECTED_USER, VALID_COOKIE, VALID_PRELOGON_COOKIE);

        let res = login_via_seam(&client, &mock, &cred).await;
        let cap = mock.only_capture();

        assert_eq!(
            cap.vals("passwd"),
            vec![OTP.to_string()],
            "issue #36 MFA defect: the retry form must contain exactly one \
             passwd key (the OTP); duplicates make the outcome parse-order \
             dependent. posted: {}",
            cap.summary()
        );
        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE);
            }
            other => panic!(
                "MFA retry with the OTP must reach the auth engine and \
                 succeed; got {other:?}\nposted: {}",
                cap.summary()
            ),
        }
    }

    // ------------------------------------------------------------------
    // Issue #36 review: taxonomy re-base (yuezk shipping shape /
    // openconnect #859 header classes), redaction of echoed wire
    // renderings, inputStr scrubbing, error-class preservation, and
    // bounded error-body reads.
    // ------------------------------------------------------------------

    /// The yuezk reference client's SHIPPING password-lane form — real
    /// `passwd`, present-but-empty `token=` / `prelogin-cookie=`, and
    /// non-empty sentinel values for the portal cookies — authenticates
    /// on real PAN gateways. The mock must classify it as success, or
    /// the oracle encodes the implementer's taxonomy instead of the
    /// references' and #36's root cause stays unproven. Raw POST,
    /// bypassing the client.
    #[tokio::test]
    async fn mock_gateway_accepts_yuezk_shipping_form_shape() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let http = reqwest::Client::new();
        // The real yuezk client is a FULL agent (it ships the standard
        // agent fields), which is the JNLP contract lane per S2; the
        // tolerated-shape payload under test is the empty token= /
        // prelogin-cookie= and the literal `empty` sentinel cookies.
        let r = http
            .post(mock.url())
            .form(&[
                ("user", EXPECTED_USER),
                ("passwd", CORRECT_PASSWD),
                ("ok", "Login"),
                ("jnlpReady", "jnlpReady"),
                ("clientVer", "4100"),
                ("token", ""),
                ("prelogin-cookie", ""),
                ("portal-userauthcookie", "empty"),
                ("portal-prelogonuserauthcookie", "empty"),
            ])
            .send()
            .await
            .expect("yuezk-shape POST (localhost mock)");
        assert!(
            r.status().is_success(),
            "present-but-empty token=/prelogin-cookie= must be tolerated \
             (yuezk ships this exact shape and it authenticates); got {}",
            r.status()
        );
        assert!(
            r.text().await.unwrap().contains(MOCK_AUTHCOOKIE),
            "yuezk-shape accept must return the agent JNLP authcookie"
        );
    }

    /// openconnect #859 class: a `passwd` absent/empty that reaches the
    /// auth engine is an AUTH reject — it carries
    /// `X-Private-Pan-Sslvpn: auth-failed` and the
    /// `auth-failed-password-empty` extension; it is NOT the headerless
    /// shape. Pinned with a raw POST so the taxonomy cannot silently
    /// drift.
    #[tokio::test]
    async fn mock_gateway_flags_absent_passwd_with_859_auth_failed_headers() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let http = reqwest::Client::new();
        let r = http
            .post(mock.url())
            .form(&[("user", EXPECTED_USER), ("ok", "Login")])
            .send()
            .await
            .expect("absent-passwd POST (localhost mock)");
        assert_eq!(r.status().as_u16(), 512, "must be the 512 class");
        let h = r.headers();
        assert_eq!(
            h.get("x-private-pan-sslvpn").and_then(|v| v.to_str().ok()),
            Some("auth-failed"),
            "#859: empty/absent passwd is an auth-engine reject WITH headers"
        );
        assert_eq!(
            h.get("x-private-pan-sslvpn-extension")
                .and_then(|v| v.to_str().ok()),
            Some("auth-failed-password-empty"),
            "#859: the password-empty extension must be present"
        );
    }

    /// The SAML/Prelogin lane reaches the gateway with its real secret
    /// and authenticates end-to-end through the client seam (issue #36
    /// review: `to_gateway_credential` used to coerce this credential
    /// into an empty AuthCookie, leaving the lane credential-less).
    #[tokio::test]
    async fn gateway_login_prelogin_credential_is_accepted_via_mock() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = Credential::Prelogin {
            username: EXPECTED_USER.into(),
            prelogin_cookie: Some(VALID_PRELOGIN.into()),
            token: None,
        };
        match login_via_seam(&client, &mock, &cred).await {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE)
            }
            other => panic!("valid prelogin-cookie must authenticate; got {other:?}"),
        }
    }

    /// The Prisma token lane through the seam.
    #[tokio::test]
    async fn gateway_login_token_credential_is_accepted_via_mock() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = Credential::Prelogin {
            username: EXPECTED_USER.into(),
            prelogin_cookie: None,
            token: Some(MOCK_TOKEN.into()),
        };
        match login_via_seam(&client, &mock, &cred).await {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE)
            }
            other => panic!("valid token must authenticate; got {other:?}"),
        }
    }

    /// A reflecting gateway echoes the **urlencoded wire** of the POST,
    /// so a scrub that matches only the raw password leaks the percent-
    /// encoded secret into the WARN line and the user-visible error the
    /// reporter pastes into issues (findings #36/3/7/8). The echo must
    /// be visibly REDACTED, never the secret in any rendering.
    #[tokio::test]
    async fn gateway_login_echoed_urlencoded_secret_never_reaches_error_or_log() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::EchoReject);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, PW_ECHO);
        let e = match login_via_seam(&client, &mock, &cred).await {
            Err(e) => e,
            Ok(ok) => panic!("non-matching password must not succeed; got {ok:?}"),
        };
        let es = e.to_string();
        assert!(
            es.contains("reflected"),
            "the mock's echo must have landed in the body head (otherwise \
             the absence asserts are vacuous): {es}"
        );
        for needle in [PW_ECHO, PW_ECHO_WIRE, PW_ECHO_WIRE_LOWER, PW_ECHO_PCT20] {
            assert!(
                !es.contains(needle),
                "issue #36 leak: rendering {needle:?} of the submitted \
                 password survived scrubbing in: {es}"
            );
        }
        assert!(
            es.contains("[REDACTED]"),
            "scrubbed echo must mark redaction; got: {es}"
        );
        // Still fully diagnosable:
        assert!(es.contains("auth-failed"), "{es}");
        assert!(es.contains("reflected passwd=[REDACTED]"), "{es}");
        // Checklist M3c: headers OUTSIDE the explicit allow-list are
        // never logged — the mock reflects a secret-bearing
        // X-Private-Pan-Diag header (and any other gateway could echo
        // an X-Pan-* one); neither name may surface in the error.
        assert!(
            !es.contains("x-private-pan-diag"),
            "non-allow-listed X-Private-Pan-* header leaked into: {es}"
        );
    }

    /// `inputStr` (the gateway's own MFA challenge token) is scrub-only
    /// material: a reflecting gateway must not get it back into logs or
    /// the error, and the OTP `passwd` is scrubbed too.
    #[tokio::test]
    async fn gateway_login_echoed_mfa_inputstr_and_otp_are_redacted() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::EchoReject);
        let mut params = gw_params();
        params.otp = Some(WRONG_OTP.to_string());
        params.input_str = Some(INPUT_STR.to_string());
        let client = GpClient::new(params).expect("build GpClient");
        let cred = auth_cookie(EXPECTED_USER, VALID_COOKIE, VALID_PRELOGON_COOKIE);
        let e = login_via_seam(&client, &mock, &cred)
            .await
            .expect_err("wrong OTP must reject");
        let es = e.to_string();
        assert!(
            es.contains("reflected"),
            "echo must be present so the absence asserts bite: {es}"
        );
        assert!(
            !es.contains(INPUT_STR_WIRE),
            "inputStr wire rendering leaked into the error: {es}"
        );
        assert!(
            !es.contains(INPUT_STR),
            "inputStr raw rendering leaked: {es}"
        );
        assert!(!es.contains(WRONG_OTP), "OTP passwd leaked: {es}");
    }

    /// Checklist M3b: a gateway whose 512 body echoes secret-keyed
    /// values the client never submitted must not get them into the
    /// error text (the reporter pastes these strings into issues).
    /// Value-scrubbing is blind to these; the key-name mask is not.
    #[tokio::test]
    async fn gateway_login_unsubmitted_echoed_cookie_values_are_masked() {
        let mock =
            MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::EchoUnsubmitted);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, WRONG_PASSWD);
        let e = match login_via_seam(&client, &mock, &cred).await {
            Err(e) => e,
            Ok(ok) => panic!("512 must reject, got {ok:?}"),
        };
        let es = e.to_string();
        // Non-vacuity: the echo really landed in the diagnostic path,
        // with the key visible and its value masked.
        assert!(
            es.contains("portal-userauthcookie="),
            "echo never reached the error text (assertion vacuous): {es}"
        );
        assert!(
            es.contains("portal-userauthcookie=[REDACTED]"),
            "key must survive, value must be masked: {es}"
        );
        for unsubmitted in [SURPRISE_COOKIE, SURPRISE_PRELOGIN, SURPRISE_TICKET] {
            assert!(
                !es.contains(unsubmitted),
                "issue #36 M3b leak: unsubmitted server-echoed value \
                 {unsubmitted:?} survived scrubbing in: {es}"
            );
        }
        // Still diagnosable: the discriminator and the verdict stay.
        assert!(es.contains("auth-failed"), "{es}");
        assert!(es.contains("Invalid username or password"), "{es}");
    }

    /// Checklist M3d: prelogin must carry the SAME non-2xx diagnostics
    /// as gateway_login — status, allow-listed headers, body head. The
    /// old `.error_for_status()?` discarded all three (the previous
    /// report claimed prelogin was covered; it was not: client.rs kept
    /// the chain there). Also pins M2 classification on this call.
    #[tokio::test]
    async fn prelogin_error_exposes_status_headers_and_body() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::AuthFailed503);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let url = format!("http://{}/global-protect/prelogin.esp", mock.addr);
        let e = tokio::time::timeout(Duration::from_secs(10), client.prelogin_at(&url))
            .await
            .expect("prelogin hung against the localhost mock")
            .expect_err("503 with an auth signal must reject");
        let es = e.to_string();
        assert!(es.contains("503"), "status missing: {es}");
        assert!(
            es.contains("auth-failed"),
            "M3d: the discriminator HEADER must be observable on prelogin \
             rejects (error_for_status discarded it): {es}"
        );
        assert!(
            es.contains("Invalid username or password"),
            "M3d: the body head must be observable on prelogin rejects: {es}"
        );
        assert!(
            es.contains(&mock.addr.port().to_string()),
            "M3d: full URL (port visible): {es}"
        );
        // M2 semantics on this call site: an auth-failed VALUE claims
        // the credential lane even on a 503.
        assert!(
            matches!(e, AuthError::Failed(_)),
            "auth-signal 503 at prelogin must classify Failed; got {e:?}"
        );
    }

    /// Checklist M3d: with no auth claim anywhere, prelogin 4xx/5xx
    /// keeps the LEGACY exit lane — pre-3a50d75 the `.error_for_status()?`
    /// made these `AuthError::Http` → GATEWAY_UNREACHABLE (exit 3);
    /// `AuthError::Server` maps to the same exit code in
    /// bins/opc/src/main.rs `classify_exit_code`.
    #[tokio::test]
    async fn prelogin_plain_5xx_without_auth_claim_stays_infrastructure() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::Transient503);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let url = format!("http://{}/global-protect/prelogin.esp", mock.addr);
        let e = tokio::time::timeout(Duration::from_secs(10), client.prelogin_at(&url))
            .await
            .expect("prelogin hung against the localhost mock")
            .expect_err("503 must reject");
        assert!(
            matches!(e, AuthError::Server(_)),
            "no-claim 5xx must be Server (exit-3 infrastructure lane, same \
             as the legacy Http via classify_exit_code); got {e:?}"
        );
        let es = e.to_string();
        assert!(es.contains("503"), "{es}");
        assert!(
            es.contains("no X-Private-Pan-Sslvpn header"),
            "header absence must be stated: {es}"
        );
        assert!(es.contains("Service Unavailable"), "body head: {es}");
    }

    /// Issue #36 review (no-regression, exit codes): a 5xx with no
    /// X-Private-Pan-Sslvpn auth signal is a transient server condition
    /// (maintenance window, proxy fault). It must NOT be classified as
    /// a credential failure — the legacy `.error_for_status()?` produced
    /// an `Http` error (opc exit 3, GATEWAY_UNREACHABLE, "retry \
    /// later"), and `AuthError::Server` keeps that contract while the
    /// diagnostics go into the message.
    #[tokio::test]
    async fn gateway_login_transient_503_without_headers_is_server_class() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::Transient503);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        match login_via_seam(&client, &mock, &cred).await {
            Err(AuthError::Server(msg)) => {
                assert!(msg.contains("503"), "must name the status: {msg}");
                assert!(
                    msg.contains(&mock.addr.port().to_string()),
                    "must name the full URL (port visible): {msg}"
                );
            }
            Err(e) => panic!(
                "issue #36 review: 5xx without auth-failed headers must be \
                 AuthError::Server (opc exit 3, GATEWAY_UNREACHABLE) so \
                 retry automation does not page on a phantom credential \
                 problem; got {e:?}"
            ),
            Ok(ok) => panic!("503 must not log in; got {ok:?}"),
        }
    }

    /// A 5xx that DOES carry the auth-failed header is a genuine
    /// credential reject (exit 2) despite the odd status.
    #[tokio::test]
    async fn gateway_login_503_with_auth_failed_header_is_failed_class() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::AuthFailed503);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        match login_via_seam(&client, &mock, &cred).await {
            Err(AuthError::Failed(msg)) => {
                assert!(msg.contains("503"));
                assert!(msg.contains("auth-failed"), "{msg}");
            }
            Err(e) => panic!("auth-signal 503 must classify Failed; got {e:?}"),
            Ok(ok) => panic!("503 must not log in; got {ok:?}"),
        }
    }

    /// Checklist M2: a 4xx with no PAN discriminator VALUE anywhere is
    /// NOT a credential failure — status class alone must not decide.
    /// It keeps the Server/exit-3 infrastructure lane the legacy
    /// `.error_for_status()?` gave it (proxy 403s, WAF pages); only an
    /// auth-failed/invalid-input/missing-form header or body value may
    /// claim the credential lane (covered by the reject_error_tests
    /// table and AuthFailed503 above).
    #[tokio::test]
    async fn gateway_login_4xx_without_auth_claim_is_server_class() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::Forbidden403);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        match login_via_seam(&client, &mock, &cred).await {
            Err(AuthError::Server(msg)) => assert!(msg.contains("403"), "{msg}"),
            Err(e) => panic!(
                "M2: a bare 403 (no auth-failed header/body claim) must be \
                 Server (exit 3), not a credential-failure assertion; got {e:?}"
            ),
            Ok(ok) => panic!("403 must not log in; got {ok:?}"),
        }
    }

    /// The error diagnostics must cap what they READ, not just what
    /// they display: a hostile/verbose peer (trivially reachable under
    /// `--insecure`, where the peer is unauthenticated) must not be
    /// able to make opc buffer a megabyte of error body before we
    /// truncate to 256 chars anyway.
    #[tokio::test]
    async fn gateway_login_error_body_read_is_capped() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::Trickle512);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        let started = std::time::Instant::now();
        let e = login_via_seam(&client, &mock, &cred)
            .await
            .expect_err("512 must fail");
        let elapsed = started.elapsed();
        let es = e.to_string();
        assert!(es.contains("512"), "{es}");
        assert!(es.contains("auth-failed"), "{es}");
        assert!(
            es.chars().count() < 4096,
            "error text ballooned to {} chars from the body",
            es.chars().count()
        );
        // The bite: the READ itself must be capped, not just the display.
        // The mock declared 1 MiB, sent only 8 KiB (more than enough for
        // the diagnostic head) and then stalls 5s before closing: a
        // client that streams the body (the pre-fix `.text()` path)
        // waits out the stall and dies on the truncated stream; a capped
        // reader takes its head and returns in milliseconds.
        assert!(
            elapsed < Duration::from_secs(3),
            "the error path waited {elapsed:?} — it streamed the body \
             instead of capping the read at DIAG_BODY_MAX_BYTES"
        );
    }

    /// Checklist S1: a peer that streams EXACTLY the 4096-byte
    /// diagnostic cap and then parks (no terminator, no close) must
    /// still yield the status+headers diagnostic. `read_capped_body`
    /// has to check the cap BEFORE `chunk().await`; the pre-fix order
    /// awaits a next chunk that never comes, dies at the request
    /// timeout as `AuthError::Http`, and the whole reject — headers
    /// included — is lost to a transport error.
    #[tokio::test]
    async fn gateway_login_parked_body_at_cap_still_yields_diagnostics() {
        let mock = MockGateway::start_mode(EXPECTED_USER, CORRECT_PASSWD, MockMode::ParkedBody4096);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        let started = std::time::Instant::now();
        let e = login_via_seam(&client, &mock, &cred)
            .await
            .expect_err("parked 512 must fail");
        let elapsed = started.elapsed();
        assert!(
            !matches!(e, AuthError::Http(_)),
            "S1: the parked body turned the reject into a bare transport \
             error, losing the diagnostics: {e:?}"
        );
        let es = e.to_string();
        assert!(es.contains("512"), "{es}");
        assert!(
            es.contains("auth-failed"),
            "S1: status+headers must survive the park: {es}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "S1: the error path waited {elapsed:?} — read_capped_body \
             awaited the next chunk after the buffer was already full \
             instead of breaking on the cap first"
        );
    }

    /// Checklist S2 + S3: the FULL password lane through the
    /// production chain — getconfig XML fixture (cookieless) →
    /// `PortalConfig::parse` → `to_gateway_credential` →
    /// `gateway_login_url` on the wire → 200 authcookie.
    ///
    /// This is the revert-sensitivity pin (S3): the derived fixture is
    /// an `AuthCookie` whose `password` is `Some(..)` (the five legacy
    /// headline wire fixtures all use None). Reverting the
    /// cookieless-lane replay in portal.rs drops the passwd from the
    /// POST, the mock's #859 lane rejects it, and this test goes RED.
    #[tokio::test]
    async fn full_lane_cookieless_getconfig_to_authcookie_200() {
        let xml = "<response><config-digest>MOCK-digest</config-digest></response>";
        let config = gp_proto::PortalConfig::parse(xml, "portal.example.com", EXPECTED_USER)
            .expect("getconfig fixture parses");
        let portal_cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        let gw_cred = config.to_gateway_credential(&portal_cred);
        match &gw_cred {
            Credential::AuthCookie { password, .. } => assert_eq!(
                password.as_deref(),
                Some(CORRECT_PASSWD),
                "cookieless password lane must hand the wire an AuthCookie \
                 replaying the portal password (S3 sensitivity)"
            ),
            other => panic!("expected AuthCookie, got {other:?}"),
        }

        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let res = login_via_seam(&client, &mock, &gw_cred).await;
        let cap = mock.only_capture();
        assert_eq!(
            cap.vals("passwd"),
            vec![CORRECT_PASSWD.to_string()],
            "the replayed secret must reach the wire; posted: {}",
            cap.summary()
        );
        for k in ["portal-userauthcookie", "portal-prelogonuserauthcookie"] {
            assert!(
                cap.vals(k).is_empty(),
                "{k} must be absent when the portal issued nothing: {}",
                cap.summary()
            );
        }
        assert!(
            cap.empty_secret_keys().is_empty(),
            "no present-but-empty key on the wire: {}",
            cap.summary()
        );
        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE);
                assert_eq!(cookie.username, EXPECTED_USER);
            }
            other => panic!(
                "full lane must land a 200 authcookie; got {other:?}\nposted: {}",
                cap.summary()
            ),
        }
    }

    /// Checklist S2: same full chain for the M1 sentinel getconfig —
    /// literal `empty` cookies must behave as ABSENT end to end: the
    /// password replays, no cookie keys hit the wire, 200 authcookie.
    #[tokio::test]
    async fn full_lane_sentinel_cookie_getconfig_to_authcookie_200() {
        let xml = "<response>\
            <portal-userauthcookie>empty</portal-userauthcookie>\
            <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>\
            <config-digest>MOCK-digest</config-digest>\
            </response>";
        let config = gp_proto::PortalConfig::parse(xml, "portal.example.com", EXPECTED_USER)
            .expect("sentinel getconfig fixture parses");
        let portal_cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);
        let gw_cred = config.to_gateway_credential(&portal_cred);

        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let res = login_via_seam(&client, &mock, &gw_cred).await;
        let cap = mock.only_capture();
        assert_eq!(
            cap.vals("passwd"),
            vec![CORRECT_PASSWD.to_string()],
            "sentinel cookies must not suppress the replay; posted: {}",
            cap.summary()
        );
        for k in ["portal-userauthcookie", "portal-prelogonuserauthcookie"] {
            assert!(
                cap.vals(k).is_empty(),
                "sentinel {k} must never reach the wire: {}",
                cap.summary()
            );
        }
        assert!(
            !cap.pairs.iter().any(|(_, v)| v == "empty"),
            "the literal sentinel must be normalized away, not posted: {}",
            cap.summary()
        );
        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE)
            }
            other => panic!(
                "sentinel lane must land a 200 authcookie; got {other:?}\nposted: {}",
                cap.summary()
            ),
        }
    }

    /// Checklist S3: a direct `AuthCookie` fixture carrying
    /// `password: Some(..)` (the five legacy headline wire tests all
    /// use None) must get the replayed passwd onto the wire exactly
    /// once, non-empty.
    #[tokio::test]
    async fn gateway_login_auth_cookie_with_replayed_password_reaches_wire() {
        let mock = MockGateway::start(EXPECTED_USER, CORRECT_PASSWD);
        let client = GpClient::new(gw_params()).expect("build GpClient");
        let cred = Credential::AuthCookie {
            username: EXPECTED_USER.into(),
            user_auth_cookie: String::new(),
            prelogon_user_auth_cookie: String::new(),
            password: Some(CORRECT_PASSWD.into()),
        };
        let res = login_via_seam(&client, &mock, &cred).await;
        let cap = mock.only_capture();
        assert_eq!(
            cap.vals("passwd"),
            vec![CORRECT_PASSWD.to_string()],
            "AuthCookie.password must serialize to the single wire passwd: {}",
            cap.summary()
        );
        assert!(cap.empty_secret_keys().is_empty(), "{}", cap.summary());
        match res {
            Ok(GatewayLoginResult::Success(cookie)) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE)
            }
            other => panic!("replayed-password AuthCookie must succeed; got {other:?}"),
        }
    }

    /// Checklist S2: the MFA challenge sequence against the production
    /// wire — first login answers 200 + challenge HTML; the retry (as
    /// main.rs performs it: `input_str` from the challenge + OTP as
    /// `otp`) must post inputStr together with EXACTLY ONE passwd (the
    /// OTP) and land the authcookie.
    #[tokio::test]
    async fn gateway_login_challenge_sequence_posts_inputstr_with_single_otp_passwd() {
        let mock = MockGateway::start_mode(EXPECTED_USER, OTP, MockMode::ChallengeThenOtp);
        let params = gw_params();
        let client = GpClient::new(params.clone()).expect("build GpClient");
        let cred = password_cred(EXPECTED_USER, CORRECT_PASSWD);

        let first = login_via_seam(&client, &mock, &cred)
            .await
            .expect("challenge login must not error");
        let input_str = match first {
            GatewayLoginResult::MfaChallenge { message, input_str } => {
                assert!(
                    message.contains("authenticator"),
                    "challenge message: {message}"
                );
                assert_eq!(input_str, CHALLENGE_INPUT_STR, "challenge token");
                input_str
            }
            other => panic!("expected MfaChallenge, got {other:?}"),
        };

        // Retry exactly the way main.rs does: challenge token into
        // params.input_str, user's OTP into params.otp, same credential.
        let mut retry_params = params.clone();
        retry_params.input_str = Some(input_str.clone());
        retry_params.otp = Some(OTP.to_string());
        let retry_client = GpClient::new(retry_params).expect("build retry GpClient");
        let second = login_via_seam(&retry_client, &mock, &cred)
            .await
            .expect("OTP retry must not error");
        match second {
            GatewayLoginResult::Success(cookie) => {
                assert_eq!(cookie.authcookie, MOCK_AUTHCOOKIE)
            }
            other => panic!("OTP retry must succeed, got {other:?}"),
        }

        let caps = mock.captures.lock().unwrap();
        assert_eq!(caps.len(), 2, "challenge + retry = two POSTs");
        let retry = &caps[1];
        assert_eq!(
            retry.vals("passwd"),
            vec![OTP.to_string()],
            "the retry must carry EXACTLY ONE passwd, the OTP: {}",
            retry.summary()
        );
        assert_eq!(
            retry.vals("inputStr"),
            vec![CHALLENGE_INPUT_STR.to_string()],
            "inputStr must ride alongside the OTP: {}",
            retry.summary()
        );
        assert!(retry.empty_secret_keys().is_empty(), "{}", retry.summary());
    }

    #[test]
    fn scrub_server_text_covers_urlencoded_and_case_variants() {
        let secret = "p@ss !&+~word";
        let enc = form_urlencode(secret);
        let variants = [
            secret.to_string(),
            enc.clone(),
            lowercase_percent_hex(&enc),
            secret.replace(' ', "%20"),
        ];
        assert!(
            enc.contains('%'),
            "fixture must actually exercise the encoder"
        );
        let text = variants.join(" ;; ");
        let out = scrub_server_text(&text, &[secret.to_string()], 4096);
        for v in &variants {
            assert!(!out.contains(v.as_str()), "variant {v:?} survived: {out}");
        }
        assert_eq!(
            out.matches("[REDACTED]").count(),
            variants.len(),
            "every rendering must be redacted: {out}"
        );
    }

    /// Checklist M3a (Codex-reproduced fixture): a gateway reflecting
    /// the **fully percent-encoded** rendering (`p%40%20ss`) of the
    /// submitted secret `p@ ss` must not get it back into the error
    /// text. Before the fix the needle set covered raw, `+`-form and
    /// `%XX`-of-space-only, so this rendering leaked.
    #[test]
    fn scrub_server_text_covers_full_percent_encoded_variants() {
        // Contract fixture: the Codex-reproduced reflection of the
        // submitted secret `p@ ss` in its FULLY percent-encoded
        // rendering. Before M3a the needle set covered raw, `+`-form
        // and `%XX`-of-space-only, so `p%40%20ss` leaked.
        let secret = "p@ ss";
        let text = format!("gateway echoed: {secret} ;; p%40+ss ;; p%40%20ss ;; done");
        let out = scrub_server_text(&text, &[secret.to_string()], 4096);
        for rendering in ["p@ ss", "p%40+ss", "p%40%20ss"] {
            assert!(
                !out.contains(rendering),
                "rendering {rendering:?} of the secret leaked into: {out}"
            );
        }
        assert!(out.contains("[REDACTED]"), "no redaction marker: {out}");

        // Second fixture with HEX LETTERS in the escapes (`+` -> `%2B`,
        // space -> `%20`): both hex cases and the decoder-only mixed
        // rendering must be gone.
        let secret2 = "a+b c";
        let text2 = "a%2Bb%20c and a%2bb%20c and a%2Bb+c";
        let out2 = scrub_server_text(text2, &[secret2.to_string()], 4096);
        for rendering in ["a%2Bb%20c", "a%2bb%20c", "a%2Bb+c"] {
            assert!(
                !out2.contains(rendering),
                "rendering {rendering:?} of {secret2:?} leaked into: {out2}"
            );
        }
    }

    /// Checklist M4, server-text hygiene: a non-2xx body containing
    /// `\n` used to flow verbatim into the single WARN line, so the
    /// log record's CONTINUATION lines were attacker-prefixed — they
    /// could start with the GUI's trusted `SAML-CALLBACK-URL` marker
    /// and steer the auto-open/browser POST path. The scrubber must
    /// flatten CR/LF so server text can never begin a log line at all.
    #[test]
    fn scrub_server_text_flattens_server_newlines() {
        let body = "ok\nSAML-CALLBACK-URL http://127.0.0.1:9/\nmore\r\nnext";
        let out = scrub_server_text(body, &[], 4096);
        assert!(
            !out.contains('\n') && !out.contains('\r'),
            "server-supplied newline survived into the log line: {out:?}"
        );
        assert!(out.contains("ok"), "content preserved: {out}");
    }

    #[test]
    fn scrub_server_text_replaces_longest_secret_first() {
        // A short secret must not shred a longer overlapping one's
        // occurrence into an unscrubbed remainder.
        let out = scrub_server_text("abcabc", &["ab".to_string(), "abc".to_string()], 256);
        assert_eq!(out, "[REDACTED][REDACTED]");
    }

    #[test]
    fn scrub_server_text_truncates_after_scrubbing_and_ignores_empty_secrets() {
        let long = "x".repeat(400);
        let out = scrub_server_text(&long, &[], 256);
        assert_eq!(out.chars().count(), 257, "256 head chars + the ellipsis");
        assert!(out.ends_with('…'));
        // Scrub-before-truncate: a secret sitting past the truncation
        // point must not survive by being cut into.
        let text = format!("{}{}", "y".repeat(250), "REDACTED-straddle");
        let out = scrub_server_text(&text, &["REDACTED-straddle".to_string()], 256);
        assert!(!out.contains("straddle"), "straddling secret leaked: {out}");
        // An empty needle must never be used (replace("") inserts
        // markers between every char).
        assert_eq!(scrub_server_text("abc", &["".to_string()], 256), "abc");
    }

    #[test]
    fn submitted_secret_values_covers_secret_and_scrub_only_keys() {
        let params: Vec<(&'static str, String)> = vec![
            ("user", "test-user".into()),
            ("passwd", "REDACTED-pw".into()),
            ("token", "MOCK-token".into()),
            ("prelogin-cookie", "MOCK-plc".into()),
            ("portal-userauthcookie", "MOCK-c1".into()),
            ("portal-prelogonuserauthcookie", "MOCK-c2".into()),
            ("inputStr", "MOCK-challenge".into()),
            ("computer", "TESTBOX".into()),
            ("server", "gw".into()),
            ("ok", "Login".into()),
        ];
        let secrets = submitted_secret_values(&params);
        for s in [
            "REDACTED-pw",
            "MOCK-token",
            "MOCK-plc",
            "MOCK-c1",
            "MOCK-c2",
            "MOCK-challenge",
        ] {
            assert!(secrets.iter().any(|v| v == s), "{s} missing from scrub set");
        }
        for n in ["test-user", "TESTBOX", "gw", "Login"] {
            assert!(
                !secrets.iter().any(|v| v == n),
                "{n} must NOT be a scrub needle"
            );
        }
        // Empty secret values are excluded — an empty needle would
        // replace-everything if it ever reached the scrub.
        let params2: Vec<(&'static str, String)> = vec![("passwd", String::new())];
        assert!(submitted_secret_values(&params2).is_empty());
    }

    #[test]
    fn pan_diagnostic_headers_renders_scrubs_and_states_absence() {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-private-pan-sslvpn"),
            HeaderValue::from_static("auth-failed"),
        );
        h.insert(
            HeaderName::from_static("x-private-pan-sslvpn-extension"),
            HeaderValue::from_static("auth-failed-secret=REDACTED-secret"),
        );
        // Checklist M3c: prefix wildcards (x-private-pan*, x-pan*) must
        // NOT log these — an explicit two-header allow-list decides.
        h.insert(
            HeaderName::from_static("x-private-pan-diag"),
            HeaderValue::from_static("passwd=REDACTED-secret"),
        );
        h.insert(
            HeaderName::from_static("x-private-pan-device-desc"),
            HeaderValue::from_static("gateway-model PA-3220"),
        );
        h.insert(
            HeaderName::from_static("x-pan-other"),
            HeaderValue::from_static("x-pan-secret=REDACTED-secret"),
        );
        let s = pan_diagnostic_headers(&h, &["REDACTED-secret".to_string()]);
        assert!(s.contains("x-private-pan-sslvpn=auth-failed"), "{s}");
        assert!(s.contains("x-private-pan-sslvpn-extension="), "{s}");
        assert!(
            !s.contains("x-private-pan-diag")
                && !s.contains("x-private-pan-device-desc")
                && !s.contains("x-pan-other")
                && !s.contains("PA-3220"),
            "non-allow-listed headers must never be logged: {s}"
        );
        // The one allow-listed header carrying a secret in its VALUE:
        assert!(
            s.contains("secret=[REDACTED]") || s.contains("passwd=[REDACTED]"),
            "header VALUES must be scrubbed too: {s}"
        );

        // Absence must be stated without asserting a taxonomy the
        // sources do not establish (no "pre-auth reject class" claim).
        let s = pan_diagnostic_headers(&HeaderMap::new(), &[]);
        assert!(s.contains("no X-Private-Pan-Sslvpn header"), "{s}");
        assert!(
            !s.contains("pre-auth reject class"),
            "taxonomy claim the sources do not establish: {s}"
        );

        // Non-UTF8 header values degrade safely, not panic.
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-private-pan-sslvpn"),
            HeaderValue::from_bytes(&[0xffu8]).expect("invalid-utf8 header value"),
        );
        assert!(pan_diagnostic_headers(&h, &[]).contains("<non-utf8>"));
    }
}

/// Issue #36 checklist M2: failure classification by **VALUE**.
///
/// The exit-code contract is credential-failure (exit 2) **only** when
/// a PAN discriminator header or body VALUE names an auth reject class;
/// every other non-2xx (404/408/429/5xx, and any 4xx, without an auth
/// claim) keeps the Server/exit-3 infrastructure lane the legacy
/// `.error_for_status()?` gave all non-2xx. Table-driven so the
/// classification is pinned per (status, headers, body) triple, not
/// per call-site accident.
#[cfg(test)]
mod reject_error_tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(v).expect("valid header value"),
            );
        }
        h
    }

    struct Row {
        why: &'static str,
        status: u16,
        hdrs: &'static [(&'static str, &'static str)],
        body: &'static str,
        expect_failed: bool,
    }

    const ROWS: &[Row] = &[
        // --- credential lane: PAN discriminator VALUES ---
        Row {
            why: "401 + X-Private-Pan-Sslvpn: auth-failed is a credential failure",
            status: 401,
            hdrs: &[("x-private-pan-sslvpn", "auth-failed")],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "#859: auth-failed-password-empty extension is a credential failure",
            status: 401,
            hdrs: &[(
                "x-private-pan-sslvpn-extension",
                "auth-failed-password-empty",
            )],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "invalid-input reject class is a credential failure",
            status: 400,
            hdrs: &[("x-private-pan-sslvpn", "invalid-input")],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "missing-form reject class is a credential failure",
            status: 400,
            hdrs: &[("x-private-pan-sslvpn", "missing-form")],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "5xx with the auth-failed discriminator is still a credential failure",
            status: 503,
            hdrs: &[("x-private-pan-sslvpn", "auth-failed")],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "dashed auth-failed refinements match the auth-failed class",
            status: 512,
            hdrs: &[("x-private-pan-sslvpn", "auth-failed-invalid-state")],
            body: "",
            expect_failed: true,
        },
        Row {
            why: "header values compare case-insensitively",
            status: 500,
            hdrs: &[("x-private-pan-sslvpn", "AUTH-FAILED")],
            body: "",
            expect_failed: true,
        },
        // --- body-value claims by the password/cookie engine (a
        // middlebox that strips X-Pan headers must not hide the class) ---
        Row {
            why: "body naming the password engine verdict is a credential failure",
            status: 512,
            hdrs: &[],
            body:
                "<response status=\"error\"><error>Invalid username or password</error></response>",
            expect_failed: true,
        },
        Row {
            // The cookie IS the credential for the pass-through lane;
            // main.rs already maps authcookie-expiry to exit 2, so an
            // explicit invalid-cookie verdict must not page as an
            // outage.
            why: "body naming the cookie verdict is a credential failure",
            status: 512,
            hdrs: &[],
            body:
                "<response status=\"error\"><error>Invalid authentication cookie</error></response>",
            expect_failed: true,
        },
        // --- infrastructure lane: no auth VALUE anywhere ---
        Row {
            why: "408 with no header is infrastructure (exit 3), not credentials",
            status: 408,
            hdrs: &[],
            body: "",
            expect_failed: false,
        },
        Row {
            why: "bare 512 (no auth claim) must not assert credential failure",
            status: 512,
            hdrs: &[],
            body: "custom error, no details",
            expect_failed: false,
        },
        Row {
            why: "404 is infrastructure (exit 3)",
            status: 404,
            hdrs: &[],
            body: "<html>Not Found</html>",
            expect_failed: false,
        },
        Row {
            why: "403 without any auth signal is infrastructure (exit 3), \
                  NOT a credential reject by status class alone",
            status: 403,
            hdrs: &[],
            body: "<html>Forbidden</html>",
            expect_failed: false,
        },
        Row {
            why: "401 alone (no PAN header, no body claim) is infrastructure",
            status: 401,
            hdrs: &[],
            body: "",
            expect_failed: false,
        },
        Row {
            why: "429 is infrastructure (backoff), not broken credentials",
            status: 429,
            hdrs: &[],
            body: "rate limited",
            expect_failed: false,
        },
        Row {
            why: "500 with no header is infrastructure (maintenance window)",
            status: 500,
            hdrs: &[],
            body: "<html>Internal Server Error</html>",
            expect_failed: false,
        },
        // --- value, not mere presence ---
        Row {
            why: "discriminator header PRESENT with an unrelated value is \
                  not a credential failure",
            status: 503,
            hdrs: &[("x-private-pan-sslvpn", "maintenance-window")],
            body: "<html>down</html>",
            expect_failed: false,
        },
        Row {
            why: "a value merely CONTAINING auth-failed without token \
                  equality/prefix is not the discriminator",
            status: 503,
            hdrs: &[("x-private-pan-sslvpn", "notauth-failed")],
            body: "",
            expect_failed: false,
        },
        Row {
            why: "other X-Pan-* header names carry no discriminator authority",
            status: 503,
            hdrs: &[("x-pan-diag", "auth-failed")],
            body: "",
            expect_failed: false,
        },
    ];

    #[test]
    fn reject_error_classifies_by_discriminator_value_not_status_or_presence() {
        let mut mismatches: Vec<String> = Vec::new();
        for row in ROWS {
            let status = reqwest::StatusCode::from_u16(row.status)
                .unwrap_or_else(|e| panic!("{}: bad row status: {e}", row.why));
            let msg = format!("{} {status}", row.why);
            let err = reject_error(status, &headers(row.hdrs), row.body, msg.clone());
            let ok = match (row.expect_failed, &err) {
                (true, AuthError::Failed(m)) => m == &msg,
                (false, AuthError::Server(m)) => m == &msg,
                _ => false,
            };
            if !ok {
                mismatches.push(format!(
                    "{}: expected {} for {status} {:?} body={:?}, got {err:?}",
                    row.why,
                    if row.expect_failed {
                        "Failed"
                    } else {
                        "Server"
                    },
                    row.hdrs,
                    row.body,
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "M2 value-based classification violated by:\n{}",
            mismatches.join("\n")
        );
    }
}

/// Issue #36 adversarial security resweep (re-sweeper lens: M3 scrub
/// surface + M4 GUI trust). Fixtures are localhost-only mocks
/// (`127.0.0.1:0`); every "secret" is an obvious fake literal.
///
/// History: this module first landed (d55869e) as evidence pins —
/// `known_gap_*` tests asserting the three leaks existed, mirrored by
/// `#[ignore]`d contract-correct counterparts. The final fix pass
/// RETIRED the evidence pins (deleted: once fixed they would merely
/// fail on the opposite assertion of their contract twin) and un-
/// ignored the contract tests, which are now required GREEN for the
/// three verified gaps:
/// * M3a: mixed-case per-escape and double-encoded echoes of the
///   submitted password must be scrubbed regardless of glued
///   punctuation — `scrub_robust_to_mixed_case_and_double_encoded_echoes`
///   (fixed via the fixed-point decode-compare lane).
/// * M3b: gateway-rotated cookie material must be masked in the XML
///   ELEMENT form too, plus body-embedded `Set-Cookie:` —
///   `unsubmitted_cookies_in_xml_element_form_are_masked` (fixed via
///   `mask_secret_key_values`).
/// * M4: server-influenced text must never start a stderr line with
///   the GUI's trusted marker —
///   `stderr_lines_can_never_start_with_the_trusted_marker_from_server_text`
///   (fixed via `flatten_control_chars` on every URL interpolation and
///   the `Gateway::parse_list` address gate).
///
/// The getconfig user-visible error lane got the same treatment:
/// `getconfig_reject_message_scrubs_and_flattens_server_body`.
#[cfg(test)]
mod adversarial_sweep_tests {
    use super::*;
    use gp_proto::{ClientOs, Credential};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};

    /// Password with RFC-3986-reserved chars (space, @, !, &, =, +, ~).
    const PW: &str = "REDACTED p@ss!&w=+~";
    /// What reqwest's `.form()` puts on the wire (uppercase `%XX`, `+`).
    const WIRE_UPPER: &str = "REDACTED+p%40ss%21%26w%3D%2B%7E";
    /// Same wire string with the final escape (`%7E`) case-flipped:
    /// equals NEITHER the uppercase nor the lowercase needle, so the
    /// needle lane cannot see it (checklist M3a's "mixed-case percent").
    const MIXED: &str = "REDACTED+p%40ss%21%26w%3D%2B%7e";
    /// The same trick on the `%2B` escape.
    const MIXED2: &str = "REDACTED+p%40ss%21%26w%3D%2b%7E";
    /// Double percent-encoding of the wire string (re-encoding proxy
    /// shape): one `percent_decode_bytes` pass yields the WIRE string,
    /// not the secret — the pre-fix single-pass equality belt missed
    /// this; the fixed-point loop must now unfold it (probe for
    /// checklist M3a robustness).
    const DOUBLE: &str = "REDACTED+p%2540ss%2521%2526w%253D%252B%257E";
    /// A gateway-ROTATED portal cookie the client never submitted,
    /// echoed in GlobalProtect's native XML ELEMENT form (no `key=`).
    const SURPRISE_XML: &str = "MOCK-SURPRISE-xmltag-cookie";

    const MOCK_MARKER: &str = "SAML-CALLBACK-URL http://127.0.0.1:9999/";

    /// Rendered-stderr capture: the same fmt layer shape `build_tracing_
    /// subscriber` uses in the CLI, so what we assert is what the GUI's
    /// `BufReader::lines()` will actually see.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Hostile 512 mock: echoes the submitted wire `passwd` back in
    /// mixed-case and double-encoded renderings glued to surrounding
    /// punctuation (the renderings that DEFEATED the pre-fix
    /// token-boundary decode-compare belt), carries a genuine
    /// `auth-failed` discriminator header, and publishes an
    /// XML-element form of a rotated portal cookie the client never
    /// submitted.
    struct Hostile512 {
        addr: SocketAddr,
        arrived: Arc<Mutex<bool>>,
    }

    impl Hostile512 {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind hostile mock");
            let addr = listener.local_addr().unwrap();
            let arrived = Arc::new(Mutex::new(false));
            let arrived_t = arrived.clone();
            std::thread::Builder::new()
                .name("test-adversarial-512".into())
                .spawn(move || {
                    for stream in listener.incoming().flatten() {
                        let arrived_t = arrived_t.clone();
                        std::thread::spawn(move || {
                            let _ = handle(stream, &arrived_t);
                        });
                    }
                })
                .expect("spawn hostile accept loop");
            Self { addr, arrived }
        }

        /// Shape a portal-advertised gateway `<entry name>` containing a
        /// raw LF produces through the production `login_url`
        /// composition (host + `/ssl-vpn/login.esp`). The request still
        /// reaches the mock: the `url` crate strips tab/LF/CR per
        /// WHATWG. The diagnostics must NEVER log that raw string —
        /// pre-fix they did (the M4 forgery lane); post-fix every URL
        /// interpolation passes `flatten_control_chars` first, and the
        /// gate below keeps control bytes out of the address at the
        /// parse boundary too.
        fn url_with_forged_marker(&self) -> String {
            format!(
                "http://{}/evil/\n{}\n/ssl-vpn/login.esp",
                self.addr, MOCK_MARKER
            )
        }
    }

    fn handle(mut stream: TcpStream, arrived: &Arc<Mutex<bool>>) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_double_crlf(&buf) {
                let cl: usize = header_content_length(&buf[..pos]).unwrap_or(0);
                while buf.len() < pos + 4 + cl {
                    let n = stream.read(&mut tmp)?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        *arrived.lock().unwrap() = true;
        let raw = String::from_utf8_lossy(&buf).into_owned();
        let body_wire = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        let wire = body_wire
            .split('&')
            .find_map(|kv| kv.strip_prefix("passwd="))
            .unwrap_or_default()
            .to_string();
        // Independent oracle: the wire rendering must be the uppercase
        // form we scrub against.
        assert_eq!(wire, WIRE_UPPER, "unexpected wire rendering: {wire}");
        let mixed = wire.replace("%7E", "%7e");
        let mixed2 = wire.replace("%2B", "%2b");
        let double = wire.replace('%', "%25");
        // Compactly built so EVERY probe lands inside the 256-char
        // scrubbed body head (assertion below double-checks that).
        let body = format!(
            "<error>Invalid username or password</error> \
             (credential={mixed})[{double}](engine-arg={mixed2}) \
             <portal-userauthcookie>{SURPRISE_XML}</portal-userauthcookie>",
        );
        // Every probe must sit inside the first BODY_HEAD_CHARS chars of
        // the body, or the 256-char cap (not the scrubber) would hide it.
        let head = &body[..body.len().min(BODY_HEAD_CHARS)];
        assert!(
            head.contains(SURPRISE_XML),
            "fixture bug: SURPRISE_XML outside the body head: {body}"
        );
        for probe in [&mixed, &double, &mixed2] {
            assert!(
                head.contains(probe.as_str()),
                "fixture bug: probe outside the body head: {body}"
            );
        }
        let resp = format!(
            "HTTP/1.1 512 Custom Error\r\ncontent-type: text/html\r\n\
             x-private-pan-sslvpn: auth-failed\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes())?;
        stream.flush()
    }

    use std::net::TcpStream;

    fn find_double_crlf(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn header_content_length(head: &[u8]) -> Option<usize> {
        let s = String::from_utf8_lossy(head).to_ascii_lowercase();
        s.lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
    }

    fn gw_params() -> GpParams {
        GpParams {
            ignore_tls_errors: true,
            ..GpParams::new(ClientOs::Win)
        }
    }

    /// Drive the production `gateway_login_url` non-2xx lane against
    /// the hostile 512 and return (mock, rendered stderr stream,
    /// user-visible error message).
    fn hostile_login() -> (Hostile512, String, String) {
        let mock = Hostile512::start();
        let url = mock.url_with_forged_marker();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cap = CaptureWriter::default();
        let sub = tracing_subscriber::fmt::Subscriber::builder()
            .with_ansi(false)
            .with_max_level(tracing::metadata::LevelFilter::DEBUG)
            .with_writer(cap.clone())
            .finish();
        let cred = Credential::Password {
            username: "test-user".into(),
            password: PW.into(),
        };
        let res = tracing::subscriber::with_default(sub, || {
            rt.block_on(async {
                let client = GpClient::new(gw_params()).expect("build GpClient");
                client
                    .gateway_login_url(&url, "gw.example.com", &cred)
                    .await
            })
        });
        let err = match res {
            Err(AuthError::Failed(msg)) => msg,
            other => panic!("hostile 512 with auth-failed header must be Failed, got {other:?}"),
        };
        let rendered = String::from_utf8_lossy(&cap.0.lock().unwrap().clone()).into_owned();
        (mock, rendered, err)
    }

    // The d55869e `known_gap_*` EVIDENCE pins (asserting the leak
    // exists) are RETIRED by this fix pass, as their docs demanded:
    // after the fix they can only fail against their contract twins
    // below, which now run as required tests.

    /// CONTRACT (M3a, resweep fix landed): no rendering of a submitted
    /// secret — raw, wire-case, opposite-case, mixed-case per-escape, or
    /// double-encoded — may survive into the rendered stderr stream or
    /// the user-visible error, regardless of surrounding punctuation.
    #[test]
    fn scrub_robust_to_mixed_case_and_double_encoded_echoes() {
        let (mock, rendered, err) = hostile_login();
        assert!(*mock.arrived.lock().unwrap(), "request must reach the mock");
        for leak in [MIXED, MIXED2, DOUBLE, PW] {
            assert!(
                !rendered.contains(leak),
                "submitted secret leaked into stderr: {leak:?}"
            );
            assert!(
                !err.contains(leak),
                "submitted secret leaked into user-visible error: {leak:?}"
            );
        }
    }

    /// CONTRACT (M3b, resweep fix landed): server-minted secret
    /// material for known PAN cookie keys must be masked in the XML
    /// element form the protocol actually uses, not just `key=VALUE`.
    #[test]
    fn unsubmitted_cookies_in_xml_element_form_are_masked() {
        let (_mock, rendered, _err) = hostile_login();
        assert!(
            !rendered.contains(SURPRISE_XML),
            "rotated portal cookie leaked into stderr"
        );
    }

    /// CONTRACT (M4, resweep fix landed): server-influenced text must
    /// never be able to start a stderr line with the trusted marker —
    /// every URL/status interpolation in the diagnostics passes the
    /// same control-char flattening the body lane got, and the
    /// portal-advertised gateway address is charset-gated at parse
    /// (gp-proto gateway.rs).
    #[test]
    fn stderr_lines_can_never_start_with_the_trusted_marker_from_server_text() {
        let (_mock, rendered, _err) = hostile_login();
        assert!(
            !rendered
                .split('\n')
                .any(|line| line.starts_with("SAML-CALLBACK-URL")),
            "server-influenced text forged a GUI-trusted marker line:\n{rendered}"
        );
    }

    /// CONTRACT (PR-B item 3): the ONE gp-auth escaper renders every
    /// line-starter and C0 control as a VISIBLE token — same
    /// forgery closure as the old space-flattening, but now the
    /// escape is observable in the field log (a report can see WHAT
    /// the hostile peer sent). Table-driven: every character that can
    /// start a new line for a consumer, plus the pass-through lane.
    #[test]
    fn flatten_control_chars_renders_visible_tokens() {
        assert_eq!(flatten_control_chars("a\r\nb"), "a<CR><LF>b");
        assert_eq!(flatten_control_chars("x\u{85}y"), "x<NEL>y");
        assert_eq!(flatten_control_chars("x\u{2028}y"), "x<LS>y");
        assert_eq!(flatten_control_chars("x\u{2029}y"), "x<PS>y");
        assert_eq!(flatten_control_chars("a\u{0}b"), "a<0x00>b");
        assert_eq!(flatten_control_chars("a\u{7}b"), "a<0x07>b");
        assert_eq!(flatten_control_chars("a\u{7f}b"), "a<DEL>b");
        assert_eq!(flatten_control_chars("plain text 123"), "plain text 123");
        // The GUI marker cannot survive as a standalone line.
        let hostile = "\r\nSAML-CALLBACK-URL http://127.0.0.1:1/";
        let flattened = flatten_control_chars(hostile);
        assert!(
            !flattened
                .split('\n')
                .any(|l| l.starts_with("SAML-CALLBACK-URL")),
            "flattened output still forges a marker line: {flattened:?}"
        );
    }

    /// CONTRACT (M4 extension found in the final pass): the gateway
    /// getconfig non-2xx lane puts server-controlled body text on the
    /// USER-VISIBLE error path (`opc` prints the AuthError to stderr,
    /// and the reporter pastes it). It must go through the same
    /// scrub+flatten pipeline as the login diagnostics: no secret-keyed
    /// value (even one the client never submitted), and no line that
    /// could impersonate the GUI's trusted marker.
    #[test]
    fn getconfig_reject_message_scrubs_and_flattens_server_body() {
        let err = getconfig_reject_error(
            reqwest::StatusCode::from_u16(512).unwrap(),
            "ok\nSAML-CALLBACK-URL http://127.0.0.1:9999/\nmore authcookie=MOCK-SURPRISE-getconfig-cookie tail",
        );
        let AuthError::Failed(msg) = &err else {
            panic!("getconfig non-2xx must stay Failed, got {err:?}");
        };
        assert!(
            !msg.split('\n').any(|l| l.starts_with("SAML-CALLBACK-URL")),
            "server body forged a marker-led line into the user-visible \
             error: {msg:?}"
        );
        assert!(
            !msg.contains("MOCK-SURPRISE-getconfig-cookie"),
            "server-minted authcookie value leaked: {msg:?}"
        );
        assert!(
            msg.contains("authcookie="),
            "the KEY stays visible for diagnosis (M3b rule): {msg:?}"
        );
        assert!(
            msg.contains("HTTP 512"),
            "status must still be reported: {msg:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Issue #43 — HIP URL lane: port characterization + wire proof at the
// `_at` seams (gateway_login_url pattern; plain-HTTP loopback mocks,
// nothing leaves 127.0.0.1, no TLS material, no real network).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod hip_lane_tests {
    use super::*;
    use gp_proto::{ClientOs, GpParams};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    fn win_params() -> GpParams {
        // Mirrors --insecure; irrelevant over plain http but keeps the
        // builder path identical to production.
        GpParams {
            ignore_tls_errors: true,
            ..GpParams::new(ClientOs::Win)
        }
    }

    #[derive(Clone)]
    struct HipCaptured {
        path: String,
        host_header: Option<String>,
        pairs: Vec<(String, String)>,
    }

    struct HipMock {
        addr: SocketAddr,
        captures: Arc<Mutex<Vec<HipCaptured>>>,
    }

    impl HipMock {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .expect("bind hip localhost mock on ephemeral port");
            let addr = listener.local_addr().expect("local_addr");
            let captures = Arc::new(Mutex::new(Vec::new()));
            let cap_t = captures.clone();
            std::thread::Builder::new()
                .name("test-hip-mock".into())
                .spawn(move || {
                    for stream in listener.incoming().flatten() {
                        let cap = cap_t.clone();
                        std::thread::spawn(move || {
                            let _ = handle(stream, &cap);
                        });
                    }
                })
                .expect("spawn hip mock accept loop");
            Self { addr, captures }
        }

        fn only(&self) -> HipCaptured {
            let v = self.captures.lock().unwrap();
            assert_eq!(v.len(), 1, "expected exactly one HIP POST, got {}", v.len());
            v[0].clone()
        }
    }

    /// Minimal raw-form parser (no percent-decode needed: the asserted
    /// wire values are plain tokens; `report=` content is asserted by
    /// key presence only).
    fn parse_form_raw(body: &str) -> Vec<(String, String)> {
        body.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (p.to_string(), String::new()),
            })
            .collect()
    }

    fn handle(mut stream: TcpStream, captures: &Mutex<Vec<HipCaptured>>) -> std::io::Result<()> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut req_line = String::new();
        if reader.read_line(&mut req_line)? == 0 {
            return Ok(());
        }
        let path = req_line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut content_length = 0usize;
        let mut host_header = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            if line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => content_length = v.trim().parse().unwrap_or(0),
                    "host" => host_header = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        let mut buf = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut buf)?;
        }
        let raw = String::from_utf8_lossy(&buf).into_owned();
        let pairs = parse_form_raw(&raw);
        captures.lock().unwrap().push(HipCaptured {
            path: path.clone(),
            host_header,
            pairs,
        });
        let body = if path.ends_with("hipreportcheck.esp") {
            // The gateway DOES want a report (drives Auto mode onward).
            "<response><hip-report-needed>yes</hip-report-needed></response>"
        } else {
            "<response status=\"success\"/>"
        };
        let bb = body.as_bytes();
        let mut out = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            bb.len()
        )
        .into_bytes();
        out.extend_from_slice(bb);
        stream.write_all(&out)?;
        stream.flush()?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    // ---------- characterization: the builders keep the advertised port
    // in the request authority (today's inline format! behaviour, pinned
    // so the #43 split-at-consumers refactor cannot regress it) ----------

    #[test]
    fn hipreportcheck_url_keeps_advertised_port() {
        assert_eq!(
            hip_report_check_url("203.0.113.7:11443"),
            "https://203.0.113.7:11443/ssl-vpn/hipreportcheck.esp"
        );
        assert_eq!(
            hip_report_check_url("gw.example.com"),
            "https://gw.example.com/ssl-vpn/hipreportcheck.esp"
        );
        // Historic profile shape (scheme + trailing slash) survives normalize.
        assert_eq!(
            hip_report_check_url("https://gw.example.com:11443/"),
            "https://gw.example.com:11443/ssl-vpn/hipreportcheck.esp"
        );
    }

    #[test]
    fn hipreport_url_keeps_advertised_port() {
        assert_eq!(
            hip_report_url("203.0.113.7:11443"),
            "https://203.0.113.7:11443/ssl-vpn/hipreport.esp"
        );
        assert_eq!(
            hip_report_url("ra.vpn.unsw.edu.au"),
            "https://ra.vpn.unsw.edu.au/ssl-vpn/hipreport.esp"
        );
    }

    // ---------- wire proof: the advertised port reaches the socket ----------

    #[tokio::test]
    async fn hip_report_check_at_mock_posts_to_advertised_port() {
        let mock = HipMock::start();
        let client = GpClient::new(win_params()).expect("build GpClient");
        // The gateway label carries the MOCK's port; the production
        // builder must put it in the URL authority, and the mock's
        // accepted socket (its own bound port, via the Host header)
        // proves it survived to the wire.
        let gateway = format!("127.0.0.1:{}", mock.addr.port());
        let url = hip_report_check_url(&gateway).replacen("https://", "http://", 1);
        let check = tokio::time::timeout(
            Duration::from_secs(10),
            client.hip_report_check_at(
                &url,
                "authcookie=MOCK-c1&user=test-user",
                "203.0.113.99",
                "MOCKmd5",
            ),
        )
        .await
        .expect("hip_report_check_at hung against the localhost mock")
        .expect("hipreportcheck must succeed against the mock");
        assert!(check.needed, "mock advertises hip-report-needed=yes");
        let c = mock.only();
        assert_eq!(c.path, "/ssl-vpn/hipreportcheck.esp");
        assert_eq!(
            c.host_header.as_deref(),
            Some(mock.addr.to_string().as_str()),
            "request authority must carry the advertised port"
        );
        for (k, v) in [
            ("client-role", "global-protect-full"),
            ("client-ip", "203.0.113.99"),
            ("md5", "MOCKmd5"),
            ("authcookie", "MOCK-c1"),
        ] {
            assert!(
                c.pairs.iter().any(|(pk, pv)| pk == k && pv == v),
                "form field {k}={v} missing from captured POST: {:?}",
                c.pairs
            );
        }
    }

    #[tokio::test]
    async fn submit_hip_report_at_mock_receives_report_on_advertised_port() {
        let mock = HipMock::start();
        let client = GpClient::new(win_params()).expect("build GpClient");
        let gateway = format!("127.0.0.1:{}", mock.addr.port());
        let url = hip_report_url(&gateway).replacen("https://", "http://", 1);
        let xml = "<hip-report><ip-address>203.0.113.99</ip-address></hip-report>";
        tokio::time::timeout(
            Duration::from_secs(10),
            client.hip_report_submit_at(
                &url,
                "authcookie=MOCK-c1&user=test-user",
                "203.0.113.99",
                xml,
            ),
        )
        .await
        .expect("submit_hip_report_at hung against the localhost mock")
        .expect("hipreport submission must succeed against the mock");
        let c = mock.only();
        assert_eq!(c.path, "/ssl-vpn/hipreport.esp");
        assert_eq!(
            c.host_header.as_deref(),
            Some(mock.addr.to_string().as_str()),
            "request authority must carry the advertised port"
        );
        assert!(
            c.pairs
                .iter()
                .any(|(k, v)| k == "client-role" && v == "global-protect-full"),
            "client-role missing: {:?}",
            c.pairs
        );
        assert!(
            c.pairs
                .iter()
                .any(|(k, v)| k == "client-ip" && v == "203.0.113.99"),
            "client-ip missing: {:?}",
            c.pairs
        );
        assert!(
            c.pairs.iter().any(|(k, _)| k == "report"),
            "report field missing entirely: {:?}",
            c.pairs
        );
    }
}

// ---------------------------------------------------------------------------
// Issue #43 review (completeness): the portal getconfig `server=`/`host=`
// form values must be hostname-only like the sibling gateway-login field
// (#42). Upstream `auth-globalprotect.c:742` sends `server=vpninfo->
// hostname` on BOTH the portal getconfig and the gateway login POST, and
// that hostname is port-free by construction (`openconnect_parse_url`).
// A port-bearing value risks the portal/gateway-name mismatch reject
// class documented in params.rs (#42 rationale). The REQUEST URL keeps
// the advertised port (#42 URL contract, characterized separately) —
// only these form VALUES change.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod portal_config_lane_tests {
    use super::*;

    #[test]
    fn portal_config_form_host_is_hostname_only() {
        // The reporter's exact #43 connect shape: portal at :11443.
        assert_eq!(
            portal_config_form_host("198.51.100.7:11443"),
            "198.51.100.7"
        );
        assert_eq!(portal_config_form_host("203.0.113.7:11443"), "203.0.113.7");
        assert_eq!(portal_config_form_host("[fd00::1]:11443"), "[fd00::1]");
        // Trailing-colon (empty advertised port) label follows the
        // same splitter rule (review findings 2/3).
        assert_eq!(
            portal_config_form_host("vpn.example.com:"),
            "vpn.example.com"
        );
    }

    #[test]
    fn portal_config_form_host_no_port_is_verbatim_unsw_pin() {
        // Maintainer daily-connect no-regression pin: with no port in
        // the label the value is byte-identical to normalize_server's.
        assert_eq!(
            portal_config_form_host("ra.vpn.unsw.edu.au"),
            "ra.vpn.unsw.edu.au"
        );
        assert_eq!(
            portal_config_form_host("https://ra.vpn.unsw.edu.au"),
            "ra.vpn.unsw.edu.au"
        );
        // Bare IPv6 never chopped (shares the splitter guard).
        assert_eq!(portal_config_form_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn portal_config_url_lane_keeps_advertised_port_only_form_values_split() {
        // #42 URL contract stays whole: login_url(portal) keeps the
        // :port in the authority while the form VALUES lose it.
        let mut p = GpParams::new(ClientOs::Win);
        p.is_gateway = false;
        assert_eq!(
            p.login_url("203.0.113.7:11443"),
            "https://203.0.113.7:11443/global-protect/getconfig.esp"
        );
        assert_eq!(
            p.login_url("ra.vpn.unsw.edu.au"),
            "https://ra.vpn.unsw.edu.au/global-protect/getconfig.esp"
        );
        assert_eq!(portal_config_form_host("203.0.113.7:11443"), "203.0.113.7");
    }

    /// Issue #43 review S4(a): the production portal_config PATH —
    /// not just the pure helper — must build `server=`/`host=` through
    /// [`portal_config_form_host`]. The wire capture pins the call
    /// site: reqwest renders the form literally, so a hostname-only
    /// pair is `server=127.0.0.1` on the wire; reverting the call
    /// site to `normalize_server(portal)` (which keeps the advertised
    /// port) turns the pairs into `server=127.0.0.1%3A<port>` and
    /// flips this test — a mutation the helper's own unit tests could
    /// never see. Loopback-only, plain HTTP (the `*_at`/`_url` mock
    /// pattern from issue #36; no TLS material in dev-deps, nothing
    /// leaves `127.0.0.1`).
    #[tokio::test]
    async fn portal_config_wire_sends_hostname_only_server_and_host() {
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind portal mock");
        let addr = listener.local_addr().expect("local_addr");
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let bodies_t = bodies.clone();
        std::thread::Builder::new()
            .name("test-portal-config-mock".into())
            .spawn(move || {
                for stream in listener.incoming().flatten() {
                    let bodies = bodies_t.clone();
                    std::thread::spawn(move || {
                        let _ = serve_portal_config_post(stream, &bodies);
                    });
                }
            })
            .expect("spawn portal mock");

        // The reporter's shape: portal ADVERTISED with a service port.
        // The URL authority keeps it (#42 — reqwest must actually
        // connect to this port, which the capture also proves); only
        // the form VALUES are hostname-only (#43/#36).
        let portal = format!("127.0.0.1:{}", addr.port());
        let url = format!("http://{addr}/global-protect/getconfig.esp");
        let client = GpClient::new(GpParams::new(ClientOs::Win)).expect("client");
        let cred = Credential::Password {
            username: "test-user".into(),
            password: "REDACTED-pw".into(),
        };
        let cfg = client
            .portal_config_url(&url, &portal, &cred)
            .await
            .expect("portal config round-trip against the mock");
        assert_eq!(cfg.portal, portal, "the verbatim label is kept for display");

        let sent = bodies.lock().expect("bodies lock");
        assert_eq!(sent.len(), 1, "exactly one getconfig POST reached the mock");
        let pairs: Vec<&str> = sent[0].split('&').filter(|p| !p.is_empty()).collect();
        assert!(
            pairs.contains(&"server=127.0.0.1"),
            "server= must be hostname-only on the WIRE (call site uses \
             portal_config_form_host); raw form body was {:?}",
            sent[0]
        );
        assert!(
            pairs.contains(&"host=127.0.0.1"),
            "host= must be hostname-only on the WIRE; raw form body was {:?}",
            sent[0]
        );
    }

    fn serve_portal_config_post(
        mut stream: std::net::TcpStream,
        bodies: &std::sync::Mutex<Vec<String>>,
    ) -> std::io::Result<()> {
        use std::io::{BufRead as _, Write as _};
        use std::time::Duration;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = std::io::BufReader::new(stream.try_clone()?);
        let mut req_line = String::new();
        if std::io::BufRead::read_line(&mut reader, &mut req_line)? == 0 {
            return Ok(());
        }
        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header)? == 0 {
                break;
            }
            if header.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = header.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut buf = vec![0u8; content_length];
        std::io::Read::read_exact(&mut reader, &mut buf)?;
        let raw = String::from_utf8_lossy(&buf).into_owned();
        // Record BEFORE answering: once the caller has a response, the
        // capture is visible (no sleep/race).
        bodies.lock().expect("bodies lock").push(raw);
        let xml = "<response status=\"success\"><result></result></response>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            xml.len(),
            xml
        );
        stream.write_all(resp.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}
