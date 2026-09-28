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
