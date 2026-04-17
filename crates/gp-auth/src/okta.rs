//! Okta headless authentication provider.
//!
//! Drives the full Okta password + MFA flow without a browser, using the
//! Okta REST API directly, then hands the resulting session token off to
//! the GlobalProtect portal's SAML SSO endpoint to extract a
//! `prelogin-cookie` (or Prisma Access JWT) for the gateway login step.
//!
//! Compared to the paste provider, Okta is fully non-interactive:
//! the user never has to open a browser, copy a `globalprotectcallback:`
//! URL, or touch the terminal between prelogin and tunnel-up. Requires
//! the IdP to actually be Okta AND the user to have their password +
//! MFA factor available non-interactively (or via terminal prompts).
//!
//! # Architecture
//!
//! The provider is split into two layers:
//!
//! 1. **State machine** ([`okta_authenticate`]) — pure logic that walks
//!    Okta's `/api/v1/authn` transaction states (`PASSWORD_WARN`,
//!    `MFA_REQUIRED`, `MFA_CHALLENGE`, `SUCCESS`) and dispatches to
//!    factor handlers. Talks to a generic [`OktaTransport`] trait so
//!    unit tests can inject canned JSON responses.
//!
//! 2. **HTTP transport** ([`ReqwestOktaTransport`]) — the production
//!    impl that uses our shared `reqwest` client. Tests use
//!    `MockTransport` in this file's `#[cfg(test)]` block.
//!
//! The GP-side handoff (parse SAML form → POST to Okta IdP → use
//! sessionCookieRedirect → follow form chain back to the portal →
//! extract `prelogin-cookie` headers) is implemented in
//! [`OktaAuthProvider::authenticate`] using both layers.
//!
//! # Reference
//!
//! Logic ported from `_refs/pan-gp-okta/gp-okta.py` (MIT, A. Raugulis et
//! al). OpenProtect re-implements the protocol from scratch in idiomatic
//! Rust — no shell-out, no Python helper, no shared globals.
//!
//! # Live verification status
//!
//! The state machine and transport layer are unit-tested against canned
//! Okta API responses. End-to-end verification against a real Okta
//! tenant + GP portal is pending — that path requires a live customer
//! environment we don't currently have, and it's documented as such in
//! the README. The pure state machine is testable as-is and is the
//! complex part.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use gp_proto::prelogin::{PreloginResponse, SamlPrelogin};
use gp_proto::Credential;

use crate::context::AuthContext;
use crate::error::AuthError;
use crate::saml_common::{looks_like_jwt, SamlCapture};
use crate::AuthProvider;

/// Default poll interval when waiting on an Okta push factor.
pub const OKTA_PUSH_POLL_INTERVAL: Duration = Duration::from_millis(3_330);

/// Maximum number of poll iterations for a push factor before we give
/// up. 60 × 3.33s ≈ 200 seconds — long enough for a user to fish their
/// phone out, short enough to not hang indefinitely if they didn't.
pub const OKTA_PUSH_MAX_POLLS: u32 = 60;

/// HTTP transport abstraction used by [`okta_authenticate`].
///
/// Real code uses [`ReqwestOktaTransport`]; tests inject a
/// `MockTransport` (in this file's test module) that returns canned
/// responses. Keeping this trait small — three methods — makes the
/// mock implementation tiny and the test fixtures explicit.
#[async_trait]
pub trait OktaTransport: Send + Sync {
    /// POST a JSON body to `url`, parse the response body as JSON.
    /// The response status is NOT inspected — Okta returns its
    /// transaction-state JSON with a 200 even for `MFA_REQUIRED`.
    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, AuthError>;

    /// GET a URL, return the response body as bytes plus any
    /// interesting headers (we look at `prelogin-cookie`,
    /// `saml-username`, `saml-auth-status`).
    async fn get(&self, url: &str) -> Result<HttpResponse, AuthError>;

    /// POST a `application/x-www-form-urlencoded` body. Same return
    /// shape as `get`.
    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<HttpResponse, AuthError>;
}

/// Minimal HTTP response shape needed by the Okta + GP-handoff dance.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    /// The URL the response actually came from after redirects.
    pub final_url: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Production transport built on `reqwest::Client`.
pub struct ReqwestOktaTransport {
    client: reqwest::Client,
}

impl ReqwestOktaTransport {
    pub fn new(insecure: bool) -> Result<Self, AuthError> {
        let client = reqwest::ClientBuilder::new()
            .cookie_store(true)
            .danger_accept_invalid_certs(insecure)
            .user_agent(gp_proto::ClientOs::default().user_agent())
            .build()
            .map_err(AuthError::from)?;
        Ok(Self { client })
    }

    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OktaTransport for ReqwestOktaTransport {
    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, AuthError> {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(AuthError::from)?;
        let status = resp.status();
        let text = resp.text().await.map_err(AuthError::from)?;
        if !status.is_success() && status.as_u16() != 401 {
            // Okta returns 401 for failed-but-structured auth (bad
            // password etc.). 4xx other than 401 is a hard error;
            // 5xx too. Accept 401 because the body still parses as
            // a transaction-state JSON.
            return Err(AuthError::Failed(format!(
                "okta {url} returned HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            AuthError::Failed(format!("okta {url} response not JSON: {e}; body={text}"))
        })
    }

    async fn get(&self, url: &str) -> Result<HttpResponse, AuthError> {
        let resp = self.client.get(url).send().await.map_err(AuthError::from)?;
        Self::convert_response(resp).await
    }

    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<HttpResponse, AuthError> {
        let resp = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(AuthError::from)?;
        Self::convert_response(resp).await
    }
}

impl ReqwestOktaTransport {
    async fn convert_response(resp: reqwest::Response) -> Result<HttpResponse, AuthError> {
        let status = resp.status().as_u16();
        let final_url = resp.url().as_str().to_string();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                let v = v.to_str().ok()?.to_string();
                Some((k.as_str().to_string(), v))
            })
            .collect();
        let body = resp.bytes().await.map_err(AuthError::from)?.to_vec();
        Ok(HttpResponse {
            status,
            body,
            headers,
            final_url,
        })
    }
}

/// One Okta MFA factor parsed out of `_embedded.factors`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaFactor {
    pub id: String,
    /// e.g. `"token:software:totp"`, `"sms"`, `"push"`, `"webauthn"`.
    pub factor_type: String,
    /// e.g. `"OKTA"`, `"DUO"`, `"SYMANTEC"`.
    pub provider: String,
    /// Verification endpoint URL.
    pub verify_url: String,
}

impl OktaFactor {
    /// Parse the relevant fields out of an Okta factor JSON object.
    /// Returns `None` if any required field is missing — the caller
    /// filters those out silently.
    pub fn from_json(value: &Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?.to_string();
        let factor_type = value.get("factorType")?.as_str()?.to_lowercase();
        let provider = value.get("provider")?.as_str()?.to_lowercase();
        let verify_url = value
            .get("_links")?
            .get("verify")?
            .get("href")?
            .as_str()?
            .to_string();
        Some(Self {
            id,
            factor_type,
            provider,
            verify_url,
        })
    }

    /// Priority for factor selection. Higher = preferred. Mirrors
    /// gp-okta.py's defaults: push > totp > sms.
    ///
    /// Note: only factors that [`is_supported`](Self::is_supported)
    /// returns `true` for participate in selection. A higher-priority
    /// unsupported factor (e.g. webauthn) is filtered out so we don't
    /// pick it and then dead-end in `run_factor`.
    pub fn priority(&self) -> u32 {
        match self.factor_type.as_str() {
            "push" => 100,
            "token:software:totp" => 90,
            "token" if self.provider == "symantec" => 80,
            "sms" => 70,
            "webauthn" => 60,
            _ => 0,
        }
    }

    /// Whether `run_factor` knows how to verify this factor type.
    /// Selection filters on this BEFORE sorting by priority, so an
    /// Okta tenant offering Symantec-token + push will pick push;
    /// a tenant offering only webauthn will surface a clear "no
    /// supported factors" error instead of silently picking
    /// webauthn and failing later.
    pub fn is_supported(&self) -> bool {
        matches!(
            self.factor_type.as_str(),
            "push" | "token:software:totp" | "sms"
        )
    }
}

/// User input callback for MFA codes. Returns the entered code, or
/// `None` if the user cancelled.
///
/// Boxed-closure form so tests can inject canned responses without
/// touching stdin.
pub type MfaPrompt = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

fn default_terminal_prompt() -> MfaPrompt {
    Arc::new(|prompt: &str| {
        use std::io::{BufRead, Write};
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = write!(out, "{prompt}: ");
        let _ = out.flush();
        let stdin = std::io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            return None;
        }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// Drive Okta's `/api/v1/authn` state machine to completion.
///
/// Returns the `sessionToken` on success. On failure returns an
/// `AuthError` with a human-readable message.
///
/// `okta_url` is the base URL of the Okta tenant
/// (e.g. `https://example.okta.com`). The transport sends one POST
/// per state transition.
pub async fn okta_authenticate(
    transport: &dyn OktaTransport,
    okta_url: &str,
    username: &str,
    password: &str,
    prompt: &MfaPrompt,
) -> Result<String, AuthError> {
    let url = format!("{}/api/v1/authn", okta_url.trim_end_matches('/'));
    let initial_body = json!({
        "username": username,
        "password": password,
        "options": {
            "warnBeforePasswordExpired": true,
            "multiOptionalFactorEnroll": true
        }
    });

    let mut current = transport.post_json(&url, &initial_body).await?;

    // Drive the transaction state machine. The loop never exceeds
    // a few iterations in practice (PASSWORD_WARN + MFA_REQUIRED +
    // SUCCESS), so a hard cap of 8 is a paranoia bound, not a
    // policy.
    for _round in 0..8 {
        let status = current
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();

        match status.as_str() {
            "SUCCESS" => {
                return current
                    .get("sessionToken")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| AuthError::Failed("okta SUCCESS without sessionToken".into()));
            }
            "PASSWORD_WARN" => {
                // Skip the password-expiration warning by POSTing
                // to the `skip` link with the current state token.
                let state_token = current
                    .get("stateToken")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::Failed("PASSWORD_WARN without stateToken".into()))?;
                let skip_url = current
                    .get("_links")
                    .and_then(|v| v.get("skip"))
                    .and_then(|v| v.get("href"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::Failed("PASSWORD_WARN without skip link".into()))?;
                tracing::info!("okta: skipping password expiration warning");
                current = transport
                    .post_json(skip_url, &json!({ "stateToken": state_token }))
                    .await?;
            }
            "MFA_REQUIRED" => {
                let state_token = current
                    .get("stateToken")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::Failed("MFA_REQUIRED without stateToken".into()))?
                    .to_string();
                let factors = current
                    .get("_embedded")
                    .and_then(|v| v.get("factors"))
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| AuthError::Failed("MFA_REQUIRED without factors".into()))?;
                let mut parsed: Vec<OktaFactor> = factors
                    .iter()
                    .filter_map(OktaFactor::from_json)
                    // Drop factors run_factor() can't verify BEFORE
                    // priority sort. Otherwise a tenant offering
                    // (webauthn, push) — webauthn has a higher raw
                    // priority than… no, push > webauthn, but the
                    // reverse case (symantec token + sms, where
                    // symantec is unsupported) would silently pick
                    // the unsupported one and dead-end.
                    .filter(OktaFactor::is_supported)
                    .collect();
                if parsed.is_empty() {
                    let raw_count = factors.len();
                    return Err(AuthError::Failed(format!(
                        "okta MFA_REQUIRED but no factors openprotect can verify \
                         (got {raw_count} factor(s); supported: push, totp, sms)"
                    )));
                }
                parsed.sort_by_key(|f| std::cmp::Reverse(f.priority()));
                let factor = parsed.into_iter().next().unwrap();
                tracing::info!(
                    "okta: selected factor type={} provider={}",
                    factor.factor_type,
                    factor.provider
                );

                current = run_factor(transport, &factor, &state_token, prompt).await?;
            }
            "MFA_CHALLENGE" => {
                // We arrive here for push polling that wasn't
                // collapsed into the factor handler — drop straight
                // back into the loop body so the next iteration
                // re-classifies. Defensive: we shouldn't normally
                // see MFA_CHALLENGE at the top of the loop because
                // run_factor() already polls until terminal.
                return Err(AuthError::Failed(
                    "okta returned MFA_CHALLENGE outside a push poll loop".into(),
                ));
            }
            "LOCKED_OUT" => return Err(AuthError::Failed("okta account is locked out".into())),
            "PASSWORD_EXPIRED" => {
                return Err(AuthError::Failed(
                    "okta password expired — change it in the web UI and retry".into(),
                ))
            }
            other => {
                return Err(AuthError::Failed(format!(
                    "unexpected okta status: {other}"
                )))
            }
        }
    }
    Err(AuthError::Failed(
        "okta state machine did not terminate after 8 transitions".into(),
    ))
}

/// Dispatch an MFA factor to its handler. Returns the post-verify
/// transaction-state JSON.
async fn run_factor(
    transport: &dyn OktaTransport,
    factor: &OktaFactor,
    state_token: &str,
    prompt: &MfaPrompt,
) -> Result<Value, AuthError> {
    match factor.factor_type.as_str() {
        "push" => run_push(transport, factor, state_token).await,
        "token:software:totp" => run_totp(transport, factor, state_token, prompt).await,
        "sms" => run_sms(transport, factor, state_token, prompt).await,
        other => Err(AuthError::Failed(format!(
            "okta factor type {other:?} not yet supported in openprotect (push, totp, sms only)"
        ))),
    }
}

/// Push factor: POST to /verify, then poll until the response is
/// SUCCESS (or some terminal state).
async fn run_push(
    transport: &dyn OktaTransport,
    factor: &OktaFactor,
    state_token: &str,
) -> Result<Value, AuthError> {
    let body = json!({
        "factorId": factor.id,
        "stateToken": state_token,
    });
    tracing::info!("okta: push request sent — approve on your device");
    let mut response = transport.post_json(&factor.verify_url, &body).await?;
    for poll in 0..OKTA_PUSH_MAX_POLLS {
        let status = response
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        if status != "MFA_CHALLENGE" {
            return Ok(response);
        }
        // Optional: check `factorResult` field for `WAITING` /
        // `REJECTED` / `TIMEOUT`. gp-okta.py just polls; we do the
        // same and fail on the next status read.
        if let Some(result) = response
            .get("factorResult")
            .and_then(|v| v.as_str())
            .map(str::to_uppercase)
        {
            if result == "REJECTED" {
                return Err(AuthError::Failed(
                    "okta push factor was rejected on the device".into(),
                ));
            }
            if result == "TIMEOUT" {
                return Err(AuthError::Failed("okta push factor timed out".into()));
            }
        }
        tracing::debug!("okta push: poll #{poll}, still waiting");
        tokio::time::sleep(OKTA_PUSH_POLL_INTERVAL).await;
        response = transport.post_json(&factor.verify_url, &body).await?;
    }
    Err(AuthError::Failed(format!(
        "okta push factor did not resolve after {OKTA_PUSH_MAX_POLLS} polls"
    )))
}

/// TOTP factor: prompt the user, POST passCode.
async fn run_totp(
    transport: &dyn OktaTransport,
    factor: &OktaFactor,
    state_token: &str,
    prompt: &MfaPrompt,
) -> Result<Value, AuthError> {
    let prompt_text = format!("Okta {} TOTP code", factor.provider);
    let code = prompt(&prompt_text).ok_or(AuthError::Cancelled)?;
    let body = json!({
        "factorId": factor.id,
        "stateToken": state_token,
        "passCode": code,
    });
    transport.post_json(&factor.verify_url, &body).await
}

/// SMS factor: trigger a code, prompt, POST the code back.
async fn run_sms(
    transport: &dyn OktaTransport,
    factor: &OktaFactor,
    state_token: &str,
    prompt: &MfaPrompt,
) -> Result<Value, AuthError> {
    let trigger = json!({
        "factorId": factor.id,
        "stateToken": state_token,
    });
    transport.post_json(&factor.verify_url, &trigger).await?;
    let prompt_text = format!("Okta {} SMS code", factor.provider);
    let code = prompt(&prompt_text).ok_or(AuthError::Cancelled)?;
    let body = json!({
        "factorId": factor.id,
        "stateToken": state_token,
        "passCode": code,
    });
    transport.post_json(&factor.verify_url, &body).await
}

/// Configuration for the [`OktaAuthProvider`].
#[derive(Clone)]
pub struct OktaAuthConfig {
    /// Base URL of the Okta tenant (e.g. `https://example.okta.com`).
    /// **Required** — there's no reliable way to discover this from
    /// the GP SAML form alone.
    pub okta_url: String,
    /// Accept invalid TLS certificates on Okta + portal HTTPS calls.
    /// Mirrors the `--insecure` flag.
    pub insecure: bool,
}

/// Headless Okta SAML provider.
///
/// Implements [`AuthProvider`]: takes a `PreloginResponse::Saml`,
/// drives Okta's API, then completes the GP portal SAML handshake
/// using the resulting session token — all without any browser.
pub struct OktaAuthProvider {
    pub config: OktaAuthConfig,
    pub prompt: MfaPrompt,
}

impl OktaAuthProvider {
    pub fn new(config: OktaAuthConfig) -> Self {
        Self {
            config,
            prompt: default_terminal_prompt(),
        }
    }

    /// Replace the default stdin prompt with a custom callback —
    /// used by tests to inject canned MFA codes.
    pub fn with_prompt(mut self, prompt: MfaPrompt) -> Self {
        self.prompt = prompt;
        self
    }
}

#[async_trait]
impl AuthProvider for OktaAuthProvider {
    fn name(&self) -> &str {
        "okta"
    }

    fn can_handle(&self, prelogin: &PreloginResponse) -> bool {
        // The provider can in principle handle ANY SAML prelogin —
        // the discriminator is whether the user opted in via
        // `--auth-mode okta`, not auto-detection. The GP prelogin
        // payload doesn't tell us which IdP is wired up.
        matches!(prelogin, PreloginResponse::Saml(_))
    }

    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        ctx: &AuthContext,
    ) -> Result<Credential, AuthError> {
        let saml = match prelogin {
            PreloginResponse::Saml(s) => s.clone(),
            _ => {
                return Err(AuthError::Failed(
                    "okta provider needs a SAML prelogin".into(),
                ))
            }
        };
        let username = ctx
            .username
            .clone()
            .ok_or_else(|| AuthError::Failed("okta provider requires --user".into()))?;
        let password = ctx
            .password
            .clone()
            .ok_or_else(|| AuthError::Failed("okta provider requires --passwd-on-stdin".into()))?;

        let transport = ReqwestOktaTransport::new(self.config.insecure)?;

        // Stage 1: pure Okta API auth → sessionToken.
        let session_token = okta_authenticate(
            &transport,
            &self.config.okta_url,
            &username,
            &password,
            &self.prompt,
        )
        .await?;
        tracing::info!("okta: obtained session token");

        // Stage 2: GP portal SAML handshake.
        let capture =
            okta_complete_gp_handshake(&transport, &saml, &session_token, &username).await?;
        tracing::info!("okta: GP capture user={}", capture.username);

        Ok(capture.into_credential())
    }
}

/// Drive the post-Okta dance: parse the GP SAML form, post it (which
/// is the moment Okta would normally redirect a real browser to a
/// login page), then use the session token via
/// `/login/sessionCookieRedirect` to follow the chain back to the GP
/// portal/gateway, where the final response carries
/// `prelogin-cookie` + `saml-username` headers (or the
/// `globalprotectcallback:` URI for Prisma Access).
async fn okta_complete_gp_handshake(
    transport: &dyn OktaTransport,
    saml: &SamlPrelogin,
    session_token: &str,
    username_hint: &str,
) -> Result<SamlCapture, AuthError> {
    // The SAML prelogin gives us either:
    //   * REDIRECT method → saml.saml_request is a URL we GET
    //   * POST method     → saml.saml_request is a base64-encoded
    //                        HTML form we parse and POST
    //
    // In either case the first hop is meant for the IdP, which in
    // our case is Okta. We need to convert that hop into something
    // that Okta will accept after we already have a session token.
    //
    // The conventional approach (from gp-okta.py) is:
    //   1. Issue the IdP-bound request.
    //   2. Okta responds with its login form.
    //   3. Replace its login flow by hitting
    //      /login/sessionCookieRedirect with token=<sessionToken>
    //      and redirectUrl=<the URL Okta wants to land on>.
    //   4. Follow the resulting form chain back to the GP portal.
    //
    // We approximate steps 1-3 by sending the SAML request, then
    // using sessionCookieRedirect with the response's final URL as
    // the redirect target. Many tenants accept this directly.

    let initial_response = match saml.saml_auth_method.as_str() {
        "REDIRECT" => transport.get(&saml.saml_request).await?,
        "POST" => {
            // saml.saml_request is base64-encoded HTML containing an
            // auto-submit form. Decode it, extract the action URL +
            // hidden inputs, and POST. The action in the GP-emitted
            // form is conventionally absolute (it's the IdP entry
            // URL); we hard-fail on a relative action here because
            // there's no sensible base URL to resolve against at
            // the start of the chain.
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine;
            let html_bytes = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            let html = String::from_utf8_lossy(&html_bytes).to_string();
            let (action, fields) = parse_saml_form(&html)
                .ok_or_else(|| AuthError::Failed("could not parse SAML POST form".into()))?;
            if !action.starts_with("http://") && !action.starts_with("https://") {
                return Err(AuthError::Failed(format!(
                    "GP-emitted SAML form has relative action {action:?}; expected an absolute IdP URL"
                )));
            }
            let form_pairs: Vec<(&str, &str)> = fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            transport.post_form(&action, &form_pairs).await?
        }
        other => {
            return Err(AuthError::Failed(format!(
                "unknown saml-auth-method: {other}"
            )))
        }
    };

    // Try to extract a `prelogin-cookie` directly — some configs
    // shortcut the whole redirect chain because the cookie store
    // already carries the Okta session.
    if let Some(cap) = capture_from_response(&initial_response, username_hint) {
        return Ok(cap);
    }

    // Fallback: convert the session token into a cookie via Okta's
    // session-cookie-redirect endpoint, pointing back at whatever
    // URL the IdP wanted to land on, and follow up to ten hops.
    let redirect_url = initial_response.final_url.clone();
    let okta_base = okta_base_from_url(&redirect_url).ok_or_else(|| {
        AuthError::Failed(format!(
            "could not derive Okta base URL from {redirect_url:?}"
        ))
    })?;
    let cookie_url = format!("{okta_base}/login/sessionCookieRedirect");
    let cookie_form: [(&str, &str); 4] = [
        ("checkAccountSetupComplete", "true"),
        ("report", "true"),
        ("token", session_token),
        ("redirectUrl", &redirect_url),
    ];
    let mut current = transport.post_form(&cookie_url, &cookie_form).await?;

    for hop in 0..10 {
        if let Some(cap) = capture_from_response(&current, username_hint) {
            return Ok(cap);
        }
        // Look for a follow-on form in the response body. The
        // form's `action` may be relative (root-relative
        // `/path/x`, scheme-relative `//host/x`, or relative
        // `rel/path`); resolve it against the URL the response
        // came from so we POST to the right place.
        let body = current.body_str().to_string();
        let base_url = current.final_url.clone();
        let Some((next_action_raw, next_fields)) = parse_saml_form(&body) else {
            return Err(AuthError::Failed(format!(
                "okta redirect chain stopped at hop {hop} with no form and no GP cookie headers"
            )));
        };
        let next_action = resolve_relative_url(&base_url, &next_action_raw);
        let pairs: Vec<(&str, &str)> = next_fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        current = transport.post_form(&next_action, &pairs).await?;
    }
    Err(AuthError::Failed(
        "okta redirect chain too deep (>10 hops)".into(),
    ))
}

/// Inspect a response for the GP portal's SAML success headers OR a
/// `globalprotectcallback:` URI in the body, returning a [`SamlCapture`]
/// if either is present.
fn capture_from_response(resp: &HttpResponse, username_hint: &str) -> Option<SamlCapture> {
    let username = resp
        .header("saml-username")
        .map(str::to_string)
        .unwrap_or_else(|| username_hint.to_string());
    if let Some(cookie) = resp.header("prelogin-cookie") {
        return Some(SamlCapture {
            username,
            prelogin_cookie: cookie.to_string(),
            portal_user_auth_cookie: resp.header("portal-userauthcookie").map(str::to_string),
        });
    }
    // Some Prisma Access configurations land the browser on a page
    // whose body contains `globalprotectcallback:` — try the
    // existing parser.
    let body = resp.body_str();
    if let Some(idx) = body.find("globalprotectcallback:") {
        let tail = &body[idx..];
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '\'')
            .unwrap_or(tail.len());
        if let Some(cap) = crate::saml_common::parse_globalprotect_callback(&tail[..end]) {
            return Some(cap);
        }
    }
    // If the body looks like a JWT all by itself (rare but seen on
    // some tenants), wrap it.
    let trimmed = body.trim();
    if looks_like_jwt(trimmed) {
        return Some(SamlCapture {
            username,
            prelogin_cookie: trimmed.to_string(),
            portal_user_auth_cookie: None,
        });
    }
    None
}

/// Parse the first `<form>` out of an HTML body and return
/// `(action, hidden_fields)`. Hand-rolled to avoid pulling in an
/// HTML parser crate.
///
/// **ASCII-lowercase only** (`str::to_ascii_lowercase`): preserves
/// byte indices on non-ASCII input. The full Unicode `to_lowercase`
/// can change byte length (e.g. some letters lowercase to multi-byte
/// sequences), which would make the byte indices we compute against
/// the lowercase copy invalid when sliced into the original — and
/// crash.
///
/// Limitations: this is a tag-scanner, not an HTML parser. It does
/// NOT handle:
///   - HTML comments containing `<form>`
///   - `<script>` / CDATA blocks containing `<form>`
///   - Nested forms (HTML5 prohibits them but real-world tenants
///     occasionally emit them)
///
/// All three are documented as known gaps. The fallback when the
/// parser misbehaves is the outer redirect-chain hop limit (10) —
/// we'll fail with a clear "redirect chain stopped" rather than
/// loop forever.
fn parse_saml_form(html: &str) -> Option<(String, Vec<(String, String)>)> {
    let lower = html.to_ascii_lowercase();
    let form_start = lower.find("<form")?;
    let form_end = lower[form_start..]
        .find("</form>")
        .map(|i| form_start + i + "</form>".len())?;
    let form = &html[form_start..form_end];
    let form_lower = &lower[form_start..form_end];

    let action = extract_attr(form, form_lower, "action")?;
    let mut fields = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = form_lower[cursor..].find("<input") {
        let abs = cursor + rel;
        let close = form_lower[abs..].find('>')?;
        let tag_end = abs + close + 1;
        let tag = &form[abs..tag_end];
        let tag_lower = &form_lower[abs..tag_end];
        if let (Some(name), Some(value)) = (
            extract_attr(tag, tag_lower, "name"),
            extract_attr(tag, tag_lower, "value"),
        ) {
            fields.push((name, value));
        }
        cursor = tag_end;
    }
    Some((action, fields))
}

/// Extract a quoted attribute value from an HTML tag fragment.
///
/// `tag` is the original substring (preserves casing of values);
/// `tag_lower` is the byte-aligned ASCII-lowercase view used for
/// case-insensitive needle matching. The two MUST be byte-equal in
/// length and refer to the same logical fragment.
///
/// Tries `name="..."` first, then `name='...'`.
fn extract_attr(tag: &str, tag_lower: &str, name: &str) -> Option<String> {
    debug_assert_eq!(tag.len(), tag_lower.len());
    let needle_dq = format!("{name}=\"");
    if let Some(start) = tag_lower.find(&needle_dq) {
        let after = start + needle_dq.len();
        if let Some(end) = tag[after..].find('"') {
            return Some(tag[after..after + end].to_string());
        }
    }
    let needle_sq = format!("{name}='");
    if let Some(start) = tag_lower.find(&needle_sq) {
        let after = start + needle_sq.len();
        if let Some(end) = tag[after..].find('\'') {
            return Some(tag[after..after + end].to_string());
        }
    }
    None
}

/// Resolve a (possibly relative) URL against a base URL.
///
/// This is the URL-resolution rule SAML form chains rely on: an
/// `action="/path/...."` or `action="relative/file"` in a response
/// body must be resolved against the URL the response came from
/// before being POSTed.
///
/// Cases:
///   - `https://...` or `http://...` → returned verbatim
///   - `//host/path` (scheme-relative) → inherit base scheme
///   - `/abs/path` (root-relative) → inherit base origin
///   - `rel/path` or `?query` (relative) → strip the last
///     path segment from base, append
///
/// Hand-rolled to avoid pulling in `url` crate just for this.
pub(crate) fn resolve_relative_url(base: &str, target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    let (scheme, rest) = match base.split_once("://") {
        Some(p) => p,
        None => return target.to_string(),
    };
    if let Some(after_slashes) = target.strip_prefix("//") {
        return format!("{scheme}://{after_slashes}");
    }
    // origin = scheme://host[:port]
    let origin_end = rest.find('/').unwrap_or(rest.len());
    let origin = &rest[..origin_end];
    let base_path = &rest[origin_end..];
    if let Some(abs) = target.strip_prefix('/') {
        return format!("{scheme}://{origin}/{abs}");
    }
    if let Some(query) = target.strip_prefix('?') {
        let path_no_query = base_path.split('?').next().unwrap_or(base_path);
        return format!("{scheme}://{origin}{path_no_query}?{query}");
    }
    // Relative path: drop the last segment of base_path's path
    // (the bit after the final `/`) and append `target`.
    let path_no_query = base_path.split('?').next().unwrap_or(base_path);
    let parent = match path_no_query.rfind('/') {
        Some(idx) => &path_no_query[..=idx],
        None => "/",
    };
    format!("{scheme}://{origin}{parent}{target}")
}

/// Derive the Okta base URL (`https://example.okta.com`) from a full
/// URL like `https://example.okta.com/app/.../sso/saml`. Returns
/// `None` for non-https URLs.
fn okta_base_from_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host_end = rest.find('/').unwrap_or(rest.len());
    Some(format!("https://{}", &rest[..host_end]))
}

// ============================================================
// Okta Identity Engine (OIE) — /idp/idx/* state machine
// ============================================================
//
// The classic `okta_authenticate` above drives Okta's
// `/api/v1/authn` state machine, which Okta now calls the
// "legacy Authentication API." Modern Okta tenants that have
// been migrated to Okta Identity Engine (OIE) expose a
// different surface: `/idp/idx/introspect`,
// `/idp/idx/identify`, `/idp/idx/challenge`,
// `/idp/idx/challenge/answer`, `/idp/idx/authenticators/poll`,
// `/idp/idx/skip`. Some features — notably enrollment flows,
// FIDO2/WebAuthn, and adaptive MFA — require the IDX path even
// when `/api/v1/authn` is still technically exposed.
//
// This block implements the subset of IDX that covers the
// common openprotect case: password + push / TOTP / SMS MFA.
// WebAuthn and enrollment are deliberately out of scope (no
// hardware, no live test environment). The state machine is a
// straight port of `okta_oie_*` in
// `_refs/pan-gp-okta/gp-okta.py`, adjusted for Rust's error
// handling conventions.
//
// Integration strategy (future — not yet wired): the
// provider's `authenticate` method currently only drives the
// classic `/api/v1/authn` path. A follow-up session will add
// a SAML-first entry that GETs the prelogin SAML URL, feeds
// the resulting HTML to [`extract_state_token_from_html`], and
// pivots into [`okta_authenticate_oie`] when a state token is
// present. Classic remains the fallback for tenants that
// still expose the legacy endpoint. As of this commit the OIE
// function is a STANDALONE building block with unit tests —
// reachable from tests but not from `OktaAuthProvider::authenticate`.
//
// This function pair is NOT YET live-tested against a real
// OIE tenant — see the module-level "Live verification status"
// docstring. The state machine + state-token extractor are
// unit-tested against canned IDX JSON responses. The wire
// protocol was ported from `_refs/pan-gp-okta/gp-okta.py`
// `okta_oie_*` functions (lines 807-1087 in that file) and
// independently reviewed against the reference for shape
// correctness.
//
// One deliberate structural divergence from the reference:
// the Python `okta_oie_login` at gp-okta.py:905-938 calls
// `/idp/idx/introspect` a SECOND time at the top of the
// identify step, re-fetching the state before POSTing the
// identifier. Our Rust port omits that second call and
// threads the stateHandle from the initial introspect
// directly into the `/idp/idx/identify` POST. The reasoning
// is that the IDX server accepts an identify POST against
// the first stateHandle it issued — Python's second
// introspect looks like a code-organisation artefact (each
// "step" function is self-contained in the Python source)
// rather than a protocol requirement. That reasoning is
// NOT yet confirmed against a live OIE tenant. If a live
// test surfaces an "invalid stateHandle" error on the
// identify POST, restore the second introspect in
// `okta_authenticate_oie` before the identify step. Tracked
// as a follow-up verification item.

/// Result of running the OIE state machine to terminal.
///
/// Today the only terminal state we recognise is a success
/// `href` — Okta's IDX flow finishes with a redirect URL that
/// resumes the SAML dance. We don't yet handle post-success
/// enrollment prompts or re-auth challenges that fire after a
/// successful login (those are OIE features openprotect does not
/// need to drive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OieOutcome {
    /// OIE completed. The contained URL is the next hop in
    /// the SAML chain — GET it and continue the GP handshake
    /// from wherever the redirect lands.
    SuccessHref(String),
}

/// A single MFA factor option surfaced by OIE's
/// `select-authenticator-authenticate` remediation. The
/// structure parallels `OktaFactor` for the classic flow but
/// the field names come straight from the IDX response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OieFactor {
    /// Human-readable label from the authenticator option
    /// (e.g. `"Okta Verify"`, `"Google Authenticator"`).
    pub label: String,
    /// IDX authenticator `id` — opaque string, echoed back on
    /// the challenge request.
    pub id: String,
    /// Optional enrollment id. Only present for authenticators
    /// the user has multiple instances of.
    pub enrollment_id: Option<String>,
    /// `methodType` — `"push"`, `"totp"`, `"otp"`, `"sms"`,
    /// `"email"`, `"password"`, `"webauthn"`, …
    pub method_type: String,
    /// Derived priority for automatic selection. Higher wins.
    /// Same scale as `OktaFactor::priority()` so operators
    /// reading logs can compare classic and OIE choices.
    pub priority: u32,
}

impl OieFactor {
    /// Priority hierarchy for OIE factors. Deliberately matches
    /// classic [`OktaFactor::priority`] (push > totp > sms >
    /// email > webauthn > password) so users who cross the
    /// classic/OIE boundary don't see a different factor
    /// selection depending on which code path their tenant
    /// takes.
    ///
    /// This ordering **diverges from the pan-gp-okta Python
    /// reference** at `mfa_priority` (gp-okta.py:332-352),
    /// which defaults to `totp > sms > push > webauthn`. The
    /// divergence was introduced in the original openprotect
    /// classic-flow port — rationale: push is typically the
    /// lowest-friction factor for users (one tap vs pulling up
    /// an authenticator app), and modern Okta tenants also
    /// consider push the "recommended" factor. Users who need
    /// a different ordering should file an issue; we can add
    /// a `PGN_OKTA_MFA_ORDER` env var in a follow-up.
    ///
    /// `password` as a factor is a new OIE-only concept — in
    /// classic `/api/v1/authn` the password is the initial
    /// credential, not an MFA factor. OIE can surface it as a
    /// secondary challenge. We give it the lowest non-zero
    /// score since the user has already provided it once.
    fn priority_from_method(method_type: &str) -> u32 {
        match method_type {
            "push" => 100,
            "otp" | "totp" => 90,
            "sms" => 80,
            "email" => 70,
            "webauthn" => 60,
            "password" => 50,
            _ => 0,
        }
    }
}

/// Drive Okta Identity Engine's IDX state machine to terminal.
///
/// `okta_url` is the tenant base URL. `state_token` is the
/// token obtained either from `/idp/idx/introspect` response
/// to a classic-API pivot OR by scraping the SAML landing
/// page's `stateToken` JS variable. `username` + `password`
/// feed the `identify` remediation. `prompt` is used to
/// request TOTP / SMS codes interactively when a factor
/// requires one.
///
/// Returns [`OieOutcome::SuccessHref`] on success. The caller
/// is responsible for following that URL and continuing the
/// SAML chain that leads back to the GP portal — typically by
/// feeding it into the same code path that handles classic
/// `okta_complete_gp_handshake`.
pub async fn okta_authenticate_oie(
    transport: &dyn OktaTransport,
    okta_url: &str,
    state_token: &str,
    username: &str,
    password: &str,
    prompt: &MfaPrompt,
) -> Result<OieOutcome, AuthError> {
    let base = okta_url.trim_end_matches('/');
    let introspect_url = format!("{base}/idp/idx/introspect");
    let identify_url = format!("{base}/idp/idx/identify");
    let challenge_url = format!("{base}/idp/idx/challenge");
    let challenge_answer_url = format!("{base}/idp/idx/challenge/answer");
    let poll_url = format!("{base}/idp/idx/authenticators/poll");
    let skip_url = format!("{base}/idp/idx/skip");

    // Step 1: introspect → get stateHandle + initial remediation.
    tracing::info!("okta OIE: /idp/idx/introspect");
    let mut current = transport
        .post_json(&introspect_url, &json!({ "stateToken": state_token }))
        .await?;
    let state_handle = oie_require_state_handle(&current)?;

    // Step 2: identify → POST identifier + credentials.
    tracing::info!("okta OIE: /idp/idx/identify");
    current = transport
        .post_json(
            &identify_url,
            &json!({
                "stateHandle": state_handle,
                "identifier": username,
                "credentials": { "passcode": password },
            }),
        )
        .await?;

    // Step 3: walk the identify-parse state machine. In practice
    // this loops through: success | select-authenticator →
    // challenge → answer/poll → (repeat until success). A hard
    // cap of 10 rounds is a paranoia bound — each round is one
    // IDX POST, and real tenants converge in 3-4.
    for round in 0..10 {
        // Terminal: success with href.
        if let Some(href) = current
            .get("success")
            .and_then(|v| v.get("href"))
            .and_then(|v| v.as_str())
        {
            tracing::info!("okta OIE: success after {round} round(s)");
            return Ok(OieOutcome::SuccessHref(href.to_string()));
        }

        let state_handle = oie_require_state_handle(&current)?;
        let rem_items = oie_remediation_items(&current)?;
        let rem_names: Vec<String> = rem_items
            .iter()
            .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(str::to_string))
            .collect();

        // Password expiring? OIE surfaces this as a `skip`
        // remediation alongside a message with
        // `i18n.key == "idx.password.expiring.message"`. Click
        // skip if present — the user's password still works,
        // they're just being reminded to change it.
        if rem_names.iter().any(|n| n == "skip") && oie_is_password_expiring(&current) {
            tracing::warn!("okta OIE: password expiring soon; skipping the prompt and continuing");
            current = transport
                .post_json(&skip_url, &json!({ "stateHandle": state_handle }))
                .await?;
            continue;
        }

        // Password already expired? OIE signals this by
        // exposing ONLY a `reenroll-authenticator` remediation
        // (no `skip`, no `select-authenticator-authenticate`).
        // openprotect does not drive the password-change flow —
        // emit a dedicated error message pointing the user at
        // the Okta web UI. Mirrors pan-gp-okta's
        // `okta_oie_identify_parse` behaviour around lines
        // 972-974 of gp-okta.py.
        if rem_names == ["reenroll-authenticator"] {
            return Err(AuthError::Failed(
                "okta OIE: password has expired — change it in the Okta web UI \
                 and retry. openprotect does not drive the password-reset flow."
                    .into(),
            ));
        }

        // The main happy path: pick an authenticator.
        let Some(select_auth) = rem_items.iter().find(|r| {
            r.get("name").and_then(|v| v.as_str()) == Some("select-authenticator-authenticate")
        }) else {
            return Err(AuthError::Failed(format!(
                "okta OIE: round {round} exposed no `select-authenticator-authenticate` \
                 remediation and no success href; available remediations = {rem_names:?}"
            )));
        };

        let factors = oie_parse_factors(select_auth)?;
        if factors.is_empty() {
            return Err(AuthError::Failed(
                "okta OIE: select-authenticator-authenticate exposed no factors".into(),
            ));
        }
        let mut sorted = factors;
        sorted.sort_by_key(|f| std::cmp::Reverse(f.priority));
        let factor = sorted
            .into_iter()
            .find(|f| {
                matches!(
                    f.method_type.as_str(),
                    "push" | "otp" | "totp" | "sms" | "password"
                )
            })
            .ok_or_else(|| {
                AuthError::Failed(
                    "okta OIE: no supported factor available \
                     (openprotect OIE flow handles push, totp, sms, password)"
                        .into(),
                )
            })?;
        tracing::info!(
            "okta OIE: selected factor '{}' ({})",
            factor.label,
            factor.method_type
        );

        // POST /idp/idx/challenge with the chosen authenticator.
        let mut authenticator = json!({
            "id": factor.id,
            "methodType": factor.method_type,
        });
        if let Some(eid) = &factor.enrollment_id {
            authenticator
                .as_object_mut()
                .unwrap()
                .insert("enrollmentId".into(), Value::String(eid.clone()));
        }
        current = transport
            .post_json(
                &challenge_url,
                &json!({
                    "stateHandle": state_handle,
                    "authenticator": authenticator,
                }),
            )
            .await?;
        let post_challenge_handle = oie_require_state_handle(&current)?;

        // Now handle the challenge response based on factor type.
        match factor.method_type.as_str() {
            "push" => {
                // Validate the post-challenge response really
                // carries a `challenge-poll` remediation. Python
                // (gp-okta.py:876-878) emits a clear error here
                // if the server got the authenticator wrong —
                // e.g. a tenant that claims a push factor in
                // select-authenticator but then comes back with
                // a challenge-authenticator instead. Without
                // the check we would silently start polling and
                // time out 200 seconds later with no diagnostic.
                let post_challenge_rem = oie_remediation_items(&current)?;
                let has_poll = post_challenge_rem
                    .iter()
                    .any(|r| r.get("name").and_then(|v| v.as_str()) == Some("challenge-poll"));
                if !has_poll {
                    let names: Vec<String> = post_challenge_rem
                        .iter()
                        .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(str::to_string))
                        .collect();
                    return Err(AuthError::Failed(format!(
                        "okta OIE: push challenge response did not expose a \
                         `challenge-poll` remediation; available = {names:?}"
                    )));
                }
                current = oie_poll_push(transport, &poll_url, &post_challenge_handle).await?;
                // Loop top will read the success href.
                continue;
            }
            "otp" | "totp" => {
                let prompt_text = format!("Okta {} TOTP code", factor.label);
                let code = prompt(&prompt_text).ok_or(AuthError::Cancelled)?;
                current = transport
                    .post_json(
                        &challenge_answer_url,
                        &json!({
                            "stateHandle": post_challenge_handle,
                            "credentials": { "passcode": code },
                        }),
                    )
                    .await?;
            }
            "sms" => {
                let prompt_text = format!("Okta {} SMS code", factor.label);
                let code = prompt(&prompt_text).ok_or(AuthError::Cancelled)?;
                current = transport
                    .post_json(
                        &challenge_answer_url,
                        &json!({
                            "stateHandle": post_challenge_handle,
                            "credentials": { "passcode": code },
                        }),
                    )
                    .await?;
            }
            "password" => {
                // OIE can require the user to re-enter their
                // password as a second factor. We reuse the
                // supplied password rather than re-prompting.
                current = transport
                    .post_json(
                        &challenge_answer_url,
                        &json!({
                            "stateHandle": post_challenge_handle,
                            "credentials": { "passcode": password },
                        }),
                    )
                    .await?;
            }
            other => {
                return Err(AuthError::Failed(format!(
                    "okta OIE: method_type {other:?} not implemented (push, totp, sms, password only)"
                )));
            }
        }
    }
    // Round budget exhausted. Dump the last-seen state so the
    // operator can see WHERE the machine got stuck — the round
    // count alone is not actionable, but "stuck on these
    // remediations" pinpoints the missing feature.
    let last_rem_names: Vec<String> = oie_remediation_items(&current)
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    Err(AuthError::Failed(format!(
        "okta OIE: state machine exceeded 10 rounds without terminating; \
         last-seen remediations = {last_rem_names:?}"
    )))
}

/// Extract `stateHandle` from an IDX response, or return a
/// clear error if missing. Called at every step of the state
/// machine — a missing stateHandle is always fatal.
fn oie_require_state_handle(response: &Value) -> Result<String, AuthError> {
    response
        .get("stateHandle")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AuthError::Failed("okta OIE: response missing stateHandle".into()))
}

/// Extract the `remediation.value` array (each entry is a
/// remediation descriptor). Returns an empty error-wrapped
/// vector if remediation is absent, which in the IDX protocol
/// means the response is expected to have been a success
/// (checked earlier by the caller) — the loop body will
/// propagate the error upward.
fn oie_remediation_items(response: &Value) -> Result<Vec<Value>, AuthError> {
    let rem = response
        .get("remediation")
        .ok_or_else(|| AuthError::Failed("okta OIE: response missing remediation".into()))?;
    if rem.get("type").and_then(|v| v.as_str()) != Some("array") {
        return Err(AuthError::Failed(
            "okta OIE: remediation.type is not 'array'".into(),
        ));
    }
    Ok(rem
        .get("value")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Check whether an IDX response carries a
/// `idx.password.expiring.message` i18n marker. Used together
/// with the presence of a `skip` remediation to decide whether
/// to auto-skip the password-expiring nag screen.
fn oie_is_password_expiring(response: &Value) -> bool {
    let Some(messages) = response
        .get("messages")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_array())
    else {
        return false;
    };
    messages.iter().any(|m| {
        let by_i18n = m
            .get("i18n")
            .and_then(|v| v.get("key"))
            .and_then(|v| v.as_str())
            == Some("idx.password.expiring.message");
        let by_substring = m
            .get("message")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("password expires"))
            .unwrap_or(false);
        by_i18n || by_substring
    })
}

/// Parse the `select-authenticator-authenticate` remediation
/// into a flat list of factor options. Each authenticator may
/// expose one methodType directly on its `value.methodType`
/// field OR multiple via `options[]` — both are flattened to
/// separate `OieFactor` entries so the caller can just sort by
/// priority and pick the best.
///
/// This mirrors the Python reference's option-walk in
/// `okta_oie_identify_parse` around lines 975-1022. The shape
/// is deeply nested: the top `select_auth.value[]` contains one
/// entry named `authenticator` whose `options[]` contains one
/// entry per authenticator the user has enrolled. Each option
/// carries a `label` + a nested `value.form.value[]` that
/// holds the `id`, `enrollmentId`, and `methodType` fields.
pub(crate) fn oie_parse_factors(select_auth: &Value) -> Result<Vec<OieFactor>, AuthError> {
    let outer = select_auth
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AuthError::Failed("select-authenticator: missing value array".into()))?;
    let authenticator = outer
        .iter()
        .find(|v| v.get("name").and_then(|n| n.as_str()) == Some("authenticator"))
        .ok_or_else(|| {
            AuthError::Failed("select-authenticator: missing `authenticator` value entry".into())
        })?;
    let options = authenticator
        .get("options")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            AuthError::Failed("select-authenticator: authenticator has no options[]".into())
        })?;

    let mut factors = Vec::new();
    for opt in options {
        let label = opt
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if label.is_empty() {
            continue;
        }

        // Authenticator option → value.form.value[] carries the
        // required fields: id, (optional) enrollmentId, methodType.
        let form = opt.get("value").and_then(|v| v.get("form"));
        let form_fields = form
            .and_then(|f| f.get("value"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut id: Option<String> = None;
        let mut enrollment_id: Option<String> = None;
        let mut method_field: Option<&Value> = None;
        for fi in &form_fields {
            let name = fi.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name == "id" {
                id = fi.get("value").and_then(|v| v.as_str()).map(str::to_string);
            } else if name == "enrollmentId" {
                enrollment_id = fi.get("value").and_then(|v| v.as_str()).map(str::to_string);
            } else if name == "methodType" {
                method_field = Some(fi);
            }
        }
        let id = match id {
            Some(id) => id,
            None => {
                // The Python reference errors out on this path
                // (gp-okta.py:991-1001) on the reasoning that a
                // missing `id` is a protocol violation. We warn
                // and skip instead so one broken option in a
                // list of many doesn't fail the whole login —
                // the caller will error with "no supported
                // factor" if ALL options get dropped, which is
                // where a real protocol problem would surface.
                // The warn makes the decision visible.
                tracing::warn!(
                    "okta OIE: skipping authenticator option '{label}' — missing required `id` field"
                );
                continue;
            }
        };

        // methodType can be either a single `value: "totp"` or
        // a list of `options[]` when the authenticator offers
        // multiple methods. Flatten to one OieFactor per method.
        let mut method_types: Vec<String> = Vec::new();
        if let Some(mf) = method_field {
            if let Some(v) = mf.get("value").and_then(|v| v.as_str()) {
                method_types.push(v.to_string());
            } else if let Some(opts) = mf.get("options").and_then(|v| v.as_array()) {
                for o in opts {
                    if let Some(v) = o.get("value").and_then(|v| v.as_str()) {
                        method_types.push(v.to_string());
                    }
                }
            }
        }
        if method_types.is_empty() {
            continue;
        }

        for mt in method_types {
            let priority = OieFactor::priority_from_method(&mt);
            factors.push(OieFactor {
                label: label.clone(),
                id: id.clone(),
                enrollment_id: enrollment_id.clone(),
                method_type: mt,
                priority,
            });
        }
    }
    Ok(factors)
}

/// Poll `/idp/idx/authenticators/poll` until the response
/// carries a `success.href`. Matches the Python reference's
/// `okta_oie_mfa_push` loop. Reuses [`OKTA_PUSH_POLL_INTERVAL`]
/// +[`OKTA_PUSH_MAX_POLLS`] so the operator experience is
/// identical between classic and OIE push factors.
async fn oie_poll_push(
    transport: &dyn OktaTransport,
    poll_url: &str,
    initial_state_handle: &str,
) -> Result<Value, AuthError> {
    tracing::info!("okta OIE: push request sent — approve on your device");
    let mut state_handle = initial_state_handle.to_string();
    for poll in 0..OKTA_PUSH_MAX_POLLS {
        let j = transport
            .post_json(poll_url, &json!({ "stateHandle": state_handle }))
            .await?;
        if j.get("success")
            .and_then(|v| v.get("href"))
            .and_then(|v| v.as_str())
            .is_some()
        {
            return Ok(j);
        }
        if let Some(new_handle) = j.get("stateHandle").and_then(|v| v.as_str()) {
            state_handle = new_handle.to_string();
        }
        tracing::debug!("okta OIE: push poll #{poll}, still waiting");
        tokio::time::sleep(OKTA_PUSH_POLL_INTERVAL).await;
    }
    Err(AuthError::Failed(format!(
        "okta OIE: push factor did not resolve after {OKTA_PUSH_MAX_POLLS} polls"
    )))
}

/// Scrape an Okta login-page HTML body for the embedded
/// `stateToken` JavaScript variable. Mirrors the regex in
/// pan-gp-okta's `get_state_token` (gp-okta.py around line
/// 220) — looks for `stateToken` followed by `=` or `:`,
/// optional whitespace, then either a single-quoted or
/// double-quoted string, handling `\x2d` escapes for `-`
/// which Okta sometimes emits in the JSON-embedded token.
///
/// Returns `None` if no `stateToken` is present. That's the
/// classic-API signal — the caller stays on `/api/v1/authn`.
///
/// Currently only exercised by unit tests. The production
/// hook point is a SAML-first entry into [`OktaAuthProvider`]
/// that GETs the prelogin SAML URL, feeds the HTML to this
/// function, and pivots into [`okta_authenticate_oie`] when
/// a state token is present. That wiring is deliberately
/// deferred to a follow-up session — it needs a live OIE
/// tenant for verification, which we don't have today.
/// Keeping the helper here (with `allow(dead_code)`) so the
/// state-machine + scraper land together for review.
#[allow(dead_code)]
pub(crate) fn extract_state_token_from_html(html: &str) -> Option<String> {
    // Find the literal `stateToken` substring. The surrounding
    // shape is always `stateToken[optional ws][=|:][ws]"..."`
    // or the same with single quotes. Scan for the keyword,
    // then drive a tiny hand-rolled parser over the tail.
    let key = "stateToken";
    for (idx, _) in html.match_indices(key) {
        let tail = &html[idx + key.len()..];
        let after_ws = tail.trim_start();
        // Optional leading quote on the key itself
        // (`"stateToken":`) — skip it.
        let after_ws = after_ws.strip_prefix('"').unwrap_or(after_ws).trim_start();
        let (sep, after_sep) = if let Some(rest) = after_ws.strip_prefix('=') {
            ('=', rest.trim_start())
        } else if let Some(rest) = after_ws.strip_prefix(':') {
            (':', rest.trim_start())
        } else {
            continue;
        };
        let _ = sep;
        let (quote, body_start) = if let Some(rest) = after_sep.strip_prefix('"') {
            ('"', rest)
        } else if let Some(rest) = after_sep.strip_prefix('\'') {
            ('\'', rest)
        } else {
            continue;
        };
        // Read until the matching unescaped quote. Handle
        // `\x2d` as `-`, plain backslash escapes as the escaped
        // character, otherwise pass bytes through.
        let mut out = String::new();
        let bytes = body_start.as_bytes();
        let mut i = 0;
        let mut closed = false;
        while i < bytes.len() {
            let b = bytes[i];
            if b as char == quote {
                closed = true;
                break;
            }
            if b == b'\\' && i + 1 < bytes.len() {
                // `\xHH` — decode the 2-digit hex pair.
                if bytes[i + 1] == b'x' && i + 3 < bytes.len() {
                    let hi = (bytes[i + 2] as char).to_digit(16);
                    let lo = (bytes[i + 3] as char).to_digit(16);
                    if let (Some(h), Some(l)) = (hi, lo) {
                        out.push((h * 16 + l) as u8 as char);
                        i += 4;
                        continue;
                    }
                }
                // `\uXXXX` — decode the 4-digit hex quartet.
                // Python's `unicode_escape` handles this as
                // part of its escape set, so pan-gp-okta's
                // regex-based extractor picks it up
                // transparently. Mirror that here for tokens
                // whose underlying bytes include non-ASCII.
                if bytes[i + 1] == b'u' && i + 5 < bytes.len() {
                    let mut code: u32 = 0;
                    let mut ok = true;
                    for j in 0..4 {
                        match (bytes[i + 2 + j] as char).to_digit(16) {
                            Some(d) => code = code * 16 + d,
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                }
                // `\<newline>` (line continuation) — drop both
                // the backslash and the newline so the token
                // comes out unbroken.
                if bytes[i + 1] == b'\n' {
                    i += 2;
                    continue;
                }
                if bytes[i + 1] == b'\r' {
                    // Windows line endings: `\\r\n` → drop 3.
                    if i + 2 < bytes.len() && bytes[i + 2] == b'\n' {
                        i += 3;
                    } else {
                        i += 2;
                    }
                    continue;
                }
                // Generic `\X` → X.
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            out.push(b as char);
            i += 1;
        }
        if closed && !out.is_empty() {
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock transport: returns a fixed response from a queue keyed
    /// on the call sequence. Tests assert against a queue rather
    /// than per-URL keys so they double as flow-order regression
    /// tests.
    type FormCallLog = Mutex<Vec<(String, Vec<(String, String)>)>>;

    #[derive(Default)]
    struct MockTransport {
        post_json_responses: Mutex<Vec<Result<Value, AuthError>>>,
        get_responses: Mutex<Vec<Result<HttpResponse, AuthError>>>,
        post_form_responses: Mutex<Vec<Result<HttpResponse, AuthError>>>,
        post_json_calls: Mutex<Vec<(String, Value)>>,
        post_form_calls: FormCallLog,
        get_calls: Mutex<Vec<String>>,
    }

    impl MockTransport {
        fn push_post_json(&self, value: Value) {
            self.post_json_responses.lock().unwrap().push(Ok(value));
        }
    }

    #[async_trait]
    impl OktaTransport for MockTransport {
        async fn post_json(&self, url: &str, body: &Value) -> Result<Value, AuthError> {
            self.post_json_calls
                .lock()
                .unwrap()
                .push((url.to_string(), body.clone()));
            self.post_json_responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Err(AuthError::Failed("mock: no more post_json".into())))
        }

        async fn get(&self, url: &str) -> Result<HttpResponse, AuthError> {
            self.get_calls.lock().unwrap().push(url.to_string());
            self.get_responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Err(AuthError::Failed("mock: no more get".into())))
        }

        async fn post_form(
            &self,
            url: &str,
            form: &[(&str, &str)],
        ) -> Result<HttpResponse, AuthError> {
            self.post_form_calls.lock().unwrap().push((
                url.to_string(),
                form.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ));
            self.post_form_responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Err(AuthError::Failed("mock: no more post_form".into())))
        }
    }

    fn null_prompt() -> MfaPrompt {
        Arc::new(|_| Some("000000".to_string()))
    }

    #[tokio::test]
    async fn okta_authenticate_happy_path_no_mfa() {
        let mock = MockTransport::default();
        // Responses are popped in reverse — push the SUCCESS first
        // so the first call gets it.
        mock.push_post_json(json!({
            "status": "SUCCESS",
            "sessionToken": "session-12345",
        }));
        let token = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(token, "session-12345");

        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://example.okta.com/api/v1/authn");
        assert_eq!(calls[0].1["username"], "alice");
        assert_eq!(calls[0].1["password"], "hunter2");
    }

    #[tokio::test]
    async fn okta_authenticate_skips_password_warn() {
        let mock = MockTransport::default();
        // Pop order: SUCCESS first (reached after skip), then
        // PASSWORD_WARN (returned by initial post).
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "SUCCESS",
            "sessionToken": "session-after-skip",
        })));
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "PASSWORD_WARN",
            "stateToken": "state-warn",
            "_links": {
                "skip": { "href": "https://example.okta.com/api/v1/authn/skip" }
            }
        })));
        let token = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(token, "session-after-skip");
        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "https://example.okta.com/api/v1/authn/skip");
        assert_eq!(calls[1].1["stateToken"], "state-warn");
    }

    #[tokio::test]
    async fn okta_authenticate_totp_factor() {
        let mock = MockTransport::default();
        // Pop order (reverse of call order):
        //   3rd call: post to /verify with passCode → SUCCESS
        //   1st call (post initial): MFA_REQUIRED with TOTP factor
        // So push in reverse-of-pop order, which is forward-of-call:
        // No wait — push order in vec means later pushes are popped first.
        // We want call 1 → MFA_REQUIRED, call 2 → SUCCESS.
        // So push SUCCESS first (popped second? no, popped LAST? no.
        // pop() removes from end. push appends to end. So last pushed
        // is first popped. We want call 1 to pop the FIRST thing we
        // pushed, so push in REVERSE call order: push SUCCESS, then
        // push MFA_REQUIRED. MFA_REQUIRED gets popped first (call 1),
        // then SUCCESS (call 2). Right.
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "SUCCESS",
            "sessionToken": "session-mfa",
        })));
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-mfa",
            "_embedded": {
                "factors": [
                    {
                        "id": "factor-1",
                        "factorType": "token:software:totp",
                        "provider": "OKTA",
                        "_links": {
                            "verify": {
                                "href": "https://example.okta.com/api/v1/authn/factors/factor-1/verify"
                            }
                        }
                    }
                ]
            }
        })));

        let prompted_for: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let prompted_clone = Arc::clone(&prompted_for);
        let prompt: MfaPrompt = Arc::new(move |p: &str| {
            prompted_clone.lock().unwrap().push(p.to_string());
            Some("123456".to_string())
        });

        let token = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &prompt,
        )
        .await
        .unwrap();
        assert_eq!(token, "session-mfa");
        assert_eq!(prompted_for.lock().unwrap().len(), 1);
        assert!(prompted_for.lock().unwrap()[0].contains("TOTP"));

        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[1].0,
            "https://example.okta.com/api/v1/authn/factors/factor-1/verify"
        );
        assert_eq!(calls[1].1["passCode"], "123456");
        assert_eq!(calls[1].1["stateToken"], "state-mfa");
    }

    #[tokio::test]
    async fn run_push_returns_immediately_when_status_is_success() {
        // Direct test of run_push: POST /verify returns SUCCESS on
        // the first response. No real polling, no need to muck with
        // virtual time.
        let mock = MockTransport::default();
        mock.push_post_json(json!({
            "status": "SUCCESS",
            "sessionToken": "session-push",
        }));
        let factor = OktaFactor {
            id: "push-1".into(),
            factor_type: "push".into(),
            provider: "okta".into(),
            verify_url: "https://example.okta.com/api/v1/authn/factors/push-1/verify".into(),
        };
        let value = run_push(&mock, &factor, "state-push").await.unwrap();
        assert_eq!(
            value.get("sessionToken").and_then(|v| v.as_str()),
            Some("session-push")
        );
    }

    #[tokio::test]
    async fn run_push_returns_error_when_factor_rejected() {
        let mock = MockTransport::default();
        mock.push_post_json(json!({
            "status": "MFA_CHALLENGE",
            "factorResult": "REJECTED",
        }));
        let factor = OktaFactor {
            id: "push-1".into(),
            factor_type: "push".into(),
            provider: "okta".into(),
            verify_url: "https://example.okta.com/api/v1/authn/factors/push-1/verify".into(),
        };
        let err = run_push(&mock, &factor, "state-push").await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("rejected"));
    }

    #[tokio::test]
    async fn okta_authenticate_locked_out_is_terminal() {
        let mock = MockTransport::default();
        mock.push_post_json(json!({
            "status": "LOCKED_OUT",
        }));
        let err = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("locked out"));
    }

    #[tokio::test]
    async fn okta_authenticate_only_unsupported_factors_errors_clearly() {
        let mock = MockTransport::default();
        mock.push_post_json(json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-x",
            "_embedded": {
                "factors": [
                    {
                        "id": "wa-1",
                        "factorType": "webauthn",
                        "provider": "FIDO",
                        "_links": {
                            "verify": { "href": "https://example.okta.com/api/v1/authn/factors/wa-1/verify" }
                        }
                    }
                ]
            }
        }));
        let err = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("no factors openprotect can verify"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn okta_authenticate_picks_supported_factor_when_unsupported_has_higher_priority() {
        // Tenant offers webauthn (priority 60, unsupported) AND sms
        // (priority 70, supported). Filter must run BEFORE sort, so
        // sms wins and the dance resolves cleanly.
        //
        // Wait — webauthn priority is 60, sms is 70. So sms is
        // already higher. Better case: symantec token (priority
        // 80) + sms (70). symantec is unsupported by run_factor;
        // without filter, priority sort picks symantec → dead end.
        // With filter, sms wins.
        let mock = MockTransport::default();
        // pop order: third call (POST passCode) → SUCCESS;
        //            second call (trigger sms) → MFA_CHALLENGE;
        //            first call (initial auth) → MFA_REQUIRED.
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "SUCCESS",
            "sessionToken": "session-fallback",
        })));
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "MFA_CHALLENGE",
        })));
        mock.post_json_responses.lock().unwrap().push(Ok(json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-fb",
            "_embedded": {
                "factors": [
                    {
                        "id": "sym-1",
                        "factorType": "token",
                        "provider": "SYMANTEC",
                        "_links": {
                            "verify": { "href": "https://example.okta.com/api/v1/authn/factors/sym-1/verify" }
                        }
                    },
                    {
                        "id": "sms-1",
                        "factorType": "sms",
                        "provider": "OKTA",
                        "_links": {
                            "verify": { "href": "https://example.okta.com/api/v1/authn/factors/sms-1/verify" }
                        }
                    }
                ]
            }
        })));

        let token = okta_authenticate(
            &mock,
            "https://example.okta.com",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(token, "session-fallback");
        // Verify run_factor went through the SMS endpoint, not the
        // Symantec one.
        let calls = mock.post_json_calls.lock().unwrap();
        assert!(
            calls.iter().any(|(url, _)| url.contains("sms-1")),
            "expected fallback to SMS factor, got calls: {calls:?}"
        );
        assert!(
            !calls.iter().any(|(url, _)| url.contains("sym-1")),
            "should NOT have hit the unsupported symantec factor"
        );
    }

    #[test]
    fn factor_priority_orders_correctly() {
        let push = OktaFactor {
            id: "1".into(),
            factor_type: "push".into(),
            provider: "okta".into(),
            verify_url: "x".into(),
        };
        let totp = OktaFactor {
            id: "2".into(),
            factor_type: "token:software:totp".into(),
            provider: "okta".into(),
            verify_url: "x".into(),
        };
        let sms = OktaFactor {
            id: "3".into(),
            factor_type: "sms".into(),
            provider: "okta".into(),
            verify_url: "x".into(),
        };
        assert!(push.priority() > totp.priority());
        assert!(totp.priority() > sms.priority());
    }

    #[test]
    fn factor_from_json_extracts_required_fields() {
        let v = json!({
            "id": "f-1",
            "factorType": "PUSH",
            "provider": "OKTA",
            "_links": {
                "verify": { "href": "https://example.okta.com/v" }
            }
        });
        let f = OktaFactor::from_json(&v).unwrap();
        assert_eq!(f.id, "f-1");
        assert_eq!(f.factor_type, "push");
        assert_eq!(f.provider, "okta");
        assert_eq!(f.verify_url, "https://example.okta.com/v");
    }

    #[test]
    fn factor_from_json_returns_none_on_missing_link() {
        let v = json!({
            "id": "f-1",
            "factorType": "push",
            "provider": "OKTA",
        });
        assert!(OktaFactor::from_json(&v).is_none());
    }

    #[test]
    fn parse_saml_form_extracts_action_and_hidden_inputs() {
        let html = r#"<html><body>
            <form action="https://idp.okta.com/sso/saml" method="POST">
                <input type="hidden" name="SAMLRequest" value="encoded-blob" />
                <input type="hidden" name="RelayState" value="some-state" />
                <input type="submit" value="Continue" />
            </form>
        </body></html>"#;
        let (action, fields) = parse_saml_form(html).unwrap();
        assert_eq!(action, "https://idp.okta.com/sso/saml");
        // Submit input has no `name=...` so it's skipped.
        let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"SAMLRequest"));
        assert!(names.contains(&"RelayState"));
        let saml = fields.iter().find(|(k, _)| k == "SAMLRequest").unwrap();
        assert_eq!(saml.1, "encoded-blob");
    }

    #[test]
    fn parse_saml_form_handles_single_quotes() {
        let html =
            "<form action='https://idp.example/sso'><input name='RelayState' value='r1'/></form>";
        let (action, fields) = parse_saml_form(html).unwrap();
        assert_eq!(action, "https://idp.example/sso");
        assert_eq!(fields[0], ("RelayState".into(), "r1".into()));
    }

    #[test]
    fn parse_saml_form_returns_none_when_no_form() {
        assert!(parse_saml_form("<html><body>nothing</body></html>").is_none());
    }

    #[test]
    fn capture_from_response_uses_prelogin_cookie_header() {
        let resp = HttpResponse {
            status: 200,
            body: vec![],
            headers: vec![
                ("prelogin-cookie".into(), "the-cookie".into()),
                ("saml-username".into(), "alice@example.com".into()),
            ],
            final_url: "https://vpn.example.com/x".into(),
        };
        let cap = capture_from_response(&resp, "fallback").unwrap();
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "the-cookie");
    }

    #[test]
    fn capture_from_response_falls_back_to_username_hint() {
        let resp = HttpResponse {
            status: 200,
            body: vec![],
            headers: vec![("prelogin-cookie".into(), "c".into())],
            final_url: "https://vpn.example.com/x".into(),
        };
        let cap = capture_from_response(&resp, "alice").unwrap();
        assert_eq!(cap.username, "alice");
    }

    #[test]
    fn capture_from_response_parses_globalprotectcallback_uri_in_body() {
        let body = r#"<html><body><a href="globalprotectcallback:cas-as=1&un=alice%40example.com&token=aaa.bbb.ccc">Open</a></body></html>"#;
        let resp = HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![],
            final_url: "https://vpn.example.com/x".into(),
        };
        let cap = capture_from_response(&resp, "fallback").unwrap();
        assert_eq!(cap.username, "alice@example.com");
        assert_eq!(cap.prelogin_cookie, "aaa.bbb.ccc");
    }

    #[test]
    fn capture_from_response_returns_none_when_nothing_matches() {
        let resp = HttpResponse {
            status: 200,
            body: b"<html><body>just some content</body></html>".to_vec(),
            headers: vec![],
            final_url: "x".into(),
        };
        assert!(capture_from_response(&resp, "alice").is_none());
    }

    #[test]
    fn parse_saml_form_handles_non_ascii_without_panic() {
        // German umlaut and emoji surrounding the form. With the
        // old to_lowercase() (Unicode), byte indices shifted and
        // we'd panic on slice. With to_ascii_lowercase, they don't.
        let html = "Begrüßung 🎉<form action=\"https://idp.example/sso\"><input name=\"X\" value=\"Ä\"/></form> 谢谢";
        let (action, fields) = parse_saml_form(html).expect("must parse");
        assert_eq!(action, "https://idp.example/sso");
        assert_eq!(fields[0].0, "X");
        assert_eq!(fields[0].1, "Ä");
    }

    #[test]
    fn resolve_relative_url_handles_absolute_root_relative_and_relative() {
        // Absolute → returned verbatim
        assert_eq!(
            resolve_relative_url("https://example.com/a/b", "https://other.example/x"),
            "https://other.example/x"
        );
        // Scheme-relative
        assert_eq!(
            resolve_relative_url("https://example.com/a/b", "//cdn.example/y"),
            "https://cdn.example/y"
        );
        // Root-relative
        assert_eq!(
            resolve_relative_url("https://example.com/a/b", "/c/d"),
            "https://example.com/c/d"
        );
        // Relative path with trailing slash on base
        assert_eq!(
            resolve_relative_url("https://example.com/a/b/", "x.html"),
            "https://example.com/a/b/x.html"
        );
        // Relative path with file in base — drop last segment
        assert_eq!(
            resolve_relative_url("https://example.com/a/b/page.html", "next.html"),
            "https://example.com/a/b/next.html"
        );
        // Query-only relative
        assert_eq!(
            resolve_relative_url("https://example.com/a/b?old=1", "?new=2"),
            "https://example.com/a/b?new=2"
        );
        // Port preserved
        assert_eq!(
            resolve_relative_url("https://example.com:8443/a/", "/b"),
            "https://example.com:8443/b"
        );
    }

    #[test]
    fn factor_is_supported_filters_webauthn_and_symantec() {
        let cases = [
            ("push", "okta", true),
            ("token:software:totp", "okta", true),
            ("sms", "okta", true),
            ("webauthn", "fido", false),
            ("token", "symantec", false),
            ("call", "okta", false),
        ];
        for (ft, pv, expected) in cases {
            let f = OktaFactor {
                id: "x".into(),
                factor_type: ft.into(),
                provider: pv.into(),
                verify_url: "x".into(),
            };
            assert_eq!(f.is_supported(), expected, "{ft}/{pv}");
        }
    }

    #[test]
    fn okta_base_from_url_strips_path() {
        assert_eq!(
            okta_base_from_url("https://example.okta.com/app/foo/sso/saml"),
            Some("https://example.okta.com".to_string())
        );
        assert_eq!(
            okta_base_from_url("https://example.okta.com"),
            Some("https://example.okta.com".to_string())
        );
        // Port preserved.
        assert_eq!(
            okta_base_from_url("https://example.okta.com:8443/app/foo"),
            Some("https://example.okta.com:8443".to_string())
        );
        assert_eq!(okta_base_from_url("http://insecure.example.com"), None);
    }

    // ---------- OIE state-token HTML scraper ----------

    #[test]
    fn extract_state_token_double_quoted() {
        let html = r#"<script>var config = { stateToken: "abc-123-xyz" };</script>"#;
        assert_eq!(
            extract_state_token_from_html(html),
            Some("abc-123-xyz".to_string())
        );
    }

    #[test]
    fn extract_state_token_single_quoted() {
        let html = "var x = { stateToken: 'tok-single' };";
        assert_eq!(
            extract_state_token_from_html(html),
            Some("tok-single".to_string())
        );
    }

    #[test]
    fn extract_state_token_json_shape_with_colon_and_quoted_key() {
        // Okta often renders this as JSON embedded in a script:
        // `"stateToken":"abc"`. Our scanner strips the optional
        // leading quote before the `:` separator, so this must
        // still parse.
        let html = r#"{"foo":1,"stateToken":"json-embedded-tok"}"#;
        assert_eq!(
            extract_state_token_from_html(html),
            Some("json-embedded-tok".to_string())
        );
    }

    #[test]
    fn extract_state_token_handles_x2d_hex_escape() {
        // Okta emits `\x2d` in place of literal `-` inside its
        // JSON-in-HTML blobs. The scraper must translate.
        let html = r#"stateToken = "abc\x2ddef\x2dghi""#;
        assert_eq!(
            extract_state_token_from_html(html),
            Some("abc-def-ghi".to_string())
        );
    }

    #[test]
    fn extract_state_token_handles_u_unicode_escape() {
        // `\u002d` == `-`. Some Okta deployments emit this
        // form instead of `\x2d`, and pan-gp-okta picks it up
        // via Python's `unicode_escape`.
        let html = r#"stateToken = "abc\u002ddef""#;
        assert_eq!(
            extract_state_token_from_html(html),
            Some("abc-def".to_string())
        );
    }

    #[test]
    fn extract_state_token_handles_line_continuation() {
        // Literal backslash followed by newline in the source
        // string should be dropped, so a multi-line token
        // survives as a single string. Rarely seen in practice
        // but Python's escape-handling does it.
        let html = "stateToken = \"abc\\\ndef\"";
        assert_eq!(
            extract_state_token_from_html(html),
            Some("abcdef".to_string())
        );
    }

    #[test]
    fn extract_state_token_missing_returns_none() {
        assert_eq!(
            extract_state_token_from_html("<html><body>hi</body></html>"),
            None
        );
        // `stateToken` mentioned but no value — reject.
        assert_eq!(extract_state_token_from_html("stateToken"), None);
    }

    // ---------- OIE factor parsing ----------

    #[test]
    fn oie_parse_factors_single_authenticator_totp() {
        let select_auth = json!({
            "name": "select-authenticator-authenticate",
            "value": [
                {
                    "name": "authenticator",
                    "options": [
                        {
                            "label": "Google Authenticator",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut123", "required": true },
                                        { "name": "methodType", "value": "otp", "required": true }
                                    ]
                                }
                            }
                        }
                    ]
                }
            ]
        });
        let factors = oie_parse_factors(&select_auth).unwrap();
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].label, "Google Authenticator");
        assert_eq!(factors[0].id, "aut123");
        assert_eq!(factors[0].method_type, "otp");
        assert_eq!(factors[0].enrollment_id, None);
        assert_eq!(factors[0].priority, 90);
    }

    #[test]
    fn oie_parse_factors_authenticator_multiple_method_types() {
        // Okta Verify with both push and totp — should flatten
        // to two distinct factors, same authenticator id.
        let select_auth = json!({
            "name": "select-authenticator-authenticate",
            "value": [
                {
                    "name": "authenticator",
                    "options": [
                        {
                            "label": "Okta Verify",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "okta-verify-id", "required": true },
                                        { "name": "enrollmentId", "value": "enr-1", "required": true },
                                        {
                                            "name": "methodType",
                                            "required": true,
                                            "options": [
                                                { "label": "Push", "value": "push" },
                                                { "label": "TOTP", "value": "totp" }
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            ]
        });
        let factors = oie_parse_factors(&select_auth).unwrap();
        assert_eq!(factors.len(), 2);
        // Both share the same authenticator id and enrollment id.
        assert!(factors.iter().all(|f| f.id == "okta-verify-id"));
        assert!(factors
            .iter()
            .all(|f| f.enrollment_id.as_deref() == Some("enr-1")));
        let types: Vec<&str> = factors.iter().map(|f| f.method_type.as_str()).collect();
        assert!(types.contains(&"push"));
        assert!(types.contains(&"totp"));
    }

    #[test]
    fn oie_parse_factors_skips_malformed_options_without_id() {
        let select_auth = json!({
            "name": "select-authenticator-authenticate",
            "value": [
                {
                    "name": "authenticator",
                    "options": [
                        {
                            "label": "Broken Option",
                            "value": { "form": { "value": [] } }
                        },
                        {
                            "label": "Valid TOTP",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "ok-id" },
                                        { "name": "methodType", "value": "totp" }
                                    ]
                                }
                            }
                        }
                    ]
                }
            ]
        });
        let factors = oie_parse_factors(&select_auth).unwrap();
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].label, "Valid TOTP");
    }

    #[test]
    fn oie_password_expiring_detected_from_i18n_key() {
        let response = json!({
            "messages": {
                "value": [
                    { "i18n": { "key": "idx.password.expiring.message" }, "message": "Your password will expire" }
                ]
            }
        });
        assert!(oie_is_password_expiring(&response));
    }

    #[test]
    fn oie_password_expiring_detected_from_substring_fallback() {
        let response = json!({
            "messages": {
                "value": [
                    { "message": "Your password expires in 7 days" }
                ]
            }
        });
        assert!(oie_is_password_expiring(&response));
    }

    #[test]
    fn oie_password_expiring_absent_returns_false() {
        assert!(!oie_is_password_expiring(&json!({})));
        assert!(!oie_is_password_expiring(&json!({
            "messages": { "value": [{ "message": "something else" }] }
        })));
    }

    // ---------- OIE state machine: happy paths ----------

    /// Fixture: an IDX response whose `success.href` is set —
    /// equivalent to "authentication complete, here's the
    /// redirect URL to follow."
    fn oie_success_response(href: &str) -> Value {
        json!({
            "stateHandle": "sh-success",
            "remediation": { "type": "array", "value": [] },
            "success": { "href": href }
        })
    }

    /// Fixture: the first IDX response returned from
    /// `/idp/idx/introspect` before identify has run. Carries a
    /// stateHandle and an `identify` remediation (which we
    /// don't inspect in detail — the code just POSTs identifier
    /// + credentials).
    fn oie_introspect_response() -> Value {
        json!({
            "stateHandle": "sh-introspect",
            "remediation": {
                "type": "array",
                "value": [
                    { "name": "identify", "value": [] }
                ]
            }
        })
    }

    #[tokio::test]
    async fn oie_happy_path_no_mfa() {
        let mock = MockTransport::default();
        // Response order (LIFO pop): push in reverse — so the
        // first call (introspect) gets the LAST thing we push.
        //
        // Flow:
        //   1. POST /idp/idx/introspect   → sh-introspect
        //   2. POST /idp/idx/identify     → success with href
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_success_response(
                "https://example.okta.com/app/success/redir",
            )));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let outcome = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "state-token-xyz",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OieOutcome::SuccessHref("https://example.okta.com/app/success/redir".to_string())
        );

        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "https://example.okta.com/idp/idx/introspect");
        assert_eq!(calls[0].1["stateToken"], "state-token-xyz");
        assert_eq!(calls[1].0, "https://example.okta.com/idp/idx/identify");
        assert_eq!(calls[1].1["identifier"], "alice");
        assert_eq!(calls[1].1["credentials"]["passcode"], "hunter2");
        assert_eq!(calls[1].1["stateHandle"], "sh-introspect");
    }

    #[tokio::test]
    async fn oie_totp_factor_flow() {
        let mock = MockTransport::default();
        // Fixture: select-authenticator-authenticate with one
        // TOTP factor; after answer, success.
        let select_auth = json!({
            "stateHandle": "sh-identify",
            "remediation": {
                "type": "array",
                "value": [{
                    "name": "select-authenticator-authenticate",
                    "value": [{
                        "name": "authenticator",
                        "options": [{
                            "label": "Google Authenticator",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut-totp-id" },
                                        { "name": "methodType", "value": "totp" }
                                    ]
                                }
                            }
                        }]
                    }]
                }]
            }
        });
        let post_challenge = json!({
            "stateHandle": "sh-challenge",
            "remediation": {
                "type": "array",
                "value": [
                    { "name": "challenge-authenticator", "value": [] }
                ]
            }
        });
        // LIFO: push in reverse.
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_success_response("https://example.okta.com/success")));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(post_challenge));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(select_auth));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        // null_prompt() returns "000000" for any prompt → gets
        // POSTed as the TOTP credentials passcode.
        let outcome = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "state-token",
            "alice",
            "hunter2",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OieOutcome::SuccessHref("https://example.okta.com/success".to_string())
        );

        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        // 1. introspect
        assert_eq!(calls[0].0, "https://example.okta.com/idp/idx/introspect");
        // 2. identify
        assert_eq!(calls[1].0, "https://example.okta.com/idp/idx/identify");
        // 3. challenge (pick TOTP factor)
        assert_eq!(calls[2].0, "https://example.okta.com/idp/idx/challenge");
        assert_eq!(calls[2].1["authenticator"]["id"], "aut-totp-id");
        assert_eq!(calls[2].1["authenticator"]["methodType"], "totp");
        // 4. challenge/answer with TOTP code
        assert_eq!(
            calls[3].0,
            "https://example.okta.com/idp/idx/challenge/answer"
        );
        assert_eq!(calls[3].1["credentials"]["passcode"], "000000");
    }

    #[tokio::test]
    async fn oie_password_expiring_auto_skips() {
        let mock = MockTransport::default();
        // Fixture: identify returns a response with BOTH the
        // password-expiring message AND a `skip` remediation.
        // The state machine must POST /idp/idx/skip and keep
        // going.
        let expiring = json!({
            "stateHandle": "sh-expiring",
            "remediation": {
                "type": "array",
                "value": [
                    { "name": "skip", "value": [] },
                    { "name": "reenroll-authenticator", "value": [] }
                ]
            },
            "messages": {
                "value": [
                    { "i18n": { "key": "idx.password.expiring.message" }, "message": "Your password will expire" }
                ]
            }
        });
        // LIFO: push in reverse.
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_success_response(
                "https://example.okta.com/after-skip",
            )));
        mock.post_json_responses.lock().unwrap().push(Ok(expiring));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let outcome = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, OieOutcome::SuccessHref(_)));

        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "https://example.okta.com/idp/idx/introspect");
        assert_eq!(calls[1].0, "https://example.okta.com/idp/idx/identify");
        assert_eq!(calls[2].0, "https://example.okta.com/idp/idx/skip");
        assert_eq!(calls[2].1["stateHandle"], "sh-expiring");
    }

    #[tokio::test]
    async fn oie_sms_factor_flow() {
        let mock = MockTransport::default();
        let select_auth = json!({
            "stateHandle": "sh-identify",
            "remediation": {
                "type": "array",
                "value": [{
                    "name": "select-authenticator-authenticate",
                    "value": [{
                        "name": "authenticator",
                        "options": [{
                            "label": "SMS",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut-sms-id" },
                                        { "name": "methodType", "value": "sms" }
                                    ]
                                }
                            }
                        }]
                    }]
                }]
            }
        });
        let post_challenge = json!({
            "stateHandle": "sh-challenge",
            "remediation": {
                "type": "array",
                "value": [{ "name": "challenge-authenticator", "value": [] }]
            }
        });
        // LIFO.
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_success_response("https://example.okta.com/done")));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(post_challenge));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(select_auth));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let outcome = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OieOutcome::SuccessHref("https://example.okta.com/done".to_string())
        );
        let calls = mock.post_json_calls.lock().unwrap();
        assert_eq!(calls[2].1["authenticator"]["methodType"], "sms");
        // The fourth call is the answer with the SMS code
        // from the prompt (null_prompt returns "000000").
        assert_eq!(
            calls[3].0,
            "https://example.okta.com/idp/idx/challenge/answer"
        );
        assert_eq!(calls[3].1["credentials"]["passcode"], "000000");
    }

    #[tokio::test]
    async fn oie_push_challenge_poll_returns_success_on_first_round() {
        let mock = MockTransport::default();
        // Fixture: push factor selected, challenge returns a
        // `challenge-poll` remediation (the shape that tells
        // the state machine "poll the poll endpoint"), then
        // the first poll call returns a success.href.
        //
        // We deliberately do NOT exercise the multi-round
        // retry here: driving sleep() under cargo test
        // requires tokio's `test-util` feature which the
        // workspace doesn't currently enable. The one-round
        // case still covers the full push code path —
        // factor selection, challenge POST, challenge-poll
        // remediation validation, poll endpoint, success
        // extraction. A future commit that adds `test-util`
        // can extend this test to exercise the retry loop.
        let select_push = json!({
            "stateHandle": "sh-identify",
            "remediation": {
                "type": "array",
                "value": [{
                    "name": "select-authenticator-authenticate",
                    "value": [{
                        "name": "authenticator",
                        "options": [{
                            "label": "Okta Verify",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut-push-id" },
                                        { "name": "methodType", "value": "push" }
                                    ]
                                }
                            }
                        }]
                    }]
                }]
            }
        });
        let post_challenge_with_poll = json!({
            "stateHandle": "sh-push-wait",
            "remediation": {
                "type": "array",
                "value": [{ "name": "challenge-poll", "value": [] }]
            }
        });
        let poll_success = oie_success_response("https://example.okta.com/push-ok");
        // LIFO push order.
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(poll_success));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(post_challenge_with_poll));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(select_push));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let outcome = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OieOutcome::SuccessHref("https://example.okta.com/push-ok".to_string())
        );

        let calls = mock.post_json_calls.lock().unwrap();
        // introspect + identify + challenge + poll == 4
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[2].0, "https://example.okta.com/idp/idx/challenge");
        assert_eq!(calls[2].1["authenticator"]["methodType"], "push");
        assert_eq!(
            calls[3].0,
            "https://example.okta.com/idp/idx/authenticators/poll"
        );
    }

    #[tokio::test]
    async fn oie_push_challenge_without_poll_remediation_errors() {
        let mock = MockTransport::default();
        // Fixture: we selected push, but the server's
        // challenge response carries `challenge-authenticator`
        // instead of `challenge-poll`. That's a protocol
        // mismatch — openprotect should fail fast rather than
        // silently start polling an endpoint the server
        // didn't advertise.
        let select_push = json!({
            "stateHandle": "sh-identify",
            "remediation": {
                "type": "array",
                "value": [{
                    "name": "select-authenticator-authenticate",
                    "value": [{
                        "name": "authenticator",
                        "options": [{
                            "label": "Okta Verify",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut-push-id" },
                                        { "name": "methodType", "value": "push" }
                                    ]
                                }
                            }
                        }]
                    }]
                }]
            }
        });
        let post_challenge_wrong_shape = json!({
            "stateHandle": "sh-wrong",
            "remediation": {
                "type": "array",
                "value": [{ "name": "challenge-authenticator", "value": [] }]
            }
        });
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(post_challenge_wrong_shape));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(select_push));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let err = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("challenge-poll"),
            "expected 'challenge-poll' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn oie_introspect_missing_state_handle_errors_cleanly() {
        let mock = MockTransport::default();
        // Malformed introspect response with no stateHandle.
        mock.post_json_responses.lock().unwrap().push(Ok(
            json!({ "remediation": { "type": "array", "value": [] } }),
        ));
        let err = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("missing stateHandle"),
            "expected 'missing stateHandle' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn oie_reenroll_authenticator_fails_with_migration_hint() {
        let mock = MockTransport::default();
        // Fixture: identify returns a response with ONLY
        // `reenroll-authenticator` remediation, meaning the
        // password has actually expired (not just "expiring
        // soon"). We should error out with a clear pointer to
        // the Okta web UI.
        let expired = json!({
            "stateHandle": "sh-expired",
            "remediation": {
                "type": "array",
                "value": [{ "name": "reenroll-authenticator", "value": [] }]
            }
        });
        mock.post_json_responses.lock().unwrap().push(Ok(expired));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let err = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("password has expired"),
            "expected 'password has expired' in error, got: {msg}"
        );
        assert!(
            msg.contains("Okta web UI"),
            "expected 'Okta web UI' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn oie_no_supported_factor_errors_clearly() {
        let mock = MockTransport::default();
        // Fixture: select-authenticator-authenticate exposes
        // only a webauthn factor, which openprotect doesn't
        // implement yet. The state machine must bail with a
        // message mentioning the supported-factor list.
        let webauthn_only = json!({
            "stateHandle": "sh-webauthn",
            "remediation": {
                "type": "array",
                "value": [{
                    "name": "select-authenticator-authenticate",
                    "value": [{
                        "name": "authenticator",
                        "options": [{
                            "label": "Security Key",
                            "value": {
                                "form": {
                                    "value": [
                                        { "name": "id", "value": "aut-wa-id" },
                                        { "name": "methodType", "value": "webauthn" }
                                    ]
                                }
                            }
                        }]
                    }]
                }]
            }
        });
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(webauthn_only));
        mock.post_json_responses
            .lock()
            .unwrap()
            .push(Ok(oie_introspect_response()));

        let err = okta_authenticate_oie(
            &mock,
            "https://example.okta.com",
            "st",
            "alice",
            "pw",
            &null_prompt(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no supported factor"),
            "expected 'no supported factor' in error, got: {msg}"
        );
    }
}
