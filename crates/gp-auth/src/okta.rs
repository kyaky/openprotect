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
//!    [`MockTransport`] in this file's `#[cfg(test)]` block.
//!
//! The GP-side handoff (parse SAML form → POST to Okta IdP → use
//! sessionCookieRedirect → follow form chain back to the portal →
//! extract `prelogin-cookie` headers) is implemented in
//! [`OktaAuthProvider::authenticate`] using both layers.
//!
//! # Reference
//!
//! Logic ported from `_refs/pan-gp-okta/gp-okta.py` (MIT, A. Raugulis et
//! al). Pangolin re-implements the protocol from scratch in idiomatic
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
/// [`MockTransport`] (in this file's test module) that returns canned
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
            .user_agent("PAN GlobalProtect")
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

    /// Whether [`run_factor`] knows how to verify this factor type.
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
                        "okta MFA_REQUIRED but no factors pangolin can verify \
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
            "okta factor type {other:?} not yet supported in pangolin (push, totp, sms only)"
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
            err.to_string().contains("no factors pangolin can verify"),
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
}
