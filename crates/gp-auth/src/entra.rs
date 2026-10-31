//! Headless Entra ID (Azure AD) login client: scripted, browser-free
//! SAML auth for Prisma Access portals fronted by Entra + MFA.
//!
//! Blueprint: saml2aws' AzureAD provider (Versent/saml2aws pkg/provider/
//! aad) + openconnect's gp-saml; live-verified against a production
//! Prisma Access + Entra deployment (see docs/research/).
//!
//! The wire shape, one loop:
//!
//! ```text
//! prelogin (PAN) -> cloud-auth POST -> 302 Entra saml2?SAMLRequest
//!   -> GET (x2: BSSO interrupt, then ConvergedSignIn $Config)
//!   -> POST credentials (sFT/sCtx/canary)
//!   -> MFA: SAS BeginAuth/EndAuth (TOTP submit, number-match digit
//!      display + poll, or push poll)
//!   -> SAS ProcessAuth -> KMSI -> hiddenform SAMLResponse
//!   -> POST to the SP ACS -> globalprotectcallback capture
//! ```
//!
//! Flow state is exactly three things: `ctx` (`$Config.sCtx`),
//! `flow_token` (`$Config.sFT`, field name from `sFTName`), and the
//! cookie jar. Every ESTS response ROTATES flowToken and apiCanary;
//! always overwrite with the newest values.

use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::AuthError;
use crate::okta::MfaPrompt;

/// Typed headless-flow failure. `Drift` means the scripted flow met a
/// page it cannot handle (Entra drift, unknown gate) — the caller
/// demotes to the webview/paste providers. `Auth`/`Timeout` are
/// terminal for the attempt (wrong password, operator walked away).
#[derive(Debug)]
pub enum HeadlessFlowError {
    Drift(String),
    Auth(String),
    Timeout(String),
}

impl std::fmt::Display for HeadlessFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadlessFlowError::Drift(m) => write!(f, "headless flow drifted: {m}"),
            HeadlessFlowError::Auth(m) => write!(f, "headless auth failed: {m}"),
            HeadlessFlowError::Timeout(m) => write!(f, "headless flow timed out: {m}"),
        }
    }
}

impl std::error::Error for HeadlessFlowError {}

impl From<HeadlessFlowError> for AuthError {
    fn from(e: HeadlessFlowError) -> Self {
        AuthError::Failed(e.to_string())
    }
}
use crate::saml_common::{parse_globalprotect_callback, saml_launch, SamlCapture, SamlLaunch};

/// A page parsed out of an ESTS response: the `$Config = {...};` JS blob.
///
/// One page can carry several blobs (the BSSO interrupt page re-encodes
/// the config); the extractor must prefer the blob that actually holds
/// flow state (contains `sFT`) rather than cutting at the first match.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EstsConfig {
    pub pgid: Option<String>,
    pub url_post: Option<String>,
    pub url_get_credential_type: Option<String>,
    pub url_begin_auth: Option<String>,
    pub url_end_auth: Option<String>,
    pub sft: Option<String>,
    pub sft_name: Option<String>,
    pub s_ctx: Option<String>,
    pub canary: Option<String>,
    pub api_canary: Option<String>,
    pub s_post_username: Option<String>,
    pub session_id: Option<String>,
    pub correlation_id: Option<String>,
    pub enable_number_matching: bool,
    pub arr_user_proofs: Vec<UserProof>,
    pub saml_response: Option<String>,
    pub saml_relay_state: Option<String>,
    /// All key NAMES in the parsed blob (no values) — drift diagnostics.
    pub raw_keys: Vec<String>,
    /// Entra's sErrorCode when the page redisplayed with an error.
    pub error_code: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UserProof {
    pub auth_method_id: String,
}

/// Extract the meaningful `$Config` blob from an ESTS page.
///
/// Brace-balanced scan (JSON strings may contain braces), collecting
/// every candidate, then preferring the one with a `sFT` field: the
/// BSSO interrupt page re-embeds a config without flow state, and a
/// naive first-match cut picks the wrong blob.
pub fn parse_ests_config(page: &str) -> Option<EstsConfig> {
    let marker = "$Config";
    let mut search_from = 0usize;
    let mut fallback: Option<EstsConfig> = None;
    while let Some(rel) = page[search_from..].find(marker) {
        let start = search_from + rel + marker.len();
        let after = &page[start..];
        let Some(brace) = after.find('{') else { break };
        let brace_at = start + brace;
        // Brace-balanced scan honouring JSON string escapes.
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        let bytes = page.as_bytes();
        let mut end = None;
        for (i, b) in bytes[brace_at..].iter().enumerate() {
            let c = *b as char;
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' if in_string => escaped = true,
                '"' => in_string = !in_string,
                '{' if !in_string => depth += 1,
                '}' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(brace_at + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end?;
        let blob = &page[brace_at..end];
        if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(blob) {
            let parsed = config_from_json(&cfg);
            // The blob with flow state wins outright; a stateless blob
            // (BSSO interrupt re-encoding) is only a fallback.
            if cfg.get("sFT").is_some() {
                return Some(parsed);
            }
            if fallback.is_none() {
                fallback = Some(parsed);
            }
        }
        search_from = end;
    }
    fallback
}

fn config_from_json(v: &serde_json::Value) -> EstsConfig {
    EstsConfig {
        pgid: v.get("pgid").and_then(|x| x.as_str()).map(String::from),
        url_post: v.get("urlPost").and_then(|x| x.as_str()).map(String::from),
        url_get_credential_type: v
            .get("urlGetCredentialType")
            .and_then(|x| x.as_str())
            .map(String::from),
        url_begin_auth: v
            .get("urlBeginAuth")
            .and_then(|x| x.as_str())
            .map(String::from),
        url_end_auth: v
            .get("urlEndAuth")
            .and_then(|x| x.as_str())
            .map(String::from),
        sft: v.get("sFT").and_then(|x| x.as_str()).map(String::from),
        sft_name: v
            .get("sFTName")
            .and_then(|x| x.as_str())
            .map(String::from)
            .or_else(|| Some("flowToken".into())),
        s_ctx: v.get("sCtx").and_then(|x| x.as_str()).map(String::from),
        canary: v.get("canary").and_then(|x| x.as_str()).map(String::from),
        api_canary: v
            .get("apiCanary")
            .and_then(|x| x.as_str())
            .map(String::from),
        s_post_username: v
            .get("sPOST_Username")
            .and_then(|x| x.as_str())
            .map(String::from),
        session_id: v
            .get("sessionId")
            .and_then(|x| x.as_str())
            .map(String::from),
        correlation_id: v
            .get("correlationId")
            .and_then(|x| x.as_str())
            .map(String::from),
        enable_number_matching: v
            .get("fEnableNumberMatching")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        arr_user_proofs: v
            .get("arrUserProofs")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        p.get("authMethodId")
                            .and_then(|x| x.as_str())
                            .map(|id| UserProof {
                                auth_method_id: id.to_string(),
                            })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        saml_response: v
            .get("SAMLResponse")
            .and_then(|x| x.as_str())
            .map(String::from),
        saml_relay_state: v
            .get("RelayState")
            .and_then(|x| x.as_str())
            .map(String::from),
        raw_keys: v
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default(),
        error_code: v.get("sErrorCode").and_then(|x| x.as_u64()),
    }
}

/// Sanitized page summary for drift reports: byte size, <title> text,
/// and the presence of the structural keys. NEVER logs token/cookie
/// values (sFT/sCtx/canary are session credentials).
fn page_diagnostic(page: &str, cfg: Option<&EstsConfig>) -> String {
    let size = page.len();
    let title = between(page, "<title>", "</title>").unwrap_or("(no title)");
    let title = title.chars().take(60).collect::<String>();
    let mut keys = Vec::new();
    if let Some(c) = cfg {
        for (name, present) in [
            ("pgid", c.pgid.is_some()),
            ("urlPost", c.url_post.is_some()),
            ("sFT", c.sft.is_some()),
            ("sCtx", c.s_ctx.is_some()),
            ("urlBeginAuth", c.url_begin_auth.is_some()),
            ("SAMLResponse", c.saml_response.is_some()),
        ] {
            if present {
                keys.push(name);
            }
        }
    }
    format!("page {size}B title={title:?} keys=[{}]", keys.join(","))
}

/// Classify a parsed page into the flow's next step. Pure for the tests.
#[derive(Debug, PartialEq)]
pub enum PageKind {
    /// Credential entry (ConvergedSignIn): has urlPost + sFT.
    SignIn,
    /// MFA stage (urlBeginAuth present or an MFA sErrorCode).
    Mfa,
    /// "Stay signed in?" (pgid=KmsiInterrupt).
    Kmsi,
    /// Auto-submit form carrying the SAMLResponse: completion.
    Completion,
    /// The BSSO interrupt "Redirecting" page: a $Config blob WITHOUT
    /// flow state (no sFT). Entra serves it on the first GET of the
    /// saml2 authorize URL; the SAME URL re-GET returns the real
    /// credential page (verified live: hop 1 BSSO, hop 2 SignIn).
    BssoInterrupt,
    /// A conditional-access gate this provider cannot satisfy
    /// (proof-up, terms of use, passkey registration): fall back.
    UnsupportedGate(String),
    /// No recognizable structure: the flow drifted.
    Drift,
}

pub fn classify_page(cfg: &EstsConfig, raw_page: &str) -> PageKind {
    // Auto-submit completion wins first: it can co-occur with leftover
    // config fields on the same page.
    if raw_page.contains("name=\"SAMLResponse\"") || cfg.saml_response.is_some() {
        return PageKind::Completion;
    }
    match cfg.pgid.as_deref() {
        Some("KmsiInterrupt") => return PageKind::Kmsi,
        Some("ConvergedProofUpRedirect") => {
            return PageKind::UnsupportedGate("proof-up required".into())
        }
        Some("TermsOfUse") => return PageKind::UnsupportedGate("terms of use".into()),
        Some("ConvergedTFA") => return PageKind::Mfa,
        _ => {}
    }
    if cfg.url_begin_auth.is_some()
        || cfg
            .url_end_auth
            .as_deref()
            .is_some_and(|u| u.contains("SAS"))
    {
        return PageKind::Mfa;
    }
    if cfg.url_get_credential_type.is_some() || (cfg.url_post.is_some() && cfg.sft.is_some()) {
        return PageKind::SignIn;
    }
    // BSSO interrupt: a config blob exists but carries NO flow state at
    // all (no sFT, no completion, no MFA urls) — the saml2 two-hop
    // pattern's first GET. Distinguishable from Drift by the presence of
    // urlPost (the re-encoding) and the absence of any SAS/MFA markers.
    if cfg.url_post.is_some() {
        return PageKind::BssoInterrupt;
    }
    PageKind::Drift
}

/// SAS JSON body builder: BeginAuth/EndAuth share the shape; the canary
/// rides a HEADER (apiCanary) for JSON calls, not the form.
pub(crate) fn sas_body(
    method: &str,
    auth_method_id: &str,
    ctx: &str,
    flow_token: &str,
    session_id: Option<&str>,
    additional: Option<&str>,
) -> String {
    let mut body = serde_json::json!({
        "AuthMethodId": auth_method_id,
        "Method": method,
        "Ctx": ctx,
        "FlowToken": flow_token,
    });
    if let Some(sid) = session_id {
        body["SessionId"] = serde_json::Value::String(sid.to_string());
    }
    if let Some(a) = additional {
        body["AdditionalAuthData"] = serde_json::Value::String(a.to_string());
    }
    body.to_string()
}

/// The number-match digit the operator must approve on their phone.
/// Lives ONLY in the BeginAuth response `Entropy` field; never scraped
/// from HTML. `Entropy == 0` means plain push (no number to match).
pub fn number_match_digit(begin_auth_json: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(begin_auth_json).ok()?;
    v.get("Entropy").and_then(|e| e.as_u64()).map(|e| e as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(pairs: &[(&str, serde_json::Value)]) -> EstsConfig {
        let mut v = serde_json::Map::new();
        for (k, val) in pairs {
            v.insert(k.to_string(), val.clone());
        }
        config_from_json(&serde_json::Value::Object(v))
    }

    #[test]
    fn parse_prefers_the_blob_with_flow_state() {
        // Two blobs: the BSSO interrupt's re-encoded config first
        // (no sFT), the real ConvergedSignIn second. First-match
        // parsing would return the wrong one.
        let page = "$Config = {\"pgid\":\"BSSO\",\"urlPost\":\"/bad\"};\n\
                    $Config = {\"pgid\":\"ConvergedSignIn\",\"urlPost\":\"/t/login\",\
                    \"sFT\":\"FT-VALUE\",\"sFTName\":\"flowToken\"};";
        let cfg = parse_ests_config(page).expect("flow-state blob must win");
        assert_eq!(cfg.pgid.as_deref(), Some("ConvergedSignIn"));
        assert_eq!(cfg.sft.as_deref(), Some("FT-VALUE"));
        assert_eq!(cfg.url_post.as_deref(), Some("/t/login"));
    }

    #[test]
    fn parse_survives_braces_inside_json_strings() {
        let page = "$Config = {\"pgid\":\"X\",\"sFT\":\"a{\\\"b\\\"}c\",\"x\":\"}\"};";
        let cfg = parse_ests_config(page).expect("brace-balanced parse");
        assert_eq!(cfg.sft.as_deref(), Some("a{\"b\"}c"));
    }

    #[test]
    fn parse_returns_none_without_config() {
        assert_eq!(parse_ests_config("<html><body>nope</body></html>"), None);
    }

    #[test]
    fn bsso_interrupt_is_its_own_page_kind() {
        // Live shape: the saml2 hop-1 page carries a $Config with urlPost
        // but NO sFT/sCtx/MFA urls — the BSSO re-encoding. Must NOT
        // classify as Drift (the production drift report).
        let bsso = cfg_with(&[("urlPost", "/t/saml2?client_id=x".into())]);
        assert_eq!(classify_page(&bsso, "x"), PageKind::BssoInterrupt);
        // With sFT it is the real credential page instead.
        let sign_in = cfg_with(&[("urlPost", "/t/login".into()), ("sFT", "FT".into())]);
        assert_eq!(classify_page(&sign_in, "x"), PageKind::SignIn);
        // With nothing at all it stays Drift.
        assert_eq!(classify_page(&cfg_with(&[]), "x"), PageKind::Drift);
    }

    #[test]
    fn classification_covers_the_documented_page_kinds() {
        let sign_in = cfg_with(&[
            ("pgid", "ConvergedSignIn".into()),
            ("urlPost", "/t/login".into()),
            ("sFT", "FT".into()),
        ]);
        assert_eq!(classify_page(&sign_in, "x"), PageKind::SignIn);

        let mfa = cfg_with(&[
            ("pgid", "ConvergedTFA".into()),
            ("urlBeginAuth", "/common/SAS/BeginAuth".into()),
            ("urlEndAuth", "/common/SAS/EndAuth".into()),
        ]);
        assert_eq!(classify_page(&mfa, "x"), PageKind::Mfa);

        let kmsi = cfg_with(&[("pgid", "KmsiInterrupt".into())]);
        assert_eq!(classify_page(&kmsi, "x"), PageKind::Kmsi);

        let proofup = cfg_with(&[("pgid", "ConvergedProofUpRedirect".into())]);
        assert!(matches!(
            classify_page(&proofup, "x"),
            PageKind::UnsupportedGate(_)
        ));

        let completion = classify_page(
            &cfg_with(&[]),
            "<form name=\"hiddenform\"><input name=\"SAMLResponse\"></form>",
        );
        assert_eq!(completion, PageKind::Completion);

        assert_eq!(
            classify_page(&cfg_with(&[]), "<html></html>"),
            PageKind::Drift
        );
    }

    #[test]
    fn number_match_digit_comes_from_the_entropy_field() {
        assert_eq!(
            number_match_digit("{\"Success\":true,\"Entropy\":42,\"FlowToken\":\"t\"}"),
            Some(42)
        );
        // Entropy 0 = plain push, no digit to match.
        assert_eq!(
            number_match_digit("{\"Success\":true,\"Entropy\":0}"),
            Some(0)
        );
        assert_eq!(number_match_digit("{\"Success\":false}"), None);
    }

    #[test]
    fn sas_body_carries_the_documented_fields() {
        let body = sas_body(
            "BeginAuth",
            "PhoneAppNotification",
            "CTX",
            "FT",
            Some("S"),
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["Method"], "BeginAuth");
        assert_eq!(v["AuthMethodId"], "PhoneAppNotification");
        assert_eq!(v["Ctx"], "CTX");
        assert_eq!(v["FlowToken"], "FT");
        assert_eq!(v["SessionId"], "S");
        let end = sas_body(
            "EndAuth",
            "PhoneAppOTP",
            "CTX",
            "FT",
            Some("S"),
            Some("123456"),
        );
        let v: serde_json::Value = serde_json::from_str(&end).unwrap();
        assert_eq!(v["AdditionalAuthData"], "123456");
    }
}

// ---------------------------------------------------------------------------
// Headless flow: the scripted HTTP state machine
// ---------------------------------------------------------------------------

/// Operator-supplied inputs for the headless run, collected up front so
/// the one-shot ACS JWT is never blocked by terminal latency.
pub struct HeadlessInputs {
    pub username: String,
    pub password: String,
    /// TOTP codes (and any other typed factor) come through this prompt.
    /// Not `Debug`: the closure may capture secrets.
    pub mfa_prompt: MfaPrompt,
}

impl std::fmt::Debug for HeadlessInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadlessInputs")
            .field("username", &self.username)
            .field("password", &"<REDACTED>")
            .finish()
    }
}

/// Generic form scraper: the first <form> with an `action`, and every
/// hidden input in it. Serves the launch form (cloud-auth Token/RelayState)
/// and the completion hiddenform (SAMLResponse) alike.
pub(crate) fn parse_form(html: &str) -> Option<(String, Vec<(String, String)>)> {
    let action_start = html.find("action=\"")? + 8;
    let action = &html[action_start..];
    let action_end = action.find('"')?;
    let action = action[..action_end].to_string();

    let mut inputs = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find("<input") {
        rest = &rest[pos + 6..];
        let Some(end) = rest.find('>') else { break };
        let tag = &rest[..end];
        let name = between(tag, "name=\"", "\"");
        let value = between(tag, "value=\"", "\"");
        if let Some(n) = name {
            inputs.push((n.to_string(), value.unwrap_or_default().to_string()));
        }
    }
    Some((action, inputs))
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let rest = &s[start..];
    let end = rest.find(close)?;
    Some(&rest[..end])
}

/// Run the complete headless chain and return the capture.
///
/// `portal` is the bare portal host; `path_prefix` the portal path
/// (usually `/global-protect`). Operator inputs are collected before
/// prelogin; the only mid-flow interaction is the MFA prompt.
pub async fn run_headless(
    client: &reqwest::Client,
    prelogin_url: String,
    inputs: &HeadlessInputs,
    cap: Duration,
) -> Result<SamlCapture, HeadlessFlowError> {
    let deadline = Instant::now() + cap;
    let started = Instant::now();

    // 1. Own prelogin: SESSID lands in OUR jar (the cloud-auth broker
    //    refuses to start the SSO orchestration without it — verified
    //    live: cookieless POST gets the failure relay form).
    let prelogin_resp = client
        .post(&prelogin_url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&[
            ("tmp", "tmp"),
            ("clientVer", "0.1.0"),
            ("clientos", "Mac"),
            ("os-version", "10.15.7"),
            ("host-id", "opc-headless"),
            ("ipv6-support", "yes"),
            ("default-browser", "1"),
            ("cas-support", "yes"),
        ])
        .send()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless prelogin unreachable: {e}")))?;
    let body = prelogin_resp
        .text()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless prelogin body: {e}")))?;
    let saml = match gp_proto::prelogin::PreloginResponse::parse(&body) {
        Ok(gp_proto::prelogin::PreloginResponse::Saml(s)) => s,
        Ok(_) => {
            return Err(HeadlessFlowError::Drift(
                "portal did not offer SAML (headless not applicable)".into(),
            ))
        }
        Err(e) => {
            return Err(HeadlessFlowError::Drift(format!(
                "headless prelogin parse: {e}"
            )))
        }
    };
    let launch = saml_launch(&saml)
        .map_err(|e| HeadlessFlowError::Drift(format!("saml launch decode: {e}")))?;
    let (action, fields) = match &launch {
        SamlLaunch::Redirect(url) => (url.clone(), Vec::new()),
        SamlLaunch::Post(html) => parse_form(&String::from_utf8_lossy(html))
            .ok_or_else(|| HeadlessFlowError::Drift("saml launch form unparseable".into()))?,
    };
    let portal_host = prelogin_url
        .strip_prefix("https://")
        .and_then(|rest| rest.find('/').map(|i| &rest[..i]))
        .unwrap_or(prelogin_url.as_str());
    let portal_referer = format!("https://{portal_host}/global-protect/prelogin.esp");

    // 2. cloud-auth broker POST -> follow the 302 to the Entra saml2
    //    authorize endpoint ourselves (the redirect is the signed
    //    AuthnRequest; do NOT auto-follow: the BSSO interrupt page needs
    //    its own GET hop).
    let resp = client
        .post(&action)
        .header("User-Agent", BROWSER_UA)
        .header("Referer", &portal_referer)
        .form(&fields)
        .send()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: cloud-auth POST: {e}")))?;
    if !resp.status().is_redirection() && !resp.status().is_success() {
        return Err(HeadlessFlowError::Drift(format!(
            "cloud-auth broker did not start the SSO flow (HTTP {})",
            resp.status()
        )));
    }
    let mut current = resp.url().clone();

    // 3. The page machine: every response goes through the same
    //    process_page classifier, bounded by the gateway's timeout.
    let mut st = FlowState::new(inputs.username.clone());
    let mut credential_pages = 0u32;
    let mut bsso_hops = 0u32;
    let capture;
    loop {
        if Instant::now() >= deadline {
            return Err(HeadlessFlowError::Timeout(format!(
                "timed out after {}s in the Entra flow (gateway \
                 <saml-request-timeout>); if no window is involved and the flow \
                 is stuck, retry with --auth-mode webview/paste",
                started.elapsed().as_secs()
            )));
        }

        let resp = client
            .get(current.clone())
            .header("User-Agent", BROWSER_UA)
            .send()
            .await
            .map_err(|e| {
                HeadlessFlowError::Drift(format!(
                    "headless: GET {}: {e}",
                    flatten(current.as_ref())
                ))
            })?;
        current = resp.url().clone();
        let page = resp
            .text()
            .await
            .map_err(|e| HeadlessFlowError::Drift(format!("headless: page body: {e}")))?;

        // Completion checks FIRST — the tail pages may not carry $Config.
        if page.contains("globalprotectcallback:") {
            capture =
                extract_capture(&page).map_err(|e| HeadlessFlowError::Drift(e.to_string()))?;
            break;
        }
        let (form_action, form_fields) = parse_form(&page).unwrap_or_default();
        let is_completion =
            form_fields.iter().any(|(n, _)| n == "SAMLResponse") && !form_action.is_empty();
        if is_completion {
            // The IdP's auto-submit form: POST SAMLResponse to the SP ACS
            // (the gateway's Assertion Consumer Service), then expect the
            // callback page.
            let resp = client
                .post(&form_action)
                .header("User-Agent", BROWSER_UA)
                .form(&form_fields)
                .send()
                .await
                .map_err(|e| {
                    HeadlessFlowError::Drift(format!(
                        "headless: SP ACS POST {}: {e}",
                        flatten(&form_action)
                    ))
                })?;
            let acs_page = resp
                .text()
                .await
                .map_err(|e| HeadlessFlowError::Drift(format!("headless: ACS body: {e}")))?;
            capture =
                extract_capture(&acs_page).map_err(|e| HeadlessFlowError::Drift(e.to_string()))?;
            break;
        }

        let Some(cfg) = parse_ests_config(&page) else {
            return Err(HeadlessFlowError::Drift(
                "page without $Config and without a SAML completion form (Entra flow drifted)"
                    .into(),
            ));
        };
        st.absorb(&cfg);

        match classify_page(&cfg, &page) {
            PageKind::SignIn => {
                // Wrong-password rounds surface as fresh credential pages:
                // count them and stop to protect the account.
                credential_pages += 1;
                if credential_pages > 1 {
                    return Err(HeadlessFlowError::Auth(
                        "authentication failed (check username/password); not retrying to protect the account"
                            .into(),
                    ));
                }
                tracing::debug!("headless: credential page");
                let post_url = absolute(cfg.url_post.clone().unwrap_or_default());
                let form = [
                    ("login", st.username.clone()),
                    ("loginfmt", st.username.clone()),
                    ("passwd", inputs.password.clone()),
                    ("ctx", st.ctx.clone()),
                    (st.sft_name.as_str(), st.flow_token.clone()),
                    ("canary", st.canary.clone()),
                    ("hpgrequestid", st.session_id.clone()),
                    ("type", "11".to_string()),
                    ("LoginOptions", "3".to_string()),
                ];
                let resp = client
                    .post(&post_url)
                    .header("User-Agent", BROWSER_UA)
                    .header("Referer", current.to_string())
                    .form(&form)
                    .send()
                    .await
                    .map_err(|e| {
                        HeadlessFlowError::Drift(format!(
                            "headless: login POST {}: {e}",
                            flatten(&post_url)
                        ))
                    })?;
                current = resp.url().clone();
            }
            PageKind::Mfa => {
                // mfa_leg walks BeginAuth/EndAuth/ProcessAuth and returns
                // the post-MFA page for the main loop to finish (KMSI /
                // completion / callback).
                let (url, page_text) = mfa_leg(client, &cfg, &st, inputs, deadline).await?;
                current = url;
                st.absorb(&parse_ests_config(&page_text).unwrap_or_default());
                // The next loop pass processes the returned page.
                if let Ok(c) = extract_capture(&page_text) {
                    capture = c;
                    break;
                }
                if page_text.contains("name=\"SAMLResponse\"") {
                    let (action, fields) = parse_form(&page_text).ok_or_else(|| {
                        HeadlessFlowError::Drift("headless: completion form broken".into())
                    })?;
                    let resp = client
                        .post(&action)
                        .header("User-Agent", BROWSER_UA)
                        .form(&fields)
                        .send()
                        .await
                        .map_err(|e| {
                            HeadlessFlowError::Drift(format!("headless: SP ACS POST: {e}"))
                        })?;
                    let acs_page = resp.text().await.map_err(|e| {
                        HeadlessFlowError::Drift(format!("headless: ACS body: {e}"))
                    })?;
                    capture = extract_capture(&acs_page)
                        .map_err(|e| HeadlessFlowError::Drift(e.to_string()))?;
                    break;
                }
            }
            PageKind::BssoInterrupt => {
                // The saml2 two-hop pattern: hop 1 is the BSSO
                // "Redirecting" page, hop 2 (same URL, cookies now set)
                // is the real credential page. Bounded so a persistent
                // BSSO loop cannot spin forever.
                bsso_hops += 1;
                if bsso_hops > 3 {
                    return Err(HeadlessFlowError::Drift(
                        "BSSO interrupt page repeated beyond the two-hop pattern \
                         (Entra flow drifted)"
                            .into(),
                    ));
                }
                tracing::debug!("headless: BSSO interrupt; re-GET hop {}", bsso_hops + 1);
            }
            PageKind::Kmsi => {
                let url = absolute(cfg.url_post.clone().unwrap_or_else(|| "/kmsi".into()));
                let form = [
                    ("ctx", st.ctx.clone()),
                    ("flowToken", st.flow_token.clone()),
                    ("LoginOptions", "1".to_string()),
                    ("type", "28".to_string()),
                ];
                let resp = client
                    .post(&url)
                    .header("User-Agent", BROWSER_UA)
                    .form(&form)
                    .send()
                    .await
                    .map_err(|e| {
                        HeadlessFlowError::Drift(format!(
                            "headless: KMSI POST {}: {e}",
                            flatten(&url)
                        ))
                    })?;
                current = resp.url().clone();
            }
            PageKind::Completion => {
                let (action, fields) = parse_form(&page).ok_or_else(|| {
                    HeadlessFlowError::Drift("headless: completion form unparseable".into())
                })?;
                let resp = client
                    .post(&action)
                    .header("User-Agent", BROWSER_UA)
                    .form(&fields)
                    .send()
                    .await
                    .map_err(|e| {
                        HeadlessFlowError::Drift(format!(
                            "headless: SP ACS POST {}: {e}",
                            flatten(&action)
                        ))
                    })?;
                let acs_page = resp
                    .text()
                    .await
                    .map_err(|e| HeadlessFlowError::Drift(format!("headless: ACS body: {e}")))?;
                capture = extract_capture(&acs_page)
                    .map_err(|e| HeadlessFlowError::Drift(e.to_string()))?;
                break;
            }
            PageKind::UnsupportedGate(why) => {
                return Err(HeadlessFlowError::Drift(format!(
                    "the IdP requires an interactive gate ({why}); falling back to \
                     the webview/paste flows"
                )));
            }
            PageKind::Drift => {
                return Err(HeadlessFlowError::Drift(format!(
                    "page without recognizable structure ({})",
                    page_diagnostic(&page, Some(&cfg))
                )));
            }
        }
    }
    Ok(capture)
}

/// Flow state carried across pages: exactly the three rotated values
/// (ctx, flowToken, cookie jar) plus the display-adjacent fields.
struct FlowState {
    username: String,
    ctx: String,
    flow_token: String,
    sft_name: String,
    canary: String,
    api_canary: String,
    session_id: String,
}

impl FlowState {
    fn new(username: String) -> Self {
        Self {
            username,
            ctx: String::new(),
            flow_token: String::new(),
            sft_name: "flowToken".into(),
            canary: String::new(),
            api_canary: String::new(),
            session_id: String::new(),
        }
    }

    /// Rotate with the newest values from the page (every ESTS response
    /// rotates flowToken/apiCanary; overwriting is the contract).
    fn absorb(&mut self, cfg: &EstsConfig) {
        if let Some(c) = &cfg.s_ctx {
            self.ctx = c.clone();
        }
        if let Some(f) = &cfg.sft {
            self.flow_token = f.clone();
        }
        if let Some(n) = &cfg.sft_name {
            self.sft_name = n.clone();
        }
        if let Some(c) = &cfg.canary {
            self.canary = c.clone();
        }
        if let Some(c) = &cfg.api_canary {
            self.api_canary = c.clone();
        }
        if let Some(s) = &cfg.session_id {
            self.session_id = s.clone();
        }
    }
}

fn flatten(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 OPR/132.0.0.0";

fn absolute(path: String) -> String {
    if path.starts_with("http") {
        path
    } else {
        format!("https://login.microsoftonline.com{path}")
    }
}

fn extract_capture(page: &str) -> Result<SamlCapture, AuthError> {
    let Some(idx) = page.find("globalprotectcallback:") else {
        return Err(AuthError::Failed(
            "headless: page reached the end of the flow without a callback URL".into(),
        ));
    };
    let rest = &page[idx..];
    let end = rest.find(['"', '\'', '<', ' ']).unwrap_or(rest.len());
    let uri = rest[..end].trim_end_matches('\\');
    parse_globalprotect_callback(uri)
        .ok_or_else(|| AuthError::Failed("headless: callback URL present but unparseable".into()))
}

/// The MFA leg: classify factors, drive BeginAuth/EndAuth, close with
/// ProcessAuth, and return the post-MFA page (KMSI/completion/callback)
/// for the main loop to finish.
async fn mfa_leg(
    client: &reqwest::Client,
    cfg: &EstsConfig,
    st: &FlowState,
    inputs: &HeadlessInputs,
    deadline: Instant,
) -> Result<(reqwest::Url, String), HeadlessFlowError> {
    let begin_url = absolute(
        cfg.url_begin_auth
            .clone()
            .unwrap_or_else(|| "/common/SAS/BeginAuth".into()),
    );
    let end_url = absolute(
        cfg.url_end_auth
            .clone()
            .unwrap_or_else(|| "/common/SAS/EndAuth".into()),
    );

    // Factor preference: TOTP (PhoneAppOTP) is deterministic — no
    // silent-push risk; push (PhoneAppNotification) displays the
    // number-match digit from BeginAuth's Entropy field.
    let method = cfg
        .arr_user_proofs
        .iter()
        .map(|p| p.auth_method_id.clone())
        .find(|id| id == "PhoneAppOTP")
        .or_else(|| {
            cfg.arr_user_proofs
                .iter()
                .map(|p| p.auth_method_id.clone())
                .find(|id| id == "PhoneAppNotification")
        })
        .or_else(|| {
            cfg.arr_user_proofs
                .iter()
                .map(|p| p.auth_method_id.clone())
                .find(|id| id == "OneWaySMS")
        })
        .ok_or_else(|| {
            HeadlessFlowError::Drift(
                "no supported MFA factor offered (TOTP/push/SMS); falling back to \
                 the webview/paste flows"
                    .into(),
            )
        })?;

    let body = sas_body("BeginAuth", &method, &st.ctx, &st.flow_token, None, None);
    let resp = client
        .post(&begin_url)
        .header("User-Agent", BROWSER_UA)
        .header("canary", st.api_canary.clone())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: BeginAuth: {e}")))?;
    let begin_text = resp
        .text()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: BeginAuth body: {e}")))?;
    let bv: serde_json::Value = serde_json::from_str(&begin_text)
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: BeginAuth parse: {e}")))?;
    let mut ctx = bv
        .get("Ctx")
        .and_then(|x| x.as_str())
        .unwrap_or(&st.ctx)
        .to_string();
    let mut flow_token = bv
        .get("FlowToken")
        .and_then(|x| x.as_str())
        .unwrap_or(&st.flow_token)
        .to_string();
    let session_id = bv
        .get("SessionId")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    match method.as_str() {
        "PhoneAppNotification" => {
            // Number matching: the digit lives ONLY in the BeginAuth
            // Entropy field. Entropy 0/absent = plain push approval.
            match number_match_digit(&begin_text) {
                Some(0) | None => {
                    eprintln!("headless MFA: approve the sign-in on your Authenticator app…");
                }
                Some(digit) => {
                    eprintln!(
                        "headless MFA: approve the sign-in on your Authenticator app — \
                         enter the number {digit}"
                    );
                }
            }
            poll_push(
                client,
                &end_url,
                &method,
                st,
                Some(&session_id),
                120,
                deadline,
            )
            .await?;
        }
        "PhoneAppOTP" | "OneWaySMS" => {
            let code = (inputs.mfa_prompt)("Enter the verification code")
                .ok_or_else(|| HeadlessFlowError::Auth("headless: no MFA code entered".into()))?;
            let body = sas_body(
                "EndAuth",
                &method,
                &ctx,
                &flow_token,
                Some(&session_id),
                Some(&code),
            );
            let resp = client
                .post(&end_url)
                .header("User-Agent", BROWSER_UA)
                .header("canary", st.api_canary.clone())
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| HeadlessFlowError::Drift(format!("headless: EndAuth: {e}")))?;
            let end_text = resp
                .text()
                .await
                .map_err(|e| HeadlessFlowError::Drift(format!("headless: EndAuth body: {e}")))?;
            let ev: serde_json::Value = serde_json::from_str(&end_text)
                .map_err(|e| HeadlessFlowError::Drift(format!("headless: EndAuth parse: {e}")))?;
            if ev.get("Success").and_then(|x| x.as_bool()) != Some(true) {
                return Err(HeadlessFlowError::Auth(format!(
                    "MFA verification failed: {}",
                    ev.get("Message")
                        .and_then(|x| x.as_str())
                        .unwrap_or("(no message)")
                )));
            }
            if let Some(c) = ev.get("FlowToken").and_then(|x| x.as_str()) {
                flow_token = c.to_string();
            }
            if let Some(c) = ev.get("Ctx").and_then(|x| x.as_str()) {
                ctx = c.to_string();
            }
        }
        other => {
            return Err(HeadlessFlowError::Drift(format!(
                "unsupported MFA factor {other:?}"
            )));
        }
    }

    // ProcessAuth closes the MFA stage (server-rendered; the minimal
    // prior-art body works on the observed tenants — the live probe
    // pins the exact body for the deployment).
    let sas_post = absolute("/common/SAS/ProcessAuth".to_string());
    let body = [
        ("request", ctx.clone()),
        ("mfaAuthMethod", method.clone()),
        ("login", st.username.clone()),
        ("flowToken", flow_token.clone()),
        ("canary", st.canary.clone()),
        ("hpgrequestid", st.session_id.clone()),
        ("type", "22".to_string()),
        ("rememberMFA", "true".to_string()),
    ];
    let resp = client
        .post(&sas_post)
        .header("User-Agent", BROWSER_UA)
        .header("Referer", "https://login.microsoftonline.com/")
        .form(&body)
        .send()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: ProcessAuth: {e}")))?;
    let url = resp.url().clone();
    let page = resp
        .text()
        .await
        .map_err(|e| HeadlessFlowError::Drift(format!("headless: ProcessAuth body: {e}")))?;
    Ok((url, page))
}

/// Push poll: POST EndAuth JSON every 3s until Success/denied, capped
/// inside the gateway budget.
async fn poll_push(
    client: &reqwest::Client,
    end_url: &str,
    method: &str,
    st: &FlowState,
    session_id: Option<&str>,
    cap_secs: u64,
    deadline: Instant,
) -> Result<(), HeadlessFlowError> {
    let poll_deadline = deadline.min(Instant::now() + Duration::from_secs(cap_secs));
    loop {
        if Instant::now() >= poll_deadline {
            return Err(HeadlessFlowError::Timeout(
                "headless: push approval timed out".into(),
            ));
        }
        let body = sas_body("EndAuth", method, &st.ctx, &st.flow_token, session_id, None);
        let resp = client
            .post(end_url)
            .header("User-Agent", BROWSER_UA)
            .header("canary", st.api_canary.clone())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| HeadlessFlowError::Drift(format!("headless: push poll: {e}")))?;
        let text = resp
            .text()
            .await
            .map_err(|e| HeadlessFlowError::Drift(format!("headless: push poll body: {e}")))?;
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return Err(HeadlessFlowError::Drift(
                "headless: push poll unparseable".into(),
            ));
        };
        let success = v.get("Success").and_then(|x| x.as_bool()).unwrap_or(false);
        let retry = v.get("Retry").and_then(|x| x.as_bool()).unwrap_or(false);
        let err_code = v.get("ErrCode").and_then(|x| x.as_i64()).unwrap_or(0);
        if success {
            return Ok(());
        }
        if !retry {
            return Err(HeadlessFlowError::Auth(format!(
                "MFA not approved (ErrCode {err_code}: {})",
                v.get("Message").and_then(|x| x.as_str()).unwrap_or("")
            )));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
