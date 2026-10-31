//! macOS SAML webview auth provider: the IdP flow runs inside an
//! embedded WKWebView (wry) and the gateway's `globalprotectcallback:`
//! anchor is auto-captured from the ACS page — no terminal paste.
//!
//! Why this exists: the paste flow needs the operator to copy a
//! `globalprotectcallback:` URL out of the gateway's ACS page on every
//! login. The IdP (Azure) keeps a browser-side session for ~24h, so on
//! repeats the SSO leg auto-completes and the ONLY remaining manual
//! step is that paste. This provider removes it: the same WKWebView
//! data store that carries the IdP session also lets the embedded
//! window auto-complete the SSO leg (verified live against
//! login.microsoftonline.com — a second window landed on the account
//! page with no sign-in prompt), and the ACS anchor is read from the
//! page programmatically instead of by hand.
//!
//! Threading: AppKit wants its event loop on the process main thread.
//! The whole connect chain polls on the main thread under
//! `block_on`, so [`run_webview_flow`] runs `run_return` synchronously
//! in the caller's context: the NSApp run loop dispatches webview
//! events while the tokio WORKER threads keep the rest of the runtime
//! (phase watchdog, IPC server) alive. Blocking the main task here is
//! deliberate and bounded by the gateway's `<saml-request-timeout>`.
//!
//! Windows: wry speaks WebView2 with the same builder API, so the
//! provider body is written platform-neutrally and gated to macOS
//! until the Windows milestone; Linux keeps the paste flow (wry there
//! needs the gtk family banned in deny.toml).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use gp_auth::saml_launch;
use gp_proto::prelogin::{PreloginResponse, SamlPrelogin};
use tao::dpi::LogicalSize;
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoop};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::WindowBuilder;
use wry::WebViewBuilder;

use crate::AuthContext;
use gp_auth::{parse_globalprotect_callback, AuthError, AuthProvider, SamlCapture};
use gp_proto::Credential;

/// The provider's own error surface. `Unavailable` means the webview
/// stack could not start at all (no WindowServer — SSH session, root
/// without console access): the connect path falls back to the paste
/// provider for THOSE only; flow-level failures (user closed the
/// window, timeout, capture malformed) are terminal for this attempt.
#[derive(Debug)]
pub enum WebviewFlowError {
    Unavailable(String),
    Failed(String),
}

impl std::fmt::Display for WebviewFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebviewFlowError::Unavailable(m) => write!(f, "webview unavailable: {m}"),
            WebviewFlowError::Failed(m) => write!(f, "webview flow failed: {m}"),
        }
    }
}

impl std::error::Error for WebviewFlowError {}

impl From<WebviewFlowError> for AuthError {
    fn from(e: WebviewFlowError) -> Self {
        match e {
            WebviewFlowError::Unavailable(m) | WebviewFlowError::Failed(m) => AuthError::Failed(m),
        }
    }
}

/// What the navigation handler may do with one attempted navigation.
#[derive(Debug)]
enum NavAction {
    /// Regular web navigation: let the webview proceed.
    Allow,
    /// The gateway's callback anchor: block the (unsupported-scheme)
    /// navigation and hand the parsed capture to the event loop.
    Capture(SamlCapture),
}

/// Classify one attempted navigation. Pure for the tests.
///
/// The gateway's ACS page anchors `globalprotectcallback:` URIs (custom
/// scheme — the browser never resolves them). The initialization script
/// clicks that anchor automatically, which surfaces HERE as an attempted
/// navigation with the full callback URI; parsing it yields the capture.
/// A scheme URI that fails to parse is allowed through (the webview
/// shows its own unsupported-scheme behaviour) — never a capture, never
/// a crash.
fn classify_navigation(uri: &str) -> NavAction {
    if uri.starts_with("globalprotectcallback:") {
        match parse_globalprotect_callback(uri) {
            Some(capture) => NavAction::Capture(capture),
            None => NavAction::Allow,
        }
    } else {
        NavAction::Allow
    }
}

pub struct SamlWebviewAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for SamlWebviewAuthProvider {
    fn name(&self) -> &str {
        "saml-webview"
    }

    fn can_handle(&self, prelogin: &PreloginResponse) -> bool {
        prelogin.is_saml()
    }

    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        ctx: &AuthContext,
    ) -> Result<Credential, AuthError> {
        // Thin wrapper: the typed body preserves the Unavailable/Failed
        // distinction for the connect/re-auth fallback logic; the trait
        // contract erases it into AuthError.
        self.authenticate_typed(prelogin, ctx)
            .await
            .map_err(Into::into)
    }
}

impl SamlWebviewAuthProvider {
    /// Typed authenticate: preserves [`WebviewFlowError::Unavailable`]
    /// so the connect/re-auth paths can fall back to the paste flow
    /// without string-matching error text. The [`AuthProvider`] trait
    /// impl above is a thin wrapper that erases the distinction.
    pub async fn authenticate_typed(
        &self,
        prelogin: &PreloginResponse,
        _ctx: &AuthContext,
    ) -> Result<Credential, WebviewFlowError> {
        let saml = match prelogin {
            PreloginResponse::Saml(s) => s.clone(),
            _ => {
                return Err(WebviewFlowError::Failed(
                    "not a SAML prelogin response".into(),
                ))
            }
        };

        // Deliberately blocking on the MAIN thread: see the module docs.
        // The event loop must be constructed and run there anyway; the
        // gateway's own saml-request-timeout bounds the stay.
        let cap = Duration::from_secs(saml.saml_request_timeout_secs);
        let capture = run_webview_flow(&saml, cap)?;
        tracing::info!("saml capture (webview): user={}", capture.username);
        Ok(capture.into_credential())
    }
}

/// The initialization script that auto-clicks the gateway's callback
/// anchor. Runs on EVERY page the webview loads (IdP pages included,
/// where the selector simply never matches); the retry loop is bounded
/// so a stray page cannot leave a runaway timer behind.
const AUTOCLICK_SCRIPT: &str = r#"
(function () {
    let tries = 0;
    const tick = () => {
        const a = document.querySelector('a[href^="globalprotectcallback:"]');
        if (a) { a.click(); return; }
        if (tries++ < 300) { setTimeout(tick, 100); }
    };
    tick();
})();
"#;

fn run_webview_flow(saml: &SamlPrelogin, cap: Duration) -> Result<SamlCapture, WebviewFlowError> {
    let launch = saml_launch(saml)
        .map_err(|e| WebviewFlowError::Failed(format!("saml launch decode: {e}")))?;

    enum LoopExit {
        Captured,
        WindowClosed,
        TimedOut,
    }
    // Single-threaded UI state: the navigation handler, the event-loop
    // closure and this function all run on the same thread, so Rc/RefCell
    // is enough (no Send/Sync needed — nothing crosses threads).
    let captured: Rc<RefCell<Option<SamlCapture>>> = Rc::new(RefCell::new(None));
    let exit_reason: Rc<RefCell<Option<LoopExit>>> = Rc::new(RefCell::new(None));
    let handler_captured = captured.clone();
    let loop_captured = captured.clone();

    let mut event_loop = EventLoop::new();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("OpenProtect SSO — sign in if asked; this window closes itself")
        .with_inner_size(LogicalSize::new(560.0, 760.0))
        .build(&event_loop)
        .map_err(|e| WebviewFlowError::Unavailable(format!("create window: {e}")))?;
    window.set_focus();

    let webview_build = match &launch {
        gp_auth::SamlLaunch::Redirect(url) => WebViewBuilder::new().with_url(url),
        gp_auth::SamlLaunch::Post(html) => {
            // The POST form is raw bytes (a portal may declare a legacy
            // charset); the webview needs text, so this provider-side
            // conversion is the only lossy step — the paste server keeps
            // serving the verbatim bytes.
            WebViewBuilder::new().with_html(String::from_utf8_lossy(html))
        }
    };
    let webview = webview_build
        .with_initialization_script(AUTOCLICK_SCRIPT)
        .with_navigation_handler(move |uri: String| match classify_navigation(&uri) {
            NavAction::Allow => true,
            NavAction::Capture(capture) => {
                *handler_captured.borrow_mut() = Some(capture);
                // Block the unsupported-scheme navigation: the webview
                // never actually navigates into globalprotectcallback:,
                // the capture has already left through the proxy
                // wake-up below.
                let _ = proxy.send_event(());
                false
            }
        })
        .build(&window)
        .map_err(|e| WebviewFlowError::Unavailable(format!("create webview: {e}")))?;

    let deadline = Instant::now() + cap;
    let loop_captured_ref = loop_captured.clone();
    let exit_for_loop = exit_reason.clone();
    // `run_return` (NOT `run`: that one process::exits on Exit) drives
    // NSApplication until Capture/Close/timeout flips ControlFlow::Exit,
    // then hands control back to the connect flow on this same thread.
    let _exit_code = event_loop.run_return(move |event, _target, control_flow| {
        // Re-arm the deadline on every wake: Wait sleeps until events,
        // WaitUntil guarantees the timeout check fires even with no
        // window events at all.
        *control_flow = ControlFlow::WaitUntil(deadline);
        match event {
            Event::UserEvent(()) => {
                if loop_captured_ref.borrow().is_some() {
                    *exit_for_loop.borrow_mut() = Some(LoopExit::Captured);
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::WindowEvent {
                event: tao::event::WindowEvent::CloseRequested,
                ..
            } => {
                *exit_for_loop.borrow_mut() = Some(LoopExit::WindowClosed);
                *control_flow = ControlFlow::Exit;
            }
            Event::NewEvents(tao::event::StartCause::ResumeTimeReached { .. }) => {
                if Instant::now() >= deadline {
                    *exit_for_loop.borrow_mut() = Some(LoopExit::TimedOut);
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });

    // Drop the views before reading the outcome: the webview must not
    // outlive decisions made about its teardown ordering.
    drop(webview);
    drop(window);

    let exit = exit_reason.borrow_mut().take();
    let capture = captured.borrow_mut().take();
    match (exit, capture) {
        (_, Some(capture)) => Ok(capture),
        (Some(LoopExit::TimedOut), _) => Err(WebviewFlowError::Failed(format!(
            "saml-webview: timed out after {}s waiting for the SSO flow              (gateway <saml-request-timeout>)",
            cap.as_secs()
        ))),
        // Window closed, or the loop ended without either reason: the
        // operator walked away mid-flow.
        _ => Err(WebviewFlowError::Failed(
            "saml-webview: window closed before the SAML flow completed".into(),
        )),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn provider_shape_matches_the_paste_contract() {
        let provider = SamlWebviewAuthProvider;
        assert_eq!(provider.name(), "saml-webview");
        // SAML prelogin responses are handled; the plain-password
        // variant is the password provider's job (same split as
        // the paste provider).
        assert!(provider.can_handle(&PreloginResponse::Saml(SamlPrelogin {
            region: String::new(),
            saml_auth_method: "REDIRECT".into(),
            saml_request: String::new(),
            saml_request_timeout_secs: 60,
        })));
        assert!(!provider.can_handle(&PreloginResponse::Standard(
            gp_proto::prelogin::StandardPrelogin {
                region: String::new(),
                auth_message: String::new(),
                label_username: String::new(),
                label_password: String::new(),
            }
        )));
    }

    #[test]
    fn navigation_capture_parses_the_gateway_callback() {
        let uri = "globalprotectcallback:cas-as=1&un=alice%40ad.unsw.edu.au&token=aaa.bbb.ccc";
        match classify_navigation(uri) {
            NavAction::Capture(capture) => {
                assert_eq!(capture.username, "alice@ad.unsw.edu.au");
                assert_eq!(capture.prelogin_cookie, "aaa.bbb.ccc");
            }
            NavAction::Allow => panic!("gateway callback must classify as a capture"),
        }
    }

    #[test]
    fn navigation_allows_regular_traffic_and_unparseable_schemes() {
        assert!(matches!(
            classify_navigation("https://login.microsoftonline.com/common/login"),
            NavAction::Allow
        ));
        // A scheme URI that fails to parse is allowed through (the
        // webview shows its own unsupported-scheme behaviour); it
        // must never panic the auth flow.
        assert!(matches!(
            classify_navigation("globalprotectcallback:not-a-known-shape"),
            NavAction::Allow
        ));
        assert!(matches!(classify_navigation(""), NavAction::Allow));
    }

    #[test]
    fn autoclick_script_only_targets_the_callback_anchor() {
        // The initialization script runs on EVERY page; a runaway
        // timer there would tick for the whole session on every IdP
        // page. Bound: 300 retries at 100ms.
        assert!(AUTOCLICK_SCRIPT.contains("tries++ < 300"));
        assert!(AUTOCLICK_SCRIPT.contains("globalprotectcallback:"));
    }
}
