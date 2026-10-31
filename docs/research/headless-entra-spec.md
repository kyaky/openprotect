# Headless Entra+SAML auth provider: implementation spec

Branch: `feat/headless-entra-saml`. Synthesis of four web-research reports
(prior art: saml2aws AzureAD provider, openconnect gp-saml, GlobalProtect-
openconnect gp-saml helper, azol, openconnect-socks; plus the live HTTP
trace recorded in entra-headless-live-capture.md), cross-checked against
this repo. Deployment identifiers anonymized per project policy.

HEADLESS ENTRA+SAML AUTH PROVIDER SPEC FOR OPENPROTECT (production Prisma Access + Entra deployment)
Branch feat/headless-entra-saml. Synthesis of four research reports (prior art, live HTTP trace of 2026-10-31, MFA-leg survey, SP/ACS tail), cross-checked against the repo: crates/gp-auth/src/saml_common.rs, crates/gp-auth/src/lib.rs (AuthProvider trait), crates/gp-proto/src/prelogin.rs (DEFAULT_SAML_REQUEST_TIMEOUT_SECS = 600), bins/opc/src/saml_webview.rs. Live captures from the anonymous trace are preserved under research fixtures (see docs/research/fixtures/) (pa.html, h2.html, gct_resp.json, prelogin.xml, launch_form.html) and double as test fixtures.

1. SHAPE OF THE NEW CODE
- New AuthProvider "saml-headless" in crates/gp-auth implementing gp_auth::AuthProvider (name / can_handle / authenticate), alongside saml_paste and the macOS saml_webview provider. Reuse gp_auth::saml_common::{saml_launch, SamlCapture, parse_globalprotect_callback, looks_like_jwt} unchanged; SamlCapture::into_credential already routes JWTs into Credential::Prelogin, so the downstream login.esp/getconfig replay needs zero changes.
- Transport: one reqwest Client with cookie_store enabled for the whole Entra leg. Pin an Opera-family User-Agent (Chromium but non-Chrome, e.g. Chrome/148.0.0.0 Safari/537.36 OPR/132.0.0.0) plus sec-ch-ua and Sec-Fetch-* headers. Portal .esp calls keep the existing "PAN GlobalProtect" UA that gp-proto already sets.
- $Config parsing: brace-balanced scan for "$Config = {", JSON-decode, prefer the blob containing sFT, else the first. One page may carry several blobs; a naive regex cuts the wrong one (Entrance lesson).
- Flow state is exactly three things: ctx ($Config.sCtx), flowToken ($Config.sFT, field name read from sFTName, currently "flowToken", historically PPFT), and the cookie jar. canary goes into form POSTs, apiCanary into the "canary" HEADER of JSON API calls. GetCredentialType and every SAS response ROTATE FlowToken and apiCanary: overwrite locals with the newest values each time. Never hardcode field names.
- Timing: saml_request_timeout_secs from prelogin bounds the whole run; the push poll budget (120s) must fit inside the remaining budget. All operator input (username, password, TOTP code or the decision to wait for a push) is collected BEFORE prelogin; between EndAuth success and getconfig there is zero operator latency because the ACS JWT is one-shot with a ~60s TTL.

2. THE ORDERED FLOW (full detail in steps[])
1. POST /global-protect/prelogin.esp (PAN UA). Extract saml-auth-method=POST, saml-request-timeout, decode saml-request via saml_launch -> action https://cloud-auth.au.apps.paloaltonetworks.com/auth + hidden Token JWT (one-shot).
2. POST cloud-auth /auth with Token -> 302 Location: login.microsoftonline.com/<TENANT_ID>/saml2?SAMLRequest=...&RelayState=... Save the ORIGINAL URL. Reuse = 401; every restart starts here.
3. GET the original saml2 URL (hop 1) -> BSSO interrupt "Redirecting" page: no pgid, urlPost is a re-encoding you must NOT use (observed 400). Set-Cookie: esctx, esctx-<rand>, fpc, stsservicecookie, x-ms-gateway-slice.
4. GET the SAME original URL (hop 2) -> ConvergedSignIn: pgid=ConvergedSignIn, urlPost=/{tenant}/login, sFT, sFTName, sCtx, canary, apiCanary, sPOST_Username, sessionId; Set-Cookie buid.
5. Optional POST /common/GetCredentialType (JSON, canary header = apiCanary): confirm HasPassword, read SasParams, detect FederationRedirectUrl (abort to fallback if present), harvest rotated FlowToken/apiCanary. Non-fatal on failure.
6. POST urlPost with login, loginfmt, passwd, ctx, flowToken, canary, hpgrequestid, type=11, LoginOptions=3, Referer -> next $Config. Wrong password (AADSTS50126) stops, max 3 user-driven attempts; 50053 lockout stops; no $Config = drift.
7. Classify the response (mfa_tree below).
8. POST urlBeginAuth {AuthMethodId, Method:'BeginAuth', ctx, flowToken}, canary header=apiCanary -> Ctx/FlowToken/SessionId (+ Entropy for push). 500121 duplicate-request = challenge already in flight, go straight to polling.
9. TOTP: one POST urlEndAuth with AdditionalAuthData=<6-digit code>, retry max 3 on wrong code. Push: print response Entropy (%02d) to stderr as the number-match digit, then poll urlEndAuth (POST JSON every 3s, 120s cap; GET variant with X-Ms-* headers as fallback) until Success / denied / timeout. Every response overwrites ctx/flowToken.
10. POST /common/SAS/ProcessAuth form: push type=22 {request, mfaAuthMethod, login, flowToken, canary, hpgrequestid, rememberMFA}; TOTP type=19 {otc, GeneralVerify=false, ...}. Pin the body to our the deployment capture (probe item 1).
11. KMSI if present (pgid=KmsiInterrupt or urlPost ends /kmsi): POST /kmsi {ctx, flowToken, LoginOptions=1, type=28, DontShowAgain=true}.
12. The final page is an auto-submit form (hiddenform / f1 / oPostParams) carrying SAMLResponse + RelayState to https://PORTAL_HOST/SAML20/SP/ACS. Generic helper: resubmit ALL hidden inputs of the first auto-submit form. POST immediately, no auto-follow into the globalprotectcallback: scheme.
13. Parse the ACS response for the capture, priority: (a) body substring globalprotectcallback:cas-as=1&un=...&token=<JWT>, (b) headers saml-username + prelogin-cookie/portal-userauthcookie, (c) HTML-comment base64 blob. All feed parse_globalprotect_callback -> SamlCapture::into_credential.
14. login.esp/getconfig back-to-back (existing path). Persist the cookie jar (0600, per profile) after success.

3. MFA DECISION TREE (full version in mfa_tree)
Page classification is ordered: no $Config -> drift; urlGetCredentialType present -> password page; urlBeginAuth present or sErrorCode in {50072,50074,50076,50079,500121} -> MFA; pgid=KmsiInterrupt -> KMSI; auto-submit form with SAMLResponse -> completion; CA-gated pgids (ConvergedProofUpRedirect, TermsOfUse, appverify, passkey) -> fallback.
Factor selection from arrUserProofs: prefer PhoneAppOTP (deterministic TOTP, no silent-push risk; code from stdin or derived from --totp-secret via RFC 6238); else PhoneAppNotification (print BeginAuth's Entropy as the number-match digit, Entropy 0/absent = plain push approval; poll 3s/120s; denied and timeout are distinct stop states); else SMS via the same AdditionalAuthData mechanism; anything else (FIDO/QR only) -> fallback. The number-match digit exists ONLY in the BeginAuth Entropy field; never scrape HTML for it. Number matching is tenant-mandatory at the deployment (fEnableNumberMatching=true observed live), so printing Entropy is required UX: the operator types it into Authenticator and taps approve, which is exactly the 2FA the user asked the CLI to surface.

4. PERSISTABLES AND THE SILENT PATH
ESTSAUTHPERSISTENT is the asset: it remembers both factors for a ~90-day rolling window (the deployment CA policy can shorten it), so a persisted jar (OS keyring or encrypted file, 0600, username in the header, never logged) lets the next run seed the jar at step 1 and often complete with no password and no MFA. Persist ESTSAUTH/ESTSAUTHLIGHT/buid/fpc/stsservicecookie/x-ms-gateway-slice with it; esctx-* and everything SAS-side are per-flow only. rememberMFA=true can add a 30-day trusted-device marker (probe item 12 before enabling). The silent path needs no separate code: seed the jar, run the same state machine, and it either sails through or lands on ConvergedSignIn and continues normally.

5. FRAGILITY AND THE DETECT-AND-FALLBACK CONTRACT
Fourteen fragility points are listed in fragility[]; the ones that will bite first: flowToken rotation, the interrupt-page urlPost 400, the one-shot cloud-auth Token, UA policing (requests UA = Bad Reputation, Chrome UA = JS-only hpgid=6 page), CA gates, silent push suppression for anomalous sign-ins, smart lockout on password retries, and the 60s ACS JWT window. The contract: (a) user errors stop immediately with the verbatim AADSTS code; (b) structural drift (missing $Config, missing Entropy, unexpected pgid, JS-only pages) gets ONE attempt then automatic demotion to saml_paste or saml_webview with a WARNING naming the failed stage and a sanitized log (page title, pgid, unexpected field names only; no tokens/cookies/canaries); (c) transient network errors retry once, jittered. Cap full SSO cycles per account per hour (each burns an MFA approval), --force beyond, --auth-provider to pin a tier, one tracing span per stage so field reports localize the break. This mirrors yuezk's webview -> browser -> paste ladder and openconnect's cookie-reuse fallback: nobody fixes the pure-HTTP path forever, everyone fails over.

6. WHAT IS UNCERTAIN (live_probe_plan has the full list)
UPDATE 2026-10-31: the authenticated legs are now pinned and the
provider is live-validated end-to-end (both TOTP and push reach
`state: connected`); see entra-headless-live-capture.md sections 4-7
for the observed shapes, including the two findings the prior art did
not cover: the credential POST returns the FULL MFA page as a 200
(process the response, never re-GET), and the portal binds the issued
callback token to the chain prelogin's declared client identity
(a mismatched identity gets getconfig rejected with HTTP 512).
The anonymous 2026-10-31 trace verified everything up to the credential page and GetCredentialType, but NOT the authenticated legs. Needs a live probe with a dedicated test account: the exact ProcessAuth body the deployment expects (type 19 vs 22 and its companions), whether PhoneAppOTP is even offered to the test account, EndAuth POST-vs-GET acceptance and the live poll-interval values, whether LoginOptions=3 suppresses KMSI under the deployment CA policy, which of the three ACS capture encodings a raw client actually receives, the empirical 60s JWT rejection string, whether the persisted jar truly yields silent runs, whether plain reqwest TLS survives the authenticated legs, and whether the deployment CA injects appverify/ToU pages for the test account. Probe discipline: fresh prelogin per probe, per-stage spans, log statuses and $Config keys only, abort on the first unrecognized page.

7. ESTIMATED IMPLEMENTATION
Modules in crates/gp-auth: config.rs ($Config brace-balanced parser + typed struct), sas.rs (BeginAuth/EndAuth/ProcessAuth), flow.rs (the step state machine + classifier), jar.rs (persist/load). ~400-700 LoC plus tests replaying the /tmp/ests_research fixtures. The novel composition (saml2aws-style Entra leg + GP ACS capture + existing login.esp replay) has no published Rust equivalent; every GP-specific project stops at a real browser and scrapes the callback, which is exactly the tier our fallback keeps.