# Entra headless SAML: live capture of a Prisma Access + Entra connect flow

Branch: `feat/headless-entra-saml`. Captured 2026-10-31 with plain HTTP probes
(python stdlib) against a production Prisma Access portal fronted by Entra ID
(the deployment that motivated this work; hostnames and tenant identifiers
anonymized below). No credentials involved. Redactions noted inline. This document is the observed ground truth that the
`--auth-mode headless` provider implements; the Entra leg (steps 4-5) field
details come from the prior-art research tracked in the same branch.

## The chain, as observed

```
opc                    cloud-auth.au.apps      login.microsoftonline.com     PORTAL_HOST
  |  1. POST /global-protect/prelogin.esp      |                              |
  |------------------------------------------->|                              |   (portal; form host)
  |  <- SESSID cookie + saml-request:           |                              |
  |     POST form -> cloud-auth/auth            |                              |
  |     Token_A (JWT, 120s TTL) + RelayState    |                              |
  |                                             |                              |
  |  2. POST Token_A + RelayState (+SESSID)     |                              |
  |------------------------------------------->|                              |
  |  <- 302 Location: login.microsoftonline.com/<tenant>/saml2?SAMLRequest=...   |
  |     (signed AuthnRequest; tenant <TENANT_ID>)       |
  |                                                                           |
  |  3. GET saml2?SAMLRequest=...                                             |
  |------------------------------------------->|                              |
  |  <- 200 credential page: sFT (flow token), sCtx, canary,                   |
  |     urlPost "/<tenant>/login"; cookies esctx/fpc/stsservicecookie/...      |
  |                                                                           |
  |  4. POST credentials to urlPost (headless; prior-art field names)          |
  |  5. MFA leg: SAS/ProcessAuth — TOTP submit, or number-match digit          |
  |     display + approval poll, or push poll                                  |
  |                                                                           |
  |  6. Azure POSTs SAML response -> cloud-auth ACS                            |
  |  <- relay form: POST Token_B (RS256 JWT, Result:true) to                   |
  |     https://PORTAL_HOST:443/SAML20/SP/ACS                          |
  |                                                                           |
  |  7. POST Token_B -> portal ACS                                             |
  |  <- page carrying globalprotectcallback:cas-as=1&un=...&token=<JWT>        |
  |  8. parse_globalprotect_callback -> SamlCapture -> normal connect flow     |
```

## Step details (observed)

### 1. prelogin (unauthenticated)

`POST https://PORTAL_HOST/global-protect/prelogin.esp` with opc's
standard form (`tmp`, `clientVer`, `clientos`, `os-version`, `host-id`,
`ipv6-support`, `default-browser`, `cas-support`).

Response sets `SESSID` (portal session cookie; REQUIRED for step 2) and
returns the SAML bind:

- `saml-auth-method: POST`
- `saml-request-timeout: 600` (seconds; the whole cloud-auth+IdP+ACS chain
  must fit inside this window)
- `saml-request` base64-decodes to a form:
  `POST https://CLOUD_AUTH_HOST/auth` with hidden
  fields `Token` (4345 B JWT) and `RelayState`.

The cloud-auth Token JWT is signed by `<ISSUING-CA-CN>`
(x5c chain embedded). Claims: `iat`/`exp` (**120 s TTL** — the POST to
cloud-auth must happen within two minutes of prelogin), `SID`, `TID`,
`PID`, `SN`, `PanOSversion`, `UserType`, `CB`, `post`, `ForceMFA`,
`RelayState`, `APTO`, `Opaque` (140 B opaque session blob).

### 2. cloud-auth broker

`POST https://CLOUD_AUTH_HOST/auth`
(form: `Token`, `RelayState`)

- WITHOUT the portal `SESSID` cookie: `401` + a relay form already shaped
  for the failure path (`Result: false`, `Message: "[<sid>] Failed to
  ve..."`). The cookie is what makes the broker start the SSO orchestration.
- WITH `Cookie: SESSID=...` (+ Referer/Origin of the portal):
  `302 Location: https://login.microsoftonline.com/3ff6cfa4-e715-48db-b8e1-
  0867b9f9fba3/saml2?SAMLRequest=<deflated AuthnRequest>&RelayState=...
  &SigAlg=...rsa-sha256&Signature=...`

The broker is the SAML SP for the Azure leg and the relay between it and
the portal.

### 3. Azure authorize (credential page)

`GET https://login.microsoftonline.com/<tenant>/saml2?SAMLRequest=...`
→ `200` server-rendered credential page (45 KB) carrying everything a
headless client needs:

- `sFT` — flow token for the credential POST
- `sCtx` — session context carried through the MFA leg
- `canary` — anti-CSRF canary
- `urlPost: /<tenant>/login` — where the credential POST goes
- Cookies: `esctx`, `esctx-<id>`, `fpc`, `stsservicecookie`,
  `x-ms-gateway-slice`, `buid`

No JS gate on the API path: the page shape is the classic
GetCredentialType/Login flow the prior art scripts.

### 4-5. Entra credential + MFA legs (pinned by the 2026-10-31 probe cycle)

`POST urlPost` with `login`/`loginfmt`/`passwd`/`ctx`/`<sFTName>`/
`canary`/`hpgrequestid`/`type=11`/`LoginOptions=3`, `Origin:
https://login.microsoftonline.com`. The response is **200 with the
full server-rendered MFA page** (no redirect): pgid=ConvergedTFA,
`urlPost=https://login.microsoftonline.com/common/SAS/ProcessAuth`,
`urlBeginAuth`/`urlEndAuth` (`/common/SAS/BeginAuth`, `/common/SAS/
EndAuth`), `arrUserProofs`, and ROTATED `sFT`/`sCtx`/`canary`/
`apiCanary`. The next page must be processed from the POST response
itself: re-GETting the login urlPost hits a POST-only endpoint and
yields the AADSTS900561 ConvergedError page.

SAS legs (JSON, `canary` HEADER = apiCanary, `Content-Type:
application/json`, browser Referer/Origin):

- `BeginAuth` `{AuthMethodId, Method, Ctx, FlowToken}` → `Success`,
  `Entropy` (the number-match digit; 0/absent = plain push),
  `SessionId`, and ROTATED `Ctx`/`FlowToken`.
- Push: poll `EndAuth` `{..., SessionId}` every 3 s until
  `Success`/terminal. Every poll returns `Retry:true,
  ErrCode:0, "AuthenticationPending"` while pending. The **Success
  response rotates Ctx/FlowToken again** — the closing ProcessAuth
  must use the rotated pair. Using the pre-rotation values returns a
  FRESH ConvergedTFA page (a second challenge → a second push), and
  the duplicate challenge then denies approvals with
  `ErrCode 399275 / ResultValue 55`.
- TOTP: one `EndAuth` with `AdditionalAuthData=<6-digit code>`.
  A wrong code returns `OathCodeIncorrect` and can be retried
  in-session (up to 3); a slow single submit (~2.5 min) dies with
  `InvalidSession` / `AADSTS50089 flow token expired` — push polls
  keep the session alive, single submits do not.
- `BeginAuth` with a challenge still pending server-side returns
  `ErrCode 500121 UserAuthFailedDuplicateRequest` (not pollable from
  a new session; wait for expiry).
- Closing `POST /common/SAS/ProcessAuth` form: `request` (ctx),
  `mfaAuthMethod`, `login`, `flowToken`, `canary`, `hpgrequestid`,
  `type=22`, `rememberMFA=true` → the completion page.

### 6-7. The SAML relay tail (pinned)

The closing ProcessAuth response (no `$Config`) is the IdP's
auto-submit form: `SAMLResponse` + `RelayState` → POST to the
cloud-auth SP ACS. Its response is a SECOND auto-submit form —
`Token` (RS256 JWT, `Result:true`, ~60 s TTL) + `RelayState` +
`Username` → POST to `https://PORTAL_HOST:443/SAML20/SP/ACS`. That
response carries `globalprotectcallback:cas-as=1&amp;un=...&amp;
token=<JWT>` (HTML-escaped ampersands: unescape before parsing).

**Session identity binding (the HTTP 512)**: the portal binds the
issued callback token to the client identity the chain's PRELOGIN
declared. A getconfig.esp whose declared identity (clientVer/
clientos/host-id) differs from the chain prelogin's is rejected with
`HTTP 512`, empty body, no `X-Private-Pan-Sslvpn` header. Verified
by A/B: identical fast TOTP runs, only the prelogin identity
reverted → 512; identity-consistent → 200 + tunnel. The headless
provider therefore prelogins with the caller's real
`gp_params.to_prelogin_params()`.

## Fragility + fallback contract

- The cloud-auth Token's 120 s TTL: prelogin and the broker POST must run
  back-to-back in the headless provider.
- The Entra login flow changes shape periodically (field names, JS
  checks); the provider must detect each step's expected marker and fall
  back to `--auth-mode webview` (hidden window) on any mismatch.
- Failed Entra logins count toward lockout policy: the provider must not
  retry blindly.
- Conditional access can require additional factors at any time; the MFA
  classifier must degrade to "unknown factor → open the webview" rather
  than guessing.
- The prelogin identity must match the downstream client identity
  (the 512 binding above); never prelogin with placeholder values.
- Approving a STALE push on the phone (from an earlier aborted run)
  denies the live challenge (ResultValue 55): the operator should
  clear old Authenticator requests before retrying.

## Live-probe results (2026-10-31, operator participated)

1. Steps 4-5 field names/responses: pinned above (password entered
   locally, output redacted).
2. The relay tail reaches the callback page from a raw HTTP client:
   confirmed end-to-end (both relay forms POSTed by the client).
3. Factors for the test account: `PhoneAppNotification` (default,
   number matching enabled) and `PhoneAppOTP`. BOTH validated
   end-to-end through the production binary: TOTP (terminal code
   entry) and push (number-match approval), each reaching
   `state: connected` with a single challenge per run.
