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

### 4-5. Entra credential + MFA legs

Field-level details tracked in the prior-art research (gp-saml et al.).
Expected shape: `POST urlPost` with `loginfmt`/`passwd`/`sFT`/`canary`
→ MFA leg via `SAS/ProcessAuth`: TOTP code submit, or number-match digit
extracted from the response for CLI display + approval poll, or push
poll. To be pinned by a live probe with operator participation.

### 6-7. The SAML relay tail

When the IdP leg completes, Azure POSTs the SAML response to the
cloud-auth ACS; cloud-auth answers with the SAME relay-form shape we
observed on the failure path — a form POSTing a RS256 JWT to
`https://PORTAL_HOST:443/SAML20/SP/ACS` with claims
`InResponseTo`, `Result` (bool), `Message`, and (on success) the auth
payload. On `Result: true` the portal ACS renders the page carrying
`globalprotectcallback:cas-as=1&un=...&token=<JWT>` — the existing
`parse_globalprotect_callback` capture.

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

## What still needs a live probe (operator participation)

1. The exact field names/response of steps 4-5 against
   `<UPN-SUFFIX>` (prior art + live capture; password entered locally,
   output redacted).
2. Whether the final `Result: true` relay form POSTed to the portal ACS
   returns the callback page directly to an HTTP client (expected yes —
   the paste flow already relies on the operator's browser receiving it).
3. The MFA factor actually configured for the test account
   (TOTP vs number-match vs push).
