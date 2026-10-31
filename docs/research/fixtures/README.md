# Fixtures

Structural captures from a production Prisma Access + Entra connect flow
(2026-10-31, identifiers and session artifacts anonymized). These back the
unit tests of the headless auth provider:

- `prelogin.xml` / `prelogin2.xml` — portal prelogin.esp response shape
  (saml-auth-method=POST, saml-request-timeout, base64 form placeholder)
- `launch_form.html` / `launch_form2.html` — the decoded auto-submit form
  (cloud-auth broker action + Token/RelayState field names; token value
  redacted)
- `cloudauth.txt` / `ca3.txt` / `cloudauth2.txt` / `jar_cloud.txt` — broker
  response header shapes (SESSID-dependent 302 vs 401 relay-form)
- `step1_url.txt` / `hop1_urlpost.txt` — prelogin URL + POST body shapes
- `gct_body.json` / `gct_resp.json` — GetCredentialType request/response
  shapes (arrUserProofs / SasParams / HasPassword classification inputs;
  flow tokens and canaries redacted)

The hop2 login-page HTML from the original capture carried live session
artifacts (esctx, embedded sFT) and is intentionally NOT committed; tests
synthesize page shapes from these structural fixtures instead.
