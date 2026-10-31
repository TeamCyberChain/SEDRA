# SSO and SOAR integration — SEDRA 0.10

Open `/integrations` as Analyst to issue a named, scoped key with 1–2160 hour expiry and optional bound telemetry subjects. Copy the secret once into a connector secret store. Only its SHA-256 digest is persisted; listing does not return the secret. Revocation affects subsequent authentication immediately. Existing in-flight operations may complete. Keys and rate usage survive activity reset; reported activity is cleared. The local identity selector is still a demonstration convenience unless SSO is enabled.

## Versioned machine API

All `/api/v1/` requests require `Authorization: Bearer <key>`. Browser cookies cannot substitute for a key. The listener remains loopback-only; run a connector on this machine or supply a separately reviewed TLS/authenticated deployment front end. No remote network exposure, firewall change, production tenant or external SOAR was configured here.

| Operation | Required scope | Contract |
| --- | --- | --- |
| GET `/api/v1/alerts?before=...` | alerts:read | Latest bounded alert summaries; use returned older cursor as supported by alert feed |
| POST `/api/v1/alerts/action` | alerts:write | Existing READ/ACKNOWLEDGE/RESOLVE/REOPEN schema, revision and action ID |
| GET `/api/v1/cases` | cases:read | Latest 100 cases with exact counts and truncation flag |
| GET `/api/v1/cases/changes?after=0` | cases:read | Durable ordered history projection; no prompt body or private Windows record payload |
| GET `/api/v1/ueba?subject=lab-001` | ueba:read | Detailed subject context, including scoped endpoint evidence; treat this scope as privileged |
| POST `/api/v1/cases/action` | cases:write | ACKNOWLEDGE/RESOLVE/REOPEN; expected_revision and globally unique action_id required |
| POST `/api/v1/telemetry` | telemetry:write | Batch of 1–100 registered-document access reports for explicitly bound subjects |

120 requests/minute/key. Expired/invalid/revoked key: 401; missing scope/subject permission: 403; stale revision/generation or changed source facts: 409; quota: 429. API case/alert actions retain the key ID as actor. Resolving findings cannot resend/unblock data or change the behavior score. Read scopes grant realm-wide laboratory visibility, not tenant isolation. No automatic outbound webhook or arbitrary target URL is accepted.

A SOAR consumer requests changes with `after=0`, saves the returned `generation` and `next_cursor` **after** durable processing, then sends both on subsequent requests. Retry the same cursor after failure; consumption is at least once and the consumer deduplicates by generation/cursor or case/revision. A reset changes generation; on 409 restart from after=0. No external broker or cross-database transactional outbox is claimed.

Telemetry payload:

```json
{"events":[{"event_id":"collector-a:unique-source-event-uuid","subject_id":"lab-001","occurred_at":1793462400,"kind":"protected_document_access","doc_id":"araz-plan"}]}
```

Replace occurred_at with actual UTC epoch seconds in the preceding 30 minutes. Unknown fields, client scores, unknown document IDs, future/old times and unbound subjects are rejected. IDs must be globally unique per subject, including across collectors and key rotation. Identical retries deduplicate; changed facts conflict and the entire batch rolls back. The source is **AUTHENTICATED_EXTERNAL_REPORT**: a trusted key holder's report, not independent OS proof. Accepted reports feed the declared UEBA windows and can open a case/tighten policy; no incoming score is trusted. A compromised collector can still submit false reports within its assigned scope. Collector attestation and enterprise directory mapping remain future work.

## Configure real OIDC SSO

Install optional pinned dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements-sso.txt
```

Keep the configuration in ignored `data/oidc/config.json`; supply its path via `SEDRA_OIDC_CONFIG` before starting `python -m sedra.app`. Do not commit a client secret. Required fields:

```json
{
  "issuer":"https://your-issuer.example/realm",
  "client_id":"sedra",
  "client_secret":"CONFIGURE_PRIVATELY",
  "authorization_endpoint":"https://your-issuer.example/realm/authorize",
  "token_endpoint":"https://your-issuer.example/realm/token",
  "jwks_uri":"https://your-issuer.example/realm/keys",
  "redirect_uri":"http://127.0.0.1:8765/auth/callback",
  "identities":{"provider-subject-id":"analyst","another-provider-subject":"lab-001"}
}
```

Use actual provider endpoints and register the exact callback. This implementation supports Authorization Code + S256 PKCE, confidential client HTTP Basic authentication and RS256 ID tokens with RSA keys of at least 2048 bits. Endpoints are pinned server-side, same issuer origin, HTTPS, with redirects refused. Issuer/audience/signature/expiry/issued-at/nonce/authorized-party are validated, and state is one-time, browser-bound and expires after five minutes. Unknown provider subjects are denied; role claims/emails cannot self-assign access. No discovery/SAML/provider-specific logout or dynamic group provisioning is claimed. Explicit subject mapping currently targets the lab roles and actors; a company directory/model enrollment process is still needed.

With SSO enabled, unauthenticated APIs fail closed, demo identity switching is disabled, a successful callback rotates the session, and local session lifetime cannot exceed the ID token expiry or eight hours. POST `/api/logout` ends the local session; it does not end the provider session. SameSite=Lax is necessary for the OIDC callback, while mutating browser routes retain Origin/CSRF checks. Invalid/missing config or optional dependencies fail startup rather than falling back to demo admin. The UI has an SSO sign-in link and a separate integration administration page.

The local HTTP issuer used in tests is constructor-injected only and is never enabled by an environment flag. It generates a temporary RSA key, performs real loopback authorization/code/token/JWKS requests and checks PKCE. These tests establish protocol behavior, not a live connection to Entra/Okta/Keycloak or an enterprise deployment. No company IdP credentials or tenant were provided.

## Verification

`tests/test_integrations.py` exercises actual HTTP bearer authentication, 401/403/409 boundaries, key hashing/revocation/expiry/persistence/rate limits, subject/time/schema checks, atomic ingestion, deduplication across key rotation, live UEBA response/case creation, cursor generations, attributed/idempotent SOAR actions and a real loopback RSA-signed OIDC code flow plus adversarial claims and local logout. Install optional requirements before running the full suite; GitHub CI installs them explicitly. The core offline package still uses the five original scientific wheels; optional SSO dependencies/provider connectivity require separate setup.

Machine-readable contract: [OpenAPI 3.1](../static/openapi.json), served at `/openapi.json`. `scripts/soar_poll.py` demonstrates one pull using `SEDRA_API_KEY` from the process environment and an ignored local checkpoint. Replace its stdout handler with your downstream durable/idempotent integration before using its checkpoint in a real SOAR.
