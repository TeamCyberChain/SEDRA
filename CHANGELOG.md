## 0.17.0 — Focused UEBA, mandatory MFA and reporting

- Split UEBA into seven directly accessible sidebar subsections, with collapsed graphs and bounded timelines.
- Require TOTP or one-use recovery verification for every local account; seal seeds using a DPAPI-protected key on Windows, rotate sessions and reject atomic replay/stale account versions. Require MFA evidence from OIDC assertions.
- Add four operational/executive dashboards; exclude synthetic daily scores from live high-priority counts and preserve unresolved delivery states.
- Generate retained, authorized Executive, Security and Activity report snapshots with local PDF/CSV/JSON exports, integrity digests and metadata audit events.
- Fix a browser-observed session rotation race: late unauthorized polls cannot overwrite completed sign-in cookies.

## 0.16.0 — Scoped Users and application UEBA v3

- Hide privileged navigation and omit population evaluation/alternate identities from subject-scoped User state; independently verify API denials and actor isolation.
- Deduplicate repeated document source IDs and add a conservative rolling 24-hour distributed sensitive-attempt rule with count, time-span and active-bin gates.
- Preserve older active rule references and detailed gateway hashes independently of recent public activity; aggregate case episodes using the active rule window.
- Correct nested dark-mode surfaces in casework, UEBA, inventory and transfer panels; label frozen capture narrative separately from live priority.
- Preserve original CERT measurements and state the new rule's engineering thresholds and independent evaluation limits.

## 0.15.0 — Sidebar settings and account operations

- Extend Settings from its sidebar trigger, keep the workspace visible, and split Users into User Creation, User Management and Roles.
- Replace blue dark-mode surfaces with shared graphite and teal styling; add directory search and clearer account status/actions.
- Add Administrator-controlled account permission delegation on custom Analyst roles; enforce privileges and target restrictions independently on the server.
- Add password resets with metadata-only audit records and durable revocation of all prior sessions. Disable/re-enable no longer restores old sessions.
- Preserve existing accounts through additive migration; verify legacy passwords, CSRF, reset redaction, role immutability and delegated escalation denial with isolated HTTP tests.

## 0.14.0 — Settings and persisted account RBAC

- Replace the lower-left service label with a same-page Settings modal; move Audit Logs and theme choices inside it on all web surfaces.
- Add Profile/account and Administrator-only Manage users with separate account and role creation tabs.
- Add local password-hashed accounts, atomic first-admin setup, login throttling, session rotation/revalidation and persistent fixed-profile custom roles.
- Enforce subject-scoped Users, administrative account management, immediate session revocation and last-active-administrator protection on the server.
- Preserve existing optional OIDC as a separate mode; no embedded default credential, MFA or per-action role editor claim.

## 0.13.0 — Dark mode and persistent platform audit

- Add shared light/dark preferences across console, AI Workspace and browser validation surfaces, including cross-tab updates.
- Add Analyst-only Audit Logs with source/event filtering, keyset pagination, metadata inspection and loaded-record export.
- Persist API/HTTP status, server-derived actors, request IDs, bounded UI reports and existing application events separately from resettable activity.
- Exclude headers, query strings, bodies and credentials; preserve response-status versus delivery and client-report provenance distinctions.
- Add real HTTP access/redaction/reset tests, concurrent storage/pagination checks and theme preference regression coverage.

## 0.12.0 — Unified console navigation and investigation

- Add first-class Identity & integrations with scoped credential management, role-aware form states, single-display secrets and conditional SSO navigation.
- Open alert investigations at dedicated new-tab deep links; retain queue context, masked evidence, authorization and revision-based review.
- Apply a shared neutral console theme to operations and AI Workspace, balanced refresh icon, readable evidence contrast and responsive navigation.
- Present user-friendly workspace terminology and identity aliases without changing original source text, payloads, API bindings or exported evidence.
- Validate real browser flows, key create/revoke and secret clearing on role change, desktop/mobile overflow, plus 210 Python and ten Node tests.
- Pin the API budget test clock and explicitly verify minute rollover after CI exposed a wall-clock boundary race; production rate limits remain unchanged.

## 0.11.1 — Browser Guard and observed Gemini control correction

- Add a scoped MV3 Chrome/Edge guard, bound browser inspection API, masked alert context, conservative one-use release accounting and bounded offline metadata reports.
- Inspect bounded UTF text and DOCX/XLSX; reject unsupported, encrypted, embedded-binary and resource-exceeding input without claiming successful content inspection.
- Add a synthetic local composer and independent receipt ledger, exact-origin authorization and a seven-file CRX3 signing pipeline for explicitly authorized managed deployment.
- Correct the live-reproduced Gemini Upload & tools false positive: a default submit type counts only when a button belongs to a form. Preserve explicit Send selectors/labels and add a regression.
- Record 208 Python and six Node tests passing. Local Chrome negative/public controls and live Gemini synthetic paste/send/file checks were executed; no universal network or external-delivery attestation is claimed.

# SEDRA development record

This records implemented work; executed evidence and its dates remain in the linked artifacts. Historical packages and original failed CERT v1 artifacts are preserved.

## 0.10.2 — 31 October 2026

- Preserve bounded app-rule source metadata independently of the recent 60-row display timeline, preventing newer public activity from suppressing evidence-bound case creation.
- Show referenced records outside the recent timeline in the investigation screen; retain provenance and metadata-only limits.
- Preserve the reproduced 6-protected/61-public failure and repaired real loopback HTTP evidence.

## 0.10.1 — 31 October 2026

- Refresh finite case priorities on headless case/change-feed reads; preserve peak evidence and review status, emit one durable expiry revision and report refresh status.
- Retain the reproduced stale-score finding and real Windows endpoint-to-API demonstration, including cursor replay/checkpoint and key revocation evidence.

## 0.10.0 — 31 October 2026

- Add optional pinned OIDC Code + PKCE, strict RS256/JWKS validation, explicit subject binding, session rotation/expiry/logout and fail-closed SSO mode.
- Add scoped, expiring, hashed machine keys; revocation/rate limits and attributed SOAR case/alert actions.
- Add generation-aware durable case change consumption and atomic authenticated external access-report ingestion with actor binding/deduplication across key rotation.
- Expose a separate integration administration page and explicit protocol/deployment limits. No live company IdP or external SOAR connection is claimed.

## 0.9.0 — 31 October 2026

- Rename the actual Python package/import path to `sedra`, update launchers, headers, cookie, environment names, download names and local model alias.
- Version the renamed synthetic corpus as 3; keep historical private runtime admissions separate from new activity.
- Exclude presentation/PPTX, speaker/Q&A assets, superseded embedded ZIP and older screenshots from the current repository and packages.
- Record historical metadata normalization with original/current hashes; preserve original numeric measurements and private original artifacts.

## 0.8.0 — 31 October 2026

- Independent durable UEBA cases from observed rules, bounded typed evidence graph, peak/current priority, strongest-evidence retention and revisioned analyst review.
- Read-only rule ablation over frozen admission facts; no resend, unblock, reservation or policy mutation. Hard sensitive-data policy remains.
- Distinct-file and exact-run process correlation; dead/old process attribution and duplicate source-sequence churn repaired. Sensor freshness and stop control.
- Full local regression: 184 tests passed. Separate real Windows loopback smoke and browser review/export checks passed. No enterprise efficacy claim.
- Private GitHub review preparation: reviewer guide, requirement mapping, technical report, repository boundary check and a pinned Windows verification workflow. Remote CI has its own run status and is not claimed to have passed before execution.

## 0.7.0

Opt-in scoped Windows session/removable-presence/owned-process/test-file telemetry and actual same-quote policy effect. Physical USB unavailable; Security log inaccessible; accessible session records retain original times.

## 0.6.0

Explained live application UEBA, supported personal history gate, separate dated synthetic daily model, freshness controls, trend, rule references and observed activity validation.

## 0.5.0

Durable gateway security alerts, unread queue, masked investigation, revisioned review and idempotent actions.

## 0.4.0

Structured credential/PII controls, pinned IBAN structures, contextual/checksum validation, supported Unicode/separator/Base64 views and live example catalog.

## 0.3.0 and earlier SEDRA builds

SEDRA branding and governed metadata/sensitivity labels; real local AI portal; cumulative registered-content controls, atomic send/reservation lifecycle and receipt reconciliation. Original file-only CERT v1 retained 0 TP / 476 positive test user-days. CERT multichannel v2 remains unmeasured.
