# SEDRA 0.10 current status

Recorded 31 October 2026. Current values come from executed artifacts.

## Scoped integration and identity

OIDC Code + PKCE/RS256 and explicit issuer-subject bindings are implemented as an optional server-configured mode. A real loopback RSA-signed issuer test validates the protocol; no company tenant is connected. SSO disables demo switching and unauthenticated API access. Expiring/hashed/revocable machine keys enable bounded SOAR reads, generation-aware case changes, attributed revision/idempotency actions and atomic bound-subject document-access telemetry. External reports retain their provenance and can change UEBA/case behavior. See INTEGRATIONS.md and the current test summary for executed verification. Optional requirements-sso.txt is installed by CI; core offline wheels remain separate.

The 0.10 suite has 192 executed tests with zero failures/errors/skips; the exact current execution is artifacts/test_summary.json. An additional live Windows endpoint-to-API test observed 0 → 90, an automatic independent case and a bearer-authenticated OPENED event with 11 process/file source references. Retry/checkpoint behavior and 401/403/revocation checks passed. The demo key was revoked and no secret/raw Windows packet is published. See docs/API_LIVE_DEMO.md and artifacts/api_endpoint_main_smoke_v1.json. This is controlled functional proof without an external SOAR, not enterprise efficacy.

## Current naming and publication scope

All active package/import paths, launchers, examples, environment variables and model alias use SEDRA. Start with `python -m sedra.app`; the synthetic corpus is version 3. Presentation/PPTX, speaker/Q&A files, old screenshots and the superseded embedded source ZIP are excluded from the current GitHub tree and packages. Existing Git history remains historical.

Historical report metadata was branding-normalized with original/current hashes recorded in artifacts/branding_migration.json. Original byte copies and the pre-migration Git bundle remain private locally. Original numeric CERT measurements and trained model are preserved; published metadata reports are no longer claimed byte-identical to their originals. See docs/BRANDING_MIGRATION.md. New regression/live proof is executed separately under the current package.

## SEDRA 0.8 behavior casework

Observed high-priority sequences now open durable Analyst cases independently of DLP blocks. Cases retain the strongest source graph, peak/current priority, baseline/sensor support and revisioned review actions after live activity cools. Typed relationships explicitly distinguish same controlled run, source match and temporal context. The private packet has a consistency-checked SHA-256 history; this is not independent attestation. Frozen-policy comparisons exclude only recorded behavioral components, retain original admission facts and hard content prohibitions, and never resend/unblock/change policy.

The actual isolated Windows HTTP smoke passed independent case creation before a block, same-quote ALLOW -> BLOCK at 20% -> 10%, BLOCK -> hypothetical ALLOW without resend, hard FİN still BLOCK, retained quiet case, Analyst workflow, 403/409 checks and bound consistent history. Main application quote/FİN comparisons also passed. See artifacts/behavior_cases_http_smoke_v1.json, behavior_cases_main_summary_v1.json and docs/BEHAVIOR_CASES.md. Reproduced prior false process/file correlation is retained in artifacts/ueba_cases_before_v1.json; repairs require distinct files and exact owned run and reject dead/old PID evidence. Partial sequence expiry preserves the peak graph.

The 0.8 suite passed 184 tests, zero failures/errors/skips, including 21 new behavior-case, endpoint-quality and frozen-policy tests. The current execution is in artifacts/test_summary.json; earlier version sections record their own executed totals. Presentation/Q&A remain deferred. Scope is the authorized local test environment; no enterprise efficacy claim is made. Physical USB remains untested, Security log access unavailable, enterprise rollout/collection/retention open, and CERT multichannel v2 unmeasured. Original CERT v1 remains 0 TP / 476 positives; the later branding migration and hash record are described above.

## Prior 0.7 local endpoint integration

The full regression suite passed **163 tests, 0 failures/errors**, including 11 new endpoint tests. Actual main-browser Windows observations include ten scoped file changes, one CIM-confirmed owned process and the session snapshot; endpoint score changed 0 → 90. Ten genuine earlier current-identity session records were retained with their original times. An independent real Windows HTTP smoke observed same-payload ALLOW → BLOCK at 20% → 10%, frozen endpoint context, alert creation, a public negative control still allowed and two receiver receipts. See artifacts/endpoint_http_smoke_v1.json and endpoint_main_summary_v1.json. Private Windows source records are excluded from source archives.

USB/removable presence polling is implemented, but the user has no USB device, so physical arrival/removal was not tested. Security log access is unavailable; the permitted session channel works. No OS audit/security policy was changed. File scope is the named endpoint-lab folder; process scope is the exact owned test child; identity mapping is explicitly local-test lab-001. This is scoped telemetry, not endpoint-wide enterprise EDR. Read docs/LOCAL_ENDPOINT.md.

## SEDRA 0.6 explained UEBA

The 0.6 full suite passed **152 tests, 0 failures/errors**, including 19 new UEBA tests. The separate real HTTP smoke recorded the same original quote changing ALLOW → BLOCK at 20% → 10% after 3 protected reads followed by 2 sensitive blocked requests. Public text remained allowed, the original request replay retained its frozen context, the local-AI route blocked before inference, another employee's UEBA evidence returned 403 and the live priority decayed outside the window. See artifacts/ueba_http_smoke_v2.json. This is functional evidence, not population efficacy.

The UEBA screen now shows personal/peer daily comparisons with support, completed-day trend and exact values, 30-minute observed activity, six explained live rules, source-ID timeline, model freshness, telemetry coverage, masked subject export, controlled synthetic validation and existing synthetic detector/actor/alert-load evaluation. Current app personal baselines require at least 14 earlier active bins across 7 days; insufficient history is explicit. Dated daily IF and live rules remain separate. Stale/future/unsupported daily scores are excluded from current policy. Observed inputs are bounded per actor, with an explicitly separate quality guard at saturation.

Reproduced earlier weaknesses are preserved in artifacts/ueba_before_v1.json: future-dated reads counted, duplicate unbacked block audit messages counted and stale daily score still applied. Tests verify their correction, ordered correlation, non-additive scores, cold start, label independence, large reversed sequences and bounded evidence. The main browser's observed-sequence control has also executed: daily component 0, live component 85, controlled 4-gram budget 10%. Policy-block Alerts retain their original UEBA context; live findings are not separate security-alert rows. Those endpoint channels were not connected in 0.6; 0.7 adds the scoped opt-in Windows sensor. General HTTP remains unconnected. See docs/UEBA.md for precise contracts and limits.

## SEDRA 0.5 alert operations

The full suite passed **133 tests, 0 failures/errors**, including 15 new alert tests. Admission/alert atomicity, request retry deduplication, stale-send uncertainty, restart/backfill persistence, analyst-action idempotency and concurrent revision conflicts are covered. The separate actual HTTP smoke passed block/portal prevention, masked evidence, employee 403, missing CSRF 403, stale revision 409, acknowledgement/resolution and receipt reconciliation without resend. See artifacts/alerts_http_smoke_v1.json and docs/ALERTS.md.

The console now has an Analyst-only alert queue, unread bell, persistent new-event banner, filters, loaded-result export and masked investigation with workflow history. Polling is every two seconds while the tab is visible. Retained gateway events migrate with an imported-event marker and original timestamp. Block prevention and unconfirmed delivery remain distinct. Analyst resolution does not change enforcement or automatically establish compromise. External notification integrations and enterprise identity/retention remain open.

## SEDRA 0.4 structured controls

Outgoing structured-data inspection is independent of the registered corpus. The profile supports contextual FİN, AZ/international IBAN, contextual Luhn cards, credential assignments, AWS IDs, private PEM, authorization bearer and synthetic markers. The local SWIFT registry snapshot has 89 country structures from release 103 (September 2026); exact lengths, structures and MOD97 are checked without any bank/identity lookup.

Executed regression: 7/43 expected types detected by the frozen previous code; 43/43 by the new code. Negative controls: 1/20 flagged before, 0/20 after. This is a finite synthetic control set, not population efficacy. See artifacts/structured_regression_v3.json. The HTTP smoke independently observed 43 blocked cases, 20 forwarded negative controls with 20 independent receipts, two portal blocks before inference, and a real local model reply. See artifacts/structured_http_smoke_v3.json. The full suite passed 118 tests.

The UI exposes the actual rule catalog, validation scope, input/encoding limits and synthetic examples. Evidence masks values while retaining canonical value hashes, original payload hash/bytes, validation checks and Unicode transformation steps. New queries use the new detector profile; historical request evidence remains frozen. JSON depth overflow fails closed at 64; Base64 remains one bounded decode. Supported FİN format/context is not proof of assignment; IBAN checks do not establish account existence or ownership. The 118-test count above records the prior 0.4 run, not the current suite total.

## Prior 0.3 governance update

The SEDRA UI replaces the former marketing-style headings with an operations console, Data Inventory, metadata inspector and integrated AI Workspace. Eight tests added in 0.3 exercise governed labels. The then-current suite had 103 passing tests; current totals are reported above. `artifacts/sedra_live_smoke.json` records a real isolated HTTP run: the same body changes from ALLOW to BLOCK after a Restricted label; original request replay keeps its prior verdict without sending again; the managed local model replies 42; the restricted AI request never contacts the model; acknowledgement reconciliation does not resend.

Governed label revisions and before/after history are stored transactionally with the gateway. Labels are read in the same write transaction as admission. Business tags are descriptive, not independent policy. New admissions use current labels; old requests and reservations retain their original policy snapshot. Resetting activity preserves governed labels. The four registered synthetic source hashes and historical CERT artifacts remain unchanged.

Presentation and Q&A are deferred; existing presentation files refer to the previous build. The SEDRA 0.3 application packages are separate from earlier SEDRA deliverables.

## Historical functional build (0.8)

- 184 executed tests, 0 failures, 0 errors, 0 skips; successful=True.
- Real loopback smoke: {'attempted': 7, 'forwarded': 4, 'blocked': 3, 'unknown': 0}.
- Fresh isolated Python 3.12 environment installed from local wheels without network; its separate live smoke successful=True.
- Overview, Investigation, Transfer Lab and offline presentation navigation visually checked. Saved screenshots are under artifacts/screenshots.
- External-review synthetic bypasses: the same 11 attack cases block after repair. Benign technical boilerplate regressions now allow. This small control set is not a population false-positive estimate.

The working build includes anchored short fragments, bounded distinctive-token co-occurrence, TR39/mixed-script/AZ handling, structured credential/PII checks, cautious one-level Base64, separate 24h/30d accounting, atomic reservations, idempotency, concurrency, TTL, unknown delivery, scoped authorization and real receipt reconciliation.

Actual observed document requests and blocked attempts feed a separate 120-second live policy rule. The dated daily IF is not silently retrained. The same body has executed as ALLOW before the live signal and BLOCK afterward.

## Opt-in real AI portal

The portal supports real local Qwen CPU inference and the optional OpenAI route. Local model reply verified=True; OpenAI reply verified=False. The OpenAI account returned 429; no cloud success is claimed. See artifacts/local_ai_live_smoke.json, local_ai_http_smoke.json, ai_portal_live_smoke.json and docs/LOCAL_AI.md. External API keys stay in process memory; the local service has a generated private token file excluded from all packages. Provider evidence is an observed API response, not an independent receiver receipt. Enterprise SSO and production deployment remain open.

## Original CERT file-only v1

The failed original benchmark is retained unchanged. All three frozen detectors had 0 TP among 476 incident-associated positive test days. Rules had 0 FP, IF 120 FP and combined 100 FP. Coverage-adjusted incident recall was 0/40. These remain evidence of a failed configuration, not efficacy.

Original preserved CERT artifacts checked against the starter manifest: 5 files, unchanged=True.

The local source recheck independently recovered the complete file.csv member and matched its pinned SHA-256: 193,055,265 bytes, 445,581 events and 45,907 active copy user-days. That recheck did not rerun the old model or rejoin LDAP. The multichannel archive verification and execution state is recorded below.

## Four-channel v2 development experiment

**Not yet measured.** Research stage: downloading_official_archive; status: failed. Official archive transfer has been severely slow. No pending source intake, fixture score or test pass is presented as a CERT v2 result. The importer/model protocol and tests are implemented; full source ingestion and actual evaluation remain open.

## Deliverables and limitations

The source, tests, review documentation, architecture and setup/reset guidance are published to the private TeamCyberChain/SEDRA repository. Runtime databases, credentials, raw endpoint records, provider/model files, offline wheels and presentation assets remain local and excluded from the current GitHub tree. Presentation and Q&A work is deferred at the user's request.

The lab controls its own requests. Optional OIDC is implemented and locally protocol-tested; a real company IdP pilot, production provider deployment, endpoint-wide capture, semantic/OCR/arbitrary encoding handling and cross-identity collusion defense remain future work. Finite windows do not provide lifetime protection. Production use requires independent review and shadow-mode evaluation.
