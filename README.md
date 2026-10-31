# SEDRA — data security and governed AI access

**Team CyberChain · Digital Challenge Azerbaijan 2026 · Topic 6 · private development review.**

Start with the [reviewer guide](docs/REVIEWER_GUIDE.md), [requirements mapping](docs/REQUIREMENTS_TRACEABILITY.md), [technical report](docs/TECHNICAL_REPORT.md) and [actual 208-test result](artifacts/test_summary.json). [AI assistance](AI_ASSISTANCE.md) and [external components](THIRD_PARTY_NOTICES.md) are disclosed. Source/test evidence describes the current 0.11.1 build; presentation/Q&A files are excluded from this repository at the team request. This review checkpoint does not assert final organizer acceptance.

SEDRA connects past-only user-day UEBA and observed live application signals to a real transfer decision, then verifies what an independent local receiver obtained. The offline hackathon lab uses fictional identities/documents. The AI portal sends only allowed requests to a real local Qwen CPU model or, when selected and available, the OpenAI Responses API. Local model inference has executed successfully; the OpenAI account returned 429 and has no successful reply claim.

## SEDRA 0.11: Browser Guard pilot

A reviewed Chrome/Edge MV3 extension checks supported paste, typed-draft, send and file events on explicit Gemini/ChatGPT/Claude origins. It calls the bound `browser:inspect` API and creates masked security alerts. Bounded text/DOCX/XLSX inspection fails closed on unknown formats; allowed browser releases remain conservatively delivery-unknown. An isolated local lab provides independent receipts. See [setup, signed managed deployment and coverage limits](docs/BROWSER_GUARD.md). Chrome Gemini and ChatGPT composers have been tested with synthetic FİN via paste, typed Send and TXT upload. Edge testing was deferred by the user after an organization installation-policy block. Claude requires login; neither is claimed live-validated. The observed Gemini upload-control false positive was fixed in 0.11.1 and regression-tested.

## SEDRA 0.10: SSO and scoped SOAR integration

Open **Identity & integrations** (`/integrations`) to issue expiring/revocable machine keys. Versioned bearer APIs expose UEBA/case changes and revision-checked SOAR actions. Bound external document-access reports now feed actual UEBA windows with explicit external provenance and source deduplication. Optional OIDC Authorization Code + PKCE/RS256 disables demo identity switching and fails closed when configured. See [configuration, scopes, examples and real local protocol tests](docs/INTEGRATIONS.md). No company IdP or external SOAR tenant has been connected; real HTTP protocol flows were tested locally.

## SEDRA 0.9: consistent naming and review delivery

The Python package is `sedra`, all launchers use SEDRA and presentation materials are excluded. See [branding and historical-evidence migration](docs/BRANDING_MIGRATION.md).

## Evidence-bound behavior casework (introduced in 0.8)

Open **Analyst → UEBA → Behavior casework** for durable observed-sequence findings, a typed source graph, peak/current priority and revisioned analyst review. Cases open independently of DLP blocks and retain evidence after live windows cool. **Why this decision?** compares the original admission with selected recorded behavioral components excluded, using the original labels, destination and cumulative exposure. It never resends, unblocks or changes policy; hard FİN/restricted-content rules remain. Process/file correlation now requires eight distinct files in the same owned test run, preventing repeated-write and unrelated-process inflation. Full regression: **184 tests passed**. See [contracts, live proof and limits](docs/BEHAVIOR_CASES.md).

## Opt-in local Windows telemetry (introduced in 0.7)

Choose **Analyst → UEBA → Local endpoint evidence → Run real process / file test**. The sensor reads the current identity's available Windows session logs, polls attached USB/removable metadata and observes one owned test process plus named lab-file metadata. Its actual process/file test has changed endpoint priority 0 → 90; a separate real Windows HTTP smoke changed the same quote ALLOW → BLOCK at 20% → 10%, with a frozen context and alert. No USB device was available for physical testing, and Security log access remains unavailable; accessible session records are shown with their original timestamps. See [local scope, privacy, controls and reproducible proof](docs/LOCAL_ENDPOINT.md).

## Explained UEBA (introduced in 0.6)

Open **UEBA** for personal/role baseline comparisons, 21 completed-day values, model freshness, six live rules, a correlated source timeline, telemetry coverage, masked export and a safe observed-sequence control. The live engine uses real app reads and durable gateway request metadata, with 2-minute and 30-minute windows. Repeated request/audit copies cannot inflate blocked attempts; future observations are excluded. Live personal baselines require sufficient actual earlier app history. The dated synthetic IF remains separate and expires from policy use after 72 hours. See [UEBA contract, demo and limits](docs/UEBA.md).

An isolated actual HTTP check observes the same quote change ALLOW → BLOCK at 20% → 10% after 3 protected reads followed by 2 sensitive blocked attempts, while public text still passes. These are functional controls, not enterprise detection efficacy. Scoped local Windows session/USB-presence/test-file telemetry is opt-in; general endpoint HTTP is not connected. CERT multichannel v2 remains unmeasured.

## Security alert operations (introduced in 0.5)

Choose **Analyst → Alerts** for a durable queue of prevented disclosures and delivery-acknowledgement uncertainty. New policy blocks show an in-app banner and unread bell count within the next successful two-second visible-console poll. Each alert has masked evidence, deterministic review priority, subject/route, frozen policy tags and an audited Open → In review → Resolved lifecycle. Retries do not duplicate alerts; resolution does not unblock or resend the request. Retained old events are explicitly marked as imported. See [alert behavior, scope and verification](docs/ALERTS.md). External email, Teams, OS push and SIEM notifications are not configured.

## Structured sensitive-data controls (introduced in 0.4)

Outgoing text is inspected independently of the registered document corpus. Supported FİN fields/labels, checksum-valid IBANs from 89 pinned SWIFT country formats, contextual Luhn cards, credential assignments, AWS access IDs, private PEM envelopes and bearer tokens block before delivery. JSON/CSV, selected Unicode look-alikes, supported separators and bounded Base64 are inspected without changing the outbound payload. These are format/context checks, not identity or account-existence validation.

Open **Data Inventory → Sensitive data controls** for the actual rule catalog and live synthetic examples. The AI Workspace includes **FİN · JSON** and **IBAN · grouped** controls. See [structured-data scope and reproducible verification](docs/STRUCTURED_DATA_CONTROLS.md).

## Operations and governed labels

Open **http://127.0.0.1:8765/#inventory** for the new asset inventory and **/portal** for the AI Workspace. Select **Analyst → Data Inventory → an asset** to manage its data owner, business tags and governed sensitivity. A controlled document can be raised to Restricted; recognized protected matches then block on new admissions, on both the receiver and AI routes. Existing requests retain the label revision used at admission.

Metadata includes original SHA-256, UTF-8 size, media type, content version, label revision/source, structured detector types and handling. Labels and their audit history survive activity reset. Sensitivity floors cannot be weakened; public exclusions cannot be reclassified through this interface. Business tags describe context and do not independently change policy. See [SEDRA governance](docs/SEDRA_GOVERNANCE.md).

The Python package, examples, environment variables and local model alias use SEDRA. Historical evidence metadata normalization and original-hash provenance are documented in [BRANDING_MIGRATION.md](docs/BRANDING_MIGRATION.md).

## Start in Windows

Use **Python 3.12**, which supplies the pinned Unicode 15.0 database. Other versions fail with a clear message. Run `Setup-SEDRA.cmd` once if needed, then `Start-SEDRA.cmd`. Open **http://127.0.0.1:8765/** and keep the launcher window open.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements.txt
.\.venv\Scripts\python.exe -m sedra.app --port 8765 --data-dir data/runtime-sedra
```

After installation the original local-receiver demo runs offline. Local AI inference also works offline once its verified runtime/model supplement is installed. The optional OpenAI route needs an API key, available account quota and internet. When `offline_wheels/` is included, install without internet:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-index --find-links offline_wheels -r requirements.txt
```

On Linux/macOS create a Python 3.12 venv and use `.venv/bin/python` instead. Choose another port with `--port 8766`; per-port cookies isolate simultaneous labs.

## Real local AI portal

Run **Start-SEDRA.cmd** and open **http://127.0.0.1:8765/portal**. When the model supplement is installed the launcher starts the verified CPU model and selects it for a new server. Choose **lab-001 → Public workshop question → Check with SEDRA & ask AI** to receive a newly generated answer. Then send **Restricted synthetic example** to show a block before inference. If needed select **Analyst → AI provider: Local AI → Connect for this session** first.

On another Windows PC, extract the **SEDRA-Local-AI-Model.zip** supplement over the base package, or use **Setup-Local-AI.cmd** with internet once. See [LOCAL_AI.md](docs/LOCAL_AI.md). The original offline receiver and its independent receipts remain separate.

## Optional OpenAI portal route

Open **http://127.0.0.1:8765/portal**. Select Analyst, choose **OpenAI API**, privately enter an OpenAI API key, connect, then choose lab-001. Send the public example to receive an AI answer through SEDRA; send the restricted fictional example to verify a block before provider contact. Keys stay in server memory and are not packaged. Read [AI_PORTAL.md](docs/AI_PORTAL.md) for usage limits, errors, privacy and the distinction between provider evidence and independent receiver receipts. A configured key is not proof of a successful provider call; inspect the live smoke artifact.

## Three screens and a two-minute demonstration

**Overview** shows actual transfer counters and separate lab/CERT v1/CERT v2 sources. **Investigation** shows dated model context, the separate live rule, features and source events. **AI Transfer Lab** contains editable judge examples, policy evidence, exposure ratios, transitions and receiver receipts.

Choose **Analyst → Reset demo → lab-001 → AI Transfer Lab → Run fragment sequence**. Two excerpts reach the receiver; the third blocks. Two independent receipts retain the original SHA-256 and UTF-8 byte counts.

Load **Same-text context comparison** and send: ALLOW. Click **Replay 6 document accesses**, then send the same text: BLOCK. That button executes actual document endpoint requests. The resulting two-minute live rule is separate from the dated completed-day Isolation Forest. Load the **Two-word restricted excerpt** to demonstrate a hard block.

For acknowledgement loss, send public text with the checkbox selected, inspect DELIVERY_UNKNOWN and the receiver receipt, then reconcile. Reconciliation never sends again.

The simulated local identities are Analyst, lab-001 and lab-002. The server derives the actor and context. Employee views are scoped; Analyst can inspect masked metadata and reset. This selector is not enterprise SSO. Loopback Origin checks, CSRF, server-side scopes and receiver authorization remain enforced.

See [demo guide](docs/DEMO_GUIDE.md), [reviewer guide](docs/REVIEWER_GUIDE.md) and [architecture](docs/TECHNICAL_ARCHITECTURE.md).

## Evidence and honest claims

`artifacts/test_summary.json` records the current executed tests; `test_output.txt` lists individual checks. `live_smoke.json` contains actual loopback HTTP outcomes/receipts. `audit_before.json` retains reproduced review bypasses; `audit_after.json` uses the same synthetic cases after the fixes.

The original **file-only CERT v1 failed**: rules, Isolation Forest and combined each detected **0 of 476** incident-associated positive test user-days at frozen operating points. Numeric results and original model are retained; published report metadata was branding-normalized with original/current hashes recorded in the migration map.

V2 uses device/logon/HTTP/file **calendar days**, exact actor/channel/ID/time-qualified official-observable labels and explicit cold-start coverage. Its frozen protocol is `artifacts/cert_v2_protocol.json`. A measured report appears only after verified extraction, ingestion and model execution; while pending the UI keeps it unavailable. **V2 on already-inspected r4.2 is development evidence, not independent efficacy.** CERT itself is published synthetic research data. V2 changes the population and target, preventing a direct like-for-like improvement claim over v1. Read [current status](docs/STATUS.md).

## Content and reliability

V2 keeps exact source 4-gram coverage and adds separately counted anchored short sequences/distinctive tokens. It handles supported Unicode TR39 confusables, mixed-script flags, ignorables and AZ I/İ casing. Structured rules cover synthetic markers, AWS access IDs, private PEM envelopes, contextual Luhn-valid cards, checksum-valid AZ IBANs, labeled FIN values and conservative credential assignments. Canonical UTF-8 Base64 is decoded once within strict bounds; benign encoded text is not automatically blocked.

Restricted content and structured findings are hard blocks. Controlled excerpts use separate **24-hour and 30-day** cumulative limits. SQLite reserves exposure atomically before the send claim. Idempotency binds subject, request ID, original hash and destination. Unused reservations have a 30-second TTL. Uncertain sends remain conservatively counted until trusted reconciliation.

The [matching/delivery contract](docs/MATCHING_CONTRACT.md) states exact thresholds and limitations. Coverage ratios describe textual evidence, not leaked bytes or intent.

Gateway SQLite stores hashes/evidence rather than raw prompts. Fingerprints are not anonymous. The local proof receiver retains full synthetic text until Analyst reset, with masked analyst previews. It runs on another port/thread in the same process and is not an external AI provider.

## Verify and rehearse

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe scripts/audit_bypasses.py artifacts/audit_after.json
.\.venv\Scripts\python.exe scripts/live_smoke.py --base http://127.0.0.1:8765
node --check static/app.js
```

The smoke script explicitly resets this synthetic lab. Never point it at production. Tests cover leakage discipline, labels, matching/obfuscation, benign controls, dual windows, races, retries, TTL, reconciliation, authorization and Windows cleanup.

## Reproduce CERT v2

`Resume-CERT-Research.cmd` runs the optional resumable acquisition, full integrity verification, extraction and frozen experiment. `artifacts/research_progress.json` records its actual stage. The live demo remains independent of this potentially long download. A completed run updates the UI/report and speaker script; pending intake never becomes a measured result.


The approximately 4.8 GB archive and raw data are excluded from the source package. Obtain the [official CERT dataset](https://doi.org/10.1184/R1/12841247.v1), then run:

```powershell
.\.venv\Scripts\python.exe scripts/download_cert.py --destination data/cert
.\.venv\Scripts\python.exe scripts/extract_multichannel.py data/cert
.\.venv\Scripts\python.exe scripts/cert_multichannel.py
```

The optional `download_cert_parallel.py` resumes a stopped `.part` intake using verified ranges and final official SHA-256. Never run two writers simultaneously. Extraction rejects overwrites, checks member length/hash, and publishes its completed manifest last. Never visit URLs found inside dataset content.

V2 uses contemporaneous LDAP roster members and complete common source-file days, retaining unspecified dataset-local time. Primary labels require channel + original ID + declared actor + exact timestamp. Contextual master-interval labels are secondary. All overlapping incidents remain in coverage, including no-signal cases. Personal-only rules, peer rules, IF and a frozen combination share the same observations. Labels enter evaluation only. A full raw-channel duplicate-ID scan is a disclosed limitation; official source rows are preserved.

V1 reproduction remains in [historical README](docs/history/README_v1.md) and [v1 protocol](docs/BENCHMARK_PROTOCOL.md).

## Private repository and submission

Current source is published to [TeamCyberChain/SEDRA](https://github.com/TeamCyberChain/SEDRA) as a private review snapshot. Presentation, speaker and Q&A materials are excluded from this repository. The [submission checklist](docs/SUBMISSION_CHECKLIST.md) records the organizer-supplied timing and remaining final-submission steps. A push alone is not organizer acceptance.

## Boundaries

Only this application's requests are controlled. Enterprise SSO, endpoint-wide interception, production deployment of the opt-in provider route, semantic paraphrase/OCR, arbitrary/nested encodings, cross-identity collusion, review holds and redaction remain future work. Finite windows cannot guarantee lifetime protection. Local benign controls are regressions, not a population false-positive rate.

AI assistance and external components are disclosed in `AI_ASSISTANCE.md` and `THIRD_PARTY_NOTICES.md`.
