# Start here — SEDRA 0.9 review

This is Team CyberChain's private development snapshot for Topic 6, Digital Challenge Azerbaijan 2026. It is prepared for the seven reviewer accounts named by the team. A push is a review checkpoint, not an assertion of organizer acceptance or final submission.

## Read in order

1. [README](../README.md): setup, product paths and operating scope.
2. [Requirements traceability](REQUIREMENTS_TRACEABILITY.md): supplied MVP/extensions mapped to actual components and evidence.
3. [Technical report](TECHNICAL_REPORT.md) and [architecture](TECHNICAL_ARCHITECTURE.md).
4. [Current status](STATUS.md), [actual test run](../artifacts/test_summary.json), [UEBA case live proof](../artifacts/behavior_cases_http_smoke_v1.json) and [main-run aggregate proof](../artifacts/behavior_cases_main_summary_v1.json).
5. [AI assistance](../AI_ASSISTANCE.md), [third-party notices](../THIRD_PARTY_NOTICES.md) and [security boundary](../SECURITY.md).

## Reproduce the core without a key or model download

Use Windows and **Python 3.12**. From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements.txt
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe -m sedra.app --port 8765 --data-dir data/runtime-sedra
```

Open `http://127.0.0.1:8765/`. Installation needs the pinned Python packages; the receiver/gateway and generated daily model then operate offline. `Setup-SEDRA.cmd` and `Start-SEDRA.cmd` provide the same Windows route. Optional local AI requires the separately acquired verified runtime/weights; see [LOCAL_AI.md](LOCAL_AI.md). No API key, model binary or private runtime data is committed.

## Inspect behavior and policy

- **Analyst → UEBA → lab-001 → Run real process / file test**: real owned process and ten synthetic test files. Wait for the next Windows/console polls. A source-backed case opens independently of a DLP block. Inspect the typed graph, peak/current priority and review history.
- **Transfer Control**: choose employee lab-001; use the supplied synthetic examples. Sensitive FİN/restricted content blocks; public text can reach the independent local receiver. Original hash, bytes and delivery state are retained.
- **Analyst → UEBA → Why this decision?**: select a recorded request and compare selected recorded rule exclusions. This is a frozen-facts explanation, not a resend or current admission authorization.
- For an isolated repeatable 20% → 10% same-quote proof without old exposure, run `scripts/smoke_behavior_cases.py`. It uses temporary databases, actual scoped Windows observations and loopback HTTP, leaves the main ledger intact and makes no AI call.

Current main-run request IDs in the aggregate report are demonstrations from the developer's local ledger. They are not fabricated seed records in a clean clone. Private exported Windows packets stay local; only aggregate outcomes are in this repository.

## Assessment boundaries

The completed-day Isolation Forest and its lab evaluation are generated synthetic data. The current application rules and opt-in local sensor use observed metadata; neither is a trained enterprise endpoint model. A high score is review/policy priority, not maliciousness probability. The graph is typed relationship evidence, not a claim of causation or exfiltration.

Original file-only CERT v1: **0 TP / 476 positive test user-days**. Its five frozen artifacts are retained and hash checked. Multichannel v2: **unmeasured**, because complete verified acquisition/execution did not finish. No lab result is substituted for CERT efficacy. Physical USB insertion/removal was not tested; no USB was available. Security log access is unavailable and the permitted session-channel fallback is disclosed.

Presentation, offline slides and speaker/Q&A materials are excluded from the repository at the team's request. The final GitHub window is 1 November 2026, 13:00–13:30 Asia/Baku according to the supplied agenda; later organizer instructions take precedence. Historical report metadata normalization is documented in [BRANDING_MIGRATION.md](BRANDING_MIGRATION.md).
