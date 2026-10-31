# SEDRA 0.8 technical report

Team CyberChain · Digital Challenge Azerbaijan 2026 · Topic 6 · 31 October 2026 development review snapshot.

## Problem and implemented result

SEDRA connects user behavior evidence to governed outbound AI access. The local prototype builds explainable completed-day behavior profiles, assesses observed application/scoped endpoint sequences, applies registered-content and structured-data controls before sending, and records the difference between policy permission and confirmed delivery. The current build adds independent behavior casework and a read-only explanation of how recorded behavioral components affected an admission.

The supplied source MVP is one-log baseline, three anomaly rules and a risk panel. Graph correlation and investigation are extensions. [Requirements traceability](REQUIREMENTS_TRACEABILITY.md) maps these to files, observed results and open gaps. [Architecture](TECHNICAL_ARCHITECTURE.md) describes the modules and trust boundaries.

## Behavioral methods and separation

`behavior.py` generates a deterministic completed-day laboratory dataset, fits a real scikit-learn Isolation Forest and evaluates chronological user-day splits. Personal/role context uses earlier available history. Incident/scenario labels are evaluation inputs, not model/baseline inputs. Rules, anomaly tail score and their declared combination are visible, with actor/alert-load measures. These generated results cannot establish enterprise efficacy.

`ueba.py` separately reads actual protected-document access and durable gateway metadata. Declared 120-second/30-minute rules consider bursts, unique blocked requests, sensitive attempts/types, ordered access-to-attempt sequences and supported personal active-window deviation. Personal live norms need at least 14 earlier active bins across seven observed days; missing support remains explicit. A dated daily model contributes only within the declared 72-hour freshness/quality contract. Effective policy priority takes the maximum eligible component, avoiding summation of correlated rules.

`endpoint.py` is an opt-in Windows test sensor. Process/file correlation requires an actually observed owned process plus at least eight distinct later named files in the same server-issued run. Repeated modifications of one file and separate partial runs cannot satisfy that sequence. Current-identity historical session records retain original dates; current-session snapshots are not new authentication. USB polling was implemented but no physical USB was available. Security-log access is unavailable. This is scoped collection, not an enterprise endpoint agent.

## Governance and prevention

Governed asset labels and revisions are stored with the admission snapshot. Restricted-content matches and supported structured findings block independently of behavioral priority. FİN, supported IBAN structures/checksums, contextual payment cards and credential forms use explicit format/context checks; they do not verify actual identity/account ownership. Unicode/confusable/AZ transformations and bounded one-level Base64 inspection produce additional comparison views without changing outbound text.

Controlled excerpts use separate 24-hour and 30-day registered 4-gram and distinctive-token limits, tightened at priority ≥70. Exposure reservations and send transitions use SQLite transactions. Request identity binds actor, original body hash and destination. Unused reservations expire; uncertain sends remain counted until trusted reconciliation. Reconciliation never resends. Local receiver proof records original request/actor/hash/byte count. Provider responses are observed API results, not an independent receiver or cryptographic attestation.

## Evidence and casework

Source-backed observed rules can open a case before a DLP block. The case retains its strongest captured evidence as live priority cools, with separate review status, support/freshness, typed relationships and bounded source counts. Analyst actions use expected revisions and idempotent action IDs. A SHA-256 revision chain checks internal consistency and binds the displayed snapshot; a privileged writer can recompute it, so it is not independent attestation. Private Windows packets are excluded from Git.

Frozen-policy comparison first reproduces the original verdict under a supported contract. It then excludes selected recorded rules and/or the eligible daily component while retaining hard controls, quality guards, original labels, destination and admission-time exposure. The comparison cannot resend, change labels, reserve exposure or authorize a current admission. Deterministic narratives and rule ablation are not causal explanations of ML or judgments of intent.

## Executed results

| Check | Actual result | Evidence |
| --- | --- | --- |
| Full local regression | 184 tests; 0 failures/errors/skips | `artifacts/test_summary.json`, `test_output.txt` |
| Extracted archive checks | 21 targeted tests; 75 code-file hashes matched final checkout at verification | `artifacts/behavior_cases_archive_check_v1.json` |
| Actual Windows sequence | Independent case before first block; live priority 90; same quote ALLOW 20% → BLOCK 10% | `artifacts/behavior_cases_http_smoke_v1.json` |
| Frozen comparison | BLOCK → hypothetical ALLOW, original stays BLOCK and no resend; FİN remains BLOCK | Same isolated live artifact and main aggregate |
| Investigation persistence | Peak process/file graph retained through partial expiry and quiet state; revisioned expected-test resolution and consistent export | Case smoke, `behavior_cases_main_summary_v1.json` |
| Original CERT file-only v1 | 0 TP / 476 positive test user-days; failed configuration, preserved | Five original pinned artifacts in `artifacts/v1_package_manifest.json` |
| CERT multichannel v2 | Unmeasured; verified acquisition/execution incomplete | `artifacts/research_progress.json`, frozen protocol and current status |
| Local model | Earlier actual Qwen replies observed; managed local provider still available | `local_ai_live_smoke.json`, `local_ai_http_smoke.json`, `sedra_live_smoke.json` |
| OpenAI | No successful reply claimed; earlier account returned 401/429 | AI portal evidence and guide |

GitHub CI is configured to execute local tests on Windows with Python 3.12, read-only workflow permissions and no provider secrets. Its remote result must be read from the actual run; configuring CI does not count as a pass. Functional regression cases are not a population false-positive/recall estimate.

## Reproduction, scope and remaining work

Follow [REVIEWER_GUIDE.md](REVIEWER_GUIDE.md) for clean setup and isolated live proof. Activity reset requires Analyst, rejects an active send/probe, clears demo activity/cases and preserves governed labels; named test files and private service material are not published. Never reset or test an unauthorized environment.

Enterprise identity, collection/interception, trusted retention, cross-node admission, general cloud/email/VPN/endpoint telemetry and prospective independent efficacy remain open. Semantic paraphrase/translation/OCR, arbitrary nested encoding and cross-identity collusion are outside the current matcher. Finite windows are not lifetime protection. Original v1 is failed; v2 must not be described as measured success. Presentation/Q&A updates are deferred and earlier materials are retained as history.

AI-assisted development and external components are disclosed in [AI_ASSISTANCE.md](../AI_ASSISTANCE.md) and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). The team remains responsible for reviewing, explaining and submitting the actual work under the organizers' final instructions.
