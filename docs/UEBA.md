# SEDRA 0.6 UEBA operations

Open **UEBA** (`/#investigation`). Choose a subject as Analyst, or select lab-001 to exercise the synthetic validation sequence. Current policy context, completed-day evidence and actual app activity are displayed separately. This document describes the 0.6 app profile. Version 0.7 adds a separate opt-in scoped Windows sensor; see [LOCAL_ENDPOINT.md](LOCAL_ENDPOINT.md). Version 0.8 adds independent persistent behavior cases, typed evidence graphs and frozen-policy component comparisons; see [BEHAVIOR_CASES.md](BEHAVIOR_CASES.md). General browsing and endpoint-wide collection remain unconnected.

## Scoring contract

The dated synthetic user-day model remains `iforest-lab-daily-v1`: actual Isolation Forest, prior-only personal/role baselines, chronological training/validation/test, label-free fitting/calibration and frozen triage operating points. Its daily score remains `round(100 × (0.6 × rules + 0.4 × IF tail))`. The new screen shows personal and peer copy medians, role cohort support, 21 completed-day values, exact chart data, declared contributions and the existing detector/actor/alert-load evaluation. These small generated-scenario results are not enterprise efficacy.

The daily component is eligible for current policy only when its timestamp is not in the future, its age is at most 72 hours and it has at least 14 earlier observed baseline days. A stale, future or unsupported record remains visible with its original score but contributes zero to the daily policy component. This is a declared laboratory freshness policy. It does not refresh/retrain the fixed historical model or guarantee data completeness.

Live profile `sedra-app-ueba-v2` uses only server-observed registered-document reads and durable gateway request metadata. Live requests never enter the completed-day IF. Independent delivery/audit records are not counted as extra request attempts. Prompt bodies, detected values, AI answers, scenario labels and actor intent are not scoring inputs.

| Live rule | Exact laboratory activation | Priority |
| --- | --- | --- |
| Protected-content access burst | At least 6 protected reads in 120 seconds | 80 |
| Repeated policy blocks | At least 3 unique blocked requests in 120 seconds | 85 |
| Sustained sensitive attempts | At least 4 blocked requests with supported detector findings in 30 minutes | 75 |
| Multiple sensitive types | At least 3 such requests with 2 different detector types in 30 minutes | 90 |
| Access then sensitive attempts | At least 3 protected reads must precede at least 2 sensitive blocked requests, within 30 minutes | 85 |
| Personal activity deviation | At least 10 current 30-minute app actions and robust deviation at least 6, with sufficient observed baseline | 60, advisory alone |

Protected reads include repeated reads of one document; the distinct-document count is also shown. The sequence rule is temporal correlation, not proof that an attempted value came from the accessed document. All thresholds above are visible engineering settings, not learned probabilities or validated maliciousness. Public messages continue through ordinary policy checks at high priority; supported sensitive matches and Restricted content always block independently of UEBA.

Effective policy priority is **max(eligible daily component, maximum active live rule, input-quality guard)**. Correlated rules are not summed. At 70 or higher, the existing controlled-excerpt 24-hour 4-gram limit tightens from 20% to 10%; anchored-token and 30-day limits remain separately enforced. A source bound of 20,000 document events or 20,000 requests per actor over 28 days activates a distinct quality guard of 80. It is labeled as a quality safeguard, not anomalous behavior, and disables the personal baseline comparison.

The current request is evaluated using earlier recorded observations. It enters subsequent contexts after its durable admission. Independent requests racing concurrently may observe the same preceding context; this is not a serializable cross-database stream processor. Atomic content reservations, request idempotency and delivery transitions retain their existing gateway transaction guarantees.

## Live personal baseline

Only observed app actions from earlier complete fixed 30-minute **active** bins are used, over 28 days. Every bin must end before the current rolling 30-minute window starts. At least 14 active bins across 7 observed UTC days are required. There is no substitution of generated daily records, peer records or imputed idle workdays. Median and scale are unavailable while support is insufficient.

Scale is `max(1, sqrt(median), 1.4826 × MAD)`; the current deviation is `(current actions - median) / scale`. The comparison is a rolling 30-minute count against prior fixed active bins of the same duration. This remains a limited app-activity reference, not a complete work schedule or production time-of-week model. Role-based peer support displayed above it belongs to the separate synthetic completed-day model.

## Evidence and alerts

Each live rule reports observed counts, activation, window, exact source IDs and capped source references. The timeline displays the latest 60 qualifying actions of the last 30 minutes; rule source lists contain at most 12 IDs with an uncapped observed count. Gateway requests are deduplicated by subject/request identity. Future events and other actors are excluded. Block counts are read from durable gateway rows, so a duplicate or missing secondary audit message cannot fabricate or erase those observations.

The gateway freezes the full compact rule/model/policy context at admission. Existing request replays preserve the original decision and context, even after risk changes or live rules expire. Policy-block alerts show that **frozen UEBA context**, while the UEBA subject screen shows current context. Existing Alerts workflow and delivery uncertainty/reconciliation remain unchanged. Live rule activation itself is a current review finding, not an independent new row in the security alert queue; gateway enforcement events generate the durable alert rows.

The current display recomputes on console refresh, normally every 8 seconds; policy admissions compute server context on each new request. Finite live windows decay, and the immutable request/alert record remains for investigation. Activity reset clears the observed app history and live baseline support while preserving governed labels; the fixed generated daily model remains dated.

Employee evidence and export are restricted to the employee's own subject. The Analyst demo role may inspect all fictional subjects. `GET /api/ueba?subject=lab-001` is read-only; no arbitrary endpoint-event ingestion API is exposed. Subject exports contain masked metadata, not raw detector values or provider responses. Source IDs/hashes and identities still require access controls. The local role selector remains a demonstration, not enterprise SSO.

## Safe live validation

Select **lab-001 → UEBA → Run observed sequence**. The button performs 3 real `/api/document` reads and 2 hard-blocked synthetic FİN submissions. It does not call AI inference or send the values to the local receiver. It keeps existing activity; pre-existing events can activate additional rules. Inspect rule evidence and the current 10% budget. Repeating the button deliberately creates a new set of actions; it is not a retry of the same run.

For an isolated before/after with no pre-existing exposure:

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe scripts/smoke_ueba.py
```

The HTTP smoke records an ALLOW at 20%, 3 observed reads and 2 blocked FİN requests, then BLOCK for the same original quote at 10%. It verifies the unchanged SHA-256, frozen retry context/no resend, an allowed public negative control, a local-AI route block before inference, employee scope rejection and live-rule decay. Its temporary database does not reset the user's main demo. Exact results and local response timings belong to `artifacts/ueba_http_smoke_v2.json`; three timings are not a performance benchmark. If the managed local service is absent, only the pre-inference blocked-route check uses an explicitly recorded server-side route fixture; it never attempts inference. `artifacts/ueba_main_live_v2.json` records the main browser scenario and a subsequent block with frozen UEBA evidence.

`artifacts/ueba_before_v1.json` preserves three reproduced prior limitations: future-dated reads counted, duplicate unbacked block audit rows counted and an aged daily score applied without a freshness gate. They are server-side integrity fixtures, not a claim of remote exploitation. Tests cover the repaired boundaries, cold start, ordering, label independence, source deduplication, large reversed sequences, bounded evidence and policy effects.

Original file-only CERT v1 remains **0 TP / 476 positive test user-days**. CERT multichannel v2 remains **unmeasured**. This build adds functional UEBA evidence and operations; independent real-world efficacy, production retention, identity/endpoint integration, time-of-week calibration and prospective shadow-mode validation remain open.
