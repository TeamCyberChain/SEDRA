# SEDRA 0.8 — evidence-bound behavior casework

SEDRA now connects an observed behavior sequence, a durable analyst finding and the exact policy consequences in one investigation. This is the demonstrated product distinction; no claim of competitor exclusivity or production detection superiority is made.

## Use the console

1. Open `http://127.0.0.1:8765/#investigation`, choose **Analyst** and investigate **lab-001**.
2. In **Local endpoint evidence**, choose **Run real process / file test**. It starts one owned Python child and creates ten synthetic files in the named local test folder. Windows CIM and filesystem observations are real; their content is synthetic.
3. **Behavior casework** opens a finding independently of a DLP block. Inspect peak versus current live priority, recorded rule references, the evidence graph and exact source metadata. The console refreshes every eight seconds. Input controls are preserved while focused; actions check the current revision.
4. **Acknowledge**, choose a disposition and **Resolve case**. Review status is separate from live activity. The finding and captured evidence remain when the two-minute endpoint window expires. Resolution never sends or unblocks a request. Fresh qualifying unseen source evidence may open another case.
5. Expand **Why this decision?**, select a recorded request, exclude its recorded behavioral components and choose **Compare frozen decisions**. This computes a hypothetical verdict without transmitting text, changing policy, reserving exposure or modifying the original admission.

For the actual main-run samples, `case-main08-quote` is BLOCK at priority 90 / 10%. Excluding both endpoint rules produces ALLOW at priority 0 / 20%, over the original coverage. `case-main08-fin` remains BLOCK even with every behavioral component excluded. These IDs refer to an executed local run, not preloaded state in a fresh archive.

## Case semantics and evidence

An active observed application or endpoint rule at priority 70 or above with resolvable source references creates a case. A generated daily model score alone cannot create an observed-evidence case. Advisory personal-baseline deviation alone is 60 and does not qualify. Synthetic-origin endpoint fixtures never contribute to the real endpoint component.

`behavior_cases.sqlite` stores one latest episode per subject, source IDs already consumed, immutable evidence revisions and analyst actions. Concurrent observations serialize through SQLite transactions. Identical polling does not create revisions; model-age and sensor-heartbeat ages are excluded from the semantic evidence digest. Current priority changes can add a signal-state revision without discarding the strongest captured evidence. Lower-priority activity cannot replace that peak snapshot; it remains available in raw source history and current live views. Equally strong or stronger qualifying activity refreshes the captured graph. Current live priority is refreshed by observed actions or console state assessment, not an independently scheduled decay service. A signal gap over 30 minutes or a resolved finding plus new triggering evidence starts a new episode. Re-reading old evidence does not reopen it.

Snapshots retain rule IDs, source references, original timestamps and origins, bounded gateway metadata, policy context, model freshness, baseline support and sensor freshness. They do not retain raw prompt bodies or use incident/scenario labels. Latest three gateway contexts are included even if they are not triggering evidence. Such nodes have no inferred causal edge simply because they are displayed. Captures are bounded to 40 nodes and 60 edges, with qualified counts visible. The latest 100 cases and 100 history entries per case are returned with truncation/complete-history flags. Older queue pagination, production retention and long-term archival remain open.

Graph edges have explicit, limited meanings:

| Relationship | Evidence required | Claim boundary |
| --- | --- | --- |
| Same server probe run and time | Owned CIM process and later named files carry the same server-issued run ID | Controlled run association; not syscall-level file-writer attribution |
| Registered source match after access | Source ID matches a registered document accessed earlier | Content match and time order; not proof of employee intent |
| Same lab subject temporal context | Endpoint event precedes a gateway request by at most five minutes | Temporal context only; not proof of copying or exfiltration |

Narratives are deterministic templates derived from stored facts. No LLM adjudicates a person, assigns maliciousness probability or invents an incident explanation. The Windows identity binding is an explicit fictional `lab-001` mapping, not enterprise identity resolution.

## Correlation repairs confirmed before implementation

`artifacts/ueba_cases_before_v1.json` preserves the old isolated failure: eight modifications of one file and an unrelated process incorrectly reached 90. The corrected endpoint profile counts distinct file fingerprints; a process/file rule requires at least eight distinct later files in the **same** server-issued run. Two partial four-file runs do not combine into a 90 sequence. The generic eight-distinct-file burst remains a declared lab rule at 75. Finished processes, old creation timestamps and synthetic-origin events cannot establish owned-process evidence. An exact source retry no longer advances the SQLite sequence.

Sensor health reports fresh/pending/stale/partial/stopped independently of behavior priority. Thirty seconds without the required poll is stale. **Stop collection** preserves stored evidence; existing signals expire under their normal windows. Restart refuses duplicate still-stopping workers. No OS security or audit policy is changed.

## Frozen-policy comparison

`policy_explain.py` uses the same four budget limits as gateway admission: 24-hour and 30-day registered 4-gram and distinctive-token coverage. It replays admission-time prospective coverage, original destination trust and original governed labels. First it must reproduce the original verdict under the supported frozen policy profile. Unsupported/incomplete historical contracts produce an explicit unavailable result, never a fabricated ALLOW.

Only rule IDs actually stored in the original request and the eligible completed-day component can be excluded. The score is the maximum remaining component, with quality guards retained. Restricted-content and supported structured-data hard blocks remain. This is **rule ablation over frozen facts**, not a new live admission, a prediction of current eligibility or causal explanation of the Isolation Forest. Current labels, cumulative exposure and live behavior may differ, so an ALLOW comparison is never a permission to resend.

Analyst-only endpoints:

| Endpoint | Behavior |
| --- | --- |
| GET `/api/ueba/cases` | Latest queue, exact global status counts and generation |
| GET `/api/ueba/cases?id=...` | Evidence snapshot, action history and consistency check |
| GET `/api/ueba/cases?id=...&packet=1` | Private packet with complete payloads for returned history |
| POST `/api/ueba/cases/action` | ACKNOWLEDGE / RESOLVE / REOPEN, expected revision and bound idempotent action ID |
| POST `/api/ueba/counterfactual` | Recorded subject/request identity and declared exclusions only |

Mutations require the existing CSRF/Origin protections; employee access is rejected. Revision conflicts return 409. The review database is separate from enforcement; capture failure is diagnostic and does not roll back completed delivery. This separation is not a cross-database atomicity or externally durable case-capture guarantee.

History is SHA-256 chained and the displayed snapshot is checked against a recorded revision. This detects ordinary inconsistent changes. It is a **self-contained consistency check, not a signature or independently trusted attestation**; a privileged database writer can recompute the chain. Private exports include Windows metadata and must stay out of public submission archives. Production needs externally trusted retention/access controls and enterprise identity.

## Executed verification

The full suite executed **184 tests, zero failures/errors/skips**. Twenty-one new tests cover false-correlation boundaries, same-run isolation, PID lifetime, source retry stability, case persistence/concurrency/idempotency/revision conflicts, history inconsistency, frozen replay and hard-policy invariance, authorization/CSRF and no resend.

`artifacts/behavior_cases_http_smoke_v1.json` records a separate real Windows loopback run: independent case before the first DLP block, priority 90, same-payload ALLOW → BLOCK at 20% → 10%, frozen BLOCK → hypothetical ALLOW with no resend/unblock, FİN still blocked, retained quiet case, analyst workflow, 403/409 checks and consistent bound evidence history. `behavior_cases_main_summary_v1.json` contains aggregate results from the main application. No private Windows packet is packaged.

Reproduce on the authorized Windows test computer:

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe scripts/smoke_behavior_cases.py
```

The smoke uses temporary isolated databases and does not reset the main application or contact an AI provider. USB hardware was unavailable; physical USB insertion/removal remains untested. Security-log access remains unavailable; permitted session-channel records keep their original times. Live personal history remains insufficient until the declared support gate is met. Original CERT file-only v1 remains **0 TP / 476 positive user-days**, with all five artifacts unchanged. CERT multichannel v2 remains **unmeasured**. Functional sequence checks are not a population efficacy or false-positive estimate.
