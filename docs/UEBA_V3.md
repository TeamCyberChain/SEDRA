# UEBA v3: scope, isolation and evidence

This release strengthens the application UEBA path, not the CERT detection model. The original file-only CERT v1 result (0 true-positive test user-days) and the unmeasured multichannel experiment remain unchanged. Scores are triage priorities, not probabilities or proof of employee intent.

## Identity and least privilege

Local User accounts receive one explicit synthetic subject binding. Their state, UEBA export, request/event/receipt lists and portal subjects are scoped to that binding. Population evaluation and alternative workspace identities are omitted. Audit, alert/case review, account operations, integration credentials and endpoint control remain separately protected by server authorization; privileged navigation is also hidden. The registered demonstration corpus is a shared library, not personal account data. Two accounts sharing a subject binding share that subject's context; this is not automatic real employee identity resolution.

`ilham.mammadli` is provisioned locally as User, bound to User 001. Its generated initial password stays outside Git and chat in the user's protected local credential folder. No human credential is embedded in tests or deployment artifacts.

## Detection and baseline discipline

| Component | Evidence and boundary |
| --- | --- |
| Completed-day rules + Isolation Forest | Dated synthetic snapshot; only eligible when timestamp is nonfuture, within 72 hours and supported by at least 14 history days. It is not inference over partial live days. |
| Personal live activity baseline | Earlier complete active 30-minute bins, 28-day lookback; at least 14 bins over 7 days. No zero-filled quiet periods or substitution of synthetic history. Deviation alone is advisory at 60. |
| Burst rules | Protected reads and distinct durable blocked requests over 120 seconds. Repeated source IDs and request retries do not multiply observations. |
| Sequence/type rules | Ordered protected access and supported sensitive attempts over 30 minutes; correlation does not establish value origin, causation or intent. |
| Distributed sensitive attempts | Rolling 24 hours, at least 12 distinct sensitive blocked requests, 4 distinct active half-hour bins and 2 hours between first and last. Priority 75; a declared engineering threshold awaiting pilot calibration. |
| Local endpoint | Explicit local test mapping; owned process, scoped file metadata, available current-identity logon observations and removable presence. No physical USB arrival is claimed without observation. |
| Policy | Maximum of eligible components, never a sum of correlated scores. Input saturation is a separate quality guard. Restricted-content/structured-sensitive hard policy remains independent. |

Baseline comparison follows the general behavior-profile approach described by [MITRE D3FEND Web Session Activity Analysis](https://d3fend.mitre.org/technique/d3f%3AWebSessionActivityAnalysis/). Access and audit tests are implementation checks, not a NIST certification; [NIST SP 800-53A Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf) describes assessment of access and audit controls.

## Evidence and case behavior

The display timeline stays capped at 60 recent 30-minute records. A separate bounded projection retains current rule references across each rule's declared window, including older 24-hour sources. Referenced gateway metadata takes precedence over ordinary latest activity, so a busy public timeline cannot erase the case's source hashes. Source bounds, provenance and incomplete-history states remain explicit.

Case episodes use the longest active qualifying rule window, preventing each two-hour distributed attempt from opening a separate episode. Resolved findings still require fresh source evidence to reopen a new case. Case review status and current live priority are independent. The UI labels frozen evidence and its capture time separately from the current score; original stored snapshots/hashes are not rewritten for presentation.

## Executed checks and limits

The initial reproducer observed a single duplicated read source producing priority 80 and twelve attempts spread over 22 hours producing priority zero. The same controlled inputs now produce zero and 75 respectively. These are functional before/after cases, not false-positive/recall estimates.

Regression coverage includes actor/time boundaries, event/request deduplication, support/cold-start gates, stale/future snapshots, non-summation, public/inspection-error negative controls, distributed-window count/span gates, expiry, durable HTTP-ledger evidence, capture after newer public records and episode aggregation. User isolation is tested through direct API requests as well as live browser sign-in. Real-time synthetic access/block validation is separate from the clock-controlled 24-hour fixture; no 24-hour enterprise pilot is claimed.

Remaining validation gates: a prospective, consented shadow pilot; independently evaluated CERT/enterprise models; calibrated alert load and false positives; sustained collector coverage, identity resolution and organizational response workflows. Missing/quiet telemetry is not proof of benign behavior. See NEXT_ML_EXPERIMENT.md for the untouched holdout requirement.
