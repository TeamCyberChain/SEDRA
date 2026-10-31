# SEDRA prototype status

## Working build

This package contains an executable local application with three screens, an actual Isolation Forest pipeline, a registered-text matcher, durable SQLite admission, a separate localhost HTTP receiver and source-linked reports. Its identities and live documents are synthetic. The public CERT dataset is also synthetic, but is independently published and has separate fitted models and provenance.

The complete current functional result is recorded by `artifacts/test_summary.json`; `artifacts/test_output.txt` lists the executed checks. The tests include real loopback HTTP delivery, role scoping, CSRF, payload digest and byte counts, cumulative admission, concurrency, idempotency, unused-reservation TTL, uncertain delivery, Unicode/Azerbaijani normalization, data leakage guards and dataset completeness checks.

The exact demonstration excerpts produce these observed outcomes on a fresh ledger:

| Scenario | Observed result |
|---|---|
| Public request | Reaches the local receiver unchanged |
| Recognized synthetic secret | Blocked; no receiver receipt |
| Normal subject, first 18-word Araz fragment | 8.24% eligible fingerprint coverage; forwarded |
| Same subject, second fragment | 16.48% cumulative coverage; forwarded |
| Same subject, third fragment | 24.73% prospective coverage; blocked |
| Same 32-word comparison excerpt | 15.93%; normal context forwards, high context blocks |
| Receiver accepts, acknowledgment discarded | DELIVERY_UNKNOWN, then receiver-validated reconciliation |

Coverage is distinct eligible normalized 4-grams, not document bytes or guaranteed reconstruction. The 20%/10% limits apply only to the explicitly permitted controlled-excerpt document class. Restricted excerpts and recognized test-secret markers remain blocked regardless of behavior.

## Actual CERT acquisition

The official 4,824,287,500-byte r4.2 archive was downloaded and checked against its published SHA-256. The extracted copy log is 193,055,265 bytes and was independently re-extracted and verified against its recorded member digest after a partial local copy was detected. Partial-source benchmark outputs were quarantined and are not included in this package.

The valid source contains **445,581 events**, which produce **45,907 active copy user-days** from **264 copy-active identities**. The dated LDAP roster contains **1,000 identities**. The latter does not mean the copy log behaviorally observes all 1,000 people. Metadata, the release README, checksums and extraction evidence are in `artifacts/data_provenance/`.

## Public-data performance gate failed

The frozen file-only experiment has 14,963 training, 8,861 validation and 18,812 test user-days. It excludes 3,271 warm-up observations. The test period is 2010-10-01 to 2011-05-16. Labels mean actual copies by a declared insider during the official incident interval; they are not per-copy maliciousness labels.

| Detector | TP | FP | FN | TN | Average precision |
|---|---:|---:|---:|---:|---:|
| Rules | 0 | 0 | 476 | 18,336 | 0.025719 |
| Isolation Forest | 0 | 120 | 476 | 18,216 | 0.022285 |
| Combined | 0 | 100 | 476 | 18,236 | 0.025451 |

All three have zero recall at their frozen operating points. With zero rule alerts, rule precision is mathematically undefined; the JSON uses an explicit zero-denominator convention. The fixed validation alert budget was one per 100 user-days; achieved test workload is reported separately.

Coverage-adjusted actor and incident recall is 0/40. Eight incidents have no observed copy in their test interval, ten have copies but insufficient prior copy-active history, and twenty-two have scoreable positive copy days. All forty remain in the denominator.

The diagnosis identifies three separate limitations. The contextual labels are dominated by 471 scenario-2 days although its official observables contain device, HTTP and email rows and no exact file rows. Fourteen prior copy-active days can exclude a first-use incident even when the employee has existed for months. Finally, 481 maximum rule scores tie in validation against a budget of 88, causing the conservative rule threshold to move above its attainable range. IF and combined ranking are also weak, so changing that threshold alone cannot establish efficacy.

The original experiment remains reproducible in `cert_benchmark.json`, its model artifact, run summary and failure diagnosis. Its poor result is evidence for changing the next experiment, not a successful detector claim.

## Verification boundary

Python and frontend syntax checks and actual local HTTP integration tests were executed. Browser visual QA remains unverified: the managed preview runs in a separate environment that lacks the required NumPy package. The normal Python 3.12 startup and dependency commands are in the README. No public deployment was performed.

The interface uses simulated local identities; enterprise authentication, broader traffic capture, redaction/hold workflows, SHAP, semantic paraphrase detection and cross-user collusion prevention are not part of this first build.
