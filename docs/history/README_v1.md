# SADD — Behavior to boundary

**SADD connects explainable behavioral priority to a real data-transfer decision, then proves what the receiver actually obtained.**

The prototype combines a completed-user-day anomaly model, explicit handling rules for registered documents, cumulative fragment accounting, and a local HTTP receiver. Its central demonstration is a sequence of individually small excerpts that becomes a policy violation when considered together.

## Current verified status

The local gateway and HTTP receiver pass the functional integration checks. The shipped public-data experiment is an **unsuccessful file-only CERT baseline**: at its frozen validation-selected operating points, all three compared detectors have zero true positives on 476 incident-associated positive test days. The recorded result is retained. Controlled lab success demonstrates the implementation; it does not establish external threat-detection efficacy.

Analysts can switch Overview between **Live lab** and **CERT benchmark**. The namespaces, fitted models and evidence remain separate. See [current status](../STATUS.md), [the next declared ML experiment](../NEXT_ML_EXPERIMENT.md), and [the complete blueprint](../BLUEPRINT.md). The next ML gate is source/target alignment and calendar-day cold-start coverage, before extra model complexity or presentation polish.

## Run the workbench

Use **Python 3.12**. The matcher checks its pinned Unicode 15.0 normalization profile; a different Python Unicode database is not silently accepted. Run the commands from this directory, which contains `requirements.txt` and the `sadd/` package.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m sadd.app
```

These commands use the virtual environment directly and do not require changing PowerShell's execution policy.

### macOS / Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m sadd.app
```

Open **http://127.0.0.1:8765/**. The browser needs JavaScript. No Node build step, CDN, API key, or paid AI service is required. After Python dependencies are installed, the default demonstration runs offline.

To choose another port or a separate demonstration ledger:

```bash
python -m sadd.app --port 8766 --data-dir data/rehearsal
```

On Windows, replace `python` in subsequent commands with `.\.venv\Scripts\python.exe` unless the environment is activated. Stop the server with `Ctrl+C`. Keep the default loopback binding for the local demonstration.

## Three screens, one evidence trail

| Screen | What to inspect |
| --- | --- |
| **Overview** | Actual transfer counters, subject priorities, and measured results on the generated synthetic lab dataset. |
| **Investigation** | Completed-day behavioral features, explanations, application access events, and the selected subject's transfer history. |
| **AI Transfer Lab** | Registered document excerpts, gateway decisions, distinct fingerprint coverage, receiver receipts, and delivery reconciliation. |

The header exposes **local demonstration identities**, not enterprise SSO:

- **Analyst:** reviews all lab subjects and request metadata; receiver text previews are masked; can reset the demonstration. Cannot submit employee transfers.
- **lab-001:** lower behavioral priority in the generated fixture; can submit transfers and inspect its own records.
- **lab-002:** elevated behavioral priority in the generated fixture; can submit transfers and inspect its own records.

The HTTP session determines the subject. A caller cannot provide its own subject or behavior score to the transfer endpoint. Mutations require the session CSRF token. Employee views are scoped server-side; only the Analyst role can reset the lab.

## What is implemented

### Behavioral evidence

`sadd/behavior.py` computes personal and eligible peer baselines using earlier observations. The three explicit rules cover unusual copy volume, unusual-hour copying, and novel workstations. A genuine scikit-learn Isolation Forest adds multivariate anomaly information.

Training, validation, and testing follow chronological boundaries. Labels do not enter model features, baseline selection, fitting, or operating-point selection. The default model snapshot is generated from 40 fictional users and carries its provenance, source period, feature version, and model version.

The displayed priority is `B = round(100 × (0.6R + 0.4A))`. These are declared engineering weights. **Priority is not a probability of malicious intent.** The UI displays R and A on a 0–100 scale; the engine stores each on 0–1. This is a completed-day model: clicking a document or submitting a prompt creates a new application event, not an invented instantaneous ML prediction.

### Content matching and policy

`sadd/mosaic.py` indexes every consecutive normalized four-token tuple in the registered source corpus. It supports the documented English/Azerbaijani normalization profiles and excludes tuples found in the registered public reference corpus from protected evidence.

Four matching tokens establish a **candidate** under that profile. They do not guarantee a universal alert or block. Coverage means **distinct eligible normalized source 4-grams divided by that source version's eligible distinct 4-grams**. It is not a percentage of document bytes reconstructed.

For the UI's unapproved `public_ai` route:

- `controlled_excerpt` content is blocked at prospective coverage **≥20%**.
- Behavioral priority **≥70** tightens that limit to **≥10%**.
- Confirmed eligible `restricted` matches and the synthetic secret marker are blocked independently of behavioral priority.

The cumulative ledger is scoped to subject, source ID/version, and destination trust class. Repeated excerpts do not increase distinct coverage. The active window is 24 hours; uncertain delivery remains conservatively accounted for until reconciled.

### Enforcement and delivery proof

`sadd/gateway.py` uses SQLite transactions to reserve exposure before sending. Request IDs bind the subject, original body hash, and destination, preventing retries from silently creating another send. The original request text is forwarded unchanged.

`sadd/app.py` starts a **separate HTTP listener on another loopback port** through `sadd/receiver.py`. That receiver runs in the same application process, on another server thread, and keeps its own receipt database. It is a local receiver standing in for an external AI destination; it is not an external LLM and does not generate AI answers.

An `ALLOW` decision and a `FORWARDED_CONFIRMED` delivery state are distinct facts. The lost-acknowledgement option deliberately produces uncertain delivery after receiver acceptance. Reconciliation checks the receiver before resolving that state. This prototype does not intercept TLS or inspect arbitrary browser/endpoint traffic.

## Verify and rehearse

```bash
python -m unittest discover -s tests -v
```

The tests exercise temporal leakage guards, reproducibility, matching limits, normalization, cumulative accounting, concurrency, idempotency, expiry, uncertain delivery, reconciliation, and persistence. Test counts and performance claims should come from the run being submitted.

For the live sequence and presentation responsibilities, use [the five-minute demo guide](../DEMO_GUIDE.md). Read [the matching contract](../MATCHING_CONTRACT.md) and [the benchmark protocol](../BENCHMARK_PROTOCOL.md) before answering technical questions. AI assistance is disclosed in [AI_ASSISTANCE.md](AI_ASSISTANCE.md).

## CERT dataset reproduction

The source package deliberately excludes the approximately 4.8 GB CERT archive. The runnable synthetic demonstration does not require that archive. Obtain the research dataset from its official record:

- [CMU SEI dataset description](https://sei.cmu.edu/library/insider-threat-test-dataset/)
- [Official CERT Insider Threat Test Dataset record](https://doi.org/10.1184/R1/12841247.v1)

Download using the included helper:

```bash
python scripts/download_cert.py --destination data/cert --extract
```

The default destination is `data/cert`. The helper verifies the pinned archive checksum and extracts only the needed file-copy data, dated LDAP snapshots, and release README. Preserve its acquisition and extraction manifests. Network access is needed for this optional download; normal lab operation remains local. If the archive is already downloaded, verify and extract it with `python scripts/download_cert.py --destination data/cert --extract-only`.

The importer accepts extracted **r4.2 `file.csv`**, dated LDAP files, and the official answer archive. Inspect its available parameters:

```bash
python scripts/cert_ingest.py --help
```

After extraction, reproduce the separate benchmark with this single-line command:

```bash
python scripts/cert_ingest.py --input data/cert/extracted/file.csv --output data/cert/user_days.jsonl --metadata artifacts/cert_source_metadata.json --answers-archive data/cert/answers.tar.bz2 --ldap-dir data/cert/extracted/LDAP --benchmark-output artifacts/cert_benchmark.json --max-users 0 --train-end 2010-06-30 --validation-end 2010-09-30 --expected-size 193055265 --expected-sha256 637281bd6d8947b2cccf90bca7096e8cfad711eab1e425c61f886b0e4edfda7f
```

`file.csv` describes copies to removable media, not general document reads or AI submissions. A positive user-day associates an observed copy by the officially declared incident actor with that incident's inclusive start/end interval. This is contextual incident association, not event-level proof that every copy is malicious. Exact actor-matched file-observable IDs provide supplementary evidence; an entire actor history is not labeled positive. The provenance is `cert_r4.2_master_actor_interval_copy_days`.

The command above reproduces the shipped full-roster experiment with `--max-users 0`. The CLI's optional smaller mode selects users by a label-independent hash ordering; save that as a different experiment. The current experiment evaluates active copy user-days without inventing zero-filled calendar days and is not directly comparable to an all-channel CERT result. CERT itself is a synthetic research dataset.

The default UI shows the separate `synthetic_lab` context. An analyst can select the supplied measured CERT report; the live gateway continues to use lab identities and its own fitted model. Each report retains source hashes, population, splits, support, metrics and limitations. A downloaded archive alone is not a measured result.

## Runtime files and code map

Runtime output defaults to `data/runtime/`: the generated `lab_evaluation.json`, gateway ledger, receiver receipts, and application audit database. Gateway storage keeps hashes and matching evidence rather than raw prompts. The demonstration receiver retains the full submitted payload until an explicit demo reset; the UI exposes a limited or masked preview. The complete application therefore retains content for this controlled proof-of-delivery demonstration.

| Path | Responsibility |
| --- | --- |
| `sadd/behavior.py` | Feature extraction, baselines, Isolation Forest, calibration, evaluation. |
| `sadd/mosaic.py`, `sadd/gateway.py` | Matching, cumulative policy, durable admission, state transitions. |
| `sadd/app.py`, `sadd/receiver.py` | HTTP app, sessions, access scopes, actual local transfer and receipts. |
| `sadd/corpus.py` | Fictional English/Azerbaijani sources and demonstration excerpts. |
| `static/` | Dependency-free three-screen workbench. |
| `scripts/` | Optional research-dataset download and ingestion. |
| `tests/`, `docs/` | Reproducible verification and technical contracts. |

## Next implementation priorities

The implemented policy outputs are **ALLOW and BLOCK**. SHAP attribution, redaction, human-review holds, case creation, enterprise SSO, endpoint/browser coverage, and production AI-provider connectors are future work. The gateway core contains an approved-route policy class, but the current HTTP demonstration exposes only `public_ai`.

A practical next pilot would connect a controlled enterprise identity source and approved AI route, measure false positives on the target population, and validate the handling policy with data owners. The prototype already provides the narrower, testable foundation: dated behavioral context, explicit textual evidence, a durable boundary decision, and independently inspectable delivery receipts.
