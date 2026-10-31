# SEDRA 0.4 — governed metadata and sensitivity

SEDRA means Sensitive Enterprise Data Risk Assurance. This update covers the local application; it does not add endpoint discovery, enterprise identity or a third-party labeling connector.

## Use the inventory

1. Start with Start-SEDRA.cmd and open http://127.0.0.1:8765/#inventory.
2. Select Analyst, open a registered asset and inspect its metadata.
3. Set sensitivity, data owner, business tags and the declared change reason, then Save governed labels.
4. Select an employee before sending a request through Transfer Control or AI Workspace. Other loaded tabs should be refreshed after an identity change.

The inventory supports search by name, ID, owner and business tag, and filtering by sensitivity. Employees may read metadata but cannot change labels. Identities are simulated local roles, not enterprise SSO.

## What each tag means

| Field | Source | Effect |
| --- | --- | --- |
| Public | Registered public source | Excluded from protected matching; cannot be upgraded through this editor because the matching index excludes it. |
| Confidential | Registered controlled-excerpt source | Existing behavior-aware 24h and 30d disclosure budgets apply. |
| Restricted | Fixed registered source or analyst upgrade of a controlled source | Recognized protected matches block, irrespective of behavior priority. |
| Business tags | Analyst-governed closed vocabulary | Descriptive context: research, finance, engineering, operations, intellectual property, public communications, credentials, demo synthetic. No independent policy effect. |
| Detector tags | Existing structured rules | Supported credential/PII types block when detected; evidence retains type, representation and hash, not the detected value. |
| Unclassified request | No eligible protected source match or structured finding | Not a public-data certification. Unknown sensitive material can remain undetected. |

Catalog detector tags describe the registered original text. Request detector tags describe the inspected outgoing message, including supported bounded normalization/encoding views. A business tag called credentials does not by itself prove that an arbitrary payload contains a credential.

## Durable policy and history

Document content versions and original hashes remain fixed. Governed labels have a separate monotonically increasing revision. SQLite serializes a label update with gateway admission using BEGIN IMMEDIATE. Stale expected revisions fail instead of silently overwriting a concurrent change. The HTTP mutation requires Analyst, a valid current session, same-origin checks and CSRF.

Each new request stores the matched documents' label snapshots and derived request tags. Changing a label affects new admissions. An idempotent replay retains its original decision and revision; it does not cause another send. Already admitted reservations are not retroactively revoked. The pre-existing send-claim, TTL, unknown-delivery and reconciliation contracts are preserved.

The registered Restricted floor cannot be downgraded. A controlled source can be restored from an analyst-added Restricted label to its original Confidential floor, with another audited revision. Public sources remain Public in this interface. Structured credential hard blocks cannot be disabled through labels.

Activity reset clears synthetic requests, replies, receiver receipts and application events, but preserves governed labels and their history. Restore an analyst-added restriction explicitly in the inventory when preparing the original fragment demo. A new data directory starts with registered defaults.

## Boundaries

Discovery covers four registered synthetic texts. The metadata identifies this source explicitly. There is no arbitrary file upload, filesystem crawl, endpoint agent, OCR, semantic classifier, Microsoft Purview integration or cloud-drive sync. Registered matching and structured detectors have finite coverage; their tags are evidence, not an assertion that all sensitive information has been found. Owners are demonstration teams, not directory-synchronized business owners. Label history is application-audited, not externally signed or tamper-proof against a local database administrator.

Original source fixtures, the sadd Python package and model aliases keep legacy names to preserve matching manifests and runtime compatibility. Historical CERT v1 still has zero true positives; v2 is unmeasured. UI changes and functional tests do not establish detection efficacy.

## Verification

Run `.venv\Scripts\python.exe scripts/verify.py` for the executed 118-test suite. Run `.venv\Scripts\python.exe scripts/smoke_sedra.py` with the installed local model running for isolated real HTTP admission, labeling, inference and reconciliation checks. The latter uses temporary synthetic ledgers and saves `artifacts/sedra_live_smoke.json`; it does not reset the user's main app.

The structured-data detector profile in 0.4 scans supported outgoing values independently of the registered corpus. See STRUCTURED_DATA_CONTROLS.md for its separate scope and checks.
