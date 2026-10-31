# Real local endpoint to machine API demonstration

Executed 31 October 2026, 17:12:21–17:12:40 UTC against the running local lab. Exact sanitized evidence: [api_endpoint_main_smoke_v1.json](../artifacts/api_endpoint_main_smoke_v1.json). No token, raw Windows packet, prompt body or provider credential is included.

The client created a one-hour key with only `cases:read` and `ueba:read`. Baseline endpoint and effective priority were 0 and the case cursor was 0. The controlled local child created ten synthetic files in the named endpoint-lab folder. Windows CIM observed the owned process and the metadata sensor observed ten actual file creations. The two active rule priorities were 75 (file burst) and 90 (same-run process/file sequence); correlated priorities were not added.

UEBA automatically opened UEBA-000001 before any DLP block. The bearer-authenticated case change feed returned HTTP 200, action OPENED, priority 90, channels file/process and 11 source references. Retrying the original cursor replayed that same event with zero additional revisions. Polling after cursor 1 with generation 0 returned zero new events. This demonstrates at-least-once consumption with consumer deduplication, not exactly-once delivery.

Authentication checks returned 401 without a key, 403 for a write attempted with the read-only key, and 401 after revocation. The test revoked its key in a finally block. The local sensor remained enabled; its finite signals cool while the case retains its peak evidence. The result is functional evidence from a controlled test, not a maliciousness probability, enterprise efficacy result, physical USB test, new logon, company IdP connection or external SOAR integration.

## Repeat locally

With the Windows Python 3.12 lab running at `http://127.0.0.1:8765` in Analyst demo mode:

```powershell
.\.venv\Scripts\python.exe scripts/smoke_api_endpoint.py
```

This is an opt-in live test, excluded from CI: it creates a scoped key, starts the named endpoint sensor/probe, preserves existing activity and writes a sanitized result to ignored `work/api-endpoint-smoke/result.json`. It exits nonzero if required checks fail. It requires neither cloud AI nor SOAR. It intentionally does not use enterprise SSO credentials. A busy probe or full retained-file bound must be resolved before repeating; do not reset an active ledger casually.

For a manual demo, open `/integrations`, choose a one-hour lifetime and the two read scopes above, and issue a key. Keep the secret in the client secret store only. On UEBA, select lab-001 and run **Run real process / file test**. Query `/api/v1/ueba?subject=lab-001` and `/api/v1/cases/changes?after=0` using a Bearer header. Save generation/cursor only after durable processing, then poll with both. Existing activity may update a case rather than open another one. Revoke the demo key afterward. The listener remains loopback-only.
