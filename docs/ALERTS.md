# SEDRA security alerts

The local console now has **Alerts** and a notification bell. Select the **Analyst** demo identity, then open `http://127.0.0.1:8765/#alerts`. New gateway policy blocks create alerts for both the independent receiver route and the AI portal route. The original request stays blocked before delivery/inference.

The console checks the feed every two seconds while the tab is visible. A new event shows an in-app banner and unread count on any console screen. This is polling, not guaranteed instant push. Events persist while the browser is closed and appear on return; the build does not deliver background OS, email, Teams, webhook or SIEM notifications.

## Review an event

1. Open an alert by its title or **Investigate**.
2. Inspect subject, event time, destination, original policy decision, delivery state, frozen sensitivity/detector tags, reasons, original SHA-256 and UTF-8 length.
3. **Acknowledge & investigate** changes Open to In review and assigns the local Analyst identity.
4. Choose **Confirmed policy event**, **False positive** or **Expected synthetic test**, then **Resolve alert**. Reopen is available for a resolved alert.

Reading, acknowledgement, resolution and reopening have durable actor/timestamp history and increasing revisions. Concurrent stale updates return HTTP 409 instead of overwriting an analyst action. Action IDs bind the entire operation and make an identical retry idempotent. The local identity selector is simulated authorization, not enterprise SSO or individually attributable production accounts.

Resolution is an analyst assessment. It never unblocks, resends or changes the original enforcement evidence. A false-positive disposition also does not automatically weaken policy. Free-text analyst comments are deliberately absent to avoid accumulating pasted secrets.

## Priority and delivery evidence

Priority is a deterministic review rubric, not a breach probability, validated credential or compromise verdict:

| Event | Priority / evidence |
| --- | --- |
| Private-key envelope, labeled credential or bearer token | Critical; potential credential impact, validity not verified |
| Supported FİN, checksum-valid IBAN or contextual card rule | High; prevented sensitive-data format/context match |
| Restricted registered content or AWS access ID | High; blocked policy/format event |
| Cumulative exposure limit | Medium, or High when the recorded behavior priority is at least 70 |
| Inspection limit or other policy block | Medium; bounded inspection/enforcement event |
| Delivery acknowledgement unresolved | Medium; reliability investigation, not proof of exfiltration |

**DELIVERY_UNKNOWN** creates a separate alert. Receipt reconciliation can change its outcome from Delivery unconfirmed to Delivery confirmed or Confirmed not sent. It does not resend content or close the analyst review. Expired unused reservations do not create alerts; stale in-flight sending transitions to uncertainty conservatively.

## Storage, privacy and completeness

Policy admission and the associated alert insert share one SQLite transaction. A failed alert write rolls back admission. The unique request/kind constraint prevents duplicate alerts on request retries or restart. Delivery-uncertainty transitions also record their alert transactionally. Unchanged ALLOW requests do not produce security alerts; they remain in the normal gateway ledger.

The queue and exports contain masked evidence, detector types and hashes, not the submitted raw text, detected value, provider answer, CSRF token or API key. No raw values are added to notifications. Access to the global queue/detail/action routes is Analyst-only and mutations require the existing CSRF controls. Hashes and employee identifiers still require access controls.

On the first upgrade, retained blocked requests and currently unresolved delivery records are imported once, marked **imported event**, with their original event time. They are not announced as freshly observed events. Historical CERT benchmark rows never populate this operational queue.

The latest 200 alerts load first; **Load older alerts** pages earlier records. Counts are exact across the ledger; search/status/priority/unread filters and export apply to the records loaded in the current console. Activity reset clears request, receipt, alert and alert-action data together and advances the queue generation. Governed labels and label history remain intact. There is no automatic alert deletion or production retention policy in this prototype.

## Reproduce verification

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe scripts/smoke_alerts.py
```

The smoke uses a separate temporary database and real loopback HTTP endpoints; it does not reset the user's running demo. `artifacts/test_summary.json` records the executed suite. `artifacts/alerts_http_smoke_v1.json` records block/retry deduplication, Analyst-only scopes, CSRF rejection, stale revision rejection, lifecycle audit, portal prevention and acknowledgement reconciliation without another receipt. `artifacts/alerts_main_live_v1.json` records the synthetic event exercised against the main local app; saved screenshots document the console notification and analyst review.

These are functional control checks, not detection efficacy measurements or evidence of production notification delivery. Original CERT v1 failed results remain preserved; CERT v2 remains unmeasured.
