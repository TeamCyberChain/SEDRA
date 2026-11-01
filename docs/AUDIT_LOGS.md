# Platform audit and theme settings

Select **Audit Logs** from the operations or AI Workspace navigation. Only the server-authorized Analyst can read/export records. Source and event filters apply to the server query; Load older records uses an exclusive sequence cursor. Export includes only loaded records. Refresh explicitly for current activity; the audit table does not move while reviewing older rows.

## Stored coverage

- API and HTTP: response status, allowlisted route (unknown paths become `/unmatched`), method, server-derived actor, fixed operation enum when available, preparation duration and random request ID. The response exposes `X-SEDRA-Request-ID`. No query/headers/bodies are stored. A recorded response status does not establish provider/receiver delivery.
- APPLICATION: existing document-access, transfer and AI lifecycle audit hooks; only allowlisted identifiers/classification/hash/count/boolean fields are copied. Gateway alerts, revisioned case history and delivery evidence remain authoritative in their original stores.
- UI: page opens, recognized navigation, control clicks, select/checkbox changes, form submission, theme changes and generic errors. No typed values, prompt text, filenames, error messages or stack traces. Reports are bounded to 120/user/minute and a 20-event transient browser queue. Offline browser reports can be lost; UI events are explicitly client-reported and cannot independently prove an action occurred. SSO/CSRF/session requirements remain enforced.

`data/<runtime>/platform_audit.sqlite` is separate from the resettable behavior activity database. It is retained across restart/reset. Collection starts with version 0.13; historical events are not fabricated or backfilled. Append-only through the exposed application APIs, not immutable against a privileged OS/database administrator. No delete/prune endpoint or automatic retention expiry exists. Back up SQLite with its backup API and monitor disk space. Failed writes are counted in memory and surfaced in the audit response/UI; a storage outage cannot guarantee complete retention. Logs and runtime databases remain ignored by Git.

GET `/api/audit?source=API&event=http_response&limit=100&before=<seq>`: Analyst session required, maximum page 200. POST `/api/audit/ui`: same-origin session + CSRF, closed `{event,control}` enums; server supplies actor/time. GET `/api/audit/context`: current session CSRF context only; same-origin policy and optional SSO apply. Audit endpoints do not grant machine keys additional read privileges.

The theme button follows the OS preference until explicitly selected, persists only `sedra-theme=light|dark` in local storage, and synchronizes tabs. Prompt bodies, identifiers, secrets, evidence JSON and original source material are not rewritten by theme changes.
