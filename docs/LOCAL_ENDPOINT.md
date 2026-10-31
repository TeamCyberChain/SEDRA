# Local Windows endpoint telemetry (SEDRA 0.8)

Select **Analyst → UEBA → lab-001 → Local endpoint evidence**. **Start local sensor** enables this opt-in collector. **Run real process / file test** starts it if needed and launches one owned Python probe that creates ten synthetic text files under the runtime's `endpoint-lab` folder. Windows CIM independently observes the exact launched process ID; a one-second filesystem metadata poll observes the files. No file contents, unrelated processes, command lines or external hosts are collected. Normal app shutdown stops the collector and waits for its owned probe.

The source label is **REAL_LOCAL_OBSERVATION**. The test content/actions are deliberate laboratory fixtures; the resulting OS observations are real. Unit-test event fixtures are separate and are not live OS proof. `SYNTHETIC_TEST` records cannot contribute to the real endpoint score.

## Connected scope

- **Logon/session:** current Windows identity only. Security 4624/4625 events are read when permitted and SID-qualified. The current account cannot read Security here; no privileges, audit settings or OS protections were changed. The accessible LocalSessionManager channel supplies the current identity's genuine session records. Their original timestamps remain intact; ten older records are displayed outside the live window. A current session snapshot is state, never a fabricated new authentication.
- **USB:** fixed local CIM polling of USB disk/removable-volume metadata every five seconds. No drive contents are read. First scan or a gap longer than 30 seconds establishes a presence baseline; it does not invent an insertion. Subsequent observed arrivals/removals are deduplicated against saved presence state. Query failure does not imply removal. This is bounded presence polling, not comprehensive USB driver/device auditing, and disk/volume fingerprints are observations rather than a guaranteed physical-device count. The user has no USB device, so physical arrival/removal was not tested.
- **Endpoint:** process observation is restricted to the exact SEDRA-owned probe PID among direct server children. Files are restricted to `endpoint-lab/sedra-lab-*.txt`, metadata only, no symlink following or other folders, with a 200-file bound. This is not enterprise-wide EDR or proof of which PID performed each file I/O.

The local Windows identity is explicitly mapped to **lab-001** for the lab, not to a production directory identity or HR role. Host/user/device identifiers are salted pseudonyms. Raw Windows usernames, SIDs, IP addresses and process command lines never enter the exported records. The private salt and source records live in runtime SQLite, excluded from release archives. Public evidence artifacts contain aggregate outcomes only. The local Analyst role selector remains simulated, not enterprise SSO.

An installed, policy-permitted PowerShell is required. This computer's legacy `powershell.exe` is blocked by group policy; the already available PowerShell 7 runtime used by this workspace executes the fixed read-only collector script. No execution-policy bypass flag or policy change is used. Collection failure is reported in coverage, rather than replaced by synthetic events.

## Policy response

The endpoint component is separate from both the generated daily IF and app-only live rules:

| Rule | Lab activation | Priority |
| --- | --- | --- |
| Scoped file changes | At least 8 distinct named files in 120 seconds; repeated writes do not multiply the signal | 75 |
| Owned process then files | CIM-observed owned live process preceding 8 distinct files in the same server-issued probe run | 90 |
| USB arrival then files | Actual polled arrival preceding 8 distinct named files | 90 |
| Session event then files | Actual recent logon/reconnect preceding 8 distinct named files | 80 |

These are engineering test thresholds, not evidence of malicious intent or a trained production endpoint baseline. Temporal USB/file correlation does not prove a copy to USB. Session snapshots and older records never activate a logon-sequence rule. Synthetic-origin records never affect this component. Effective policy takes the maximum component; at 70 or above, controlled-excerpt limits tighten. Restricted and supported sensitive data still block independently.

The live endpoint window is two minutes for file/process observations; the timeline retains a 30-minute view plus explicitly historical session records. Admission freezes endpoint context with the original request, and policy blocks use the existing durable alert queue. Version 0.8 separately creates durable UEBA review cases from qualifying observed rules, even without a DLP block. These are distinct from gateway policy alerts. The strongest captured graph survives partial sequence expiry. Stop collection retains evidence and cases; declared live windows still expire. Sensor health reports freshness independently of priority. See BEHAVIOR_CASES.md. Reset is rejected during an active owned probe, then clears endpoint events with activity while preserving the local pseudonym salt and governed labels. Retained test files are not deleted by reset.

## Executed evidence

The main UI's controlled test observed ten real file changes, one actual owned process and the current-session snapshot. Endpoint priority changed **0 → 90**. Genuine older current-identity session records were also collected, without calling them new logons.

`artifacts/endpoint_http_smoke_v1.json` records an independent temporary Windows HTTP run: same quote **ALLOW at 20% → BLOCK at 10%**, same original SHA-256, frozen endpoint context and an alert; public text remains allowed. Two independent receiver receipts cover the pre-context quote and public negative control. Employee control and missing-CSRF requests return 403. `artifacts/endpoint_main_summary_v1.json` contains only aggregate main-run proof. Detailed real source records remain private runtime/scratch data and are not in the ZIP.

Reproduce on the approved local Windows test computer:

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe scripts/smoke_endpoint.py
```

The smoke requires an allowed Windows PowerShell and CIM; it performs actual read-only OS queries plus the named controlled file/process test. It does not generate USB, failed logons or a real new user login. No OpenAI/model inference or external network call is made. The generated daily model, failed CERT v1 result and unmeasured CERT v2 remain separate.

Windows source references: [Security 4624 schema](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624), [Win32_DiskDrive class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive).
