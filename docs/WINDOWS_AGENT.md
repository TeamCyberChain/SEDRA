# SEDRA Windows Agent 0.20

This is an installable native Windows Service pilot, separate from the existing in-process local sensor. It sends bounded metadata to `/api/v1/endpoint/events`. Python is not required on the endpoint. Windows 10/11 or corresponding Server and .NET Framework 4.8+ are required. Build with `windows-agent/Build-Agent.ps1`; customer packages include the executable, installer/uninstaller, example configuration and this guide. The current build is unsigned: organizational approval/code signing is a deployment gate, not something the installer bypasses.

## Enroll and install

1. In SEDRA **Identity & Integrations**, create a named credential with **only `endpoint:write`**, exactly one registered subject and an expiry. The response supplies a server-generated device ID, subject ID and one-time secret. The UI shows the device/subject separately. Keep the secret out of the config, source, command line, chat and projected screen. The server retains its hash. This is explicit device-to-subject assignment; it is not automatic company-directory enrollment.
2. Copy `agent.example.json`. Set the HTTPS server origin, enrolled device/subject, assigned employee Windows SID, explicitly approved nonrecursive directories and optional process-name allowlist. Empty process names disables process collection. The service account SID is **not** the employee SID. Target identity must be configured by the organization. Only already registered SEDRA subjects can currently be enrolled; directory provisioning remains separate.
3. Set up reviewed TLS ingress to the loopback SEDRA server. The backend still binds to loopback and validates its Host; it is not silently exposed on the network. A reverse proxy must forward the endpoint API with Host `127.0.0.1:8765`. The customer agent validates the normal Windows certificate chain, refuses HTTP except explicit literal-loopback testing, refuses URL credentials/query/fragment/path bases and does not follow redirects. No certificate-validation bypass is provided. Private CA trust must be managed by the organization.
4. Run the installer in an elevated, policy-permitted PowerShell session:

```powershell
.\Install-Agent.ps1 -ConfigPath C:\Deployment\agent.json -Start
```

The installer asks privately for the endpoint credential. It passes it over stdin, encrypts it with DPAPI LocalMachine and protects the dedicated directories with Administrators, SYSTEM and the exact service SID. The service runs as `NT AUTHORITY\LocalService`, with automatic delayed startup and bounded recovery backoff. It does not run as SYSTEM or change audit/execution/EDR policies. It grants the service SID directory-list/attribute access to the explicitly selected watch folders. Review those ACL changes with the customer. Existing unrelated installation/data directories and reparse targets are refused; binary and writable data directories must not overlap.

Default binary/data locations are `%ProgramFiles%\SEDRA\Agent` and `%ProgramData%\SEDRA\Agent`. The service command line contains paths and service name, not the secret. Microsoft describes [LocalService's local privileges and network identity](https://learn.microsoft.com/windows/win32/services/localservice-account) and the [ServiceBase start/stop lifecycle](https://learn.microsoft.com/dotnet/api/system.serviceprocess.servicebase.onstart).

5. Verify locally and centrally:

```powershell
Get-Service SEDRAAgent
Get-Content "$env:ProgramData\SEDRA\Agent\status.json"
```

Open **Identity & Integrations → Windows endpoint agents → Refresh agents**. The directory shows reported source coverage, last-contact freshness, enrollment status and dropped count. **UEBA → Endpoint** shows the bound subject's agent events and separate agent score. A heartbeat is not proof that every source works; unavailable/overflow channels remain visible.

An optional reviewed reverse-proxy configuration is in `windows-agent/Caddyfile.example`. It exposes only the ingestion path. It is not installed, does not open firewall ports and does not configure a real customer hostname/certificate automatically.

## Collection and privacy

| Source | Collected metadata and boundary |
| --- | --- |
| Files | FileSystemWatcher in at most eight explicit directories, nonrecursive. Salted path fingerprint and create/change/rename/delete kind. No file content is opened. No writer-process attribution is inferred. |
| Processes | Optional bounded process-name allowlist, filtered at WMI subscription and by configured employee SID. Salted process-instance/name fingerprints. No command line. Unavailable permissions/providers are reported. |
| USB | CIM disk presence, salted device fingerprints. First scan, restart or a long gap establishes a baseline; it does not invent insertion. No drive contents or USB-copy proof. |
| Sessions | Future LocalSessionManager logon/logoff/disconnect/reconnect records matching the explicitly configured account. No fabricated current-session logon; no historical replay is claimed across service downtime. No Security-log privilege is silently granted. |

The account SID and approved paths exist in protected local configuration. The API accepts only closed fingerprint/operation schemas, never raw paths, process names, SIDs, file contents, command lines or client-provided scores. Salted fingerprints are pseudonyms, not anonymous data. Source is `AUTHENTICATED_ENDPOINT_REPORT`: a key holder's report, not independent kernel/OS attestation. A compromised endpoint/key can forge reports within its binding. No driver, tamper resistance, automatic response, process termination, USB blocking or remote execution channel is included. Browser content blocking remains the separate Browser Guard/portal responsibility.

## Delivery, outage and identity

Events receive stable IDs and are persisted as atomic, flushed per-event files before upload. A single-instance data lock prevents concurrent workers on one enrollment directory. Capacity is 10,000 spool records / 8 MiB; capacity/expiry losses increment a persisted counter. Sources can also lose events during OS buffer overflow or downtime; this is not a complete activity archive. No content enters the spool.

Batches contain at most 50 events. Failed/uncertain requests retain their original IDs, timestamps and spool files, with bounded exponential retry. Files are removed only after an exact bound acknowledgment of every sent ID and matching accepted/duplicate counts. The server transaction deduplicates `(device,event_id)`; changed facts under an existing ID return 409 and roll back the batch. A lost acknowledgment cannot multiply a file/behavior count. TLS/HTTP/JSON failures are reflected in the protected status file without upstream bodies or secrets. Permanent config/auth errors require operator action; no silent cloud/server fallback occurs.

Spool records expire after six days with loss accounting; the server accepts nonfuture records up to seven days old. Delayed records retain their original time and cannot manufacture current two-minute activity. Agent records/enrollments survive the demonstration activity reset; current cases may be recaptured from still-active agent evidence. Server metadata retention prunes records older than eight days on ingestion, with 100,000 records/device capacity. Current pilot enrollment bounds are 256 devices total and 16 per subject. Archive/case capture is separately bounded. Production capacity and retention require review.

Enrollment origin/device/subject are bound to the local credential and queue directory. Reprovisioning an existing directory to another identity is refused. Credential expiry/revocation stops subsequent authorization; key renewal is not automatic. For a replacement device identity, use a new reviewed enrollment/data directory and retain/reconcile the old spool explicitly. Do not copy an old spool into another employee's enrollment.

## Server policy and evidence

Eight distinct watched-file fingerprints on one enrolled device in 120 seconds produce a declared priority of 75. Actual reported USB arrival before eight such files produces 90; matching logon/reconnect before files produces 80. Device files are never combined across devices to meet the count. A process start alone has no score and is not treated as proof that it wrote a file. Thresholds are engineering pilot settings, not validated maliciousness probabilities.

Agent priority participates in the maximum-component policy and tightens controlled-excerpt budgets at 70. Restricted/structured hard blocks remain unchanged. Case graphs retain the authenticated-report provenance and original source IDs. Generated daily personas are explicitly excluded from policy for enrolled agent subjects; their recorded model values remain visible for research. This prevents generated history being passed off as customer baseline. Agent events do not train the separate application personal baseline or a new enterprise IF model.

## Stop, remove and recovery

```powershell
Stop-Service SEDRAAgent
.\Uninstall-Agent.ps1
```

Uninstall verifies the exact expected binary path before stopping/removing only its service. It retains encrypted enrollment, spool, binaries and explicitly granted folder ACLs for operator-reviewed cleanup. It does not delete unrelated files. Reboot/service restart preserves the spool. Back up protected data under the organization's endpoint-access policy; DPAPI LocalMachine is tied to that Windows installation. No credential is included in customer packages.

## Executed verification

`tests/test_agent_telemetry.py` exercises HTTP device/subject/scope authorization, revocation, closed schemas, event-time bounds, concurrent retries, atomic conflicts, delayed-event/device isolation, generated-profile exclusion, cases and same-text policy changes.

`scripts/smoke_windows_agent.py` builds on real Windows execution: native collection of ten distinct synthetic files, availability failure, lost acknowledgment after commit, spool replay/drain, a source-backed case and same-original-hash ALLOW → BLOCK. `--service` uses the actual SCM installer, verifies LocalService/Running/Auto, observes real file metadata and removes the isolated test service. CI retains the exact tested executable and reports.

The developer laptop denied native EXE execution with WinError 5 and is not elevated. Its policy was not bypassed and no standalone service was installed there. `artifacts/windows_agent_local_execution_v1.json` records that boundary. A local compile or synthetic HTTP test is never described as an executed service pass. Use the exact-head Windows CI reports for native/service results; customer-specific TLS, permissions, real USB/process/session events and directory identity still need a consented pilot.
