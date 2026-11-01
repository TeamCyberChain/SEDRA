# SEDRA 0.17: focused UEBA, MFA and operational reporting

## Navigation

UEBA expands into Summary, Cases, Detection logic, Activity & sources, Endpoint, Models & baselines and Coverage. Each has a stable `/#ueba/<section>` address. Cases remains Analyst-only. Timeline tables have bounded scrolling; full latest application records and case graphs are collapsed. The same evidence and server authorization remain in place. No detection efficacy improvement is inferred from these presentation changes.

## Mandatory account MFA

Every configured local account, including Administrator and newly created Users, must complete password verification and an authenticator step before any application API is accessible. Bootstrap ends at enrollment. Legacy password-only sessions do not qualify. Account owners enroll on `/login`, using a local QR/manual setup key and the first valid code. QR generation does not contact a third party. Setup is ephemeral until successful verification and pending challenges expire after five minutes. No endpoint returns an enrolled seed.

The implementation follows [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238): six digits, SHA-1, 30-second step and one adjacent step of clock tolerance. A transaction rejects repeated counters, including concurrent requests. Five persisted attempts in five minutes limit guessing; disable/password reset invalidate pending and full sessions through the account authentication version. A late unauthorized background poll cannot replace a completed sign-in cookie. Keep server/phone clocks accurate. Session duration remains eight hours; there is no per-action step-up.

Ten random single-use recovery codes are returned once on enrollment; only their SHA-256 digests are stored. They replace the authenticator step, never the password step. Save them separately from the password. Seed values are Fernet-encrypted; the master key is protected with Windows DPAPI under the service's Windows account. Back up both `accounts.sqlite` and `accounts.sqlite.mfa.key` securely, and preserve the original Windows profile/DPAPI material. A copied database/key pair alone is not a portable Windows recovery procedure. Missing keys with existing enrollments fail closed. On non-Windows test hosts the key is a local mode-0600 file; that is a different protection boundary.

There is deliberately no public MFA-disable/reset bypass. Loss of both authenticator and recovery codes requires an operator-reviewed recovery procedure; automated recovery and WebAuthn are not implemented. TOTP is not phishing resistant and no NIST assurance-level compliance is claimed. See [NIST authentication guidance](https://pages.nist.gov/800-63-4/sp800-63b.html). Local accounts and OIDC remain mutually exclusive. OIDC login now requires signed `amr` evidence containing `mfa` or both `pwd` and `otp`; configure the organization's IdP to enforce MFA and emit these claims. A real organizational tenant has not been connected. Non-human scoped API keys remain independent credentials.

## Executive dashboards

Analyst/Administrator Dashboards contains Executive overview, Data protection, Behavior & review and Source coverage, with 24-hour, seven-day and thirty-day windows. Transfer totals and daily trend query the complete observed gateway window. Breakdowns use at most 5,000 latest records and disclose truncation. Current case status and current live priority are separately defined; the synthetic completed-day score is excluded from executive high-priority counts. No monetary savings, breach prevention or organization-wide collection rate is invented. A zero or quiet state is not proof of safety. Endpoint status refers to the explicit local test binding.

## Generated reports

Reports generates three saved templates: Executive security brief, Security operations report and Activity and delivery report. Exports are PDF, CSV and JSON. The security PDF includes destination/live-review detail; activity includes the dated gateway trend. All include scope, window, definitions, provenance limitations and a snapshot digest. A User can create/read only Activity reports for their current bound subject. Analyst/Administrator can create authorized aggregate or subject reports. A role downgrade never grants access to a previously saved global report through ownership alone.

Snapshots are immutable through application APIs and persist in `reports.sqlite` across restarts and activity reset. Canonical JSON SHA-256 detects inconsistent stored payloads; it is not a signed attestation or protection from an OS administrator. The store has no deletion/automatic pruning API, so operators must monitor disk use and apply a retention policy before sustained deployment. Creation is limited to five snapshots per owner per minute. Generation and exports record metadata-only audit events; raw prompts, credentials, enrolled MFA seeds and endpoint packet bodies are excluded. PDF rendering is local using ReportLab; the dependency is included in offline wheels.

This is a loopback prototype. TLS ingress, tenant provisioning, durable centralized key custody, prospective UEBA calibration and independent enterprise evaluation remain production gates. The historical CERT file-only v1 zero-TP result and unmeasured multichannel v2 status are unchanged.

The optional `--start-local-sensor` startup flag explicitly resumes the same scoped Windows metadata collector after a service restart. It is off by default, changes no OS policy and does not run a probe or fabricate USB/logon events. The existing authorized Start/Stop controls remain available on UEBA → Endpoint.
