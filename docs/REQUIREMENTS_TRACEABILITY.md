# Supplied requirements → implementation → evidence

Basis: the team-supplied [Topic 6](sources/topic-6.pdf), [final agenda](sources/hackathon-agenda.pdf) and [initial rules transcription](sources/hackathon-rules.txt). This maps the supplied materials to the current build; it does not invent later organizer requirements or declare organizer acceptance.

| Supplied requirement | Current implementation | Reviewable evidence / boundary |
| --- | --- | --- |
| Baseline behavior from one log source | Past-only per-user/role completed-day features; actual Isolation Forest; separate live active-window baseline support gate | `sedra/behavior.py`, `sedra/ueba.py`, `artifacts/lab_snapshot.json`; lab model is generated, not enterprise efficacy |
| Three anomaly rules | Completed-day volume deviation, after-hours copying and novel workstation context; six separate live app rules | `sedra/behavior.py`, `sedra/ueba.py`, explained UEBA UI; rule scores and ML tail score shown separately |
| Explainable risk panel | Daily/peer comparisons, trend, freshness, support, live rule source IDs and max-component policy context | `static/ueba.js`, `docs/UEBA.md`; no fabricated cold-start history |
| Investigation workflow extension | Independent durable behavior cases, peak evidence, typed graph, ACK/RESOLVE/REOPEN and private export | `sedra/behavior_cases.py`, `static/cases.js`, `artifacts/behavior_cases_http_smoke_v1.json` |
| Multisource correlation / graph extension | Observed application metadata plus opt-in current-identity session/removable-presence/owned-test process/files; typed, bounded relationships | `sedra/endpoint.py`, `docs/BEHAVIOR_CASES.md`; exact test-run association is not syscall attribution or proof of exfiltration |
| Sensitive transfer to a public LLM | Portal admission before local/OpenAI provider contact, structured sensitive controls, restricted-content hard policy, controlled-excerpt budgets | `sedra/gateway.py`, `sedra/ai_portal.py`, `docs/STRUCTURED_DATA_CONTROLS.md`; only this application's routes are controlled |
| Context-sensitive DLP | High eligible priority tightens four cumulative coverage limits; same original body flips with observed behavior | `artifacts/behavior_cases_http_smoke_v1.json`; hard content blocks stay unconditional |
| Reproducible data science | Frozen provenance, chronological splits, labels outside features, alert-load/actor measures, retained failed CERT baseline and frozen next protocol | `docs/BENCHMARK_PROTOCOL.md`, `docs/NEXT_ML_EXPERIMENT.md`, `artifacts/cert_benchmark.json`; v1 failed, v2 unmeasured |
| Functional/security checks and technical evidence | 184 executed local tests; loopback and real local Windows smoke; clean archive code/import check | `artifacts/test_summary.json`, `artifacts/behavior_cases_archive_check_v1.json`; GitHub CI has a separate execution status |
| Source, technical report and documents in GitHub | Reviewed source/tests/dependencies, current reports, reproducible setup/reset, evidence, provenance and attribution | `README.md`, `docs/TECHNICAL_REPORT.md`, `docs/SUBMISSION_CHECKLIST.md`; private repo restricted to named review accounts |
| AI/external component disclosure (initial rules 6 and 10) | AI contribution description, team verification responsibility and dependency/dataset/license attribution | `AI_ASSISTANCE.md`, `THIRD_PARTY_NOTICES.md`; no claim of unaided authorship |
| Five-minute demo and five-minute Q&A | Presentation/demo and Q&A remain final-event requirements | Materials are excluded from this repository at the team request; no completed current presentation is claimed |
| Authorized test environment and confidentiality | Loopback deployment, fictional corpus/identities, scoped opt-in sensor, private repository and excluded private runtime material | `SECURITY.md`, `scripts/check_repository.py`; not a production deployment or legal compliance certification |

The topic mentions broader email/VPN/cloud/upload sources as examples. SEDRA does not claim every example is connected: email, VPN, general browser/cloud interception, privilege escalation telemetry and enterprise identity remain open. The source MVP and implemented extensions are distinguished above.

Agenda times (Asia/Baku): 31 October 17:00–17:30 checkpoint; 1 November 12:30–13:00 final technical check; 13:00–13:30 GitHub submission; 15:00–17:00 presentations with five-minute demo and five-minute Q&A per team. This review push does not by itself complete the organizers' final submission procedure.
