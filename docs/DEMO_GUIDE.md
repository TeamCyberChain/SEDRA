# Five-minute demo guide

Use six core slides and keep slides 7–8 for Q&A. English speaking text is in SPEAKER_SCRIPT_EN.md. Event times use Asia/Baku.

## Preparation

Connect power. Open http://127.0.0.1:8765/ and the local presentation. Choose Analyst and Reset demo; verify zero requests and receipts. Keep live_smoke.json, test_summary.json and actual CERT reports ready. Choose lab-001 for transfers. Use only fictional bundled examples.

| Time | Action | Evidence |
| --- | --- | --- |
| 0:00–0:30 | Slide 1: purpose | Behavior, enforcement, receiver proof |
| 0:30–1:05 | Slide 2: cumulative excerpts | Declared 8.24 / 16.48 / 24.73% example |
| 1:05–1:45 | Slide 3: architecture | Dated model, live rule, atomic gateway, local receiver |
| 1:45–2:20 | Lab-001 / Run fragment sequence | Two deliveries, third BLOCK, two receipts |
| 2:20–2:55 | Load Same-text context comparison / send / Replay 6 document accesses / send again | Same body hash, ALLOW then BLOCK |
| 2:55–3:10 | Load Two-word restricted excerpt / send | Hard restricted-content block |
| 3:10–3:40 | Public text / lost acknowledgement checkbox / send / reconcile | UNKNOWN with receipt, then confirmed without another send |
| 3:40–4:25 | Slide 5: evaluation | Actual tests, retained failed v1, completed v2 development result only |
| 4:25–5:00 | Slide 6: pilot and limits | Enterprise next steps, scope and AI disclosure |

The six-access action executes actual audited document requests. Its rule lasts 120 seconds: submit the comparison promptly. The completed-day model remains dated and unchanged. Restricted/credential blocks never depend on low/high behavior.

Invite judges to edit the synthetic examples. Short anchors, distinctive evidence, source classification and cumulative policy determine a decision. Do not claim every two-word phrase blocks or describe coverage as bytes reconstructed.

## Live local AI answer (replace the lost-acknowledgement segment if using the portal)

Preferred prepared route: run Start-SEDRA.cmd, verify Local AI ready at `/portal`, choose lab-001, send Public workshop question, then Restricted synthetic example. Show the generated answer and blocked-before-model result. Ask an unrehearsed public question if time permits. Read LOCAL_AI.md. Local Qwen is real inference on this computer, not an OpenAI reply or a canned fallback.

### Optional OpenAI alternative

Before presenting, privately configure the connection at `/portal`; never project or paste the key. Open lab-001, send Public workshop question and show the actual answer/model/response ID. Send Restricted synthetic example and show BLOCK with Provider contact: No. Provider observations are not the independent receiver receipts. A 401/error is not an AI success: use an actually working key or label the offline receiver demonstration. Detailed setup and recovery: AI_PORTAL.md.

## Recovery

- Existing sequence ledger: Analyst → Reset demo → lab-001.
- After server restart: refresh and choose identity again.
- Two local ports: port-specific cookies isolate their sessions.
- Unknown delivery: inspect the receipt and reconcile; never create a new send to resolve it.
- Server unavailable: inspect the launcher window and restart the installed lab if needed.
- Live failure: state the observed failure and use saved live_smoke.json/screenshots. Do not present saved evidence as a new live run.

## Event checkpoints

Supplied by user: 31 October 2026 17:00 checkpoint; 1 November 13:00–13:30 final GitHub window; five-minute presentation plus five-minute Q&A. Confirm later organizer changes.
