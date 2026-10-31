# Real local AI demonstration

The portal can use **Qwen2.5-1.5B-Instruct Q4_K_M**, actually generated on the CPU with **llama.cpp**, or the existing optional OpenAI route. The local route does not require OpenAI credits and never silently falls back to a cloud service. It is not a canned-answer mode. Small-model quality is limited; the security gateway is independent of answer quality.

The prepared public workshop question has no eligible protected matches. The initial AI-safety wording matched three distinctive source tokens despite being public wording; this could cause a false block after prior exposure or elevated context. The matcher was not weakened for the demo. The observed sample review is saved in `artifacts/portal_benign_sample_review.json`; population false positives still require a pilot.

## This prepared computer

1. Run `Start-SEDRA.cmd`. When verified local-model files are installed, it starts the managed model on loopback and selects local AI for a newly started SEDRA server.
2. Open **http://127.0.0.1:8765/portal**. Verify **Local AI ready**. Choose **lab-001**.
3. Click **Public workshop question → Check with SEDRA & ask AI**. Read the newly generated response, model ID, output hash and token count. This is real local inference, not an OpenAI reply.
4. Click **Restricted synthetic example → Check with SEDRA & ask AI**. Show **BLOCK**, **Model/provider contact: No** and no model reply.
5. To demonstrate an unrehearsed message, ask `What is 17 plus 25? Answer with the number only.` The executed rehearsal returned `42`; arbitrary model answers are not guaranteed correct.

If a running server still has another route selected, use **Analyst → AI provider: Local AI → Connect for this session → lab-001**. If the local model is stopped, run `Start-Local-AI.cmd` and refresh. Keep both the SEDRA portal and model process running during the demonstration.

## Another Windows computer

Use Python 3.12 and the base source/offline Windows package. Extract **SEDRA-Local-AI-Model.zip** into the same parent folder so its `sedra/data/local_ai/` overlays the base `sedra` directory. The supplement includes the verified CPU runtime, model, source manifest and licenses, and excludes runtime keys and answer caches. Run `Setup-SEDRA.cmd`, then `Start-SEDRA.cmd`. A new private local API token is generated on that computer.

Without the supplement, run `Setup-Local-AI.cmd` once with internet. It downloads from the official ggml-org/llama.cpp release and official Qwen repository, verifies the pinned source hashes and extracts only under `data/local_ai`. Downloads can resume. It does not install a system service, register startup entries, change firewall/security settings or require administrator rights. Weights/runtime are excluded from the source/GitHub package.

## Boundary and reproducibility

- Runtime: official llama.cpp CPU build `b12020` (MIT). Model: official Qwen repository commit `91cad51170dc346986eccefdc2dd33a9da36ead9` (Apache 2.0).
- Model: 1,117,320,736 bytes; SHA-256 `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`. Runtime and per-file digests: `artifacts/local_ai_source_manifest.json`.
- Model service listens only at `127.0.0.1:8769` and requires its generated bearer token for inference. It is not directly called from the browser. Web UI, UI MCP proxy and slots endpoint are disabled. Model prompt logging is disabled. Startup validates the managed runtime and weights.
- Parameters: CPU, 8 inference threads, 4096 context tokens, one model slot, maximum 240 output tokens, temperature 0.2, seed 42; original checked message plus a fixed assistant instruction, no prior conversation or tools. Different CPUs/builds need not be bit-for-bit deterministic.
- Portal destination `local_ai` retains the same hard restricted-content rule, dual-window limits and unapproved-AI exposure class as the cloud route. Moving from cloud to local does not reset the demo budget. A blocked request never calls inference.
- Local inference is independent of the OpenAI daily call budget. Input size, output length and active-request limits still bound CPU use; content disclosure limits still apply. The 20-call cloud cost guard remains active for OpenAI only.
- An answer ID/digest is gateway-observed model evidence, not an independent delivery receipt or proof of model correctness. Timeout remains unknown; the same request ID is not resent. Outputs may repeat inputs and are cached locally until Analyst reset.
- Local token: `data/local_ai/access.key`; never display/share it. The external OpenAI API key remains a separate memory-only setting. Clearing/restarting an OpenAI connection is unrelated to the managed local token.
- Actual browser execution: `artifacts/local_ai_live_smoke.json`. Actual HTTP replay and authentication evidence: `artifacts/local_ai_http_smoke.json`. Contract tests use explicit doubles and are recorded separately.

Official sources: [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF), [llama.cpp runtime release](https://github.com/ggml-org/llama.cpp/releases/tag/b12020).
