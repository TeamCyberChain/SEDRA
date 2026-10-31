# Live AI portal

**Working judge path: Local AI (Qwen / llama.cpp).** A real CPU model is installed and has returned actual answers through SƏDD. Start with [LOCAL_AI.md](LOCAL_AI.md). This requires no OpenAI quota and never silently falls back to cloud. Local and OpenAI routes share policy/exposure accounting but have distinct destination identities.

The OpenAI integration remains available as an explicitly selected alternative. Its actual saved tests returned 401 and then 429, so no successful OpenAI answer is claimed. The instructions below describe that optional external route.

Open `http://127.0.0.1:8765/portal`. The existing three-screen loopback lab remains available at `/` and works offline. The portal is an opt-in external OpenAI Responses API route, not a local canned-answer mode.

## Connect and rehearse

1. Select the local **Analyst** identity. Privately enter an OpenAI Platform API key and an accessible Responses-compatible model (default `gpt-4.1-mini`). Click **Connect for this session**. This saves the key in process memory; it makes no API call. Configured does not mean the provider has authenticated it yet.
2. Select **lab-001**. Click **Public workshop question**, then **Check with SƏDD & ask AI**. Only after SƏDD allows the original message does the server call `https://api.openai.com/v1/responses`. A returned answer shows the model, response ID, original-input hash, observed output hash and token usage.
3. Click **Restricted synthetic example** and send. Verify **BLOCK**, **Provider contact: No**, no AI answer and the hard-policy reasons. Its synthetic credential is never sent to OpenAI.
4. Inspect the original request evidence and the security workspace. The OpenAI route and the local receiver are explicitly different evidence sources.

Use only the fictional bundled examples and public questions in the judge demonstration. No company documents, real credentials or personal data are needed. The employee must deliberately use the SƏDD portal for its checks to apply.

## Transport and evidence

The existing atomic gateway reserves exposure before a durable send claim. Destination `openai_api` belongs to the same unapproved-AI trust class as `public_ai`, preventing budget resets by switching between these demo routes. Server identity and observed behavior determine policy; clients cannot choose a destination, score, subject or provider host.

Requests contain the original permitted message, a fixed assistant instruction, `store:false`, and a 600-output-token limit. They contain no document catalog, UEBA telemetry, API key as prompt text, conversation history or tools. The HTTPS authorization header carries the key. Redirects and automatic retries are refused. API response text renders as text, never HTML. The 4096-input-byte / 20-calls-per-UTC-day limits bound demo usage; the call counter survives demo resets. External usage is billable under the user's API account, and provider model access/billing must be available.

The provider response ID and output digest are **gateway-observed evidence**, not an independent or signed delivery receipt, provider attestation of the original input digest, or proof of provider-side retention/deletion. `store:false` is a requested API storage setting, not a universal zero-retention guarantee. Official references: [text generation](https://developers.openai.com/api/docs/guides/text), [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create), [default model](https://developers.openai.com/api/docs/models/gpt-4.1-mini).

The local gateway stores input fingerprints/hashes, policy and transitions; the portal additionally caches AI output and response metadata in `ai_portal.sqlite` for idempotent recovery until Analyst reset. It does not persist the API key or the input prompt. An AI answer may repeat submitted text, so this cache is potentially sensitive and excluded from source/ZIPs. The independent loopback receiver continues to retain its own fictional payloads until reset. A server restart clears a UI-entered key; **Clear server key** explicitly disconnects. `OPENAI_API_KEY` may alternatively be supplied in the server environment; clearing disconnects the running process, not the environment itself.

## Failure and retry

- HTTP 401: the provider rejected authentication. Correct the API key privately; never paste it into a chat/report. No fabricated answer or offline fallback replaces the error.
- HTTP 403/429: verify account/model permissions, API credits and rate limits. Raw upstream error bodies are never returned or logged.
- Timeout, provider errors or unvalidated responses remain **DELIVERY_UNKNOWN** conservatively. The message may have been transmitted. `provider_contacted: true` means an outbound attempt, not proof of delivery. The same request ID never automatically sends again.
- The UI retains an unresolved request ID for a safe status retry. **Start a new request after an unresolved attempt** is an explicit new-send choice; a prior uncertain call may already have reached the provider. Changing the message also creates a new ID.
- If a valid provider answer was cached before a worker interruption, a retry/reconciliation can use that cache. Otherwise the app does not pretend that absence of a local answer proves non-delivery. With `store:false`, the prototype does not offer provider-side response retrieval.
- With no internet/key, show the offline local-receiver lab and label it accurately. Saved screenshots are previous evidence, not a fresh AI invocation.

## Deployment boundary

This remains a loopback hackathon prototype with selectable simulated roles. It has no enterprise SSO, endpoint agent, browser extension, arbitrary upload, full conversation-history management, output DLP, distributed gateway, tenant isolation or enterprise key vault. Enterprise deployment needs those relevant controls and independent security/false-positive evaluation. The real OpenAI connectivity does not establish threat-detection efficacy.

Contract tests use explicit provider doubles. The separate `artifacts/ai_portal_live_smoke.json` records actual live-provider execution and must be read before claiming a successful AI reply.
