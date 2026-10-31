# Security and review scope

SEDRA 0.8 is a local hackathon prototype. Run it on loopback with fictional documents and identities. Its development HTTP server and identity selector are not enterprise authentication. Do not expose the listener publicly or point the demonstration scripts at production systems.

The Windows sensor is opt-in and scoped to the current identity's permitted session records, removable-presence metadata, one owned test child and named synthetic lab files. It does not modify OS audit/security settings. General endpoint traffic, browser interception, enterprise SSO and unrestricted filesystem inspection are not implemented.

Only reviewed source, synthetic fixtures, attribution and reproducible aggregate results belong in Git. Keep all `data/`, `.venv/`, `work/`, raw CERT archives, runtime databases, `.env` files, API keys, generated service tokens and private Windows case packets local. `scripts/check_repository.py` checks the tracked boundary and selected credential patterns; it is not a complete secret scanner or security certification.

An allowed AI request can reach the selected provider. Prefer the local model for offline tests. The OpenAI route requires an explicitly configured key and available quota. Never submit actual customer, employee or company secrets during review. Cached responses can repeat inputs and are also private runtime data.

Report a finding privately to the repository owner through the agreed competition channel. Include version/commit, synthetic reproduction steps, expected/actual behavior and whether any send occurred. Do not post real credentials, source Windows records or another team's information in an issue. The existing authorization, CSRF, reservation, unknown-delivery and reconciliation boundaries must remain intact during review.
