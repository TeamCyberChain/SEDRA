# AI assistance disclosure

## Tools and contribution

ChatGPT/Codex assisted with concept development, architecture, Python and browser implementation, documentation, adversarial test design, code review, local Windows execution and analysis of tradeoffs. The October 31 v2 iteration reproduced the reported bypasses, added bounded matching and structured detectors, examined benign controls, implemented a separate observed live rule, prepared the multichannel development pipeline and authored the presentation package. No claim of unaided authorship or independent human review is made.

The project uses Python, NumPy, and scikit-learn; dependency versions are recorded in `requirements.txt`. The matching implementation incorporates an attributed Unicode 15.0 property profile, with its source and licensing reference in [MATCHING_CONTRACT.md](docs/MATCHING_CONTRACT.md). Official CERT data and associated documentation are external research inputs when downloaded and used. The fictional lab documents and generated behavioral fixtures are clearly labeled as such.

ChatGPT/Codex assisted development, including the opt-in OpenAI API adapter and portal. The original offline receiver demo calls no LLM. The separate AI portal uses either the real local Qwen2.5-1.5B model through llama.cpp CPU or an explicitly selected OpenAI Responses API route with a user-supplied server-side key. It labels model observations separately from local receiver receipts. Official model/runtime sources, licenses and checksums are recorded; local inference has separate executed evidence. Contract tests use doubles; actual live-provider results have a separate evidence artifact.

## Team responsibility

Codex assisted the 0.8 behavior case store, evidence graph, frozen-policy rule ablation, exact-run/distinct-file endpoint repairs and regression/live verification. Case narratives are deterministic evidence templates, not LLM judgments about employee intent. Internal hash consistency is not described as independent attestation; counterfactual verdicts never authorize a resend. The team must review and explain these boundaries.

Codex assisted the opt-in 0.7 Windows collector, controlled endpoint probe, source/fixture separation, UI and regression/live checks. Real source observations are distinguished from synthetic file content, test fixtures and generated user-day data. Missing Security permissions and untested physical USB are disclosed; production security/identity controls were not modified.

Codex assisted the SEDRA 0.6 streaming UEBA module, evidence UI and regression/HTTP verification. Live scores use declared deterministic rules and sufficient observed app history, not an LLM judgment of employee intent. The existing generated completed-day model and its evaluation remain separate from CERT and from live functional checks.

The SEDRA 0.5 alert queue, masked investigation UI, transaction integration and regression/HTTP smoke checks were also developed with Codex assistance. Alert priorities and workflow transitions are deterministic application rules; an LLM does not judge the alerts or establish compromise. Executed verification is recorded in the current test and alert smoke artifacts.

The submitting team remains responsible for the source code, dependencies, correctness of the demonstrations, measured results, and all presentation claims. AI-generated explanations are not substitutes for executing the software and checking its evidence. A successful automated test does not establish production readiness or general detection accuracy.

Before submission, every teammate should be able to explain:

1. What a completed user-day contains; which history is available at scoring time; how labels are kept out of the model and baselines.
2. How rules and Isolation Forest combine into a priority, and why that priority is not a probability of malicious intent.
3. Separate four-token and anchored-token evidence, public-reference exclusion, their denominators, TR39/encoding limits and the 24-hour/30-day accounting scope.
4. Why content sensitivity can block a low-priority subject, and why elevated behavior only tightens the controlled-excerpt threshold.
5. The difference between a policy decision, a send reservation, a receiver receipt, and an unknown delivery outcome.
6. What is implemented, which tests actually executed, the retained failed CERT v1 result, any completed v2 development result, and what requires a new holdout or enterprise integration.

## Competition rule basis

The supplied **Digital Challenge Azerbaijan — Cyber Hackathon invitation and initial rules**, section 4, rule 6, permits AI tools, internet resources, open-source software, libraries, and other external tools while making the team responsible for their results and for explaining its approach.

Section 4, rule 10, requires disclosure of external components and AI tools when requested, and prohibits fabricated results or misleading authorship claims. This file supplies that disclosure proactively. It does not claim that the prototype was developed without assistance or that organizers have separately approved this particular implementation.

The invitation states that later final rules provided during the event take precedence over conflicting preliminary provisions. The team should apply the final instructions it receives and submit the actual source, evidence, and explanation of its work.

Codex assisted the 0.10 scoped integration APIs, OIDC protocol adapter, administration UI and real loopback protocol/security tests. No external organization SSO or SOAR connection was established; protocol fixtures are labeled local tests.
