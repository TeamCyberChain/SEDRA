# SEDRA: five-minute live demonstration

## The story

**“A document can leave an organization one small excerpt at a time. SEDRA relates each transfer to the user's behavioral context, tracks what has already crossed the boundary, and shows what the receiver actually obtained.”**

Lead with that problem, then demonstrate the working control loop. Show the distinction between behavioral investigation, content handling, and delivery evidence through actual requests.

## Before presenting

Start the app using the README. Keep the terminal available, open the workbench, select **Analyst**, and click **Reset demo**. Confirm that transfer counters and receiver receipts are empty. A reset deliberately clears lab evidence; use it only at the rehearsal/demo boundaries described below.

Check the current generated scores for `lab-001` and `lab-002`, the `Araz expansion memorandum`, the restricted test runbook, and the **Context comparison excerpt** button. Keep **Simulate a lost receiver acknowledgement** unchecked until its scene. All documents and identities are synthetic. No actual credentials or organization data are needed.

Rehearse once with the exact submitted code and corpus. Use the displayed fingerprint percentages and resulting states rather than memorized rounded numbers. The same corpus version, empty ledger, fragment order, and identity matter.

## Timed sequence

### 0:00–0:40 — Show the behavioral model

In **Overview**, point to the synthetic provenance label and measured model comparison. Open **Investigation** for `lab-002`; briefly show its features and explanatory signals. Contrast with `lab-001`.

Say: **“We combine explicit behavioral rules with Isolation Forest. Baselines use prior observations and evaluation is chronological. This is the latest completed-day context, not a score invented by today's button clicks.”**

Point out that B is an investigation priority, not maliciousness probability. Mention only the measured metrics visible in this build.

### 0:40–1:05 — Allow ordinary text

Select **lab-001**, open **AI Transfer Lab**, click **Public text example**, then **Evaluate & send**. Show the `ALLOW` policy, `FORWARDED_CONFIRMED` delivery, and the new receiver receipt.

Say: **“This request crossed an actual local HTTP boundary. We have a receiver record and a body hash, not only a green interface badge.”**

### 1:05–1:30 — Block sensitive content despite low behavioral priority

Click **Synthetic secret example**, then **Evaluate & send**. Show `BLOCK`, the reason codes, and the absence of a new receiver receipt for that request.

Say: **“Low behavioral priority does not override a sensitive-content rule. This credential marker is fictional and grants access to no service.”**

### 1:30–2:25 — Demonstrate cumulative disclosure

Stay as `lab-001`. Select **Araz expansion memorandum**. Submit **Fragment 1**, then **Fragment 2**, then **Fragment 3**, inspecting the actual prospective and forwarded coverage after each request.

With the shipped 18-word fragments and a clean ledger, the first two requests are allowed; the third is blocked. The verified prospective fingerprint coverages round to **8.24%, 16.48%, and 24.73%**, respectively. Read the live values if the corpus changes. The normal threshold is 20%.

The policy checks the union of distinct eligible source fingerprints across requests. Show that the blocked request ID has no receiver receipt. Earlier allowed fragments remain recorded as delivered. Do not describe blocked coverage as if every blocked token were necessarily new information.

Say: **“The destination sees a series of small requests. SEDRA also sees their cumulative relationship to a registered source. These percentages measure distinct eligible four-gram fingerprints, not document bytes.”**

### 2:25–3:35 — Hold content constant; change behavioral context

Select **Analyst → Reset demo**. Explain that this starts a clean comparison. Switch to **lab-001**, choose **Araz expansion memorandum → Context comparison excerpt**, and submit it. Show the normal 20% threshold and the outcome.

Switch to **lab-002**. Select the **same document and same Context comparison excerpt** and submit it. Show the same matching evidence, the 10% threshold for B ≥70, and the changed decision. Do not edit the excerpt between subjects.

Say: **“The content and matcher stay the same. The earlier behavioral evidence changes the allowed exposure budget. For restricted content, both subjects would still be blocked.”**

### 3:35–4:25 — Make an uncertain network outcome visible

As an employee, click **Public text example**, enable **Simulate a lost receiver acknowledgement**, and submit. Show the `ALLOW` decision alongside `DELIVERY_UNKNOWN`. Show that the receiver nevertheless recorded the request.

Click **Reconcile with receiver**. Show the transition to confirmed delivery and that reconciliation did not create a second receipt. Uncheck the simulation option afterwards.

Say: **“A timeout does not prove that nothing left. We retain uncertain exposure until a receiver check resolves it, and a retry does not silently create another send.”**

### 4:25–5:00 — Close on the demonstrable value

Return to **Analyst** and show the transfer ledger. Finish with:

**“SEDRA gives the analyst a dated behavioral explanation, the gateway an explicit content rule, and the reviewer a delivery record. The next pilot connects this tested boundary to enterprise identity and an approved AI route, then measures the policy on the target organization's workload.”**

Leave the ledger open for the five-minute question period.

## Three-person ownership

| Owner | Primary responsibility | Must personally explain |
| --- | --- | --- |
| Security/product lead | Problem statement, policy rationale, evidence narrative, final presentation. | Why behavior changes a threshold; why content sensitivity still dominates; deployment scope. |
| Data/ML lead | Feature semantics, temporal splits, labeled evaluation, reproducibility and CERT provenance. | Prior-only baselines, Isolation Forest, calibration, false positives, metric denominators. |
| Application/security lead | HTTP app, matching, SQLite state, receiver proof, live demo and recovery. | Candidate vs confirmed match, cumulative coverage, concurrent admission, idempotency and reconciliation. |

Every teammate should also understand the other two components. Each owner reviews the other person's artifact rather than only its visual output.

### Event checkpoints and internal priorities

All times below are **Baku time (Asia/Baku)**, from the supplied final-version agenda. Later organizer instructions take precedence.

| Time | Event / team objective |
| --- | --- |
| **31 October, 17:00–17:30** | Official Checkpoint 1. Show one complete allowed transfer, one block, model provenance, and the remaining engineering risks. |
| **31 October, 20:30–22:00** | Official implementation/testing period. Stabilize the full path and record reproducible verification. |
| **1 November, 08:30–12:30** | Complete quality checks, separately identified benchmark work, documentation, and repeated timed rehearsal. |
| **1 November, 12:30–13:00** | Official final technical check. Internal target: freeze changes and have the submission ready before 13:00. |
| **1 November, 13:00–13:30** | Official GitHub-push/submission window. Use the organizer's actual final cut-off; do not assume changes are accepted after it. |
| **1 November, 15:00–17:00** | Team presentations: five minutes of presentation/live demo, then five minutes of questions for each team. |

Priority order: **correct working boundary → credible evaluation → repeatable demonstration → presentation polish**. Protect time for a clean-machine startup and a second teammate running the demo without assistance.

## Questions to be ready for

**Is this just an LLM wrapper?**

No LLM is called by the application. The model is an actual Isolation Forest, the content comparison is deterministic, and the decision/receipt path executes real Python, SQLite, and local HTTP operations. ChatGPT assisted development; see `AI_ASSISTANCE.md`.

**Is the receiver a real external AI service?**

It is a separate loopback HTTP server and receipt store, running on another port/thread in the same application process. It demonstrates the boundary and transport outcomes. An external provider connector is a next step.

**Can four words always be blocked?**

The minimum guarantee is an exact normalized four-token **candidate** for a registered source under the supported profile. Public-reference exclusion, classification, and cumulative policy determine the decision. Four tokens are not a universal secrecy or blocking guarantee.

**Can it recognize arbitrary paraphrases, screenshots, or data split into three-word messages?**

Those are outside this exact-matching contract. The prototype does not blindly concatenate separate requests. It also does not aggregate collusion across independent subjects or observe traffic bypassing its gateway.

**Are the displayed scores live employee-risk probabilities?**

They are priorities derived from completed synthetic user-days. Application events are live, while the historical model context stays dated and identifiable. Roles and reference hours affect interpretation; unusual activity alone is not proof of intent.

**Did you evaluate on CERT?**

Distinguish the generated lab from the optional published CERT research dataset. If a CERT run has completed, open its separate report and state the exact source, selected users, label definition, dates, and metrics. Incident-associated copy-day labels are contextual and do not prove every individual copy malicious. Otherwise explain that the adapter exists and the displayed model results remain synthetic-lab results. Downloading a dataset is not an evaluation.

**What exactly is stored, and what happens after a timeout?**

The gateway stores matching evidence, hashes, counts, decisions, and transitions; the demonstration receiver also stores a text preview. Uncertain delivery remains accounted for until trusted reconciliation. Expiry of an unused reservation is different from an uncertain send.

**What can the system do today?**

It returns **ALLOW/BLOCK**, records evidence, performs a local transfer, and reconciles uncertain delivery. Redaction, approval holds, SHAP attribution, case creation, production SSO, and enterprise-wide endpoint or browser coverage are not implemented.
